#!/bin/bash
# ============================================================
# DEFER — vLLM on the RTX 5090 node ("A51"), serving only.
#
# The harness, tool stubs, MMA gateway and ChromaDB all run on the H200
# server; this node exposes one OpenAI-compatible endpoint on the LAN,
# protected by an API key.  The H200 side reaches it through
# REMOTE_5090_URL / REMOTE_5090_API_KEY in its .env.
#
#   ./scripts/a51_vllm.sh start llama8b    # Role 2: Llama-3.1-8B primary (llama8b_div4)
#   ./scripts/a51_vllm.sh start attacker   # Role 1: gpt-oss-20b for E4/E5 (optional)
#   ./scripts/a51_vllm.sh wait  llama8b
#   ./scripts/a51_vllm.sh status
#   ./scripts/a51_vllm.sh stop
#
# One role at a time (32 GB).  Weights under $MODELS_DIR (set in .env):
#   meta-llama/Llama-3.1-8B-Instruct   (gated: HF_TOKEN needed to download)
#   openai/gpt-oss-20b                 (Role 1 only)
# Download with:  huggingface-cli download <repo> --local-dir "$MODELS_DIR/<repo>"
#
# .env on this node needs:
#   MODELS_DIR=/path/to/models
#   REMOTE_5090_API_KEY=<same random string as in the H200's .env>
# ============================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
[ -f "$REPO/.env" ] && set -a && . "$REPO/.env" && set +a
MODELS_DIR="${MODELS_DIR:-$REPO/models}"
LOG_DIR="${LOGS_DIR:-$REPO/logs}/vllm"
PID_DIR="$LOG_DIR/pids"
mkdir -p "$LOG_DIR" "$PID_DIR"
CONDA_ENV="${CONDA_ENV:-agenticcyops}"
VLLM_BIN="${VLLM_BIN:-vllm}"
BIND_HOST="${A51_BIND_HOST:-0.0.0.0}"     # LAN-facing; the API key gates access
API_KEY="${REMOTE_5090_API_KEY:-}"

# role | port | served name | args
declare -A SPEC
SPEC[llama8b]="8008|meta-llama/Llama-3.1-8B-Instruct|$MODELS_DIR/meta-llama/Llama-3.1-8B-Instruct --dtype bfloat16 --enable-auto-tool-choice --tool-call-parser llama3_json --gpu-memory-utilization 0.90 --max-model-len 16384"
SPEC[attacker]="8009|openai/gpt-oss-20b|$MODELS_DIR/openai/gpt-oss-20b --enable-auto-tool-choice --tool-call-parser openai --gpu-memory-utilization 0.90 --max-model-len 16384"

_field() { echo "$1" | cut -d'|' -f"$2"; }

cmd="${1:-status}"; role="${2:-llama8b}"
case "$cmd" in
    start)
        spec="${SPEC[$role]:-}"; [ -z "$spec" ] && { echo "unknown role '$role' (llama8b|attacker)"; exit 2; }
        port=$(_field "$spec" 1); served=$(_field "$spec" 2); args=$(_field "$spec" 3)
        model_path="${args%% *}"
        [ -d "$model_path" ] || { echo "[FAIL] weights not found: $model_path"; exit 1; }
        [ -n "$API_KEY" ] || { echo "[FAIL] REMOTE_5090_API_KEY is empty in $REPO/.env (must match the H200's .env)"; exit 1; }
        if curl -s --max-time 1 "http://127.0.0.1:${port}/health" > /dev/null 2>&1; then
            echo "[skip] $role already answering on :$port"; exit 0
        fi
        echo "[start] $role  port=$port  served=$served  bind=$BIND_HOST"
        nohup conda run --no-capture-output -n "$CONDA_ENV" \
            $VLLM_BIN serve $args --served-model-name "$served" --port "$port" \
            --host "$BIND_HOST" --api-key "$API_KEY" --enforce-eager \
            > "$LOG_DIR/a51_${role}.log" 2>&1 &
        echo $! > "$PID_DIR/a51_${role}.pid"
        echo "        log: $LOG_DIR/a51_${role}.log"
        echo "        H200 .env: REMOTE_5090_URL=http://<this-node-ip>:${port}/v1"
        ;;
    wait)
        spec="${SPEC[$role]:-}"; [ -z "$spec" ] && { echo "unknown role '$role'"; exit 2; }
        port=$(_field "$spec" 1); elapsed=0
        while ! curl -s --max-time 2 -H "Authorization: Bearer $API_KEY" "http://127.0.0.1:${port}/v1/models" > /dev/null 2>&1; do
            sleep 10; elapsed=$((elapsed + 10))
            [ $elapsed -ge 900 ] && { echo "[FAIL] $role not up after 900s (see $LOG_DIR/a51_${role}.log)"; exit 1; }
        done
        echo "[  ok] $role on :$port (${elapsed}s)  version=$(curl -s http://127.0.0.1:${port}/version | tr -d '\n' | head -c 60)"
        # tool-calling smoke: structured tool_calls must come back (v1 Group J failed silently here)
        conda run --no-capture-output -n "$CONDA_ENV" python3 - <<EOF
import json, os, sys
from openai import OpenAI
c = OpenAI(base_url="http://127.0.0.1:${port}/v1", api_key="${API_KEY}")
tools = [{"type": "function", "function": {"name": "block_ip", "description": "Block an IP at the firewall",
          "parameters": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}}}]
ok = 0
for i in range(5):
    r = c.chat.completions.create(model="${served}", temperature=0.7, seed=i, max_tokens=200, tools=tools, tool_choice="auto",
        messages=[{"role": "system", "content": "You are a SOC responder. Use tools when an action is needed."},
                  {"role": "user", "content": f"Alert {i}: credential stuffing from 10.0.5.{10+i}. Block the source."}])
    tc = r.choices[0].message.tool_calls
    ok += bool(tc)
print(f"tool-calling smoke: {ok}/5 responses carried structured tool_calls")
sys.exit(0 if ok >= 3 else 1)
EOF
        ;;
    status)
        for r in "${!SPEC[@]}"; do
            port=$(_field "${SPEC[$r]}" 1)
            if curl -s --max-time 1 "http://127.0.0.1:${port}/health" > /dev/null 2>&1; then echo "[ up ] $r :$port"; else echo "[down] $r :$port"; fi
        done
        nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader 2>/dev/null | sed 's/^/        /'
        ;;
    stop)
        for f in "$PID_DIR"/a51_*.pid; do
            [ -f "$f" ] || continue
            pid=$(cat "$f"); kill -0 "$pid" 2>/dev/null && { pkill -P "$pid" 2>/dev/null; kill "$pid" 2>/dev/null; echo "[stop] $(basename "$f" .pid)"; }
            rm -f "$f"
        done
        for r in "${!SPEC[@]}"; do port=$(_field "${SPEC[$r]}" 1); for pid in $(lsof -ti :"$port" 2>/dev/null); do kill -9 "$pid" 2>/dev/null || true; done; done
        echo "[done] stopped"
        ;;
    *) echo "usage: $0 {start|wait} <llama8b|attacker> | status | stop"; exit 2 ;;
esac
