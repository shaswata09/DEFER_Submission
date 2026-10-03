#!/bin/bash
# ============================================================
# DEFER — named vLLM profiles for the 5x H200 server (G2)
#
#   ./scripts/vllm_profiles.sh start q235     # Qwen3-235B TP=4 + V1 + V5
#   ./scripts/vllm_profiles.sh start mid      # Scout TP=2, V1, V5, V2 + V7
#   ./scripts/vllm_profiles.sh wait  q235     # block until every server answers
#   ./scripts/vllm_profiles.sh status
#   ./scripts/vllm_profiles.sh stop           # stop every vLLM started here
#
# Profiles:
#   q235  GPU0-3 Qwen3-235B-A22B BF16 TP=4        :8000
#         GPU4   Qwen3-32B (V1) util 0.50          :8002
#         GPU4   Mistral-Small-3.2-24B (V5) 0.40   :8003
#   mid   GPU0-1 Llama-4-Scout BF16 TP=2          :8004
#         GPU2   Qwen3-32B (V1) 0.90               :8002
#         GPU3   Mistral-Small-3.2-24B (V5) 0.90   :8003
#         GPU4   DeepSeek-R1-Distill-32B (V2) 0.52 :8005
#         GPU4   Qwen3-14B (V7) 0.30               :8007
#   glm   like q235 with GLM-4.7-FP8 on GPU0-3   :8001  (optional)
#
# Mistral-Small-3.2 and Llama-4-Scout are multimodal checkpoints; the testbed
# is text-only, so the image modality is disabled (--limit-mm-per-prompt
# {"image":0}).  This also sidesteps the transformers-5 / mistral_common
# image-processor incompatibility that aborts vLLM 0.19 at startup.
#
# All weights are served in BF16 (the v1 precision); no quantization anywhere.
#
# Every server is bound to 127.0.0.1 (the harness runs on this box) and
# announces its model as <org>/<name> (--served-model-name), so clients
# never depend on the local weights path.  Co-located servers on one GPU
# are started sequentially; the sum of --gpu-memory-utilization per GPU
# stays <= 0.92.  Weights are read from $MODELS_DIR (default <repo>/models).
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
# --enable-auto-tool-choice is added per server, only where a --tool-call-parser
# is given (vLLM refuses the flag without a parser; DeepSeek-R1 is validator-only).
# CUDA graphs are on (no --enforce-eager): on this box eager mode gave only
# 17 tok/s per stream for the BF16 235B primary.  Precision is unchanged --
# every server is --dtype bfloat16, nothing is quantized.  VLLM_EAGER=1
# restores eager mode (slower, less start-up time and memory).
COMMON="--host 127.0.0.1"
[ "${VLLM_EAGER:-0}" = "1" ] && COMMON="--enforce-eager $COMMON"

# name | gpus | port | served name | extra args
declare -A SPEC
SPEC[q235_primary]="0,1,2,3|8000|Qwen/Qwen3-235B-A22B-Instruct-2507|$MODELS_DIR/Qwen/Qwen3-235B-A22B-Instruct-2507 --tensor-parallel-size 4 --dtype bfloat16 --tool-call-parser hermes --gpu-memory-utilization 0.90 --max-model-len 32768"
SPEC[glm_primary]="0,1,2,3|8001|zai-org/GLM-4.7-FP8|$MODELS_DIR/zai-org/GLM-4.7-FP8 --tensor-parallel-size 4 --dtype auto --tool-call-parser glm47 --reasoning-parser glm45 --gpu-memory-utilization 0.90 --max-model-len 32768"
SPEC[v1_shared]="4|8002|Qwen/Qwen3-32B|$MODELS_DIR/Qwen/Qwen3-32B --dtype bfloat16 --tool-call-parser hermes --gpu-memory-utilization 0.50 --max-model-len 16384"
SPEC[v5_shared]="4|8003|mistralai/Mistral-Small-3.2-24B-Instruct-2506|$MODELS_DIR/mistralai/Mistral-Small-3.2-24B-Instruct-2506 --dtype bfloat16 --tokenizer-mode mistral --tool-call-parser mistral --limit-mm-per-prompt {\"image\":0} --gpu-memory-utilization 0.40 --max-model-len 16384"
SPEC[scout_primary]="0,1|8004|meta-llama/Llama-4-Scout-17B-16E-Instruct|$MODELS_DIR/meta-llama/Llama-4-Scout-17B-16E-Instruct --tensor-parallel-size 2 --dtype bfloat16 --tool-call-parser llama4_pythonic --limit-mm-per-prompt {\"image\":0} --gpu-memory-utilization 0.90 --max-model-len 32768"
SPEC[v1_full]="2|8002|Qwen/Qwen3-32B|$MODELS_DIR/Qwen/Qwen3-32B --dtype bfloat16 --tool-call-parser hermes --gpu-memory-utilization 0.90 --max-model-len 32768"
SPEC[v5_full]="3|8003|mistralai/Mistral-Small-3.2-24B-Instruct-2506|$MODELS_DIR/mistralai/Mistral-Small-3.2-24B-Instruct-2506 --dtype bfloat16 --tokenizer-mode mistral --tool-call-parser mistral --limit-mm-per-prompt {\"image\":0} --gpu-memory-utilization 0.90 --max-model-len 32768"
SPEC[v2_shared]="4|8005|deepseek-ai/DeepSeek-R1-Distill-Qwen-32B|$MODELS_DIR/deepseek-ai/DeepSeek-R1-Distill-Qwen-32B --dtype bfloat16 --gpu-memory-utilization 0.52 --max-model-len 16384"
SPEC[v7_shared]="4|8007|Qwen/Qwen3-14B|$MODELS_DIR/Qwen/Qwen3-14B --dtype bfloat16 --tool-call-parser hermes --gpu-memory-utilization 0.30 --max-model-len 16384"

declare -A PROFILE
PROFILE[q235]="q235_primary v1_shared v5_shared"
PROFILE[glm]="glm_primary v1_shared v5_shared"
PROFILE[mid]="scout_primary v1_full v5_full v2_shared v7_shared"

_field() { echo "$1" | cut -d'|' -f"$2"; }

start_server() {
    local name="$1" spec="${SPEC[$1]}"
    local gpus port served args
    gpus=$(_field "$spec" 1); port=$(_field "$spec" 2); served=$(_field "$spec" 3); args=$(_field "$spec" 4)
    local model_path="${args%% *}"
    if [ ! -d "$model_path" ]; then
        echo "[FAIL] $name: weights not found at $model_path (set MODELS_DIR in .env)"; return 1
    fi
    if curl -s --max-time 1 "http://127.0.0.1:${port}/health" > /dev/null 2>&1; then
        echo "[skip] $name already answering on :$port"; return 0
    fi
    # still loading from an earlier start: never launch a second copy on the same GPUs
    if [ -f "$PID_DIR/${name}.pid" ] && kill -0 "$(cat "$PID_DIR/${name}.pid")" 2>/dev/null; then
        echo "[skip] $name is already starting (pid $(cat "$PID_DIR/${name}.pid")); waiting for it"; return 0
    fi
    echo "[start] $name  gpus=$gpus  port=$port  served=$served"
    local tool_flag=""
    [[ "$args" == *"--tool-call-parser"* ]] && tool_flag="--enable-auto-tool-choice"
    CUDA_VISIBLE_DEVICES="$gpus" nohup conda run --no-capture-output -n "$CONDA_ENV" \
        $VLLM_BIN serve $args --served-model-name "$served" --port "$port" $tool_flag $COMMON \
        > "$LOG_DIR/${name}.log" 2>&1 &
    echo $! > "$PID_DIR/${name}.pid"
}

wait_server() {
    local name="$1" spec="${SPEC[$1]}" timeout="${2:-1800}" elapsed=0
    local port; port=$(_field "$spec" 2)
    while ! curl -s --max-time 2 "http://127.0.0.1:${port}/v1/models" > /dev/null 2>&1; do
        sleep 10; elapsed=$((elapsed + 10))
        if [ $elapsed -ge $timeout ]; then echo "[FAIL] $name not up after ${timeout}s (see $LOG_DIR/${name}.log)"; return 1; fi
        if [ -f "$PID_DIR/${name}.pid" ] && ! kill -0 "$(cat "$PID_DIR/${name}.pid")" 2>/dev/null; then
            echo "[FAIL] $name exited (see $LOG_DIR/${name}.log)"; return 1
        fi
    done
    echo "[  ok] $name on :$port (${elapsed}s)  version=$(curl -s http://127.0.0.1:${port}/version 2>/dev/null | tr -d '\n' | head -c 60)"
}

cmd="${1:-status}"; profile="${2:-}"
case "$cmd" in
    start)
        [ -z "${PROFILE[$profile]:-}" ] && { echo "unknown profile '$profile' (q235|mid|glm)"; exit 2; }
        # co-located servers: start one GPU's servers sequentially
        for name in ${PROFILE[$profile]}; do
            start_server "$name" || exit 1
            # let a server claim its memory before its GPU neighbour starts
            wait_server "$name" || exit 1
        done
        echo "[done] profile $profile is up"
        ;;
    wait)
        [ -z "${PROFILE[$profile]:-}" ] && { echo "unknown profile '$profile'"; exit 2; }
        for name in ${PROFILE[$profile]}; do wait_server "$name" || exit 1; done
        ;;
    status)
        for name in "${!SPEC[@]}"; do
            port=$(_field "${SPEC[$name]}" 2)
            if curl -s --max-time 1 "http://127.0.0.1:${port}/v1/models" > /dev/null 2>&1; then
                echo "[ up ] $name :$port  $(curl -s http://127.0.0.1:${port}/v1/models | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"][0]["id"])' 2>/dev/null)"
            else
                echo "[down] $name :$port"
            fi
        done | sort
        ;;
    stop)
        for f in "$PID_DIR"/*.pid; do
            [ -f "$f" ] || continue
            pid=$(cat "$f"); name=$(basename "$f" .pid)
            if kill -0 "$pid" 2>/dev/null; then echo "[stop] $name (pid $pid)"; pkill -P "$pid" 2>/dev/null; kill "$pid" 2>/dev/null; fi
            rm -f "$f"
        done
        # vLLM engine workers survive the launcher: free the ports explicitly
        for name in "${!SPEC[@]}"; do
            port=$(_field "${SPEC[$name]}" 2)
            for pid in $(lsof -ti :"$port" 2>/dev/null); do kill -9 "$pid" 2>/dev/null || true; done
        done
        # ... and the engine cores / TP workers (process title "VLLM::*"),
        # which hold the GPU memory and do not listen on any port.
        for pid in $(pgrep -u "$USER" -f "^VLLM::" 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
        sleep 5
        for pid in $(pgrep -u "$USER" -f "^VLLM::" 2>/dev/null); do kill -9 "$pid" 2>/dev/null || true; done
        echo "[done] stopped"
        nvidia-smi --query-gpu=index,memory.used --format=csv,noheader 2>/dev/null | tr '\n' ' '; echo
        ;;
    *)
        echo "usage: $0 {start|wait} <q235|mid|glm> | status | stop"; exit 2 ;;
esac
