#!/bin/bash
# ============================================================
# After scripts/run_v32.sh: the Local4 votes for the post-audit replay sets.
#
#   1. rebuild cache/replay_v31 (the v3.1 rounds as the v3.1 host built them:
#      implied actions and fallback targets hoisted) and build cache/replay_rep
#      (the reported runs: analysis.reported)
#   2. serve the four local judges (GPU0 Mistral-Small :8101, GPU1 Gemma-4
#      :8102, GPU2 gpt-oss-120b :8103, GPU3-4 Llama-4-Scout TP=2 :8104)
#   3. query each judge on every message of both sets not yet in
#      cache/validators/ (votes are cached by message hash; nothing else is
#      queried), then stop the servers
#
#   bash scripts/run_v32_votes.sh [--wait]    # --wait: until run_v32.sh completes
# Status in logs/v32_votes.log. No API is called.
# ============================================================
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
STATUS="logs/v32_votes.log"
SL="logs/vllm_v32"; mkdir -p "$SL"
V="${VLLM_BIN:-$(dirname "$(command -v python)")/vllm}"
note() { echo "$(date '+%F %T')  $*" | tee -a "$STATUS"; }
up() { curl -s --max-time 3 "http://127.0.0.1:$1/v1/models" >/dev/null 2>&1; }
wait_up() { for _ in $(seq 1 240); do up "$1" && return 0; sleep 10; done; return 1; }
stop_port() { local pid; pid=$(ps -eo pid,cmd | grep "[v]llm serve" | grep -- "--port $1 " | awk '{print $1}'); [ -n "$pid" ] && kill -TERM $pid; }

if [ "${1:-}" = "--wait" ]; then
    note "waiting for run_v32.sh"
    until grep -q "pipeline: COMPLETE" logs/v32.log 2>/dev/null; do
        grep -q "ABORT" logs/v32.log 2>/dev/null && { note "ABORT seen in logs/v32.log; not starting"; exit 1; }
        sleep 60
    done
    sleep 60
fi

note "build: replay_v31 (rebuilt) and replay_rep"
python -m analysis.replay_v31 build >>"$STATUS" 2>&1 || { note "ABORT: replay_v31 build"; exit 1; }
python -m analysis.replay_reported build >>"$STATUS" 2>&1 || { note "ABORT: replay_reported build"; exit 1; }

for p in 8000 8200 8101 8102; do stop_port $p; done; sleep 60
CUDA_VISIBLE_DEVICES=0 setsid nohup "$V" serve models/mistralai/Mistral-Small-3.2-24B-Instruct-2506 --served-model-name mistral-small-3.2 \
    --dtype bfloat16 --tokenizer-mode mistral --limit-mm-per-prompt '{"image":0}' --gpu-memory-utilization 0.90 \
    --max-model-len 8192 --port 8101 --host 127.0.0.1 > "$SL/j_mistral.log" 2>&1 < /dev/null &
CUDA_VISIBLE_DEVICES=1 setsid nohup "$V" serve google/gemma-4-31B-it --served-model-name gemma-4-31b-it --dtype bfloat16 \
    --limit-mm-per-prompt '{"image":0}' --gpu-memory-utilization 0.90 --max-model-len 8192 \
    --port 8102 --host 127.0.0.1 > "$SL/j_gemma.log" 2>&1 < /dev/null &
CUDA_VISIBLE_DEVICES=2 setsid nohup "$V" serve models/openai/gpt-oss-120b --served-model-name gpt-oss-120b \
    --gpu-memory-utilization 0.90 --max-model-len 8192 --port 8103 --host 127.0.0.1 > "$SL/j_gptoss.log" 2>&1 < /dev/null &
CUDA_VISIBLE_DEVICES=3,4 setsid nohup "$V" serve models/meta-llama/Llama-4-Scout-17B-16E-Instruct --served-model-name llama-4-scout \
    --tensor-parallel-size 2 --dtype bfloat16 --limit-mm-per-prompt '{"image":0}' --gpu-memory-utilization 0.90 \
    --max-model-len 8192 --port 8104 --host 127.0.0.1 > "$SL/j_scout.log" 2>&1 < /dev/null &
for p in 8101 8102 8103 8104; do wait_up $p || { note "ABORT: judge :$p not up"; exit 1; }; done
note "judges up"

query() {  # query <validator> <port> [extra args]
    local v="$1" p="$2"; shift 2
    for d in cache/replay_rep cache/replay_v31; do
        python -m analysis.replay_run query --validator "$v" --url "http://127.0.0.1:$p/v1" \
            --replay-dir "$d" "$@" >> "$SL/q_${v}.log" 2>&1 || note "query $v $d rc=$?"
    done
    note "votes: $v done"
}
query L1_mistral 8101 &
query L2_gemma 8102 &
query L3_gptoss 8103 --reasoning-effort low &
query L4_scout 8104 &
wait
for p in 8101 8102 8103 8104; do stop_port $p; done
note "votes: COMPLETE"
