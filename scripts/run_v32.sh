#!/bin/bash
# ============================================================
# The runs after the 2026-10-02 audit (README, provenance).
#
#   defense-freeze-v3.2   (defense fixes + v3.1.4)  CyberOps, RUN_TAG=v32:
#       q235_local2_v32                  boundary, 5 configs, all paths + benign
#       q235_local2_disabled_P<i>_v32    leave-one-out, all paths + benign
#       llama8b_local2_v32               Llama-3.1-8B boundary (REMOTE_5090_URL)
#       oss120_local2_v32                gpt-oss-120b boundary (phase B)
#   defense-freeze-v3.1.4 (harness + oracle fixes, v3.1 defense)  RUN_TAG=v314:
#       q235_local2_v314  healthcare/finance/legal: JUDGEONLY on every path
#                         + benign, and AP-9 under the other four configs
#
# Each tag runs from its own clean worktree (models/ and .env symlinked; the
# ChromaDB setup reads <worktree>/models). Every tool and MMA port stays below
# 32768: run_attack_paths.sh kill -9s whatever holds a port of its block, and
# the kernel's ephemeral range (32768-60999) carries the vLLM workers' own
# connections, so a block there can kill a model server (it did, 2026-10-02).
# Streams that share a group and domain are separated by PORT_EXTRA and
# CHROMA_TAG instead of high slot numbers. Panel live: local2 = Mistral-Small
# :8101 + Gemma-4 :8102 (2 of 2) on GPU4; Local4 offline afterwards.
#
#   bash scripts/run_v32.sh            # phases A, B, C; status in logs/v32.log
# Do not edit files in the worktrees while this runs.
# ============================================================
set -uo pipefail
MAIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W32="${W32:-$(dirname "$MAIN")/defer-v32-runs}"
W314="${W314:-$(dirname "$MAIN")/defer-v314-runs}"
STATUS="$MAIN/logs/v32.log"
SL="$MAIN/logs/vllm_v32"; mkdir -p "$SL"
V="${VLLM_BIN:-$(dirname "$(command -v python)")/vllm}"
note() { echo "$(date '+%F %T')  $*" | tee -a "$STATUS"; }
up() { curl -s --max-time 3 "http://127.0.0.1:$1/v1/models" >/dev/null 2>&1; }
wait_up() { for _ in $(seq 1 240); do up "$1" && return 0; sleep 10; done; return 1; }
stop_port() { local pid; pid=$(ps -eo pid,cmd | grep "[v]llm serve" | grep -- "--port $1 " | awk '{print $1}'); [ -n "$pid" ] && kill -TERM $pid; }

worktree() {  # worktree <dir> <tag>
    if [ ! -d "$1" ]; then git -C "$MAIN" worktree add --detach "$1" "$2" >>"$STATUS" 2>&1 || return 1; fi
    [ "$(git -C "$1" rev-parse HEAD)" = "$(git -C "$MAIN" rev-parse "$2^{commit}")" ] || { note "ABORT: $1 is not at $2"; return 1; }
    # models/ holds tracked files, so link each weights directory into it
    # (a link to models/ itself lands at models/models; ChromaDB setup and the
    # memory gateway read <worktree>/models/<org>/<name>)
    for m in "$MAIN"/models/*/; do
        m="${m%/}"; [ -e "$1/models/$(basename "$m")" ] || ln -s "$m" "$1/models/$(basename "$m")"
    done
    rm -f "$1/models/models"
    ln -sfn "$MAIN/.env" "$1/.env"
    [ -e "$1/models/Qwen/Qwen3-Embedding-8B" ] || { note "ABORT: embedding model not visible in $1"; return 1; }
    (cd "$1" && bash scripts/check_freeze.sh) >>"$STATUS" 2>&1 || { note "ABORT: freeze guard in $1"; return 1; }
}

ALL="ap1,ap2,ap3,ap4,ap5,ap6,ap7,ap8,ap9,ap10,ap11,ap12,ap13,ap14,ap15"
H1="ap1,ap2,ap3,ap4,ap5,ap6,ap7,ap8"; H2="ap9,ap10,ap11,ap12,ap13,ap14,ap15"
stream() {  # stream <worktree> <name> <slot> <group> <domain> <aps> <config> <benign 0|1> [ENV=..]
    local wt="$1" name="$2" slot="$3" g="$4" d="$5" aps="$6" cfg="$7" ben="$8"; shift 8
    (
        cd "$wt" || exit 1
        rc=0
        env "$@" SLOT="$slot" SKIP_REPORT=1 REQUIRE_FREEZE=1 scripts/run_attack_paths.sh "$g" "$d" "$aps" "$cfg" 3 || rc=$?
        if [ "$ben" = 1 ]; then
            env "$@" SLOT="$slot" SKIP_REPORT=1 REQUIRE_FREEZE=1 scripts/run_attack_paths.sh "$g" "$d" benign "$cfg" 3 || rc=$?
        fi
        note "stream $name done (rc=$rc)"
    ) > "$MAIN/logs/v32_${name}.log" 2>&1 &
    sleep 8
}
boundary() {  # boundary <worktree> <group> <prefix> <tag>: the seven streams of run_v31.sh, CyberOps
    local wt="$1" g="$2" p="$3" tag="$4"
    stream "$wt" "${p}_s0" 0 "$g" cyberops "$H1" agenticcyops 1 RUN_TAG="$tag"
    stream "$wt" "${p}_s1" 1 "$g" cyberops "$H2" agenticcyops 0 RUN_TAG="$tag"
    stream "$wt" "${p}_s2" 2 "$g" cyberops "$H1" llm_judge 1 RUN_TAG="$tag"
    stream "$wt" "${p}_s3" 3 "$g" cyberops "$H2" llm_judge 0 RUN_TAG="$tag"
    stream "$wt" "${p}_s4" 4 "$g" cyberops "$ALL" flat 1 RUN_TAG="$tag"
    stream "$wt" "${p}_s5" 5 "$g" cyberops "$ALL" acl_hardened 1 RUN_TAG="$tag"
    stream "$wt" "${p}_s6" 6 "$g" cyberops "$ALL" symbolic_only 1 RUN_TAG="$tag"
}

# PHASES: which parts to run (default all). A resume after a change of plan
# (2026-10-02: the ablation re-split into four streams per arm) runs
# PHASES="ablation B C"; the wait before phase B covers every stream still
# running from the worktrees, not only this shell's children.
PHASES="${PHASES:-boundary ablation llama other B C}"
want() { [[ " $PHASES " == *" $1 "* ]]; }
streams_running() { ps -eo cmd | grep -E "^(/bin/)?bash scripts/run_attack_paths.sh" | grep -q .; }
note "pipeline: start (phases: $PHASES)"
worktree "$W32" defense-freeze-v3.2 || exit 1
worktree "$W314" defense-freeze-v3.1.4 || exit 1
set -a; . "$MAIN/.env"; set +a

# ---------------- phase A: Qwen3-235B, local2, Llama-3.1-8B ----------------
up 8000 || CUDA_VISIBLE_DEVICES=0,1,2,3 setsid nohup "$V" serve "$MAIN/models/Qwen/Qwen3-235B-A22B-Instruct-2507" \
    --served-model-name Qwen/Qwen3-235B-A22B-Instruct-2507 --tensor-parallel-size 4 --dtype bfloat16 \
    --tool-call-parser hermes --enable-auto-tool-choice --gpu-memory-utilization 0.90 --max-model-len 32768 \
    --port 8000 --host 127.0.0.1 > "$SL/primary_q235.log" 2>&1 < /dev/null &
up 8101 || CUDA_VISIBLE_DEVICES=4 setsid nohup "$V" serve "$MAIN/models/mistralai/Mistral-Small-3.2-24B-Instruct-2506" \
    --served-model-name mistralai/Mistral-Small-3.2-24B-Instruct-2506 --tokenizer-mode mistral --dtype bfloat16 \
    --max-model-len 16384 --gpu-memory-utilization 0.40 --limit-mm-per-prompt '{"image":0}' \
    --port 8101 --host 127.0.0.1 > "$SL/mistral.log" 2>&1 < /dev/null &
wait_up 8101 || { note "ABORT: Mistral :8101 not up"; exit 1; }
up 8102 || CUDA_VISIBLE_DEVICES=4 setsid nohup "$V" serve google/gemma-4-31B-it --served-model-name gemma-4-31B-it \
    --dtype bfloat16 --max-model-len 16384 --gpu-memory-utilization 0.52 --limit-mm-per-prompt '{"image":0}' \
    --port 8102 --host 127.0.0.1 > "$SL/gemma.log" 2>&1 < /dev/null &
for p in 8000 8102; do wait_up $p || { note "ABORT: :$p not up"; exit 1; }; done
curl -s --max-time 20 -H "Authorization: Bearer ${REMOTE_5090_API_KEY:-}" "${REMOTE_5090_URL%/}/models" >/dev/null \
    || { note "ABORT: Llama-3.1-8B node unreachable"; exit 1; }
note "phase A: servers up"

want boundary && boundary "$W32" q235_local2 q235 v32
ablation() {  # each arm as four streams (one stream per arm took ~12 h); the
    # sub-streams of an arm share its slot and are kept apart by PORT_EXTRA
    # (10600/10800/11000/11200 + 3000*slot) and CHROMA_TAG
    local parts=("ap1,ap2,ap3,ap4" "ap5,ap6,ap7,ap8" "ap9,ap10,ap11,ap12" "ap13,ap14,ap15")
    local extra=(-1000 -800 -600 -400) j
    for i in 1 2 3 4 5; do
        for j in 0 1 2 3; do
            stream "$W32" "abl_P${i}_$j" $((i - 1)) q235_local2 cyberops "${parts[$j]}" agenticcyops \
                $([ $j = 3 ] && echo 1 || echo 0) RUN_TAG=v32 DISABLE_PRINCIPLES="P$i" \
                PORT_EXTRA="${extra[$j]}" CHROMA_TAG="abl$j"
        done
    done
}
want ablation && ablation
want llama && boundary "$W32" llama8b_local2 llama v32
want other && for d in healthcare finance legal; do
    stream "$W314" "${d}_judge_h1" 0 q235_local2 "$d" "$H1" llm_judge 1 RUN_TAG=v314 PORT_EXTRA=-1400
    stream "$W314" "${d}_judge_h2" 1 q235_local2 "$d" "$H2" llm_judge 0 RUN_TAG=v314 PORT_EXTRA=-1400
    s=2
    for cfg in flat acl_hardened symbolic_only agenticcyops; do
        stream "$W314" "${d}_ap9_${cfg}" $s q235_local2 "$d" ap9 "$cfg" 0 RUN_TAG=v314 PORT_EXTRA=-1400
        s=$((s + 1))
    done
done
wait
while streams_running; do sleep 60; done
note "phase A: finished"
want B || { note "pipeline: stopping before phase B"; exit 0; }

# ---------------- phase B: gpt-oss-120b primary ----------------
stop_port 8000; sleep 60
CUDA_VISIBLE_DEVICES=0 setsid nohup "$V" serve "$MAIN/models/openai/gpt-oss-120b" --served-model-name openai/gpt-oss-120b \
    --enable-auto-tool-choice --tool-call-parser openai --gpu-memory-utilization 0.90 --max-model-len 32768 \
    --port 8200 --host 127.0.0.1 > "$SL/primary_oss.log" 2>&1 < /dev/null &
wait_up 8200 || { note "ABORT: gpt-oss :8200 not up"; exit 1; }
note "phase B: gpt-oss-120b up"
boundary "$W32" oss120_local2 oss v32
wait
while streams_running; do sleep 60; done
note "phase B: finished"

# ---------------- phase C: logs into the main tree, servers down ----------------
for wt in "$W32" "$W314"; do
    for dir in "$wt"/logs/*_eval_attacks_*_v32 "$wt"/logs/*_eval_attacks_*_v314; do
        [ -d "$dir" ] && cp -rn "$dir" "$MAIN/logs/"
    done
    for dir in "$wt"/results/eval_attacks/group_*_v32 "$wt"/results/eval_attacks/group_*_v314; do
        [ -d "$dir" ] && cp -rn "$dir" "$MAIN/results/eval_attacks/"
    done
done
for p in 8200 8101 8102; do stop_port $p; done
note "pipeline: COMPLETE"
