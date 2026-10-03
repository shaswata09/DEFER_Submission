#!/bin/bash
# ============================================================
# Judges with the operating context (defense-freeze-v3.0), live.
#
# Re-runs every configuration in which the panel is consulted:
#   Qwen3-235B (:8000)        FULL in all four domains, JUDGEONLY in CyberOps
#   Llama-3.1-8B (RTX 5090)   FULL and JUDGEONLY in CyberOps
#   panel local2 = Mistral-Small :8101 + Gemma-4 :8102 (2 of 2); Local4 offline
# 3 trials per variant plus the benign scenarios. RUN_TAG=v30. No API validator.
# gpt-oss-120b runs in a second phase (scripts/run_v30_oss.sh), when its GPU is free.
# Do not edit tracked files while this runs.
# ============================================================
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
[ -f .env ] && { set -a; . ./.env; set +a; }
STATUS="logs/v30_live.log"
export SKIP_REPORT=1 REQUIRE_FREEZE=1 RUN_TAG=v30 TRIALS=3
note() { echo "$(date '+%F %T')  $*" | tee -a "$STATUS"; }
bash scripts/check_freeze.sh >>"$STATUS" 2>&1 || { note "ABORT: freeze guard"; exit 1; }
for p in 8000 8101 8102; do
    curl -s --max-time 20 "http://127.0.0.1:${p}/health" >/dev/null 2>&1 || { note "ABORT: :$p down"; exit 1; }
done
curl -s --max-time 20 -H "Authorization: Bearer ${REMOTE_5090_API_KEY:-}" "${REMOTE_5090_URL%/}/models" >/dev/null 2>&1 \
    || { note "ABORT: RTX 5090 node down"; exit 1; }

C1="ap1,ap2,ap3,ap4,ap5"; C2="ap6,ap7,ap8,ap9,ap10"; C3="ap11,ap12,ap13,ap14,ap15"
H1="ap1,ap2,ap3,ap4,ap5,ap6,ap7,ap8"; H2="ap9,ap10,ap11,ap12,ap13,ap14,ap15"
run() {  # run <group> <domain> <slot> <aps> <config> [benign]
    local g="$1" d="$2" slot="$3" aps="$4" cfg="$5" ben="${6:-}"
    {
        SLOT="$slot" scripts/run_attack_paths.sh "$g" "$d" "$aps" "$cfg" 3
        [ -n "$ben" ] && SLOT="$slot" scripts/run_attack_paths.sh "$g" "$d" benign "$cfg" 3
    } > "logs/v30_live_${g}_${d}_s${slot}.log" 2>&1
}
note "start (RUN_TAG=$RUN_TAG)"
pids=()
G=q235_local2
run $G cyberops 0 "$C1" agenticcyops benign & pids+=($!); sleep 12
run $G cyberops 1 "$C2" agenticcyops &        pids+=($!); sleep 12
run $G cyberops 2 "$C3" agenticcyops &        pids+=($!); sleep 12
run $G cyberops 3 "$C1" llm_judge benign &    pids+=($!); sleep 12
run $G cyberops 4 "$C2" llm_judge &           pids+=($!); sleep 12
run $G cyberops 5 "$C3" llm_judge &           pids+=($!); sleep 12
for d in finance healthcare legal; do
    run $G "$d" 0 "$H1" agenticcyops benign & pids+=($!); sleep 12
    run $G "$d" 1 "$H2" agenticcyops &        pids+=($!); sleep 12
done
G=llama8b_local2
run $G cyberops 0 "$H1" agenticcyops benign & pids+=($!); sleep 12
run $G cyberops 1 "$H2" agenticcyops &        pids+=($!); sleep 12
run $G cyberops 2 "$H1" llm_judge benign &    pids+=($!); sleep 12
run $G cyberops 3 "$H2" llm_judge &           pids+=($!); sleep 12
for p in "${pids[@]}"; do wait "$p"; done
note "complete"
