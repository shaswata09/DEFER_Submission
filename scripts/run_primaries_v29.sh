#!/bin/bash
# ============================================================
# The judgment boundary for two more primaries, live at defense-freeze-v2.9.
#
#   gpt-oss-120b   native MXFP4, one H200            :8200   group oss120_local2
#   Llama-3.1-8B   BF16 on the RTX 5090 node          REMOTE_5090_URL  group llama8b_local2
#   panel          local2 = Mistral-Small :8101 + Gemma-4 :8102, 2 of 2
#                  (re-adjudicated afterwards under Local4 minus the primary)
#   split          CyberOps development split, 3 trials per variant, all five
#                  boundary configurations, plus the 20 benign scenarios x 3
#
# Seven streams per primary (SLOT 0-6); the judged configurations are split
# in two by attack path. No API validator is configured.
# Do not edit tracked files while this runs: every attack-path invocation
# re-checks that the tree is clean.
# ============================================================
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
[ -f .env ] && { set -a; . ./.env; set +a; }

STATUS="logs/primaries_v29.log"
export SKIP_REPORT=1 REQUIRE_FREEZE=1 RUN_TAG=v29 TRIALS=3
note() { echo "$(date '+%F %T')  $*" | tee -a "$STATUS"; }

bash scripts/check_freeze.sh >>"$STATUS" 2>&1 || { note "ABORT: freeze guard"; exit 1; }
for p in 8200 8101 8102; do
    curl -s --max-time 20 "http://127.0.0.1:${p}/health" >/dev/null 2>&1 || { note "ABORT: :$p down"; exit 1; }
done
curl -s --max-time 20 -H "Authorization: Bearer ${REMOTE_5090_API_KEY:-}" "${REMOTE_5090_URL%/}/models" >/dev/null 2>&1 \
    || { note "ABORT: RTX 5090 node down"; exit 1; }

A1="ap1,ap2,ap3,ap4,ap5,ap6,ap7,ap8"; A2="ap9,ap10,ap11,ap12,ap13,ap14,ap15"
run() {  # run <group> <slot> <aps> <config> [then benign]
    local g="$1" slot="$2" aps="$3" cfg="$4" ben="${5:-}"
    {
        SLOT="$slot" scripts/run_attack_paths.sh "$g" cyberops "$aps" "$cfg" 3
        [ -n "$ben" ] && SLOT="$slot" scripts/run_attack_paths.sh "$g" cyberops benign "$cfg" 3
    } > "logs/primaries_v29_${g}_s${slot}.log" 2>&1
}

note "start (RUN_TAG=$RUN_TAG)"
pids=()
for g in oss120_local2 llama8b_local2; do
    run "$g" 0 all flat benign &           pids+=($!); sleep 15
    run "$g" 1 all acl_hardened benign &   pids+=($!); sleep 15
    run "$g" 2 all symbolic_only benign &  pids+=($!); sleep 15
    run "$g" 3 "$A1" llm_judge benign &    pids+=($!); sleep 15
    run "$g" 4 "$A2" llm_judge &           pids+=($!); sleep 15
    run "$g" 5 "$A1" agenticcyops benign & pids+=($!); sleep 15
    run "$g" 6 "$A2" agenticcyops &        pids+=($!); sleep 15
done
for p in "${pids[@]}"; do wait "$p"; done
note "complete"
