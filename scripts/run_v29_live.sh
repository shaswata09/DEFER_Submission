#!/bin/bash
# ============================================================
# B2 + replay calibration: FULL at defense-freeze-v2.9, live.
#
#   primary    Qwen3-235B-A22B BF16 TP=4        :8000
#   panel      local2 = Mistral-Small :8101 + Gemma-4 :8102, 2 of 2
#              (the two local validators that fit beside the primary)
#   split      CyberOps development split, 3 trials per variant, and the
#              20 benign scenarios x 3; group q235_local2_v29
#
# No API validator is configured. The payload files also carry the five
# CyberOps E2 siblings; the analysis keeps the original 75 variants.
# ============================================================
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
[ -f .env ] && { set -a; . ./.env; set +a; }

G="q235_local2"
STATUS="logs/v29_live.log"
export SKIP_REPORT=1 REQUIRE_FREEZE=1 RUN_TAG=v29 TRIALS=3
note() { echo "$(date '+%F %T')  $*" | tee -a "$STATUS"; }

bash scripts/check_freeze.sh >>"$STATUS" 2>&1 || { note "ABORT: freeze guard"; exit 1; }
for p in 8000 8101 8102; do
    curl -s --max-time 20 "http://127.0.0.1:${p}/health" >/dev/null 2>&1 || { note "ABORT: :$p down"; exit 1; }
done

note "v2.9 live run start ($G, RUN_TAG=$RUN_TAG)"
slot=0; pids=()
for aps in "ap1,ap2,ap3" "ap4,ap5,ap6" "ap7,ap8,ap9" "ap10,ap11,ap12" "ap13,ap14,ap15" "benign"; do
    SLOT="$slot" scripts/run_attack_paths.sh "$G" cyberops "$aps" agenticcyops 3 \
        > "logs/v29_live_${slot}.log" 2>&1 &
    pids+=($!); slot=$((slot + 1)); sleep 20
done
for p in "${pids[@]}"; do wait "$p"; done
note "v2.9 live run complete"
