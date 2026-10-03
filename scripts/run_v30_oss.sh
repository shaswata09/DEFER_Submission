#!/bin/bash
# Phase 2 of the v3.0 live re-run: gpt-oss-120b (:8200) as primary, FULL and
# JUDGEONLY in CyberOps, panel local2 (:8101/:8102). RUN_TAG=v30. No API validator.
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
[ -f .env ] && { set -a; . ./.env; set +a; }
STATUS="logs/v30_live.log"
export SKIP_REPORT=1 REQUIRE_FREEZE=1 RUN_TAG=v30 TRIALS=3
note() { echo "$(date '+%F %T')  $*" | tee -a "$STATUS"; }
bash scripts/check_freeze.sh >>"$STATUS" 2>&1 || { note "ABORT: freeze guard"; exit 1; }
for p in 8200 8101 8102; do
    curl -s --max-time 20 "http://127.0.0.1:${p}/health" >/dev/null 2>&1 || { note "ABORT: :$p down"; exit 1; }
done
H1="ap1,ap2,ap3,ap4,ap5,ap6,ap7,ap8"; H2="ap9,ap10,ap11,ap12,ap13,ap14,ap15"
run() { local slot="$1" aps="$2" cfg="$3" ben="${4:-}"
    { SLOT="$slot" scripts/run_attack_paths.sh oss120_local2 cyberops "$aps" "$cfg" 3
      [ -n "$ben" ] && SLOT="$slot" scripts/run_attack_paths.sh oss120_local2 cyberops benign "$cfg" 3
    } > "logs/v30_oss_s${slot}.log" 2>&1; }
note "gpt-oss phase start"
pids=()
run 0 "$H1" agenticcyops benign & pids+=($!); sleep 12
run 1 "$H2" agenticcyops &        pids+=($!); sleep 12
run 2 "$H1" llm_judge benign &    pids+=($!); sleep 12
run 3 "$H2" llm_judge &           pids+=($!)
for p in "${pids[@]}"; do wait "$p"; done
note "gpt-oss phase complete"
