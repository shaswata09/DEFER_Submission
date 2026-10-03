#!/bin/bash
# ============================================================
# The judgment boundary at defense-freeze-v3.1 (the code-audit fixes), live.
#
# Qwen3-235B (:8000), all five boundary configurations, four domains, 3 trials
# per variant plus the benign scenarios; panel local2 = Mistral-Small :8101 +
# Gemma-4 :8102 (2 of 2), Local4 offline afterwards (analysis/replay_v31.py).
# RUN_TAG=v31, no API validator. Seven streams per domain (SLOT 0..6).
# Do not edit tracked files while this runs.
# ============================================================
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
STATUS="logs/v31_live.log"
export SKIP_REPORT=1 REQUIRE_FREEZE=1 RUN_TAG=v31 TRIALS=3
note() { echo "$(date '+%F %T')  $*" | tee -a "$STATUS"; }
bash scripts/check_freeze.sh >>"$STATUS" 2>&1 || { note "ABORT: freeze guard"; exit 1; }
for p in 8000 8101 8102; do
    curl -s --max-time 20 "http://127.0.0.1:${p}/health" >/dev/null 2>&1 || { note "ABORT: :$p down"; exit 1; }
done

ALL="ap1,ap2,ap3,ap4,ap5,ap6,ap7,ap8,ap9,ap10,ap11,ap12,ap13,ap14,ap15"
H1="ap1,ap2,ap3,ap4,ap5,ap6,ap7,ap8"; H2="ap9,ap10,ap11,ap12,ap13,ap14,ap15"
G=q235_local2
run() {  # run <domain> <slot> <aps> <config> [benign]
    local d="$1" slot="$2" aps="$3" cfg="$4" ben="${5:-}" rc=0
    {
        SLOT="$slot" scripts/run_attack_paths.sh "$G" "$d" "$aps" "$cfg" 3 || rc=$?
        if [ -n "$ben" ]; then SLOT="$slot" scripts/run_attack_paths.sh "$G" "$d" benign "$cfg" 3 || rc=$?; fi
    } > "logs/v31_live_${d}_s${slot}.log" 2>&1
    note "stream $d s$slot $cfg done (rc=$rc)"
}
note "start (RUN_TAG=$RUN_TAG)"
pids=()
for d in cyberops healthcare finance legal; do
    run "$d" 0 "$H1" agenticcyops benign & pids+=($!); sleep 8
    run "$d" 1 "$H2" agenticcyops &        pids+=($!); sleep 8
    run "$d" 2 "$H1" llm_judge benign &    pids+=($!); sleep 8
    run "$d" 3 "$H2" llm_judge &           pids+=($!); sleep 8
    run "$d" 4 "$ALL" flat benign &        pids+=($!); sleep 8
    run "$d" 5 "$ALL" acl_hardened benign & pids+=($!); sleep 8
    run "$d" 6 "$ALL" symbolic_only benign & pids+=($!); sleep 8
done
fail=0
for p in "${pids[@]}"; do wait "$p" || fail=1; done
note "complete (failed streams: $fail)"
