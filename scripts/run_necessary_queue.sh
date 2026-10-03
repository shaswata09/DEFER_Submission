#!/bin/bash
# ============================================================
# The remaining arms that change a paper contribution.
#
#   E20b  second carry-over pass: benign tail after the reversed-order attack
#         sequence, same persistent state (W6 wants n=2 with a range)
#   E9    writes to critical stores routed to the panel, agenticcyops vs
#         agenticcyops_writejudge, AP-2/AP-4/AP-13 + benign, all four domains
#         (question 5, the remaining blind spot)
#
# E20b's benign tail must follow its attack pass in the same persistent state,
# so it is sequenced, not parallelised.
# ============================================================
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
[ -f .env ] && { set -a; . ./.env; set +a; }

STATUS="logs/necessary_queue.log"
G="q235_div4"
export SKIP_REPORT=1 OMP_NUM_THREADS="${OMP_NUM_THREADS:-6}"
note() { echo "$(date '+%F %T')  $*" | tee -a "$STATUS"; }

gates() {
    bash scripts/check_freeze.sh >>"$STATUS" 2>&1 || { note "ABORT: freeze guard"; exit 1; }
    d=$(${PYTHON:-python} -c \
        "from logging_utils.run_metadata import git_state; print(git_state()['git_dirty'])")
    [ "$d" = "False" ] || { note "ABORT: tree dirty"; exit 1; }
    for p in 8000 8002 8003; do
        curl -s --max-time 20 "http://127.0.0.1:${p}/health" >/dev/null 2>&1 \
            || { note "ABORT: :$p down"; exit 1; }
    done
}

# ---- E20b: benign tail, same persistent state as the attack pass ----
note "waiting for the E20b attack pass"
while pgrep -f "run_attack_paths.sh ${G} cyberops ap15" >/dev/null 2>&1; do sleep 60; done
note "E20b attacks done; running the benign tail in the same persistent state"
gates
STATE_MODE=persistent RUN_TAG=persistent2 TRIALS=1 SLOT=0 \
    scripts/run_attack_paths.sh "$G" cyberops benign agenticcyops 1 \
    > logs/e20b_benign.log 2>&1
note "E20b complete"

# ---- E9: write-judge vs baseline ----
gates
date -Iseconds > logs/e9_start.txt
note "E9 start: ap2,ap4,ap13 + benign, 4 domains, agenticcyops vs writejudge"
APS="ap2,ap4,ap13"
slot=0; pids=()
for cfg in agenticcyops_writejudge agenticcyops; do
    for dom in cyberops finance healthcare legal; do
        SLOT="$slot" TRIALS=3 scripts/run_attack_paths.sh "$G" "$dom" "$APS" "$cfg" 3 \
            > "logs/e9_${cfg}_${dom}.log" 2>&1 &
        pids+=($!); slot=$((slot+1)); sleep 25
    done
done
for p in "${pids[@]}"; do wait "$p"; done
note "E9 attack arms done; benign arms"
slot=0; pids=()
for cfg in agenticcyops_writejudge agenticcyops; do
    for dom in cyberops finance healthcare legal; do
        SLOT="$slot" TRIALS=3 scripts/run_attack_paths.sh "$G" "$dom" benign "$cfg" 3 \
            > "logs/e9_benign_${cfg}_${dom}.log" 2>&1 &
        pids+=($!); slot=$((slot+1)); sleep 25
    done
done
for p in "${pids[@]}"; do wait "$p"; done
note "E9 complete"

${PYTHON:-python} -m analysis.parse_logs >/dev/null 2>&1 || true
note "queue done"
