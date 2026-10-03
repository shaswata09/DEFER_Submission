#!/bin/bash
# ============================================================
# E20b, second attempt.
#
# The first attempt logged "complete" having run 4 of 30 attack trials:
# 13 of the 15 per-AP harness processes died at startup inside two seconds,
# and because run_attack_paths.sh pipes each process through grep and swallows
# its status with `|| true`, nothing in the log said so. print_summary()
# returns early on an empty result list, so even the summary was silent.
#
# So this wrapper does not trust the run log. It counts the rows the run
# actually produced, per AP, and fails loudly on the first AP that comes up
# short instead of carrying on to the benign tail.
#
# E20b measures carry-over across a reversed AP sequence in ONE persistent
# state, so the whole thing is redone into a fresh tag rather than topped up:
# persistent2 already holds ap15, ap1 and a benign tail in the wrong order.
# ============================================================
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
[ -f .env ] && { set -a; . ./.env; set +a; }

G="q235_div4"
TAG="persistent3"
APS="ap15,ap14,ap13,ap12,ap11,ap10,ap9,ap8,ap7,ap6,ap5,ap4,ap3,ap2,ap1"
RES="results/eval_attacks/group_${G}_${TAG}/cyberops/results.csv"
STATUS="logs/e20b_rerun.log"
EXPECT_ATTACK=30   # 15 APs x 2 variants x 1 trial
EXPECT_BENIGN=20   # 20 cyberops benign scenarios x 1 trial

note() { echo "$(date '+%F %T')  $*" | tee -a "$STATUS"; }
rows() {  # rows(ap_filter) -> count of non-error rows
    [ -f "$RES" ] || { echo 0; return; }
    ${PYTHON:-python} - "$RES" "$1" <<'PY'
import csv, sys
want = sys.argv[2]
n = 0
for r in csv.DictReader(open(sys.argv[1])):
    if r.get("outcome") in ("", "error"):
        continue
    ap = r.get("ap", "")
    if (want == "benign") == (ap == "benign"):
        n += 1
print(n)
PY
}

bash scripts/check_freeze.sh >>"$STATUS" 2>&1 || { note "ABORT: freeze guard"; exit 1; }
d=$(${PYTHON:-python} -c \
    "from logging_utils.run_metadata import git_state; print(git_state()['git_dirty'])")
[ "$d" = "False" ] || { note "ABORT: tree dirty ($d)"; exit 1; }
for p in 8000 8002 8003; do
    curl -s --max-time 20 "http://127.0.0.1:${p}/health" >/dev/null 2>&1 \
        || { note "ABORT: :$p down"; exit 1; }
done

[ -e "results/eval_attacks/group_${G}_${TAG}" ] && {
    note "ABORT: ${TAG} already exists; pick a fresh tag"; exit 1; }

note "E20b rerun: reversed AP sequence, 2 variants each, one persistent state"
STATE_MODE=persistent RUN_TAG="$TAG" MAX_VARIANTS=2 SEED=4242 TRIALS=1 SLOT=0 \
    SKIP_REPORT=1 scripts/run_attack_paths.sh "$G" cyberops "$APS" agenticcyops 1 \
    > logs/e20b_rerun_attacks.log 2>&1

got=$(rows attack)
note "attack pass produced ${got}/${EXPECT_ATTACK} trials"
if [ "$got" -lt "$EXPECT_ATTACK" ]; then
    note "FAIL: short by $((EXPECT_ATTACK - got)). APs that produced nothing:"
    for ap in ${APS//,/ }; do
        n=$(grep -c ",${ap}," "$RES" 2>/dev/null || true)
        [ "${n:-0}" -eq 0 ] && note "    $ap"
    done
    note "not running the benign tail: the carry-over state is incomplete"
    exit 1
fi

note "attack pass complete; benign tail in the same persistent state"
STATE_MODE=persistent RUN_TAG="$TAG" TRIALS=1 SLOT=0 SKIP_REPORT=1 \
    scripts/run_attack_paths.sh "$G" cyberops benign agenticcyops 1 \
    > logs/e20b_rerun_benign.log 2>&1

gotb=$(rows benign)
note "benign tail produced ${gotb}/${EXPECT_BENIGN} trials"
[ "$gotb" -lt "$EXPECT_BENIGN" ] && { note "FAIL: benign tail short"; exit 1; }
note "E20b rerun complete: ${got} attacks + ${gotb} benign in ${TAG}"
