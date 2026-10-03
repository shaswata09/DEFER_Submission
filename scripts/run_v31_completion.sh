#!/bin/bash
# ============================================================
# The remaining v3.1 runs: leave-one-out ablation, persistent state, and the
# boundary for gpt-oss-120b and Llama-3.1-8B (CyberOps), at defense-freeze-v3.1.
#
# Reconstructed from the run headers of the committed logs (each records its
# harness command); the original launcher ran the same commands from a clean
# worktree at f92bb5d, whose decision code equals defense-freeze-v3.1.1.
#
#   phase A  Qwen3-235B (:8000) + local2 (Mistral-Small :8101, Gemma-4 :8102):
#            ablation  DISABLE_PRINCIPLES=P<i>, all paths + benign, 3 trials
#                      -> group q235_local2_disabled_P<i>_v31
#            persist   STATE_MODE=persistent, 2 variants x 1 trial per path, then
#                      the benign scenarios, four domains -> q235_local2_v31persist;
#                      CyberOps again with the paths reversed -> ..._v31persist2
#            Llama-3.1-8B (REMOTE_5090_URL) streams as in scripts/run_v31.sh
#                      -> llama8b_local2_v31
#   phase B  gpt-oss-120b (:8200) + local2, streams as in run_v31.sh
#                      -> oss120_local2_v31
# Afterwards: python -m analysis.replay_v31 build, the Local4 votes
# (analysis.replay_run query ... --replay-dir cache/replay_v31), then
# make replay-v31 primaries-v31 v31-mechanisms figures.
# Do not edit tracked files while this runs.
#
#   bash scripts/run_v31_completion.sh A     # or B
# ============================================================
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
PHASE="${1:?phase A or B}"
STATUS="logs/v31b.log"
export SKIP_REPORT=1 REQUIRE_FREEZE=1
note() { echo "$(date '+%F %T')  $*" | tee -a "$STATUS"; }
bash scripts/check_freeze.sh >>"$STATUS" 2>&1 || { note "ABORT: freeze guard"; exit 1; }

ALL="ap1,ap2,ap3,ap4,ap5,ap6,ap7,ap8,ap9,ap10,ap11,ap12,ap13,ap14,ap15"
REV="ap15,ap14,ap13,ap12,ap11,ap10,ap9,ap8,ap7,ap6,ap5,ap4,ap3,ap2,ap1"
H1="ap1,ap2,ap3,ap4,ap5,ap6,ap7,ap8"; H2="ap9,ap10,ap11,ap12,ap13,ap14,ap15"

boundary() {  # boundary <group> <slot offset> <name>: the seven streams of run_v31.sh, CyberOps
    local g="$1" o="$2" n="$3" i=0 cfgs=(agenticcyops agenticcyops llm_judge llm_judge flat acl_hardened symbolic_only)
    local aps=("$H1" "$H2" "$H1" "$H2" "$ALL" "$ALL" "$ALL") ben=(1 0 1 0 1 1 1)
    for i in 0 1 2 3 4 5 6; do
        (
            rc=0
            SLOT=$((o + i)) RUN_TAG=v31 scripts/run_attack_paths.sh "$g" cyberops "${aps[$i]}" "${cfgs[$i]}" 3 || rc=$?
            if [ "${ben[$i]}" = 1 ]; then
                SLOT=$((o + i)) RUN_TAG=v31 scripts/run_attack_paths.sh "$g" cyberops benign "${cfgs[$i]}" 3 || rc=$?
            fi
            note "stream ${n}_s$i done (rc=$rc)"
        ) > "logs/v31b_${n}_s$i.log" 2>&1 &
        sleep 8
    done
}

persist() {  # persist <domain> <tag> <paths>: one persistent state, attacks then benign
    local d="$1" tag="$2" aps="$3" slot="$4" rc=0
    {
        STATE_MODE=persistent RUN_TAG="$tag" MAX_VARIANTS=2 TRIALS=1 SLOT="$slot" \
            scripts/run_attack_paths.sh q235_local2 "$d" "$aps" agenticcyops 1 || rc=$?
        STATE_MODE=persistent RUN_TAG="$tag" TRIALS=1 SLOT="$slot" \
            scripts/run_attack_paths.sh q235_local2 "$d" benign agenticcyops 1 || rc=$?
    } > "logs/v31b_${tag#v31}_${d}.log" 2>&1
    note "stream ${tag#v31}_$d done (rc=$rc)"
}

if [ "$PHASE" = A ]; then
    for p in 8000 8101 8102; do
        curl -s --max-time 20 "http://127.0.0.1:${p}/health" >/dev/null || { note "ABORT: :$p down"; exit 1; }
    done
    note "phase A: start"
    for i in 1 2 3 4 5; do
        (
            rc=0
            SLOT=$((i - 1)) RUN_TAG=v31 DISABLE_PRINCIPLES="P$i" \
                scripts/run_attack_paths.sh q235_local2 cyberops "$ALL" agenticcyops 3 || rc=$?
            SLOT=$((i - 1)) RUN_TAG=v31 DISABLE_PRINCIPLES="P$i" \
                scripts/run_attack_paths.sh q235_local2 cyberops benign agenticcyops 3 || rc=$?
            note "stream abl_P$i done (rc=$rc)"
        ) > "logs/v31b_abl_P$i.log" 2>&1 &
        sleep 8
    done
    # slots as recorded in the run headers (tool base = 10000 + group*160 +
    # domain*40 + slot*3000, so every port stays below 65535)
    for d in cyberops healthcare finance legal; do
        persist "$d" v31persist "$ALL" 5 & sleep 8
    done
    persist cyberops v31persist2 "$REV" 6 & sleep 8
    boundary llama8b_local2 0 llama
    wait
    note "phase A: finished"
elif [ "$PHASE" = B ]; then
    curl -s --max-time 20 "http://127.0.0.1:8200/health" >/dev/null || { note "ABORT: :8200 down"; exit 1; }
    note "phase B: start"
    boundary oss120_local2 0 oss
    wait
    note "phase B: finished"
fi
