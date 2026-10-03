#!/bin/bash
# ============================================================
# DEFER revision-v2 — experiment driver for the 5x H200 server.
#
# Runs the MINIMUM set of experiments the revision needs and reuses every
# v1 result that survives the harness fixes (ASB primary outputs through
# the paired replay, InjecAgent as-is).  The RTX 5090 node only serves
# Llama-3.1-8B (scripts/a51_vllm.sh); everything else runs here.
#
#   scripts/run_revision.sh preflight             # env, keys, weights, ports, A51 reachability
#   scripts/run_revision.sh serve q235|mid        # start a vLLM profile and wait for it
#   scripts/run_revision.sh e0                    # smoke (1 variant x 1 trial, all APs, CyberOps) + ASB drift check   [STOP]
#   scripts/run_revision.sh q235-main             # E1 + E2 + E3 + E1b on q235_div4, then ASB div4 replay
#   scripts/run_revision.sh mid-main              # E1 + E2 on scout_div4, mistral_div3p, llama8b_div4 in parallel;
#                                                 # ASB replay for div3 / lin3 / single
#   scripts/run_revision.sh llama8b-main          # E1 + E2 on llama8b_div4 (RTX 5090 node); can run next to q235-main
#   scripts/run_revision.sh e3-rev [group]             # helper streams for the running E3 (benign first, then APs in reverse)
#   scripts/run_revision.sh e2-rev <group> [domains]   # extra E2 streams, reverse AP order, slots 3-5 (halves E2 wall-clock)
#   scripts/run_revision.sh e1|e2|e3|e1b <group> [domains]   # single stage
#   scripts/run_revision.sh asb-replay <panel>    # div4 | div3 | lin3 | single
#   scripts/run_revision.sh tables                # make paper-tables
#   scripts/run_revision.sh reports               # make paper-reports (PDFs)
#   scripts/run_revision.sh e2b-main              # T8: q235_div4, 4 domains, 3 configs, AP-2/3/4/14 (profile q235)
#   scripts/run_revision.sh e3b                   # T8: q235_div4 CyberOps -P5 -P4 llm_judge symbolic_only, same APs
#   scripts/run_revision.sh e2b-others            # T8: scout/mistral/llama8b, CyberOps+finance, same APs (profile mid)
#
# Environment (all optional):  TRIALS=3  SEED=20260919  TEMPERATURE=0.7
#   RESUME=1 (default)  REQUIRE_FREEZE=1 (default)  DOMAINS="cyberops finance"
#
# Wall-clock budget for 2 days, measured on this box (Qwen3-235B eager mode:
# 17 tok/s per stream, ~140 tok/s aggregate at 12 streams): every (domain,
# config) pair is its own stream in its own service slot, so q235-main is
# ~20 h (E1 1 h, E2 ~8 h, E3 ~10 h, E1b 1 h) and mid-main ~10 h.
# E4 (held-out variants) and E5 (adaptive attacker) are NOT run.
# ============================================================
set -eEo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO"
[ -f .env ] && set -a && . ./.env && set +a

export TRIALS="${TRIALS:-3}"
export SEED="${SEED:-20260919}"
export TEMPERATURE="${TEMPERATURE:-0.7}"
export RESUME="${RESUME:-1}"
export REQUIRE_FREEZE="${REQUIRE_FREEZE:-1}"
export STATE_MODE="${STATE_MODE:-isolated}"
CONDA_ENV="${CONDA_ENV:-agenticcyops}"
ALL_DOMAINS="cyberops healthcare finance legal"
MAIN_GROUP="q235_div4"
LEGACY_ASB="results_legacy_v1/asb/e2e_validator_group_A/general/results.csv"
STAGE_LOG="logs/revision_stages.log"
mkdir -p logs

run_py() { conda run --no-capture-output -n "$CONDA_ENV" python3 "$@"; }
stamp()  { echo "$(date '+%F %T')  $*" | tee -a "$STAGE_LOG"; }
a51_status() { # HTTP status of the RTX 5090 endpoint with our key (000 = unreachable)
    curl -s -o /dev/null --max-time 5 -w "%{http_code}" \
        -H "Authorization: Bearer ${REMOTE_5090_API_KEY:-}" "${REMOTE_5090_URL:-http://127.0.0.1:1}/models" 2>/dev/null || echo 000
}
attack() { # attack <group> <domain> <ap|all|benign> <config|all> [trials]
    scripts/run_attack_paths.sh "$1" "$2" "$3" "$4" "${5:-$TRIALS}"
}

# The primary is latency-bound (one incident = 4 sequential LLM calls), and
# vLLM's aggregate throughput grows almost linearly with concurrent streams
# (measured on q235: 17 tok/s at 1 stream, 68 at 4, 140 at 12, 400 at 24).
# So every (domain, config) pair runs as its own stream in its own service
# slot: 4 domains x 3 configs = 12 concurrent incident streams per group.
SYSTEM_CONFIGS="flat acl_hardened agenticcyops"
SMALL_EMB="${MODELS_DIR:-$REPO/models}/Qwen/Qwen3-Embedding-0.6B"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-8}"      # 12+ torch processes share the CPU
export SKIP_REPORT=1                               # results.csv is rebuilt from the logs

parallel_domains() { # parallel_domains <group> <ap-arg> <config-arg|all> <domains...>
    local group="$1" aparg="$2" cfgarg="$3"; shift 3
    local cfgs="$cfgarg"; [ "$cfgarg" = "all" ] && cfgs="$SYSTEM_CONFIGS"
    local pids=() slot
    for dom in "$@"; do
        slot=0
        for cfg in $cfgs; do
            stamp "  start ${group} ${dom} ${aparg} ${cfg} (slot ${slot})"
            local mma_model=""
            case "$cfg" in flat|acl_hardened) mma_model="$SMALL_EMB" ;; esac
            SLOT="$slot" MMA_MODEL_PATH="$mma_model" attack "$group" "$dom" "$aparg" "$cfg" \
                > "logs/stage_${group}_${dom}_${aparg}_${cfg}${RUN_TAG:+_$RUN_TAG}.log" 2>&1 &
            pids+=($!)
            slot=$((slot + 1))
            sleep 20        # stagger service start-up (each slot seeds ChromaDB and loads an embedder)
        done
    done
    local rc=0
    for p in "${pids[@]}"; do wait "$p" || rc=1; done
    run_py -m analysis.parse_logs --group "$group" > /dev/null 2>&1 || true
    return $rc
}

# ------------------------------------------------------------
preflight() {
    stamp "preflight"
    local ok=1
    for v in ANTHROPIC_API_KEY OPENAI_API_KEY; do
        [ -n "${!v:-}" ] && echo "[  ok] $v set" || { echo "[FAIL] $v missing in .env"; ok=0; }
    done
    [ -f configs/hmac_key.txt ] || [ -n "${MMA_SHARED_SECRET:-}" ] && echo "[  ok] shared HMAC key" || { echo "[FAIL] configs/hmac_key.txt missing"; ok=0; }
    local md="${MODELS_DIR:-$REPO/models}"
    for m in Qwen/Qwen3-Embedding-0.6B Qwen/Qwen3-Embedding-8B Qwen/Qwen3-235B-A22B-Instruct-2507 Qwen/Qwen3-32B \
             mistralai/Mistral-Small-3.2-24B-Instruct-2506 meta-llama/Llama-4-Scout-17B-16E-Instruct \
             deepseek-ai/DeepSeek-R1-Distill-Qwen-32B; do
        [ -d "$md/$m" ] && echo "[  ok] weights $m" || echo "[warn] weights missing: $md/$m"
    done
    [ -d "$md/Qwen/Qwen3-14B" ] && echo "[  ok] weights Qwen/Qwen3-14B (lin3 panel)" || echo "[warn] Qwen/Qwen3-14B missing: lin3 replay unavailable (huggingface-cli download Qwen/Qwen3-14B --local-dir $md/Qwen/Qwen3-14B)"
    if [ -n "${REMOTE_5090_URL:-}" ]; then
        case "$(a51_status)" in
            200) echo "[  ok] RTX 5090 node answers at REMOTE_5090_URL and accepts REMOTE_5090_API_KEY" ;;
            401|403) echo "[FAIL] RTX 5090 node rejects REMOTE_5090_API_KEY (HTTP 401): the key in this .env differs from the one vLLM was started with on that node"; ok=0 ;;
            *)   echo "[warn] RTX 5090 node not reachable at REMOTE_5090_URL (llama8b_div4 will be skipped until it is)" ;;
        esac
    else
        echo "[warn] REMOTE_5090_URL not set: llama8b_div4 unavailable"
    fi
    scripts/check_freeze.sh && echo "[  ok] defense freeze" || { echo "[FAIL] not on the defense-freeze tag (set REQUIRE_FREEZE=0 to run anyway)"; ok=0; }
    run_py -m pytest -q -x --no-header -p no:cacheprovider 2>&1 | tail -1
    [ "$ok" = 1 ] && stamp "preflight OK" || { stamp "preflight FAILED"; return 1; }
}

serve() {
    scripts/vllm_profiles.sh start "$1"
    scripts/vllm_profiles.sh status
}

# E0: smoke + ASB drift check ---------------------------------------------
e0() {
    stamp "E0 smoke start (3 configs in parallel slots)"
    RUN_TAG=smoke MAX_VARIANTS=1 TRIALS=1 parallel_domains "$MAIN_GROUP" all all cyberops
    RUN_TAG=smoke TRIALS=1 parallel_domains "$MAIN_GROUP" benign all cyberops
    drift
}

# ASB drift check on its own (also: scripts/run_revision.sh drift)
drift() {
    stamp "E0 ASB drift check (50 cases, flat + agenticcyops, 1 trial, live)"
    run_py -m benchmarks.asb.run_e2e --group "$MAIN_GROUP" --configs flat,agenticcyops --trials 1 \
        --cases-file benchmarks/asb/representative_cases.json --tag drift --concurrency 4
    run_py - <<EOF
import csv, json
ids = set(json.load(open("benchmarks/asb/representative_cases.json")))
def llm_asr(path):
    rows = [r for r in csv.DictReader(open(path)) if r["asb_case_id"] in ids and r["config"] == "flat"]
    return (sum(r["attack_succeeded_llm"] == "True" for r in rows) / len(rows) if rows else float("nan")), len(rows)
old, n_old = llm_asr("$LEGACY_ASB")
new, n_new = llm_asr("results/asb/e2e_validator_group_${MAIN_GROUP}_drift/general/results.csv")
d = 100 * (new - old)
print(f"ASB drift check: legacy Group A llm_asr={100*old:.1f}% (n={n_old})  now={100*new:.1f}% (n={n_new})  drift={d:+.1f} pp")
print("=> within +/-5 pp: legacy ASB primary outputs may be REUSED in E6" if abs(d) <= 5 else
      "=> drift > 5 pp: rerun ASB live for q235_div4 before E6 (scripts/run_revision.sh asb-live)")
EOF
    stamp "E0 done -- STOP: review logs/revision_stages.log, results/eval_attacks/group_${MAIN_GROUP}_smoke/, the drift line above"
}

# E1: benign utility ---------------------------------------------------------
e1() { local g="$1"; shift; stamp "E1 benign ${g}: $*"; parallel_domains "$g" benign all "$@"; stamp "E1 ${g} done"; }
# E2: attack paths -----------------------------------------------------------
e2() { local g="$1"; shift; stamp "E2 attacks ${g}: $*"; parallel_domains "$g" all all "$@"; stamp "E2 ${g} done"; }
# E3: ablations (main group, CyberOps) --------------------------------------
e3() {
    local g="${1:-$MAIN_GROUP}"
    stamp "E3 ablations ${g} cyberops (7 concurrent streams, one slot each)"
    local pids=() slot=0
    for p in P1 P2 P3 P4 P5; do
        ( SLOT="$slot" DISABLE_PRINCIPLES="$p" attack "$g" cyberops all agenticcyops
          SLOT="$slot" DISABLE_PRINCIPLES="$p" attack "$g" cyberops benign agenticcyops
        ) > "logs/stage_${g}_cyberops_ablation_minus${p}.log" 2>&1 &
        pids+=($!); slot=$((slot + 1)); sleep 20
    done
    for cfg in llm_judge symbolic_only; do
        ( SLOT="$slot" attack "$g" cyberops all "$cfg"
          SLOT="$slot" attack "$g" cyberops benign "$cfg"
        ) > "logs/stage_${g}_cyberops_ablation_${cfg}.log" 2>&1 &
        pids+=($!); slot=$((slot + 1)); sleep 20
    done
    local rc=0
    for p in "${pids[@]}"; do wait "$p" || rc=1; done
    run_py -m analysis.parse_logs --group "$g" > /dev/null 2>&1 || true
    stamp "E3 done"
    return $rc
}
# E1b: persistent-state sequence (30 attack incidents then the benign set) --
e1b() {
    local g="${1:-$MAIN_GROUP}"; shift || true
    local doms="${*:-$ALL_DOMAINS}"
    stamp "E1b persistent sequence ${g}: ${doms}"
    for dom in $doms; do
        STATE_MODE=persistent RUN_TAG=persistent MAX_VARIANTS=2 attack "$g" "$dom" all agenticcyops 1
        STATE_MODE=persistent RUN_TAG=persistent attack "$g" "$dom" benign agenticcyops 1
    done
    stamp "E1b done"
}
# E2b / E3b: the reworked attack paths only (T8) --------------------------
REWORKED_APS="ap2,ap3,ap4,ap14"
# E2b-main: q235_div4, four domains, three configs, AP-2/3/4/14
e2b_main() {
    stamp "E2b-main ${MAIN_GROUP}: ${ALL_DOMAINS} [${REWORKED_APS}]"
    parallel_domains "$MAIN_GROUP" "$REWORKED_APS" all $ALL_DOMAINS
    stamp "E2b-main done"
}
# E2b-others: scout / mistral / llama8b, CyberOps + finance, three configs
e2b_others() {
    local doms="${DOMAINS:-cyberops finance}"
    local groups="scout_div4 mistral_div3p"
    [ "$(a51_status)" = "200" ] && groups="$groups llama8b_div4" \
        || stamp "llama8b_div4 skipped: RTX 5090 node not reachable (HTTP $(a51_status))"
    stamp "E2b-others: ${groups} / ${doms} [${REWORKED_APS}]"
    local pids=()
    for g in $groups; do
        ( parallel_domains "$g" "$REWORKED_APS" all $doms ) > "logs/stage_${g}_e2b-others.log" 2>&1 &
        pids+=($!)
    done
    local rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
    stamp "E2b-others done"; return $rc
}
# E3b: q235_div4 CyberOps, minus P5 / minus P4 / llm_judge / symbolic_only, AP-2/3/4/14
e3b() {
    local g="${1:-$MAIN_GROUP}"
    stamp "E3b ablations ${g} cyberops [${REWORKED_APS}]: -P5 -P4 llm_judge symbolic_only"
    local pids=() slot=0
    for p in P5 P4; do
        ( SLOT="$slot" DISABLE_PRINCIPLES="$p" attack "$g" cyberops "$REWORKED_APS" agenticcyops
        ) > "logs/stage_${g}_cyberops_e3b_minus${p}.log" 2>&1 &
        pids+=($!); slot=$((slot + 1)); sleep 20
    done
    for cfg in llm_judge symbolic_only; do
        ( SLOT="$slot" attack "$g" cyberops "$REWORKED_APS" "$cfg"
        ) > "logs/stage_${g}_cyberops_e3b_${cfg}.log" 2>&1 &
        pids+=($!); slot=$((slot + 1)); sleep 20
    done
    local rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
    run_py -m analysis.parse_logs --group "$g" > /dev/null 2>&1 || true
    stamp "E3b done"; return $rc
}

# E6: ASB paired panel replay ------------------------------------------------
asb_replay() {
    local panel="$1"
    stamp "E6 ASB replay panel=${panel} from legacy Group A primary outputs"
    run_py -m benchmarks.asb.run_e2e --group "$MAIN_GROUP" --configs agenticcyops --trials 5 \
        --replay-from "$LEGACY_ASB" --consensus-config "$panel" --tag "$panel" --concurrency 6
    stamp "E6 ${panel} done"
}
asb_live() {
    stamp "ASB live rerun for ${MAIN_GROUP} (drift check failed)"
    run_py -m benchmarks.asb.run_e2e --group "$MAIN_GROUP" --configs flat,agenticcyops --trials 5 --concurrency 4
}

# Payload gate (T5): validate-all + measurability + hygiene, before any run.
check_payloads() {
    stamp "check-payloads (validate-all, measurability, hygiene)"
    make check-payloads PY="conda run --no-capture-output -n $CONDA_ENV python3" \
        || { stamp "check-payloads FAILED -- fix payloads before running"; exit 1; }
}

tables() { stamp "tables"; make paper-tables; stamp "tables written to results/paper_tables.md"; }
reports() { stamp "reports"; make paper-reports; stamp "reports written: results/revision_report.pdf + per-run attack_report.pdf + ASB asb_analytics.pdf"; }

# ------------------------------------------------------------
cmd="${1:-}"; shift || true
# T5 gate: any stage that runs trials validates the payloads first.
case "$cmd" in
    e0|smoke-aco|e1|e2|e3|e1b|e2-rev|e3-rev|q235-main|mid-main|llama8b-main|e2b-main|e2b-others|e3b)
        check_payloads ;;
esac
case "$cmd" in
    preflight) preflight ;;
    serve)     serve "${1:?profile}" ;;
    e0)        e0 ;;
    drift)     drift ;;
    smoke-aco) RUN_TAG=smoke2 MAX_VARIANTS=1 TRIALS=1 parallel_domains "$MAIN_GROUP" all agenticcyops cyberops ;;
    e1|e2)     g="${1:?group}"; shift || true; "$cmd" "$g" ${*:-${DOMAINS:-$ALL_DOMAINS}} ;;
    e3)        e3 "${1:-$MAIN_GROUP}" ;;
    e1b)       e1b "${1:-$MAIN_GROUP}" ${DOMAINS:-} ;;
    asb-replay) asb_replay "${1:?panel}" ;;
    asb-live)  asb_live ;;
    tables)    tables ;;
    reports)   reports ;;
    e2b-main)  e2b_main ;;
    e2b-others) e2b_others ;;
    e3b)       e3b "${1:-$MAIN_GROUP}" ;;
    q235-main)
        # profile q235 must be up (scripts/run_revision.sh serve q235)
        e1 "$MAIN_GROUP" $ALL_DOMAINS
        e2 "$MAIN_GROUP" $ALL_DOMAINS
        e3 "$MAIN_GROUP"
        e1b "$MAIN_GROUP"
        asb_replay div4          # V1 + V5 are up in this profile
        tables ;;
    e2-rev)
        # Second set of E2 streams for a group: same cells, attack paths in
        # REVERSE order, on service slots 3-5 (own ports / ChromaDB), so it
        # can run next to the group's normal E2 (slots 0-2, forward order).
        # The two meet in the middle; RESUME skips whatever the other side
        # has already finished.   scripts/run_revision.sh e2-rev <group> [domains]
        #   CFGS="agenticcyops"            only these configs (default: all three)
        #   REV_CPUSETS="72-77 78-83 ..."  core blocks for the extra streams, in
        #                                  launch order (default: the normal mapping)
        g="${1:?group}"; shift || true
        doms="${*:-${DOMAINS:-$ALL_DOMAINS}}"
        cfgs="${CFGS:-$SYSTEM_CONFIGS}"
        read -r -a rev_cpus <<< "${REV_CPUSETS:-}"
        stamp "E2 (reverse order, slots 3-5) ${g}: ${doms} [${cfgs}]"
        pids=(); stream=0
        for dom in $doms; do
            slot=3
            for cfg in $cfgs; do
                mma_model=""; case "$cfg" in flat|acl_hardened) mma_model="$SMALL_EMB" ;; esac
                cpu="${rev_cpus[$stream]:-}"
                stamp "  start ${g} ${dom} reverse ${cfg} (slot ${slot}${cpu:+, cpus ${cpu}})"
                ( for n in 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1; do
                      SLOT="$slot" MMA_MODEL_PATH="$mma_model" CPUSET_OVERRIDE="$cpu" attack "$g" "$dom" "ap${n}" "$cfg"
                  done ) > "logs/stage_${g}_${dom}_rev_${cfg}.log" 2>&1 &
                pids+=($!); slot=$((slot + 1)); stream=$((stream + 1)); sleep 20
            done
        done
        rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
        run_py -m analysis.parse_logs --group "$g" > /dev/null 2>&1 || true
        stamp "E2 (reverse) ${g} done"; exit $rc ;;
    e3-rev)
        # Helper streams for E3: the same seven ablations, benign first and
        # then the attack paths in REVERSE order, next to the running E3.
        # Same slot numbers as E3 but shifted ports (PORT_EXTRA), their own
        # ChromaDB dirs (CHROMA_TAG) and their own core blocks; RESUME skips
        # whatever the forward stream has finished.
        #   scripts/run_revision.sh e3-rev [group]      ABLATIONS="P1 P2 llm_judge" to restrict
        g="${1:-$MAIN_GROUP}"
        abls="${ABLATIONS:-P1 P2 P3 P4 P5 llm_judge symbolic_only}"
        read -r -a rev_cpus <<< "${REV_CPUSETS:-42-47 48-53 54-59 60-65 66-71 72-77 78-83}"
        stamp "E3 (reverse helpers) ${g} cyberops: ${abls}"
        pids=(); stream=0
        for tok in $abls; do
            case "$tok" in
                P1) slot=0 ;; P2) slot=1 ;; P3) slot=2 ;; P4) slot=3 ;; P5) slot=4 ;;
                llm_judge) slot=5 ;; symbolic_only) slot=6 ;; *) echo "unknown ablation $tok"; exit 2 ;;
            esac
            cpu="${rev_cpus[$stream]:-}"
            stamp "  start ${g} cyberops reverse ${tok} (slot ${slot}+1500${cpu:+, cpus ${cpu}})"
            (
                export SLOT="$slot" PORT_EXTRA=1500 CHROMA_TAG=rev CPUSET_OVERRIDE="$cpu"
                case "$tok" in
                    P*) export DISABLE_PRINCIPLES="$tok"; cfg=agenticcyops ;;
                    *)  cfg="$tok" ;;
                esac
                attack "$g" cyberops benign "$cfg"
                for n in 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1; do
                    attack "$g" cyberops "ap${n}" "$cfg"
                done
            ) > "logs/stage_${g}_cyberops_ablation_${tok}_rev.log" 2>&1 &
            pids+=($!); stream=$((stream + 1)); sleep 20
        done
        rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
        stamp "E3 (reverse helpers) ${g} done"; exit $rc ;;
    llama8b-main)
        # needs only V1 + V5 on this box (up in both profiles) and the RTX 5090 node
        [ "$(a51_status)" = "200" ] || { stamp "llama8b-main: RTX 5090 node not usable (HTTP $(a51_status))"; exit 1; }
        doms="${DOMAINS:-cyberops finance}"
        e1 llama8b_div4 $doms
        e2 llama8b_div4 $doms ;;
    mid-main)
        # profile mid must be up; A51 serving llama8b (optional)
        doms="${DOMAINS:-cyberops finance}"
        groups="scout_div4 mistral_div3p"
        [ "$(a51_status)" = "200" ] && groups="$groups llama8b_div4" \
            || stamp "llama8b_div4 skipped: RTX 5090 node not reachable or key rejected (HTTP $(a51_status))"
        pids=()
        for g in $groups; do
            ( e1 "$g" $doms; e2 "$g" $doms ) > "logs/stage_${g}_mid-main.log" 2>&1 &
            pids+=($!)
        done
        for panel in div3 lin3 single; do asb_replay "$panel" || stamp "E6 ${panel} failed (see log)"; done
        rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
        tables
        [ $rc = 0 ] || { stamp "mid-main: a group failed, see logs/stage_*_mid-main.log"; exit 1; } ;;
    *)
        sed -n 2,26p "$0"; exit 2 ;;
esac
