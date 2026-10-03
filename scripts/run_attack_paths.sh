#!/bin/bash
# ============================================================
# DEFER — Unified Experiment Runner
#
# Single script for all evaluations: baseline, Eval A, Eval F.
# Select group, domain(s), APs, configs, trials interactively or via CLI.
#
# Usage:
#   ./scripts/run_attack_paths.sh                              # Interactive
#   ./scripts/run_attack_paths.sh A cyberops ap1 agenticcyops 1    # Quick test
#   ./scripts/run_attack_paths.sh A cyberops all all 6             # Full Eval A
#   ./scripts/run_attack_paths.sh A healthcare all all 10          # Eval F healthcare
#   ./scripts/run_attack_paths.sh C all benign all 1               # Baseline all domains
#   ./scripts/run_attack_paths.sh F cyberops ap1 agenticcyops 1    # Claude primary test
# ============================================================

set -eE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Auto-load .env so child Python inherits API keys etc.
if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    source ".env"
    set +a
fi

CONDA_ENV="agenticcyops"
# Tool / MMA ports are no longer global; they are computed per
# (GROUP, domain) inside run_domain() so parallel groups don't collide.
PIDS=()

ALL_DOMAINS=("cyberops" "healthcare" "finance" "legal")
ALL_CONFIGS=("flat" "acl_hardened" "agenticcyops")

# ---- Group definitions ----
declare -A GP_PRIMARY GP_PROVIDER GP_PORTS GP_CONSENSUS GP_DESC GP_API_KEY_ENV GP_EXTRA_BODY

GP_PRIMARY[A]="http://localhost:8000/v1"; GP_PROVIDER[A]="openai"; GP_PORTS[A]="8000 8002 8005"; GP_CONSENSUS[A]="default_consensus"
GP_DESC[A]="Qwen3-235B + V1(Qwen) + V2(DeepSeek) + V4(Claude) + V6(GPT-4o)"

GP_PRIMARY[B]="http://localhost:8001/v1"; GP_PROVIDER[B]="openai"; GP_PORTS[B]="8001 8002 8005"; GP_CONSENSUS[B]="default_consensus"
GP_DESC[B]="GLM-4.7-FP8 + V1 + V2 + V4 + V6"

GP_PRIMARY[C]="http://localhost:8000/v1"; GP_PROVIDER[C]="openai"; GP_PORTS[C]="8000 8002"; GP_CONSENSUS[C]="same_family"
GP_DESC[C]="Qwen3-235B + V1 x3 (same-family, need 2/3)"

GP_PRIMARY[D]="http://localhost:8004/v1"; GP_PROVIDER[D]="openai"; GP_PORTS[D]="8004 8002 8005"; GP_CONSENSUS[D]="default_consensus"
GP_DESC[D]="Llama-4-Scout + V1 + V2 + V4 + V6"

GP_PRIMARY[E]="http://localhost:8000/v1"; GP_PROVIDER[E]="openai"; GP_PORTS[E]="8000 8002 8003"; GP_CONSENSUS[E]="with_mistral"
GP_DESC[E]="Qwen3-235B + V1 + V5(Mistral) + V4 + V6"

GP_PRIMARY[F]="anthropic"; GP_PROVIDER[F]="anthropic"; GP_PORTS[F]="8002 8005 8004"; GP_CONSENSUS[F]="all_with_gpt4o"
GP_DESC[F]="Claude (API primary) + V1 + V2 + V3(Llama) + V6"

# ---- Small/mid-tier primary groups ----
# Each panel excludes the validator that duplicates the primary family
# (no_qwen_panel for G, no_mistral_panel for H) to avoid self-voting.
# GP_PORTS lists only localhost ports the preflight check should verify;
# external/API primaries are not localhost-pingable and are exercised at
# request time instead.

GP_PRIMARY[G]="http://localhost:8002/v1"; GP_PROVIDER[G]="openai"; GP_PORTS[G]="8002 8003"; GP_CONSENSUS[G]="no_qwen_panel"
GP_DESC[G]="Qwen3-32B (mid, self-host) + V5(Mistral) + V4(Claude) + V6(GPT-4o)"

GP_PRIMARY[H]="http://localhost:8003/v1"; GP_PROVIDER[H]="openai"; GP_PORTS[H]="8002 8003"; GP_CONSENSUS[H]="no_mistral_panel"
GP_DESC[H]="Mistral-Small-3.2-24B (mid) + V1(Qwen) + V4(Claude) + V6(GPT-4o)"

GP_PRIMARY[I]="${REMOTE_5090_URL:-}"; GP_PROVIDER[I]="openai"; GP_PORTS[I]="8002 8003"; GP_CONSENSUS[I]="with_mistral"; GP_API_KEY_ENV[I]="REMOTE_5090_API_KEY"
GP_DESC[I]="Llama-3.1-8B-Instruct (small, RTX 5090 node via REMOTE_5090_URL) + V1(Qwen) + V5(Mistral) + V4(Claude) + V6(GPT-4o)"

GP_PRIMARY[J]="http://localhost:8006/v1"; GP_PROVIDER[J]="openai"; GP_PORTS[J]="8006 8002 8003"; GP_CONSENSUS[J]="with_mistral"
GP_DESC[J]="GPT-OSS-120B (mid-large) + V1(Qwen) + V5(Mistral) + V4(Claude) + V6(GPT-4o)"


# ---- Revision-v2 groups ----------------------
# Served-model names come from --served-model-name in scripts/vllm_profiles.sh;
# the harness discovers them through /v1/models.
GP_PRIMARY[q235_div4]="http://localhost:8000/v1"; GP_PROVIDER[q235_div4]="openai"; GP_PORTS[q235_div4]="8000 8002 8003"; GP_CONSENSUS[q235_div4]="div4"
GP_DESC[q235_div4]="Qwen3-235B-A22B BF16 TP=4 + div4 [V1 Qwen, V5 Mistral, V4 Claude, V6 GPT-4o] 3/4"
GP_PRIMARY[scout_div4]="http://localhost:8004/v1"; GP_PROVIDER[scout_div4]="openai"; GP_PORTS[scout_div4]="8004 8002 8003"; GP_CONSENSUS[scout_div4]="div4"
GP_DESC[scout_div4]="Llama-4-Scout BF16 TP=2 + div4"
GP_PRIMARY[mistral_div3p]="http://localhost:8003/v1"; GP_PROVIDER[mistral_div3p]="openai"; GP_PORTS[mistral_div3p]="8003 8002"; GP_CONSENSUS[mistral_div3p]="mistral_div3p"
GP_DESC[mistral_div3p]="Mistral-Small-3.2-24B + [V1 Qwen, V4 Claude, V6 GPT-4o] 2/3"
GP_PRIMARY[llama8b_div4]="${REMOTE_5090_URL:-}"; GP_PROVIDER[llama8b_div4]="openai"; GP_PORTS[llama8b_div4]="8002 8003"; GP_CONSENSUS[llama8b_div4]="div4"; GP_API_KEY_ENV[llama8b_div4]="REMOTE_5090_API_KEY"
GP_DESC[llama8b_div4]="Llama-3.1-8B-Instruct BF16 on the RTX 5090 node (REMOTE_5090_URL) + div4"
GP_PRIMARY[claude_loc]="anthropic"; GP_PROVIDER[claude_loc]="anthropic"; GP_PORTS[claude_loc]="8002 8003 8004"; GP_CONSENSUS[claude_loc]="claude_loc"
GP_DESC[claude_loc]="claude-sonnet-4-5 (API) + [V1 Qwen, V5 Mistral, V3 Llama-4-Scout, V6 GPT-4o] 3/4"
# v2.9 live calibration: Qwen3-235B primary, the two local validators that fit
# beside it (Mistral-Small :8101, Gemma-4 :8102), 2 of 2. No API validator.
GP_PRIMARY[q235_local2]="http://localhost:8000/v1"; GP_PROVIDER[q235_local2]="openai"; GP_PORTS[q235_local2]="8000 8101 8102"; GP_CONSENSUS[q235_local2]="local2"
GP_DESC[q235_local2]="Qwen3-235B-A22B BF16 TP=4 + local2 [L1 Mistral, L2 Gemma] 2/2"
GP_PRIMARY[oss120_local2]="http://localhost:8200/v1"; GP_PROVIDER[oss120_local2]="openai"; GP_PORTS[oss120_local2]="8200 8101 8102"; GP_CONSENSUS[oss120_local2]="local2"
GP_DESC[oss120_local2]="gpt-oss-120b (native MXFP4) + local2 [L1 Mistral, L2 Gemma] 2/2"
GP_PRIMARY[oss120_smoke]="http://localhost:8200/v1"; GP_PROVIDER[oss120_smoke]="openai"; GP_PORTS[oss120_smoke]="8200"; GP_CONSENSUS[oss120_smoke]="local2"
GP_DESC[oss120_smoke]="gpt-oss-120b primary smoke test (panel-free configurations only)"
GP_PRIMARY[llama8b_local2]="${REMOTE_5090_URL:-}"; GP_PROVIDER[llama8b_local2]="openai"; GP_PORTS[llama8b_local2]="8101 8102"; GP_CONSENSUS[llama8b_local2]="local2"; GP_API_KEY_ENV[llama8b_local2]="REMOTE_5090_API_KEY"
GP_DESC[llama8b_local2]="Llama-3.1-8B-Instruct BF16 on the RTX 5090 node (REMOTE_5090_URL) + local2 [L1 Mistral, L2 Gemma] 2/2"
GP_PRIMARY[glm_div4]="http://localhost:8001/v1"; GP_PROVIDER[glm_div4]="openai"; GP_PORTS[glm_div4]="8001 8002 8003"; GP_CONSENSUS[glm_div4]="div4"
GP_DESC[glm_div4]="GLM-4.7-FP8 TP=4 + div4 (optional, lowest priority)"

ALL_GROUPS=("q235_div4" "q235_local2" "oss120_local2" "oss120_smoke" "llama8b_local2" "scout_div4" "mistral_div3p" "llama8b_div4" "claude_loc" "glm_div4" "A" "B" "C" "D" "E" "F" "G" "H" "I" "J")

# ---- Per-(group, domain) port + ChromaDB allocator -----------------------
# Multiple groups can now run in parallel without their tool/MMA servers
# stomping on each other.  Each (group, domain) slot gets its own
# 40-port window starting at 10000:
#
#   tool_base = 10000 + group_offset*160 + domain_offset*40
#   mma_port  = tool_base + 30
#
# Group A cyberops -> 10000-10029 tools + 10030 MMA
# Group A healthcare -> 10040-10069 tools + 10070 MMA
# ...
# Group K legal -> 11720-11749 tools + 11750 MMA
#
# Full footprint: ports 10000-11759.  ChromaDB also separates by group
# (data/chromadb/group_<G>/<domain>/) so two parallel groups can seed
# the same domain without overwriting each other.
declare -A GROUP_OFFSET DOMAIN_OFFSET
GROUP_OFFSET[A]=0;  GROUP_OFFSET[B]=1; GROUP_OFFSET[C]=2; GROUP_OFFSET[D]=3
GROUP_OFFSET[E]=4;  GROUP_OFFSET[F]=5; GROUP_OFFSET[G]=6; GROUP_OFFSET[H]=7
GROUP_OFFSET[I]=8;  GROUP_OFFSET[J]=9
GROUP_OFFSET[q235_div4]=10; GROUP_OFFSET[q235_local2]=10; GROUP_OFFSET[scout_div4]=11; GROUP_OFFSET[mistral_div3p]=12
GROUP_OFFSET[llama8b_div4]=13; GROUP_OFFSET[claude_loc]=14; GROUP_OFFSET[glm_div4]=15
GROUP_OFFSET[oss120_local2]=16; GROUP_OFFSET[oss120_smoke]=17; GROUP_OFFSET[llama8b_local2]=18
DOMAIN_OFFSET[cyberops]=0; DOMAIN_OFFSET[healthcare]=1
DOMAIN_OFFSET[finance]=2;  DOMAIN_OFFSET[legal]=3

# SLOT (0..6) gives one (group, domain) several independent service sets
# (tool stubs + MMA + ChromaDB) so configs / ablations of the same domain
# can run concurrently without sharing tool state, injection queues or
# trial-tagged memory.  Slot n shifts every port by n*3000.
compute_tool_base() {
    local _grp="$1" _dom="$2"
    # PORT_EXTRA shifts a helper stream into the gap between slot blocks
    # (each slot block spans < 2600 ports of its 3000) so it can share a SLOT
    # number with a running stream without sharing its ports.
    echo $((10000 + GROUP_OFFSET[$_grp]*160 + DOMAIN_OFFSET[$_dom]*40 + ${SLOT:-0}*3000 + ${PORT_EXTRA:-0}))
}

# ---- Helpers ----
# ---- CPU pinning -----------------------------------------------------------
# Every stream (group, domain, slot) gets its own block of cores.  Without it
# each MMA gateway / seeding job sizes its ONNX and torch thread pools to all
# 128 cores, and 18 concurrent streams drove the load average to ~280 while
# the GPUs sat idle (measured 2026-09-19).  Thread pools follow the affinity
# mask, so pinning also bounds them.  PIN_CPUS=0 disables; CPU_WIDTH = cores
# per stream; cores above 108 are left to the vLLM API servers.
declare -A CPU_BASE PIN_DOMAIN_IDX
CPU_BASE[q235_div4]=0; CPU_BASE[q235_local2]=0; CPU_BASE[glm_div4]=0; CPU_BASE[claude_loc]=0
CPU_BASE[scout_div4]=0; CPU_BASE[mistral_div3p]=36; CPU_BASE[llama8b_div4]=72
CPU_BASE[oss120_local2]=54; CPU_BASE[oss120_smoke]=54; CPU_BASE[llama8b_local2]=0
PIN_DOMAIN_IDX[cyberops]=0; PIN_DOMAIN_IDX[finance]=1; PIN_DOMAIN_IDX[healthcare]=2; PIN_DOMAIN_IDX[legal]=3
CPUSET=""
set_cpuset() { # set_cpuset <domain>
    CPUSET=""
    [ "${PIN_CPUS:-1}" = "1" ] && command -v taskset > /dev/null || return 0
    # explicit block from the driver (extra streams placed on free cores)
    if [ -n "${CPUSET_OVERRIDE:-}" ]; then CPUSET="$CPUSET_OVERRIDE"; return 0; fi
    local width="${CPU_WIDTH:-6}" ncpu; ncpu=$(nproc --all)
    local idx=$(( ${PIN_DOMAIN_IDX[$1]:-0} * 3 + ${SLOT:-0} ))
    local start=$(( ( ${CPU_BASE[$GROUP]:-0} + idx * width ) % (ncpu - width + 1) ))
    CPUSET="${start}-$(( start + width - 1 ))"
}
run_py() {
    if [ -n "$CPUSET" ]; then
        taskset -c "$CPUSET" conda run --no-capture-output -n "$CONDA_ENV" python3 "$@"
    else
        conda run --no-capture-output -n "$CONDA_ENV" python3 "$@"
    fi
}

wait_for_health() {
    local url="$1" name="$2" timeout="${3:-60}" elapsed=0
    while ! curl -s --max-time 1 "$url" > /dev/null 2>&1; do
        sleep 1; elapsed=$((elapsed + 1))
        [ $elapsed -ge $timeout ] && echo "[FAIL] $name timeout" && return 1
    done
    echo "[  ok] $name (${elapsed}s)"
}

cleanup() {
    echo ""; echo "[cleanup] Stopping background services..."
    for pid in "${PIDS[@]}"; do pkill -P "$pid" 2>/dev/null || true; kill "$pid" 2>/dev/null || true; done
    # Only kill the ports this run actually allocated so we don't disturb
    # parallel runs from other groups using their own slot.
    for port in "${ALLOCATED_PORTS[@]}"; do
        pid=$(lsof -ti :$port 2>/dev/null || true); [ -n "$pid" ] && kill -9 $pid 2>/dev/null || true
    done
    wait 2>/dev/null || true; echo "[cleanup] Done."
}
trap cleanup EXIT INT TERM
ALLOCATED_PORTS=()

# ---- Interactive or CLI ----
if [ -z "$1" ]; then
    echo ""
    echo "  DEFER — Experiment Runner"
    echo "  ──────────────────────────────────────────────"
    echo ""

    # Group
    echo "  Model Groups:"
    for g in "${ALL_GROUPS[@]}"; do
        echo "    $g) ${GP_DESC[$g]}"
    done
    echo ""
    read -p "  Select group [A]: " input_group
    GROUP="${input_group:-A}"; GROUP="${GROUP^^}"

    # Domains
    echo ""
    echo "  Domains:"
    echo "    1) cyberops   2) healthcare   3) finance   4) legal   5) all"
    read -p "  Select (e.g. 1, or 5 for all): " dom_choices
    SELECTED_DOMAINS=()
    for c in $dom_choices; do
        case "$c" in
            1) SELECTED_DOMAINS+=("cyberops") ;; 2) SELECTED_DOMAINS+=("healthcare") ;;
            3) SELECTED_DOMAINS+=("finance") ;; 4) SELECTED_DOMAINS+=("legal") ;;
            5) SELECTED_DOMAINS=("${ALL_DOMAINS[@]}"); break ;;
        esac
    done
    [ ${#SELECTED_DOMAINS[@]} -eq 0 ] && echo "  No domains." && exit 0

    # APs (show domain-appropriate options)
    echo ""
    echo "  Attack Paths:"
    echo "    1-6)   ap1-ap6 (original)     7-15) ap7-ap15 (new)"
    echo "    16) all original (1-6)         17) all new (7-15)"
    echo "    18) ALL (1-15)                 19) benign only"
    echo "    20) auto (domain-appropriate)"
    read -p "  Select (e.g. 1 2, or 18 for all): " ap_choices
    AP_MODE="custom"
    SELECTED_APS=()
    for c in $ap_choices; do
        case "$c" in
            1) SELECTED_APS+=("ap1") ;; 2) SELECTED_APS+=("ap2") ;; 3) SELECTED_APS+=("ap3") ;;
            4) SELECTED_APS+=("ap4") ;; 5) SELECTED_APS+=("ap5") ;; 6) SELECTED_APS+=("ap6") ;;
            7) SELECTED_APS+=("ap7") ;; 8) SELECTED_APS+=("ap8") ;; 9) SELECTED_APS+=("ap9") ;;
            10) SELECTED_APS+=("ap10") ;; 11) SELECTED_APS+=("ap11") ;; 12) SELECTED_APS+=("ap12") ;;
            13) SELECTED_APS+=("ap13") ;; 14) SELECTED_APS+=("ap14") ;; 15) SELECTED_APS+=("ap15") ;;
            16) SELECTED_APS=("ap1" "ap2" "ap3" "ap4" "ap5" "ap6"); break ;;
            17) SELECTED_APS=("ap7" "ap8" "ap9" "ap10" "ap11" "ap12" "ap13" "ap14" "ap15"); break ;;
            18) SELECTED_APS=("ap1" "ap2" "ap3" "ap4" "ap5" "ap6" "ap7" "ap8" "ap9" "ap10" "ap11" "ap12" "ap13" "ap14" "ap15"); break ;;
            19) AP_MODE="benign"; break ;;
            20) AP_MODE="auto"; break ;;
        esac
    done

    # Configs (production trio only -- ablations live in scripts/run_ablations.sh)
    echo ""
    echo "  Configs: 1) flat  2) acl_hardened  3) agenticcyops  4) all"
    read -p "  Select (e.g. 3, or 4 for all): " cfg_choices
    SELECTED_CONFIGS=()
    for c in $cfg_choices; do
        case "$c" in
            1) SELECTED_CONFIGS+=("flat") ;; 2) SELECTED_CONFIGS+=("acl_hardened") ;;
            3) SELECTED_CONFIGS+=("agenticcyops") ;;
            4) SELECTED_CONFIGS=("${ALL_CONFIGS[@]}"); break ;;
        esac
    done
    [ ${#SELECTED_CONFIGS[@]} -eq 0 ] && echo "  No configs." && exit 0

    # Trials
    echo ""
    read -p "  Trials per variant [3]: " input_trials
    TRIALS="${input_trials:-3}"

else
    # CLI: GROUP DOMAIN AP_FILTER CONFIG_FILTER TRIALS
    #   env: STATE_MODE=isolated|persistent  SEED=<int>  TEMPERATURE=<float>
    #        RESUME=1  REQUIRE_FREEZE=1  DISABLE_PRINCIPLES=P3,P5
    GROUP="$1"
    [ ${#GROUP} -eq 1 ] && GROUP="${GROUP^^}"     # legacy single-letter ids
    DOM_ARG="${2:-cyberops}"
    AP_ARG="${3:-all}"
    CFG_ARG="${4:-all}"
    TRIALS="${5:-3}"

    # Parse domains
    if [ "$DOM_ARG" = "all" ]; then
        SELECTED_DOMAINS=("${ALL_DOMAINS[@]}")
    else
        SELECTED_DOMAINS=("$DOM_ARG")
    fi

    # Parse APs
    AP_MODE="custom"
    if [ "$AP_ARG" = "all" ]; then
        SELECTED_APS=("ap1" "ap2" "ap3" "ap4" "ap5" "ap6" "ap7" "ap8" "ap9" "ap10" "ap11" "ap12" "ap13" "ap14" "ap15")
    elif [ "$AP_ARG" = "benign" ]; then
        AP_MODE="benign"
    elif [ "$AP_ARG" = "auto" ]; then
        AP_MODE="auto"
    else
        IFS=',' read -r -a SELECTED_APS <<< "$AP_ARG"   # "ap2" or "ap2,ap3,ap4,ap14"
    fi

    # Parse configs
    [ "$CFG_ARG" = "all" ] && SELECTED_CONFIGS=("${ALL_CONFIGS[@]}") || SELECTED_CONFIGS=("$CFG_ARG")
fi

# Validate group
if [ -z "${GP_PRIMARY[$GROUP]}" ]; then
    echo "  Unknown group: $GROUP"; exit 1
fi

LLM_URL="${GP_PRIMARY[$GROUP]}"
LLM_PROVIDER="${GP_PROVIDER[$GROUP]}"
CONSENSUS_CFG="${GP_CONSENSUS[$GROUP]}"

echo ""
echo "============================================================"
echo "  DEFER Experiment — Group ${GROUP}"
echo "  ${GP_DESC[$GROUP]}"
echo "  Domains: ${SELECTED_DOMAINS[*]}"
echo "  APs: ${AP_MODE} ${SELECTED_APS[*]}"
echo "  Configs: ${SELECTED_CONFIGS[*]}"
echo "  Trials: ${TRIALS}"
echo "============================================================"

# ---- Check servers ----
echo ""
echo "[check] Verifying servers for Group ${GROUP}..."
all_up=true
for port in ${GP_PORTS[$GROUP]}; do
    curl -s --max-time 2 http://localhost:$port/health > /dev/null 2>&1 && echo "[  ok] $port" || { echo "[FAIL] $port"; all_up=false; }
done
[ "$all_up" = false ] && echo "  Start servers: ./start_servers.sh" && exit 1

START_TIME=$(date +%s)

# ---- Run per domain ----
run_domain() {
    local domain="$1"
    # Unified naming: logs/<domain>_eval_attacks_<group> and
    # results/eval_attacks/group_<group>/<domain>/ for every domain.
    # Ablation runs (DISABLE_PRINCIPLES env) get a `_disabled_<set>`
    # suffix on both paths so they don't clobber the production run.
    local _ablation_tag=""
    if [ -n "$DISABLE_PRINCIPLES" ]; then
        # Normalize: P1,P3 -> P1P3 (sorted, uppercase)
        _ablation_tag="_disabled_$(echo "$DISABLE_PRINCIPLES" \
            | tr ',' '\n' | tr '[:lower:]' '[:upper:]' \
            | sort -u | tr -d '\n')"
    fi
    # RUN_TAG (e.g. "persistent", "smoke") keeps a special run out of the
    # group's main log / result directories.
    [ -n "${RUN_TAG:-}" ] && _ablation_tag="${_ablation_tag}_${RUN_TAG}"
    local log_dir="logs/${domain}_eval_attacks_${GROUP}${_ablation_tag}"
    local result_dir="results/eval_attacks/group_${GROUP}${_ablation_tag}/${domain}"

    # Per-(group, domain) port slot + ChromaDB path so parallel groups
    # never collide on tool/MMA ports or seed data.
    local TOOL_BASE_PORT
    TOOL_BASE_PORT=$(compute_tool_base "$GROUP" "$domain")
    local MMA_PORT=$((TOOL_BASE_PORT + 30))
    local CHROMA_DB_PATH="./data/chromadb/group_${GROUP}${SLOT:+_s${SLOT}}${CHROMA_TAG:+_${CHROMA_TAG}}"

    set_cpuset "$domain"
    echo ""
    echo "============================================================"
    echo "  ${domain} / Group ${GROUP}"
    echo "  tool_base=${TOOL_BASE_PORT}  mma=${MMA_PORT}  chromadb=${CHROMA_DB_PATH}/${domain}  cpus=${CPUSET:-all}"
    echo "============================================================"

    # Logs and results are append-only (every log file carries a timestamp,
    # results.csv is appended per trial and rebuilt from the logs), so an
    # existing run directory is never deleted: RESUME=1 continues it, and a
    # repeat without RESUME adds new log files next to the old ones.  Only
    # this slot's ChromaDB scratch directory is recreated and re-seeded.
    if [ -d "$log_dir" ] || [ -d "$result_dir" ]; then
        echo "  existing data for ${domain}/Group ${GROUP}: keeping it (RESUME=${RESUME:-0})"
    fi
    rm -rf "${CHROMA_DB_PATH:?}/${domain}" 2>/dev/null || true
    mkdir -p "$result_dir" "$CHROMA_DB_PATH"

    # Kill only stale processes in *this* group/domain's port slot --
    # don't touch ports owned by parallel runs from other (group, domain) slots.
    for port in $(seq ${TOOL_BASE_PORT} $((TOOL_BASE_PORT + 29))) ${MMA_PORT}; do
        pid=$(lsof -ti :$port 2>/dev/null || true); [ -n "$pid" ] && kill -9 $pid 2>/dev/null || true
        ALLOCATED_PORTS+=("$port")
    done
    sleep 1; PIDS=()

    # ChromaDB
    echo "[setup] ChromaDB..."
    run_py -m memory.chromadb_setup --domain "$domain" --db-path "$CHROMA_DB_PATH" 2>&1 | tail -2
    run_py -m memory.seed_data       --domain "$domain" --db-path "$CHROMA_DB_PATH" 2>&1 | tail -2

    # Tools
    echo "[tools] Starting ${domain} servers on base port ${TOOL_BASE_PORT}..."
    HARNESS_INJECTION=1 run_py -m domains.${domain}.tools.start_all --base-port "$TOOL_BASE_PORT" &
    PIDS+=($!); sleep 3
    wait_for_health "http://localhost:${TOOL_BASE_PORT}/health" "${domain} tools" 30

    # MMA
    # MMA_MODEL_PATH: flat / acl_hardened bypass P4 and P5, so their gateway
    # never embeds anything; the driver points those slots at the 0.6B model
    # to save ~30 GB of RAM per slot.  Default (unset) = the gateway's 8B model.
    local _mma_model=()
    [ -n "${MMA_MODEL_PATH:-}" ] && _mma_model=(--model-path "$MMA_MODEL_PATH")
    HARNESS_INJECTION=1 run_py -m memory.mma_gateway --domain "$domain" --port "$MMA_PORT" --db-path "$CHROMA_DB_PATH" "${_mma_model[@]}" &
    PIDS+=($!); wait_for_health "http://localhost:${MMA_PORT}/health" "MMA" 30 || true

    # Determine APs for this domain
    local domain_aps=()
    if [ "$AP_MODE" = "benign" ]; then
        domain_aps=()  # benign only, no attack APs
    elif [ "$AP_MODE" = "auto" ]; then
        # Auto-detect from payload files
        for f in domains/${domain}/payloads/ap*_variants.json; do
            [ -f "$f" ] && domain_aps+=($(basename "$f" _variants.json))
        done
    else
        domain_aps=("${SELECTED_APS[@]}")
    fi

    # Run attacks
    echo "[attack] Running trials..."
    for config in "${SELECTED_CONFIGS[@]}"; do
        echo "--- ${config} ---"

        # Forward ablation flag if set (only meaningful for agenticcyops).
        local _disable_args=()
        if [ -n "$DISABLE_PRINCIPLES" ]; then
            _disable_args=(--disable-principles "$DISABLE_PRINCIPLES")
        fi

        # Revision-v2 run settings (H3 / H7 / G3 / H11), all optional.
        local _run_args=(--state-mode "${STATE_MODE:-isolated}")
        [ -n "${SEED:-}" ] && _run_args+=(--seed "$SEED")
        [ -n "${TEMPERATURE:-}" ] && _run_args+=(--temperature "$TEMPERATURE")
        [ "${RESUME:-0}" = "1" ] && _run_args+=(--resume)
        [ "${REQUIRE_FREEZE:-0}" = "1" ] && _run_args+=(--require-freeze)
        [ -n "${MAX_VARIANTS:-}" ] && _run_args+=(--max-variants "$MAX_VARIANTS")
        [ -n "${RUN_TAG:-}" ] && _run_args+=(--run-tag "$RUN_TAG")
        if [ -n "${RUN_TAG:-}" ] || [ -n "$DISABLE_PRINCIPLES" ]; then
            _run_args+=(--results-dir "$result_dir")
        fi

        # Remote-endpoint extras (API key env var, model-specific extra_body).
        local _api_args=()
        if [ -n "${GP_API_KEY_ENV[$GROUP]:-}" ]; then
            _api_args+=(--api-key-env "${GP_API_KEY_ENV[$GROUP]}")
        fi
        if [ -n "${GP_EXTRA_BODY[$GROUP]:-}" ]; then
            _api_args+=(--extra-body-json "${GP_EXTRA_BODY[$GROUP]}")
        fi

        for ap in "${domain_aps[@]}"; do
            echo "  $ap ($TRIALS trials/variant)..."
            run_py -m attacks.harness \
                --domain "$domain" --ap "$ap" --config "$config" \
                --group "$GROUP" --model-url "$LLM_URL" --llm-provider "$LLM_PROVIDER" \
                --consensus-config "$CONSENSUS_CFG" \
                --trials "$TRIALS" --tool-port "$TOOL_BASE_PORT" \
                --mma-url "http://localhost:${MMA_PORT}" \
                "${_disable_args[@]}" "${_api_args[@]}" "${_run_args[@]}" \
                --verbose 2>&1 | grep -E "v[0-9]+ t[0-9]+|Error|SUMMARY|resumed" || true
        done

        # Benign (only if explicitly requested via "benign" AP mode):
        # every scenario of the domain x TRIALS repetitions.
        if [ "$AP_MODE" = "benign" ]; then
            echo "  benign (all scenarios x $TRIALS trials)..."
            run_py -m attacks.harness \
                --domain "$domain" --benign --config "$config" \
                --group "$GROUP" --model-url "$LLM_URL" --llm-provider "$LLM_PROVIDER" \
                --consensus-config "$CONSENSUS_CFG" \
                --trials "$TRIALS" --tool-port "$TOOL_BASE_PORT" \
                --mma-url "http://localhost:${MMA_PORT}" \
                "${_disable_args[@]}" "${_api_args[@]}" "${_run_args[@]}" \
                --verbose 2>&1 | grep -E "benign|Error|SUMMARY" || true
        fi
        echo ""
    done

    # Generate CSV + charts + PDF report (SKIP_REPORT=1: the driver rebuilds
    # results.csv from the logs with analysis.parse_logs once every slot is done)
    if [ "${SKIP_REPORT:-0}" != "1" ]; then
    echo "[report] Generating analysis..."
    run_py -c "
import json, sys, csv, os
from pathlib import Path
from collections import defaultdict
from datetime import datetime
sys.path.insert(0, '.')

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from matplotlib.backends.backend_pdf import PdfPages

sns.set_theme(style='whitegrid', font_scale=1.0, palette='muted')
CONFIGS = ['flat', 'acl_hardened', 'agenticcyops']
CONFIG_LABELS = {'flat': 'Flat MAS', 'acl_hardened': 'ACL-Hardened', 'agenticcyops': 'DEFER'}
CONFIG_COLORS = {'flat': '#e74c3c', 'acl_hardened': '#f39c12', 'agenticcyops': '#2ecc71'}
HEADER_COLOR = '#2c3e50'

log_dir = Path('${log_dir}')
result_dir = Path('${result_dir}')
domain = '${domain}'
group = '${GROUP}'

# Collect trial results
trials = []
for f in sorted(log_dir.rglob('*.jsonl')) if log_dir.exists() else []:
    with open(f) as fh:
        for line in fh:
            if line.strip():
                e = json.loads(line)
                if e.get('action') == 'trial_complete':
                    trials.append(e)

if not trials:
    print('No trial results'); sys.exit(0)

# ---- CSV (scoring v3 columns; the harness appends the same rows per trial) ----
from attacks.harness import RESULT_COLUMNS
csv_path = result_dir / 'results.csv'
with open(csv_path, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=RESULT_COLUMNS, extrasaction='ignore')
    w.writeheader()
    for t in trials:
        w.writerow({**{c: t.get(c, '') for c in RESULT_COLUMNS}, 'domain': domain, 'group': group})
print(f'Saved: {csv_path} ({len(trials)} trials)')
for t in trials:
    t['attack_succeeded'] = (t.get('outcome') == 'executed')
    t['blocking_mechanism'] = t.get('blocked_by') or 'none'

# ---- Compute ASR (scoring v3: not-measurable trials are excluded) ----
attack_trials = [t for t in trials if t.get('ap','').startswith('ap')
                 and t.get('outcome','') not in ('not_measurable', 'error')]
aps = sorted(set(t.get('ap','') for t in attack_trials), key=lambda x: int(x.replace('ap','')) if x.startswith('ap') else 0)
ap_labels = {'ap1':'AP-1 Tool Redir.','ap2':'AP-2 Mem Poison','ap3':'AP-3 Confused Dep.',
             'ap4':'AP-4 Cross-Phase','ap5':'AP-5 Irreversible','ap6':'AP-6 Replay',
             'ap7':'AP-7 Action Chain','ap8':'AP-8 Param Manip.','ap9':'AP-9 Handoff Poison',
             'ap10':'AP-10 Validator Manip.','ap11':'AP-11 Op Context','ap12':'AP-12 Concurrent',
             'ap13':'AP-13 Adv Memory','ap14':'AP-14 Read Inject','ap15':'AP-15 Infra Integrity'}

asr = {}
for ap in aps:
    for config in CONFIGS:
        mt = [t for t in attack_trials if t.get('ap')==ap and t.get('config')==config]
        if mt:
            s = sum(1 for t in mt if t.get('attack_succeeded'))
            asr[(ap,config)] = s/len(mt)*100

# ---- CLI Summary ----
print()
print(f'ASR SUMMARY — {domain.upper()} / Group {group}')
print('='*60)
for ap in aps:
    for config in CONFIGS:
        mt = [t for t in attack_trials if t.get('ap')==ap and t.get('config')==config]
        if mt:
            s = sum(1 for t in mt if t.get('attack_succeeded'))
            print(f'  {ap:<8} {config:<18} {s}/{len(mt)} ({s/len(mt)*100:.0f}% ASR)')

if not aps:
    print('  No attack trials found')
    sys.exit(0)

# ---- Chart 1: ASR Bar Chart ----
fig, ax = plt.subplots(figsize=(max(10, len(aps)*2), 6))
x = np.arange(len(aps))
width = 0.25
for i, config in enumerate(CONFIGS):
    vals = [asr.get((ap,config), 0) for ap in aps]
    bars = ax.bar(x + i*width, vals, width, label=CONFIG_LABELS.get(config,config),
                  color=CONFIG_COLORS.get(config,'#95a5a6'), edgecolor='white', linewidth=1.5)
    for bar, val in zip(bars, vals):
        if val > 0:
            ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+1,
                    f'{val:.0f}%', ha='center', va='bottom', fontsize=8, fontweight='bold')
ax.set_xticks(x + width)
ax.set_xticklabels([ap_labels.get(ap,ap) for ap in aps], fontsize=9)
ax.set_ylabel('Attack Success Rate (%)')
ax.set_title(f'Attack Success Rate — {domain.title()} / Group {group}', fontsize=14, fontweight='bold')
ax.set_ylim(0, 110)
ax.legend(title='Configuration', frameon=True)
sns.despine(ax=ax)
plt.tight_layout()
plt.savefig(result_dir / 'asr_by_ap.png', dpi=150)
plt.close()
print(f'Saved: {result_dir}/asr_by_ap.png')

# ---- Chart 2: Interception Heatmap ----
matrix = np.zeros((len(aps), len(CONFIGS)))
for i, ap in enumerate(aps):
    for j, config in enumerate(CONFIGS):
        mt = [t for t in attack_trials if t.get('ap')==ap and t.get('config')==config]
        if mt:
            blocked = sum(1 for t in mt if t.get('outcome') == 'blocked')
            matrix[i,j] = blocked/len(mt)*100
fig, ax = plt.subplots(figsize=(8, max(4, len(aps)*0.8)))
sns.heatmap(matrix, annot=True, fmt='.0f', cmap='RdYlGn',
            xticklabels=[CONFIG_LABELS.get(c,c) for c in CONFIGS],
            yticklabels=[ap_labels.get(ap,ap) for ap in aps],
            vmin=0, vmax=100, linewidths=1, linecolor='white',
            cbar_kws={'label': 'Interception Rate (%)'}, ax=ax)
ax.set_title(f'Interception Rate — {domain.title()} / Group {group}', fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(result_dir / 'interception_heatmap.png', dpi=150)
plt.close()
print(f'Saved: {result_dir}/interception_heatmap.png')

# ---- Chart 3: Mechanism breakdown (agenticcyops only) ----
aco_trials = [t for t in attack_trials if t.get('config')=='agenticcyops']
if aco_trials:
    mechs = defaultdict(int)
    for t in aco_trials:
        if t.get('outcome') == 'blocked':
            m = t.get('blocked_by') or 'unknown'
            mechs[m] += 1
    if mechs:
        fig, ax = plt.subplots(figsize=(8, 5))
        labels = list(mechs.keys())
        values = list(mechs.values())
        colors = sns.color_palette('Set2', len(labels))
        bars = ax.barh(labels, values, color=colors, edgecolor='white')
        for bar, val in zip(bars, values):
            ax.text(bar.get_width()+0.3, bar.get_y()+bar.get_height()/2,
                    str(val), va='center', fontweight='bold')
        ax.set_xlabel('Blocks')
        ax.set_title(f'Blocking Mechanisms — {domain.title()} / Group {group}', fontsize=14, fontweight='bold')
        sns.despine(ax=ax)
        plt.tight_layout()
        plt.savefig(result_dir / 'mechanism_breakdown.png', dpi=150)
        plt.close()
        print(f'Saved: {result_dir}/mechanism_breakdown.png')

# ---- PDF Report ----
with PdfPages(str(result_dir / 'attack_report.pdf')) as pdf:
    # Title
    fig, ax = plt.subplots(figsize=(11, 8.5)); ax.axis('off')
    ax.text(0.5, 0.72, 'DEFER', transform=ax.transAxes,
            ha='center', fontsize=36, fontweight='bold', color=HEADER_COLOR)
    ax.text(0.5, 0.62, 'Attack Path Evaluation Report', transform=ax.transAxes,
            ha='center', fontsize=22, color='#7f8c8d')
    ax.text(0.5, 0.52, f'Domain: {domain.title()} | Group {group}', transform=ax.transAxes,
            ha='center', fontsize=16, color='#2980b9')
    ax.text(0.5, 0.44, f'{len(trials)} trials across {len(aps)} attack paths', transform=ax.transAxes,
            ha='center', fontsize=14, color='#2980b9')
    ax.plot([0.2, 0.8], [0.48, 0.48], transform=ax.transAxes, color='#2980b9', linewidth=2)
    ax.text(0.5, 0.35, datetime.now().strftime('%B %d, %Y %H:%M'), transform=ax.transAxes,
            ha='center', fontsize=12, color='#95a5a6')
    pdf.savefig(fig, bbox_inches='tight'); plt.close()

    # R1 Table
    fig, ax = plt.subplots(figsize=(11, 8.5)); ax.axis('off')
    ax.set_title('Attack Interception Results', fontsize=18, fontweight='bold', color=HEADER_COLOR, pad=30)
    headers = ['Attack Path'] + [CONFIG_LABELS.get(c,c) for c in CONFIGS]
    cell_data = []
    for ap in aps:
        row = [ap_labels.get(ap,ap)]
        for config in CONFIGS:
            mt = [t for t in attack_trials if t.get('ap')==ap and t.get('config')==config]
            if mt:
                s = sum(1 for t in mt if t.get('attack_succeeded'))
                b = len(mt) - s
                row.append(f'{b}/{len(mt)} blocked ({s/len(mt)*100:.0f}% ASR)')
            else:
                row.append('--')
        cell_data.append(row)
    if cell_data:
        table = ax.table(cellText=cell_data, colLabels=headers, cellLoc='center',
                         loc='center', bbox=[0.05, 0.1, 0.9, 0.75])
        table.auto_set_font_size(False); table.set_fontsize(10); table.scale(1, 2.2)
        for j in range(len(headers)):
            table[0,j].set_facecolor(HEADER_COLOR)
            table[0,j].set_text_props(color='white', fontweight='bold')
        for i in range(1, len(cell_data)+1):
            table[i,0].set_text_props(fontweight='bold')
            for j, c in enumerate(['', '#fdedec', '#fef9e7', '#eafaf1']):
                if c: table[i,j].set_facecolor(c)
    pdf.savefig(fig, bbox_inches='tight'); plt.close()

    # Charts
    for img_name in ['asr_by_ap.png', 'interception_heatmap.png', 'mechanism_breakdown.png']:
        img_path = result_dir / img_name
        if img_path.exists():
            img = plt.imread(str(img_path))
            fig, ax = plt.subplots(figsize=(11, 8.5)); ax.axis('off'); ax.imshow(img)
            pdf.savefig(fig, bbox_inches='tight'); plt.close()

    # Summary
    fig, ax = plt.subplots(figsize=(11, 8.5)); ax.axis('off')
    ax.set_title('Key Findings', fontsize=18, fontweight='bold', color=HEADER_COLOR, pad=30)
    y = 0.8
    for config in CONFIGS:
        ct = [t for t in attack_trials if t.get('config')==config]
        if ct:
            s = sum(1 for t in ct if t.get('attack_succeeded'))
            b = len(ct) - s
            color = CONFIG_COLORS.get(config, '#2c3e50')
            ax.text(0.08, y, f'{CONFIG_LABELS.get(config,config)}: {s/len(ct)*100:.0f}% ASR ({s}/{len(ct)} succeeded, {b} blocked)',
                    transform=ax.transAxes, fontsize=13, color=color, fontweight='bold')
            y -= 0.07
    ax.text(0.08, y-0.05, f'Domain: {domain.title()} | Group: {group} | Trials: {len(trials)}',
            transform=ax.transAxes, fontsize=11, color='#7f8c8d')
    ax.text(0.5, 0.05, datetime.now().strftime('%Y-%m-%d %H:%M'), transform=ax.transAxes,
            ha='center', fontsize=10, color='#bdc3c7')
    pdf.savefig(fig, bbox_inches='tight'); plt.close()

print(f'Saved: {result_dir}/attack_report.pdf')
" 2>&1
    fi

    # Stop domain services -- only the ports allocated to *this* slot.
    for pid in "${PIDS[@]}"; do pkill -P "$pid" 2>/dev/null || true; kill "$pid" 2>/dev/null || true; done
    for port in $(seq ${TOOL_BASE_PORT} $((TOOL_BASE_PORT + 29))) ${MMA_PORT}; do
        pid=$(lsof -ti :$port 2>/dev/null || true); [ -n "$pid" ] && kill -9 $pid 2>/dev/null || true
    done
    wait 2>/dev/null || true; PIDS=()
}

# ---- Main ----
for domain in "${SELECTED_DOMAINS[@]}"; do
    run_domain "$domain"
done

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "============================================================"
echo "  Experiment Complete — Group ${GROUP}"
echo "  Domains: ${SELECTED_DOMAINS[*]}"
echo "  Time: $((ELAPSED / 60))m $((ELAPSED % 60))s"
echo "============================================================"
