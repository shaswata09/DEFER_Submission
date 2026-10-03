#!/bin/bash
# ============================================================
# DEFER — Agent Security Bench (ASB) End-to-End benchmark
#
# Three-step pipeline driven by a single command:
#   1.  Convert upstream YAML+JSONL into per-attack-family JSON
#   2.  Live-LLM sweep through the chosen group's primary LLM
#       + P1-P5 + P3-L6 consensus, under the neutral 'general' domain
#   3.  Generate the paper-ready PDF + tier-table CSVs
#
# Mirrors the CLI pattern of scripts/run_injecagent_e2e.sh.
#
# Usage:
#   ./scripts/run_asb_e2e.sh                          # Interactive
#   ./scripts/run_asb_e2e.sh A                        # Group A, full defaults
#   ./scripts/run_asb_e2e.sh A all 5 all 3            # Full sweep, 3 (task,attacker)/agent
#   ./scripts/run_asb_e2e.sh A DPI 1 agenticcyops 1   # Tiny smoke
#
# Positional args:
#   $1 GROUP      (A-F)
#   $2 ATTACKS    (all / DPI / IPI / MP / PoT / comma-list)   default: all
#   $3 TRIALS     (per case)                                  default: 5
#   $4 CONFIG     (all / flat / acl_hardened / agenticcyops)  default: all
#   $5 PER_AGENT  (case multiplier; total = ~per_agent x 85)  default: 3
#
# Per-agent expansion:
#   per_agent=1  ->  85 cases  (smoke)
#   per_agent=3  -> 255 cases  (recommended "full" run)
#   per_agent=5  -> 420 cases  (large; multi-hour)
#
# ASB has 1 domain (general) -- no domain projection, unlike InjecAgent.
# ============================================================

set -eE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Auto-load .env so child Python inherits API keys.
if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    source ".env"
    set +a
fi

CONDA_ENV="agenticcyops"

# `conda run -n <env> python3` sometimes silently falls back to /usr/bin/python3
# on this box -- prefer the env's interpreter directly when it exists.
PY_BIN=""
for cand in \
    "$HOME/.conda/envs/${CONDA_ENV}/bin/python3" \
    "/opt/conda/envs/${CONDA_ENV}/bin/python3" \
    "${CONDA_PREFIX:-/nonexistent}/bin/python3"; do
    [ -x "$cand" ] && PY_BIN="$cand" && break
done

ALL_ATTACKS=("DPI" "IPI" "MP" "POT")
ALL_CONFIGS=("flat" "acl_hardened" "agenticcyops")
ALL_GROUPS=("A" "B" "C" "D" "E" "F" "G" "H" "I" "J")

# ---- Group matrix (matches scripts/run_injecagent_e2e.sh) ----
# G-J = small/mid-tier primaries with self-vote-free consensus panels.
declare -A GP_PORTS GP_DESC
GP_PORTS[A]="8000 8002 8005"; GP_DESC[A]="Qwen3-235B + V1(Qwen) + V2(DeepSeek) + V4(Claude) + V6(GPT-4o)"
GP_PORTS[B]="8001 8002 8005"; GP_DESC[B]="GLM-4.7-FP8 + V1 + V2 + V4 + V6"
GP_PORTS[C]="8000 8002";      GP_DESC[C]="Qwen3-235B + V1 x3 (same-family)"
GP_PORTS[D]="8004 8002 8005"; GP_DESC[D]="Llama-4-Scout + V1 + V2 + V4 + V6"
GP_PORTS[E]="8000 8002 8003"; GP_DESC[E]="Qwen3-235B + V1 + V5(Mistral) + V4 + V6"
GP_PORTS[F]="8002 8005 8004"; GP_DESC[F]="Claude (API primary) + V1 + V2 + V3(Llama) + V6"
GP_PORTS[G]="8002 8003";      GP_DESC[G]="Qwen3-32B (mid) + V5(Mistral) + V4(Claude) + V6(GPT-4o)"
GP_PORTS[H]="8002 8003";      GP_DESC[H]="Mistral-Small-3.2-24B (mid) + V1(Qwen) + V4(Claude) + V6(GPT-4o)"
GP_PORTS[I]="8002 8003";      GP_DESC[I]="Llama-3.1-8B-Instruct (small, REMOTE_5090_URL) + V1(Qwen) + V5(Mistral) + V4(Claude) + V6(GPT-4o)"
GP_PORTS[J]="8006 8002 8003"; GP_DESC[J]="GPT-OSS-120B + V1(Qwen) + V5(Mistral) + V4(Claude) + V6(GPT-4o)"

run_py() {
    if [ -n "$PY_BIN" ]; then
        "$PY_BIN" "$@"
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
    echo "[  ok] $name  (${elapsed}s)"
}

# ---- CLI / interactive ----
if [ -z "$1" ]; then
    echo ""
    echo "  DEFER — ASB End-to-End Benchmark"
    echo "  ────────────────────────────────────────"
    echo ""
    echo "  Groups:"
    for g in "${ALL_GROUPS[@]}"; do
        printf "    %s  %s\n" "$g" "${GP_DESC[$g]}"
    done
    echo ""
    echo "  Attack families: DPI (direct PI) / IPI (indirect PI) / MP (memory poisoning) / PoT (backdoor)"
    echo ""
    read -p "  Group [A-F]: " GROUP
    read -p "  Attacks    [all / DPI / IPI / MP / PoT / comma-list] (default all): " ATTACKS
    read -p "  Trials per case (default 5): " TRIALS
    read -p "  Configs    [all / flat / acl_hardened / agenticcyops] (default all): " CONFIG
    read -p "  Per-agent  [case multiplier, default 3 -> 255 cases total]: " PER_AGENT
    [ -z "$ATTACKS" ]   && ATTACKS="all"
    [ -z "$TRIALS" ]    && TRIALS="5"
    [ -z "$CONFIG" ]    && CONFIG="all"
    [ -z "$PER_AGENT" ] && PER_AGENT="3"
else
    GROUP="${1:-A}"
    ATTACKS="${2:-all}"
    TRIALS="${3:-5}"
    CONFIG="${4:-all}"
    PER_AGENT="${5:-3}"
fi

# ---- Validate ----
GROUP=$(echo "$GROUP" | tr '[:lower:]' '[:upper:]')
case " ${ALL_GROUPS[*]} " in *" $GROUP "*) ;; *) echo "[FAIL] unknown group: $GROUP"; exit 2 ;; esac

# Attacks: normalize PoT -> POT (run_e2e expects upper); allow lower input
if [ "$(echo "$ATTACKS" | tr '[:upper:]' '[:lower:]')" = "all" ]; then
    ATTACKS_CSV=$(IFS=,; echo "${ALL_ATTACKS[*]}")
else
    ATTACKS_CSV=""
    IFS=',' read -ra _atks <<< "$ATTACKS"
    for a in "${_atks[@]}"; do
        a_up=$(echo "$a" | tr '[:lower:]' '[:upper:]')
        # Accept either POT or PoT; both normalise to POT here
        case " ${ALL_ATTACKS[*]} " in *" $a_up "*) ;;
            *) echo "[FAIL] unknown attack family: $a"; exit 2 ;;
        esac
        ATTACKS_CSV="${ATTACKS_CSV}${ATTACKS_CSV:+,}${a_up}"
    done
fi

if [ "$CONFIG" = "all" ]; then
    CONFIGS_CSV=$(IFS=,; echo "${ALL_CONFIGS[*]}")
else
    case " ${ALL_CONFIGS[*]} " in *" $CONFIG "*) CONFIGS_CSV="$CONFIG" ;;
        *) echo "[FAIL] unknown config: $CONFIG"; exit 2 ;;
    esac
fi

# Sanity: numeric trials / per_agent
[[ "$TRIALS" =~ ^[0-9]+$ ]] || { echo "[FAIL] trials must be numeric: $TRIALS"; exit 2; }
[[ "$PER_AGENT" =~ ^[0-9]+$ ]] || { echo "[FAIL] per-agent must be numeric: $PER_AGENT"; exit 2; }

# ---- Pre-flight: upstream snapshot must exist ----
UPSTREAM_DIR="benchmarks/asb/data/upstream"
if [ ! -d "$UPSTREAM_DIR" ]; then
    echo ""
    echo "[prep] upstream ASB snapshot missing -- ingesting now..."
    bash benchmarks/asb/scripts/ingest_upstream.sh
fi

echo ""
echo "  Group:       $GROUP  (${GP_DESC[$GROUP]})"
echo "  Attacks:     $ATTACKS_CSV"
echo "  Configs:     $CONFIGS_CSV"
echo "  Trials:      $TRIALS"
echo "  Per-agent:   $PER_AGENT"
echo "  Output dir:  results/asb/e2e_validator_group_${GROUP}/"
echo ""

# ---- Server-health preflight ----
echo "[preflight] Verifying vLLM endpoints required for group $GROUP"
for port in ${GP_PORTS[$GROUP]}; do
    if ! wait_for_health "http://localhost:${port}/v1/models" "port ${port}" 5; then
        echo "[FAIL] vLLM on port ${port} not reachable."
        echo "       Start it with: ./start_servers.sh"
        exit 3
    fi
done
if [[ "$GROUP" == "F" || "$GROUP" == "A" || "$GROUP" == "B" || "$GROUP" == "D" || "$GROUP" == "E" ]]; then
    [ -z "${ANTHROPIC_API_KEY:-}" ] && echo "[warn] ANTHROPIC_API_KEY unset — Claude validator will fail."
    [ -z "${OPENAI_API_KEY:-}" ]    && echo "[warn] OPENAI_API_KEY unset — GPT-4o validator will fail."
fi

# ---- Step 1a: convert cases ----
# Convert just the families we'll run (faster, also avoids leaving stale
# JSON for un-requested families)
echo ""
echo "[step 1a/4] convert_cases  --families $ATTACKS_CSV --per-agent $PER_AGENT"
run_py -m benchmarks.asb.scripts.convert_cases \
    --families "$ATTACKS_CSV" --per-agent "$PER_AGENT"

# ---- Step 1b: Tier-1 symbolic sweep (no LLM, ~30s) ----
# Produces results/asb/asb_static_results.csv which the analytics tool
# picks up via load_static_symbolic() to populate the Tier-1 column of
# injecagent_e2e_two_tier_asr.csv.
echo ""
echo "[step 1b/4] tier-1 symbolic (no LLM): run_static"
run_py -m benchmarks.asb.run_static --attacks "$ATTACKS_CSV" --configs "$CONFIGS_CSV"

# ---- Step 2: live-LLM sweep ----
ARGS=(
    --group "$GROUP"
    --attacks "$ATTACKS_CSV"
    --configs "$CONFIGS_CSV"
    --trials "$TRIALS"
)

echo ""
echo "[step 2/4] python -m benchmarks.asb.run_e2e ${ARGS[*]}"
echo ""
run_py -m benchmarks.asb.run_e2e "${ARGS[@]}"

# ---- Step 3: analytics ----
echo ""
echo "[step 3/4] generate paper-ready analytics"
# Reuses the InjecAgent e2e analytics (same CSV schema).
run_py -m analysis.injecagent_e2e_analytics \
    --results-root "${RESULTS_DIR:-results}/asb" \
    --groups "$GROUP" || \
    echo "[warn] analytics step failed -- raw results.csv + summary.csv are still in place"

echo ""
echo "[done] Results:    results/asb/e2e_validator_group_${GROUP}/"
echo "       Analytics:  results/asb/e2e_validator_group_${GROUP}/e2e_analytics/"
echo "       Audit logs: logs/asb_dpi_e2e_${GROUP}/"
