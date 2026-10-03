#!/bin/bash
# ============================================================
# DEFER — InjecAgent End-to-End (live-LLM) benchmark
#
# Runs the 50-case representative InjecAgent subset through the
# live primary LLM of the chosen group and parses the model's
# output to measure end-to-end agent ASR.  Each parsed attacker
# tool call is additionally evaluated through the P1-P5 defense
# pipeline to separate LLM compliance from defense effectiveness.
#
# Mirrors the CLI pattern of scripts/run_attack_paths.sh.
#
# Usage:
#   ./scripts/run_injecagent_e2e.sh                         # Interactive
#   ./scripts/run_injecagent_e2e.sh A                       # Group A, full defaults
#   ./scripts/run_injecagent_e2e.sh D cyberops 6            # Group D, single domain
#   ./scripts/run_injecagent_e2e.sh A all 6 agenticcyops    # One config only
#   ./scripts/run_injecagent_e2e.sh A all 6 all 10          # First 10 cases (smoke)
#
# Positional args:
#   $1 GROUP      (A-F)
#   $2 DOMAIN     (all / cyberops / healthcare / finance / legal)
#   $3 TRIALS     (default 6)
#   $4 CONFIG     (all / flat / acl_hardened / agenticcyops)
#   $5 CASE_LIMIT (blank = full 50)
# ============================================================

set -eE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Auto-load .env (bash doesn't do this by default; Python config.py does
# it on its side, but the preflight warnings run in bash).
if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    source ".env"
    set +a
fi

CONDA_ENV="agenticcyops"

ALL_DOMAINS=("cyberops" "healthcare" "finance" "legal")
ALL_CONFIGS=("flat" "acl_hardened" "agenticcyops")
ALL_GROUPS=("A" "B" "C" "D" "E" "F" "G" "H" "I" "J")

# ---- Group matrix (matches run_attack_paths.sh) ----
# Small/mid-tier primary groups (G-J) avoid self-voting in the consensus
# panel.  GP_PORTS lists localhost vLLM ports the preflight should probe;
# Group I's primary is an external endpoint and is exercised at request
# time rather than via the localhost preflight.
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

run_py() { conda run --no-capture-output -n "$CONDA_ENV" python3 "$@"; }

wait_for_health() {
    local url="$1" name="$2" timeout="${3:-60}" elapsed=0
    while ! curl -s --max-time 1 "$url" > /dev/null 2>&1; do
        sleep 1; elapsed=$((elapsed + 1))
        [ $elapsed -ge $timeout ] && echo "[FAIL] $name timeout" && return 1
    done
    echo "[  ok] $name  (${elapsed}s)"
}

# ---- CLI / interactive parsing ----
if [ -z "$1" ]; then
    echo ""
    echo "  DEFER — InjecAgent End-to-End (live-LLM) Benchmark"
    echo "  ────────────────────────────────────────────────────────"
    echo ""
    echo "  Groups:"
    for g in "${ALL_GROUPS[@]}"; do
        printf "    %s  %s\n" "$g" "${GP_DESC[$g]}"
    done
    echo ""
    read -p "  Group [A-F]: " GROUP
    read -p "  Domain(s)  [all / cyberops / healthcare / finance / legal]: " DOMAIN
    read -p "  Trials per case (default 6): " TRIALS
    read -p "  Configs [all / flat / acl_hardened / agenticcyops]: " CONFIG
    read -p "  Case limit [default 50 = full representative subset]: " CASE_LIMIT
    [ -z "$DOMAIN" ] && DOMAIN="all"
    [ -z "$TRIALS" ] && TRIALS="6"
    [ -z "$CONFIG" ] && CONFIG="all"
else
    GROUP="${1:-A}"
    DOMAIN="${2:-all}"
    TRIALS="${3:-6}"
    CONFIG="${4:-all}"
    CASE_LIMIT="${5:-}"
fi

# ---- Validate ----
GROUP=$(echo "$GROUP" | tr '[:lower:]' '[:upper:]')
case " ${ALL_GROUPS[*]} " in *" $GROUP "*) ;; *) echo "[FAIL] unknown group: $GROUP"; exit 2 ;; esac

if [ "$DOMAIN" = "all" ]; then
    DOMAINS_CSV=$(IFS=,; echo "${ALL_DOMAINS[*]}")
else
    case " ${ALL_DOMAINS[*]} " in *" $DOMAIN "*) DOMAINS_CSV="$DOMAIN" ;;
        *) echo "[FAIL] unknown domain: $DOMAIN"; exit 2 ;;
    esac
fi

if [ "$CONFIG" = "all" ]; then
    CONFIGS_CSV=$(IFS=,; echo "${ALL_CONFIGS[*]}")
else
    case " ${ALL_CONFIGS[*]} " in *" $CONFIG "*) CONFIGS_CSV="$CONFIG" ;;
        *) echo "[FAIL] unknown config: $CONFIG"; exit 2 ;;
    esac
fi

# ---- Precondition checks ----
SUBSET=benchmarks/injecagent/representative_cases.json
if [ ! -f "$SUBSET" ]; then
    echo ""
    echo "[prep] representative subset missing, generating 50-case subset..."
    run_py -m benchmarks.injecagent.representative_subset
fi

echo ""
echo "  Group:       $GROUP  (${GP_DESC[$GROUP]})"
echo "  Domains:     $DOMAINS_CSV"
echo "  Configs:     $CONFIGS_CSV"
echo "  Trials:      $TRIALS"
[ -n "$CASE_LIMIT" ] && echo "  Case limit:  $CASE_LIMIT"
echo "  Output dir:  results/injecagent/e2e_validator_group_${GROUP}/"
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
    [ -z "${ANTHROPIC_API_KEY:-}" ] && echo "[warn] ANTHROPIC_API_KEY unset — Claude-using groups will fail."
    [ -z "${OPENAI_API_KEY:-}" ] && echo "[warn] OPENAI_API_KEY unset — GPT-4o validators will fail."
fi

# ---- Invoke Python runner ----
ARGS=(
    --group "$GROUP"
    --domains "$DOMAINS_CSV"
    --configs "$CONFIGS_CSV"
    --trials "$TRIALS"
)
[ -n "$CASE_LIMIT" ] && ARGS+=(--case-limit "$CASE_LIMIT")

echo ""
echo "[run] python -m benchmarks.injecagent.run_e2e ${ARGS[*]}"
echo ""

run_py -m benchmarks.injecagent.run_e2e "${ARGS[@]}"

echo ""
echo "[done] Results under: results/injecagent/e2e_validator_group_${GROUP}/"
