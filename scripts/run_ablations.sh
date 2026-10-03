#!/bin/bash
# ============================================================
# DEFER — Ablation studies wrapper
#
# Two modes:
#   postonly   -- read existing logs/results.csv, derive UPPER-BOUND
#                 -Pn ASR per principle (no LLM cost; ~30s)
#   rerun      -- invoke attacks.harness with --disable-principles or
#                 --config llm_judge for the EXACT counterfactual
#                 (hours, $$ in API)
#
# The post-hoc upper bound is publishable as
#   "removing Pn would increase ASR by AT MOST X pp"
# without an additional sweep.  Use rerun only when you need the
# tight (exact) -Pn ASR or single-principle isolation.
#
# Usage:
#   ./scripts/run_ablations.sh                                  # interactive
#   ./scripts/run_ablations.sh postonly A cyberops              # post-hoc only
#   ./scripts/run_ablations.sh rerun A cyberops P3              # rerun -P3
#   ./scripts/run_ablations.sh rerun A cyberops llm_judge       # rerun llm_judge
#   ./scripts/run_ablations.sh rerun A cyberops "P3 P5"         # multiple
#   ./scripts/run_ablations.sh rerun A cyberops single_P2       # P2-only isolation
#
# Positional args:
#   $1 MODE       (postonly | rerun)                  default: postonly
#   $2 GROUP      (A-F)                               default: A
#   $3 DOMAIN     (cyberops/healthcare/finance/legal/all)  default: cyberops
#   $4 ABLATIONS  (postonly: ignored)
#                 (rerun: space-separated list of:
#                    P1 | P2 | P3 | P4 | P5
#                    single_P1 | single_P2 | ... | single_P5
#                    llm_judge)
#                 default: P1 P2 P3 P4 P5
#   $5 TRIALS     (rerun only)                         default: 5
#
# Outputs:
#   postonly mode:
#       results/eval_attacks/group_<G>/<domain>/ablation_from_logs.csv
#       results/eval_attacks/group_<G>/ablation_from_logs.md
#   rerun mode (per ablation):
#       logs/<domain>_eval_attacks_<G>_disabled_<set>/<config>_<ts>.jsonl
#       results/eval_attacks/group_<G>_disabled_<set>/<domain>/results.csv
# ============================================================

set -eE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Auto-load .env so child Python inherits API keys (rerun needs them)
if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    source ".env"
    set +a
fi

CONDA_ENV="agenticcyops"

# Use the env's interpreter directly when present (conda run sometimes
# silently picks /usr/bin/python3 on this box)
PY_BIN=""
for cand in \
    "$HOME/.conda/envs/${CONDA_ENV}/bin/python3" \
    "/opt/conda/envs/${CONDA_ENV}/bin/python3" \
    "${CONDA_PREFIX:-/nonexistent}/bin/python3"; do
    [ -x "$cand" ] && PY_BIN="$cand" && break
done
run_py() {
    if [ -n "$PY_BIN" ]; then
        "$PY_BIN" "$@"
    else
        conda run --no-capture-output -n "$CONDA_ENV" python3 "$@"
    fi
}

ALL_DOMAINS=("cyberops" "healthcare" "finance" "legal")
ALL_GROUPS=("A" "B" "C" "D" "E" "F")
PRINCIPLES=("P1" "P2" "P3" "P4" "P5")

# ---- Group matrix (matches run_attack_paths.sh) ----
declare -A GP_PRIMARY GP_PROVIDER GP_PORTS GP_CONSENSUS GP_DESC
GP_PRIMARY[A]="http://localhost:8000/v1"; GP_PROVIDER[A]="openai"; GP_PORTS[A]="8000 8002 8005"; GP_CONSENSUS[A]="default_consensus"
GP_DESC[A]="Qwen3-235B + V1+V2+V4+V6"
GP_PRIMARY[B]="http://localhost:8001/v1"; GP_PROVIDER[B]="openai"; GP_PORTS[B]="8001 8002 8005"; GP_CONSENSUS[B]="default_consensus"
GP_DESC[B]="GLM-4.7-FP8 + V1+V2+V4+V6"
GP_PRIMARY[C]="http://localhost:8000/v1"; GP_PROVIDER[C]="openai"; GP_PORTS[C]="8000 8002";      GP_CONSENSUS[C]="same_family"
GP_DESC[C]="Qwen3-235B + V1 x3"
GP_PRIMARY[D]="http://localhost:8004/v1"; GP_PROVIDER[D]="openai"; GP_PORTS[D]="8004 8002 8005"; GP_CONSENSUS[D]="default_consensus"
GP_DESC[D]="Llama-4 + V1+V2+V4+V6"
GP_PRIMARY[E]="http://localhost:8000/v1"; GP_PROVIDER[E]="openai"; GP_PORTS[E]="8000 8002 8003"; GP_CONSENSUS[E]="with_mistral"
GP_DESC[E]="Qwen3-235B + V1+V5+V4+V6"
GP_PRIMARY[F]="anthropic";                GP_PROVIDER[F]="anthropic"; GP_PORTS[F]="8002 8005 8004"; GP_CONSENSUS[F]="all_with_gpt4o"
GP_DESC[F]="Claude API + V1+V2+V3+V6"

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
    echo "  DEFER -- Ablation Studies"
    echo "  ─────────────────────────────────"
    echo ""
    echo "  Modes:"
    echo "    1) postonly  (no LLM cost; UPPER-BOUND -Pn ASR from existing logs)"
    echo "    2) rerun     (LLM calls; EXACT counterfactual via --disable-principles)"
    echo ""
    read -p "  Mode [1=postonly / 2=rerun] (default 1): " mc
    [ "$mc" = "2" ] && MODE="rerun" || MODE="postonly"

    echo ""
    read -p "  Group [A-F] (default A): " GROUP
    [ -z "$GROUP" ] && GROUP="A"

    echo ""
    echo "  Domains:  cyberops / healthcare / finance / legal / all"
    read -p "  Domain (default cyberops): " DOMAIN
    [ -z "$DOMAIN" ] && DOMAIN="cyberops"

    if [ "$MODE" = "rerun" ]; then
        echo ""
        echo "  Ablations to run:"
        echo "    P1, P2, P3, P4, P5                       (leave-one-out)"
        echo "    single_P1, single_P2, ..., single_P5     (single-principle isolation)"
        echo "    llm_judge                                (P1 + consensus only)"
        echo "    symbolic_only                            (P1-P5 with L6 consensus removed)"
        echo "    Use space-separated list, e.g. 'P3 P5 llm_judge'"
        read -p "  Ablations (default 'P1 P2 P3 P4 P5'): " ABLATIONS
        [ -z "$ABLATIONS" ] && ABLATIONS="P1 P2 P3 P4 P5"
        echo ""
        read -p "  Trials per variant (default 5): " TRIALS
        [ -z "$TRIALS" ] && TRIALS="5"
    fi
else
    MODE="${1:-postonly}"
    GROUP="${2:-A}"
    DOMAIN="${3:-cyberops}"
    ABLATIONS="${4:-P1 P2 P3 P4 P5}"
    TRIALS="${5:-5}"
fi

GROUP=$(echo "$GROUP" | tr '[:lower:]' '[:upper:]')
case " ${ALL_GROUPS[*]} " in *" $GROUP "*) ;; *) echo "[FAIL] unknown group: $GROUP"; exit 2 ;; esac

# ============================================================
# Mode A: postonly  -- post-hoc upper-bound from existing logs
# ============================================================
if [ "$MODE" = "postonly" ]; then
    echo ""
    echo "  Mode:    postonly (no LLM)"
    echo "  Group:   $GROUP"
    echo "  Domain:  $DOMAIN"
    echo ""
    run_py -m analysis.ablation_from_logs --groups "$GROUP" --domain "$DOMAIN"
    echo ""
    if [ "$DOMAIN" = "all" ]; then
        echo "[done] per-domain CSVs at results/eval_attacks/group_${GROUP}/<domain>/ablation_from_logs.csv"
    else
        echo "[done] CSV at results/eval_attacks/group_${GROUP}/${DOMAIN}/ablation_from_logs.csv"
    fi
    echo "       Markdown at results/eval_attacks/group_${GROUP}/ablation_from_logs.md"
    exit 0
fi

# ============================================================
# Mode B: rerun  -- exact counterfactual via attacks.harness
# ============================================================
if [ "$MODE" != "rerun" ]; then
    echo "[FAIL] unknown mode: $MODE  (must be 'postonly' or 'rerun')"
    exit 2
fi

# Validate domain (rerun mode requires a single domain since it spins up tools)
if [ "$DOMAIN" = "all" ]; then
    echo "[FAIL] rerun mode requires a single domain (cyberops/healthcare/finance/legal)"
    exit 2
fi
case " ${ALL_DOMAINS[*]} " in *" $DOMAIN "*) ;; *) echo "[FAIL] unknown domain: $DOMAIN"; exit 2 ;; esac

[[ "$TRIALS" =~ ^[0-9]+$ ]] || { echo "[FAIL] trials must be numeric: $TRIALS"; exit 2; }

# Resolve each ablation token -> (config_name, disabled_principles_csv)
# Returns: prints "<config> <disabled_csv>" per ablation on stdout
resolve_ablation() {
    local tok="$1"
    case "$tok" in
        P1|P2|P3|P4|P5)
            echo "agenticcyops $tok"
            ;;
        single_P1|single_P2|single_P3|single_P4|single_P5)
            local keep="${tok#single_}"
            local disabled=""
            for p in "${PRINCIPLES[@]}"; do
                if [ "$p" != "$keep" ]; then
                    disabled="${disabled}${disabled:+,}${p}"
                fi
            done
            echo "agenticcyops $disabled"
            ;;
        llm_judge)
            echo "llm_judge "
            ;;
        symbolic_only)
            echo "symbolic_only "
            ;;
        *)
            return 1
            ;;
    esac
}

# Validate every token first
for tok in $ABLATIONS; do
    if ! resolve_ablation "$tok" > /dev/null 2>&1; then
        echo "[FAIL] unknown ablation token: $tok"
        echo "       valid: P1 P2 P3 P4 P5  single_P1..P5  llm_judge  symbolic_only"
        exit 2
    fi
done

LLM_URL="${GP_PRIMARY[$GROUP]}"
LLM_PROVIDER="${GP_PROVIDER[$GROUP]}"
CONSENSUS_CFG="${GP_CONSENSUS[$GROUP]}"

echo ""
echo "  Mode:        rerun (LLM calls)"
echo "  Group:       $GROUP  (${GP_DESC[$GROUP]})"
echo "  Domain:      $DOMAIN"
echo "  Ablations:   $ABLATIONS"
echo "  Trials:      $TRIALS"
echo ""

# Pre-flight server-health
echo "[preflight] vLLM endpoints"
for port in ${GP_PORTS[$GROUP]}; do
    if ! wait_for_health "http://localhost:${port}/v1/models" "port ${port}" 5; then
        echo "[FAIL] vLLM on port ${port} not reachable. Start with ./start_servers.sh"
        exit 3
    fi
done

# Run each ablation
for tok in $ABLATIONS; do
    read -r CFG DISABLED <<< "$(resolve_ablation "$tok")"

    echo ""
    echo "============================================================"
    echo "[ablation] $tok  ->  --config=$CFG  --disable-principles=$DISABLED"
    echo "============================================================"

    EXTRA=()
    [ -n "$DISABLED" ] && EXTRA+=(--disable-principles "$DISABLED")

    run_py -m attacks.harness \
        --domain "$DOMAIN" --eval A --config "$CFG" \
        --group "$GROUP" --model-url "$LLM_URL" --llm-provider "$LLM_PROVIDER" \
        --consensus-config "$CONSENSUS_CFG" \
        --trials "$TRIALS" --tool-port 9000 \
        "${EXTRA[@]}" --verbose 2>&1 | grep -E "v[0-9]+ t[0-9]+|Error|SUMMARY" || true
done

echo ""
echo "[done] rerun ablations finished."
echo "       Per-ablation logs:    logs/${DOMAIN}_eval_attacks_${GROUP}[_disabled_<set>]/"
echo "       Per-ablation results: results/eval_attacks/group_${GROUP}[_disabled_<set>]/${DOMAIN}/"
echo ""
echo "       Refresh post-hoc upper-bound view (uses original full-stack run):"
echo "         ./scripts/run_ablations.sh postonly $GROUP $DOMAIN"
