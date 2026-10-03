#!/bin/bash
# ============================================================
# DEFER — Full Baseline Verification
#
# 1. Choose model group (A-G)
# 2. Verify required servers are running
# 3. Choose domains
# 4. Run baseline, store in results/baseline/group_{X}/{domain}/
#
# Usage:
#   ./scripts/run_baseline.sh            # Interactive
#   ./scripts/run_baseline.sh A 5        # Group A, all domains
#   ./scripts/run_baseline.sh A 1        # Group A, cyberops only
#   ./scripts/run_baseline.sh B 2 3      # Group B, healthcare + finance
#   STATE_MODE=persistent ./scripts/run_baseline.sh A 1   # E1b: state accumulates
# ============================================================

set -eE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

CONDA_ENV="agenticcyops"
# Tool / MMA ports are no longer global; computed per (GROUP, domain)
# inside run_domain_baseline() so parallel baseline runs across groups
# don't collide.  Matches the layout used by run_attack_paths.sh.
PIDS=()
ALLOCATED_PORTS=()

ALL_DOMAINS=("cyberops" "healthcare" "finance" "legal")

# ---- Group definitions (kept in sync with scripts/run_attack_paths.sh) ----
# Each group: display name, primary LLM URL, required-localhost ports,
# consensus profile, api_key_env (cloud only), extra_body (model-specific
# extras like NVIDIA thinking-mode toggle).  GROUP_PORTS lists ONLY
# localhost ports the preflight should probe; external/API primaries are
# exercised at request time and are not preflight-checked here.
declare -A GROUP_NAMES GROUP_PRIMARY GROUP_PORTS GROUP_CONSENSUS GROUP_DESC
declare -A GROUP_API_KEY_ENV GROUP_EXTRA_BODY

GROUP_NAMES[A]="Group A: Main Experiments (4 validator families)"
GROUP_PRIMARY[A]="http://localhost:8000/v1"
GROUP_PORTS[A]="8000 8002 8005"
GROUP_CONSENSUS[A]="default_consensus"
GROUP_DESC[A]="Qwen3-235B (8000) + V1(Qwen) + V2(DeepSeek) + V4(Claude) + V6(GPT-4o) [need 3 of 4 to approve]"

GROUP_NAMES[B]="Group B: GLM Diversity"
GROUP_PRIMARY[B]="http://localhost:8001/v1"
GROUP_PORTS[B]="8001 8002 8005"
GROUP_CONSENSUS[B]="default_consensus"
GROUP_DESC[B]="GLM-4.7-FP8 (8001) + V1(Qwen) + V2(DeepSeek) + V4(Claude) + V6(GPT-4o) [need 3 of 4 to approve]"

GROUP_NAMES[C]="Group C: Validator Same-Family"
GROUP_PRIMARY[C]="http://localhost:8000/v1"
GROUP_PORTS[C]="8000 8002"
GROUP_CONSENSUS[C]="same_family"
GROUP_DESC[C]="Qwen3-235B (8000) + V1 Qwen3-32B x3 (8002) — same-family consensus [need 2 of 3 to approve]"

GROUP_NAMES[D]="Group D: Validator All-Local + API"
GROUP_PRIMARY[D]="http://localhost:8004/v1"
GROUP_PORTS[D]="8004 8002 8005"
GROUP_CONSENSUS[D]="default_consensus"
GROUP_DESC[D]="Llama-4-Scout (8004) + V1(Qwen) + V2(DeepSeek) + V4(Claude) + V6(GPT-4o) [need 3 of 4 to approve]"

GROUP_NAMES[E]="Group E: With Mistral"
GROUP_PRIMARY[E]="http://localhost:8000/v1"
GROUP_PORTS[E]="8000 8002 8003"
GROUP_CONSENSUS[E]="with_mistral"
GROUP_DESC[E]="Qwen3-235B (8000) + V1(Qwen) + V5(Mistral) + V4(Claude) + V6(GPT-4o) [need 3 of 4 to approve]"

GROUP_NAMES[F]="Group F: Claude Primary + V3 Llama"
GROUP_PRIMARY[F]="anthropic"
GROUP_PORTS[F]="8002 8005 8004"
GROUP_CONSENSUS[F]="all_with_gpt4o"
GROUP_DESC[F]="Claude (API primary) + V1(Qwen) + V2(DeepSeek) + V3(Llama) + V6(GPT-4o) [need 3 of 4 to approve]"

# ---- Mid/small/large primary groups (G/H/I/J/K) ----
# Each panel excludes the validator that duplicates the primary family
# (no_qwen_panel for G, no_mistral_panel for H) to avoid self-voting.

GROUP_NAMES[G]="Group G: Qwen3-32B Primary (mid-tier)"
GROUP_PRIMARY[G]="http://localhost:8002/v1"
GROUP_PORTS[G]="8002 8003"
GROUP_CONSENSUS[G]="no_qwen_panel"
GROUP_DESC[G]="Qwen3-32B (8002, self-host) + V5(Mistral) + V4(Claude) + V6(GPT-4o) [need 2 of 3 to approve, no V1]"

GROUP_NAMES[H]="Group H: Mistral-Small-3.2-24B Primary (mid-tier)"
GROUP_PRIMARY[H]="http://localhost:8003/v1"
GROUP_PORTS[H]="8002 8003"
GROUP_CONSENSUS[H]="no_mistral_panel"
GROUP_DESC[H]="Mistral-Small-3.2-24B (8003) + V1(Qwen) + V4(Claude) + V6(GPT-4o) [need 2 of 3 to approve, no V5]"

GROUP_NAMES[I]="Group I: Llama-3.1-8B-Instruct Primary (small, RTX 5090 node)"
GROUP_PRIMARY[I]="${REMOTE_5090_URL:-}"   # RTX 5090 node, address from .env only
GROUP_PORTS[I]="8002 8003"
GROUP_CONSENSUS[I]="with_mistral"
GROUP_DESC[I]="Llama-3.1-8B-Instruct (REMOTE_5090_URL) + V1(Qwen) + V5(Mistral) + V4(Claude) + V6(GPT-4o) [need 3 of 4 to approve]"
GROUP_API_KEY_ENV[I]="REMOTE_5090_API_KEY"

GROUP_NAMES[J]="Group J: GPT-OSS-120B Primary (mid-large)"
GROUP_PRIMARY[J]="http://localhost:8006/v1"
GROUP_PORTS[J]="8006 8002 8003"
GROUP_CONSENSUS[J]="with_mistral"
GROUP_DESC[J]="GPT-OSS-120B (8006) + V1(Qwen) + V5(Mistral) + V4(Claude) + V6(GPT-4o) [need 3 of 4 to approve]"


ALL_GROUPS=("A" "B" "C" "D" "E" "F" "G" "H" "I" "J")

# ---- Per-(group, domain) port + ChromaDB allocator ----
# Multiple groups can now run baselines in parallel without their tool
# / MMA servers stomping on each other.  Each (group, domain) slot gets
# its own 40-port window starting at 10000:
#
#   tool_base = 10000 + group_offset*160 + domain_offset*40
#   mma_port  = tool_base + 30
#
# Same layout as run_attack_paths.sh so attack-paths and baseline runs
# can share the same per-(group, domain) ChromaDB seed.
declare -A GROUP_OFFSET DOMAIN_OFFSET
GROUP_OFFSET[A]=0;  GROUP_OFFSET[B]=1; GROUP_OFFSET[C]=2; GROUP_OFFSET[D]=3
GROUP_OFFSET[E]=4;  GROUP_OFFSET[F]=5; GROUP_OFFSET[G]=6; GROUP_OFFSET[H]=7
GROUP_OFFSET[I]=8;  GROUP_OFFSET[J]=9
DOMAIN_OFFSET[cyberops]=0; DOMAIN_OFFSET[healthcare]=1
DOMAIN_OFFSET[finance]=2;  DOMAIN_OFFSET[legal]=3

compute_tool_base() {
    local _grp="$1" _dom="$2"
    echo $((10000 + GROUP_OFFSET[$_grp]*160 + DOMAIN_OFFSET[$_dom]*40))
}

# ---- Interactive or CLI ----
if [ -z "$1" ]; then
    echo ""
    echo "  DEFER — Baseline Verification"
    echo "  ──────────────────────────────────────────────"
    echo ""
    echo "  Step 1: Select Model Group"
    echo ""
    for g in "${ALL_GROUPS[@]}"; do
        echo "    $g) ${GROUP_NAMES[$g]}"
        echo "       ${GROUP_DESC[$g]}"
        echo ""
    done
    read -p "  Select group [A]: " group_choice
    GROUP="${group_choice:-A}"
    GROUP="${GROUP^^}"  # uppercase

    echo ""
    echo "  Step 2: Select Domains"
    echo ""
    echo "    1) cyberops"
    echo "    2) healthcare"
    echo "    3) finance"
    echo "    4) legal"
    echo "    5) all (1-4)"
    echo ""
    read -p "  Enter choices (e.g. 1 2 3, or 5 for all): " domain_choices

    DOMAINS=()
    for c in $domain_choices; do
        case "$c" in
            1) DOMAINS+=("cyberops") ;;
            2) DOMAINS+=("healthcare") ;;
            3) DOMAINS+=("finance") ;;
            4) DOMAINS+=("legal") ;;
            5) DOMAINS=("cyberops" "healthcare" "finance" "legal"); break ;;
        esac
    done
    [ ${#DOMAINS[@]} -eq 0 ] && echo "  No domains selected." && exit 0
else
    GROUP="${1^^}"
    shift
    if [ -z "$1" ]; then
        DOMAINS=("${ALL_DOMAINS[@]}")
    else
        DOMAINS=()
        for c in "$@"; do
            case "$c" in
                1|cyberops) DOMAINS+=("cyberops") ;;
                2|healthcare) DOMAINS+=("healthcare") ;;
                3|finance) DOMAINS+=("finance") ;;
                4|legal) DOMAINS+=("legal") ;;
                5|all) DOMAINS=("cyberops" "healthcare" "finance" "legal"); break ;;
            esac
        done
    fi
fi

# Validate group
if [ -z "${GROUP_NAMES[$GROUP]}" ]; then
    echo "  Unknown group: $GROUP. Use one of: ${ALL_GROUPS[*]}"
    exit 1
fi

LLM_URL="${GROUP_PRIMARY[$GROUP]}"
CONSENSUS_CONFIG="${GROUP_CONSENSUS[$GROUP]}"
REQUIRED_PORTS="${GROUP_PORTS[$GROUP]}"
RESULT_DIR="results/baseline/group_${GROUP}"
GROUP_EXTRA_BODY_VAL="${GROUP_EXTRA_BODY[$GROUP]:-}"     # may be empty
GROUP_API_KEY_ENV_VAL="${GROUP_API_KEY_ENV[$GROUP]:-}"   # may be empty

run_py() {
    conda run --no-capture-output -n "$CONDA_ENV" python3 "$@"
}

wait_for_health() {
    local url="$1" name="$2" timeout="${3:-60}" elapsed=0
    while ! curl -s --max-time 1 "$url" > /dev/null 2>&1; do
        sleep 1; elapsed=$((elapsed + 1))
        [ $elapsed -ge $timeout ] && echo "[FAIL] $name timeout" && return 1
    done
    echo "[  ok] $name ready (${elapsed}s)"
}

cleanup() {
    echo ""
    echo "[cleanup] Stopping background services..."
    for pid in "${PIDS[@]}"; do
        pkill -P "$pid" 2>/dev/null || true
        kill "$pid" 2>/dev/null || true
    done
    # Only kill the ports this run actually allocated -- don't disturb
    # parallel baseline / attack-paths runs from other (group, domain) slots.
    for port in "${ALLOCATED_PORTS[@]}"; do
        pid=$(lsof -ti :$port 2>/dev/null || true)
        [ -n "$pid" ] && kill -9 $pid 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "[cleanup] Done."
}
trap cleanup EXIT INT TERM

echo ""
echo "============================================================"
echo "  DEFER — Baseline Verification"
echo "  ${GROUP_NAMES[$GROUP]}"
echo "  ${GROUP_DESC[$GROUP]}"
echo "  Domains: ${DOMAINS[*]}"
echo "  Results: ${RESULT_DIR}/"
echo "============================================================"

# ---- Check required vLLM servers ----
echo ""
echo "[check] Verifying required servers for ${GROUP_NAMES[$GROUP]}..."
all_up=true
for port in $REQUIRED_PORTS; do
    if curl -s --max-time 2 http://localhost:$port/health > /dev/null 2>&1; then
        echo "[  ok] Port $port healthy"
    else
        echo "[FAIL] Port $port not running"
        all_up=false
    fi
done

if [ "$all_up" = false ]; then
    echo ""
    echo "  ERROR: Required servers not running."
    echo "  Start them with: ./start_servers.sh"
    echo "  Required ports: $REQUIRED_PORTS"
    exit 1
fi

# ---- Run baseline per domain ----
run_domain_baseline() {
    local domain="$1"

    # Per-(group, domain) port slot + ChromaDB path so parallel groups
    # never collide on tool/MMA ports or seed data.
    local TOOL_BASE_PORT
    TOOL_BASE_PORT=$(compute_tool_base "$GROUP" "$domain")
    local MMA_PORT=$((TOOL_BASE_PORT + 30))
    local CHROMA_DB_PATH="./data/chromadb/group_${GROUP}"

    echo ""
    echo "============================================================"
    echo "  BASELINE: ${domain} / Group ${GROUP}"
    echo "  tool_base=${TOOL_BASE_PORT}  mma=${MMA_PORT}  chromadb=${CHROMA_DB_PATH}/${domain}"
    echo "============================================================"

    # Check for existing data — prompt before overwriting
    if [ -d "logs/${domain}_baseline_${GROUP}" ] || [ -d "${RESULT_DIR}/${domain}" ]; then
        echo ""
        echo "  WARNING: Existing baseline data found for ${domain}/Group ${GROUP}."
        read -p "  Overwrite? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "  Skipping ${domain}."
            return 0
        fi
    fi

    # Clean previous data for this group+domain (only this slot's ports
    # and only this group's chromadb subdir).
    echo "[step 0/7] Cleaning previous run data + stale ports..."
    rm -rf "logs/${domain}_baseline_${GROUP}" 2>/dev/null || true
    rm -rf "${RESULT_DIR}/${domain}" 2>/dev/null || true
    rm -rf "${CHROMA_DB_PATH}/${domain}" 2>/dev/null || true
    for port in $(seq ${TOOL_BASE_PORT} $((TOOL_BASE_PORT + 29))) ${MMA_PORT}; do
        pid=$(lsof -ti :$port 2>/dev/null || true)
        [ -n "$pid" ] && kill -9 $pid 2>/dev/null || true
        ALLOCATED_PORTS+=("$port")
    done
    sleep 1
    mkdir -p "$CHROMA_DB_PATH"

    # ChromaDB
    echo "[step 2/7] Initializing ChromaDB for ${domain}..."
    run_py -m memory.chromadb_setup --domain "$domain" --db-path "$CHROMA_DB_PATH" 2>&1 | tail -5

    echo "[step 3/7] Seeding memory collections..."
    run_py -m memory.seed_data --domain "$domain" --db-path "$CHROMA_DB_PATH" 2>&1 | tail -15

    # Start tools (on this group's port slot)
    echo "[step 4/7] Starting ${domain} tool servers on base port ${TOOL_BASE_PORT}..."
    HARNESS_INJECTION=1 run_py -m domains.${domain}.tools.start_all --base-port "$TOOL_BASE_PORT" &
    PIDS+=($!)
    sleep 3
    wait_for_health "http://localhost:${TOOL_BASE_PORT}/health" "${domain} tools" 30

    # Start MMA (on this group's MMA port + chromadb path)
    echo "[step 5/7] Starting MMA gateway on port ${MMA_PORT}..."
    HARNESS_INJECTION=1 run_py -m memory.mma_gateway --domain "$domain" --port "$MMA_PORT" --db-path "$CHROMA_DB_PATH" &
    PIDS+=($!)
    wait_for_health "http://localhost:${MMA_PORT}/health" "MMA" 30 || true

    # Run benign E2E
    echo "[step 6/7] Running benign E2E tests..."
    echo ""

    mkdir -p "logs/${domain}_baseline_${GROUP}"

    for config in flat acl_hardened agenticcyops; do
        echo "  --- ${domain} / ${config} / Group ${GROUP} ---"
        # Env vars so the inline Python below stays small and quote-safe.
        export BASELINE_GROUP="$GROUP"
        export BASELINE_DOMAIN="$domain"
        export BASELINE_CONFIG="$config"
        export BASELINE_LLM_URL="$LLM_URL"
        export BASELINE_CONSENSUS="$CONSENSUS_CONFIG"
        export BASELINE_TOOL_PORT="$TOOL_BASE_PORT"
        export BASELINE_MMA_URL="http://localhost:${MMA_PORT}"
        export BASELINE_API_KEY_ENV="$GROUP_API_KEY_ENV_VAL"
        export BASELINE_EXTRA_BODY="$GROUP_EXTRA_BODY_VAL"
        export BASELINE_STATE_MODE="${STATE_MODE:-isolated}"   # H3: isolated | persistent
        run_py -c "
import asyncio, json, os, sys
sys.path.insert(0, '.')
from pathlib import Path
from logging_utils import ExperimentLogger
from logging_utils.run_metadata import build_run_header
from host.orchestrator import SOARHost
from host.manifest_enforcer import ManifestEnforcer
from mcp_servers.server_registry import ServerRegistry
from agents.monitor_agent import MonitorAgent
from agents.analyze_agent import AnalyzeAgent
from agents.admin_agent import AdminAgent
from agents.report_agent import ReportAgent

async def run():
    domain = os.environ['BASELINE_DOMAIN']
    config = os.environ['BASELINE_CONFIG']
    group = os.environ['BASELINE_GROUP']
    llm_url = os.environ['BASELINE_LLM_URL']
    llm_provider = 'anthropic' if llm_url == 'anthropic' else 'openai'
    consensus_config = os.environ['BASELINE_CONSENSUS']
    tool_base_port = int(os.environ['BASELINE_TOOL_PORT'])
    mma_url = os.environ['BASELINE_MMA_URL']
    api_key_env = os.environ.get('BASELINE_API_KEY_ENV') or None
    state_mode = os.environ.get('BASELINE_STATE_MODE') or 'isolated'
    extra_body_json = os.environ.get('BASELINE_EXTRA_BODY') or ''
    extra_body = json.loads(extra_body_json) if extra_body_json.strip() else None

    header = build_run_header(
        group=group, config=config, domain=domain, primary_url=llm_url,
        primary_provider=llm_provider, api_key_env=api_key_env,
        consensus_config=consensus_config if config in ('agenticcyops', 'llm_judge') else None,
        state_mode=state_mode,
    )
    logger = ExperimentLogger(
        eval_name=f'{domain}_baseline_{group}',
        domain=domain,
        config=config,
        model=header.get('primary_model') or f'Group_{group}',
        header=header,
    )
    logger.set_trial(ap='benign', variant=1, trial=1)

    enforcer = ManifestEnforcer(domain=domain, logger=logger)

    registry = ServerRegistry(domain=domain, logger=logger)
    registry.load_tools()
    registry.assign_ports(tool_base_port)

    all_schemas = registry.get_all_schemas()

    agents = {}
    for phase, AgentClass in [('monitor', MonitorAgent), ('analyze', AnalyzeAgent),
                               ('admin', AdminAgent), ('report', ReportAgent)]:
        manifest = enforcer.get_manifest(phase)
        phase_schemas = registry.get_phase_schemas(manifest.get('allowed_tools', []))
        agent_kwargs = dict(
            domain=domain,
            config=config,
            manifest=manifest,
            tool_schemas=phase_schemas,
            all_tool_schemas=all_schemas,
            logger=logger,
        )
        if llm_provider == 'anthropic':
            agent_kwargs['llm_provider'] = 'anthropic'
        else:
            agent_kwargs['llm_url'] = llm_url
            if api_key_env:
                agent_kwargs['api_key_env'] = api_key_env
            if extra_body:
                agent_kwargs['extra_body'] = extra_body
        agents[phase] = AgentClass(**agent_kwargs)

    consensus = None
    if config == 'agenticcyops':
        try:
            from consensus.validator import ConsensusValidator
            consensus = ConsensusValidator(config_name=consensus_config, logger=logger)
            print(f'    Consensus: {consensus_config}')
        except Exception as e:
            print(f'    Consensus: skipped ({e})')

    host = SOARHost(
        domain=domain,
        config=config,
        llm_url=llm_url if llm_provider != 'anthropic' else 'http://localhost:8000/v1',
        mma_url=mma_url,
        tool_registry=registry,
        consensus=consensus,
        agents=agents,
        logger=logger,
        state_mode=state_mode,
        adaptive_consent_path=(Path('data') / 'adaptive_consent' / group / f'{domain}.json'
                               if state_mode == 'persistent' else None),
    )

    # Load domain-appropriate benign incident
    _benign_file = Path(f'domains/{domain}/payloads/benign_alerts.json')
    if not _benign_file.exists():
        _benign_file = Path(f'domains/{domain}/payloads/benign_workflows.json')
    if _benign_file.exists():
        with open(_benign_file) as _f:
            _payloads = json.load(_f)
        _p0 = _payloads[0]
        incident = _p0.get('trigger', _p0)
        # Include memory_ops for P4/P5 baseline coverage
        if 'memory_ops' in _p0:
            incident['memory_ops'] = _p0['memory_ops']
        if 'incident_id' not in incident:
            incident['incident_id'] = f'{domain}-BENIGN-001'
    else:
        incident = {
            'incident_id': f'{domain}-BENIGN-001',
            'alert_type': 'generic_alert',
            'timestamp': '2026-04-09T10:00:00Z',
            'description': f'Benign test incident for {domain}.',
        }

    try:
        result = await host.run_incident(incident)
        phases = list(result.get('phases', {}).keys())
        print(f'    Completed phases: {phases}')
        print(f'    Log: {logger.log_file}')
    except Exception as e:
        print(f'    ERROR: {e}')
    finally:
        logger.close()

asyncio.run(run())
" 2>&1 | grep -v "TqdmWarning\|tqdm\|^$"
        echo ""
    done

    # Verification + dashboard + report
    echo "[step 7/7] Generating verification report..."
    echo ""

    # Copy logs to standard location for verify_baseline compatibility
    mkdir -p "logs/${domain}_baseline"
    cp logs/${domain}_baseline_${GROUP}/*.jsonl "logs/${domain}_baseline/" 2>/dev/null || true

    run_py -m analysis.verify_baseline --domain "$domain" --config all 2>&1

    echo ""
    echo "Generating dashboard + report + analytics..."
    mkdir -p "${RESULT_DIR}/${domain}"
    run_py -m analysis.baseline_dashboard --domain "$domain" --output "${RESULT_DIR}/${domain}/" 2>&1 || true
    run_py -m analysis.generate_report --domain "$domain" --output "${RESULT_DIR}/${domain}/" 2>&1 || true
    run_py -m analysis.baseline_analytics --domain "$domain" --group "$GROUP" --output "${RESULT_DIR}/${domain}/" 2>&1 || true

    # Clean up standard location
    rm -rf "logs/${domain}_baseline" 2>/dev/null || true

    echo ""
    echo "============================================================"
    echo "  ${domain} / Group ${GROUP} BASELINE COMPLETE"
    echo "  Results: ${RESULT_DIR}/${domain}/"
    echo "============================================================"

    # Stop domain services -- only the ports allocated to *this* slot.
    for pid in "${PIDS[@]}"; do
        pkill -P "$pid" 2>/dev/null || true
        kill "$pid" 2>/dev/null || true
    done
    for port in $(seq ${TOOL_BASE_PORT} $((TOOL_BASE_PORT + 29))) ${MMA_PORT}; do
        pid=$(lsof -ti :$port 2>/dev/null || true)
        [ -n "$pid" ] && kill -9 $pid 2>/dev/null || true
    done
    wait 2>/dev/null || true
    PIDS=()
}

# ---- Main ----
for d in "${DOMAINS[@]}"; do
    run_domain_baseline "$d"
done

# Readiness gate
if [ ${#DOMAINS[@]} -gt 1 ]; then
    echo ""
    echo "============================================================"
    echo "  READINESS GATE — Group ${GROUP}"
    echo "============================================================"

    # Temporarily copy all group logs for verification
    for d in "${DOMAINS[@]}"; do
        mkdir -p "logs/${d}_baseline"
        cp logs/${d}_baseline_${GROUP}/*.jsonl "logs/${d}_baseline/" 2>/dev/null || true
    done

    run_py -m analysis.verify_baseline --domain all --config all 2>&1

    # Clean temp copies
    for d in "${DOMAINS[@]}"; do
        rm -rf "logs/${d}_baseline" 2>/dev/null || true
    done
fi

echo ""
echo "Done. Results in ${RESULT_DIR}/"
echo ""
echo "Results directory structure:"
find "${RESULT_DIR}" -type f 2>/dev/null | sort | head -30
