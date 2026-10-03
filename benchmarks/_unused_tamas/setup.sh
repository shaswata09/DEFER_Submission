#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# TAMAS Benchmark Setup Script
# -----------------------------------------------------------------------------
# Purpose:  Bootstrap the TAMAS (Targeting Agentic Multi-Agent Systems)
#           benchmark environment for DEFER.
#
# Reference: arxiv 2506.02635
#
# Steps:
#   1) Create benchmarks/_unused_tamas/external/ directory
#   2) Clone the upstream TAMAS repository (trying a list of known candidates)
#   3) Fall back to a placeholder if no upstream source is reachable
#   4) Ensure pyautogen>=0.2.35 is installed
#   5) Run a basic import sanity check
#
# The script is idempotent: re-running it will not re-clone if external/TAMAS
# already exists, and will not reinstall pyautogen if it is already present
# at the required version.
# -----------------------------------------------------------------------------

set -u                  # Treat unset variables as errors
set -o pipefail         # Fail on any error in a pipeline

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTERNAL_DIR="${SCRIPT_DIR}/external"
TAMAS_DIR="${EXTERNAL_DIR}/TAMAS"
REQUIRED_PYAUTOGEN="0.2.35"

# Candidate repositories to try (best-effort probing).
# Paper reference: https://arxiv.org/abs/2506.02635
CANDIDATE_REPOS=(
    "https://github.com/gauphon/TAMAS.git"
    "https://github.com/TAMAS-bench/TAMAS.git"
    "https://github.com/tamas-benchmark/tamas.git"
    "https://github.com/TAMAS-agents/TAMAS.git"
)

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info()  { printf '[INFO]  %s\n'  "$*"; }
log_warn()  { printf '[WARN]  %s\n'  "$*" >&2; }
log_error() { printf '[ERROR] %s\n'  "$*" >&2; }
log_ok()    { printf '[OK]    %s\n'  "$*"; }

banner() {
    printf '\n'
    printf '==============================================================\n'
    printf '  %s\n' "$*"
    printf '==============================================================\n'
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
require_cmd() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        log_error "Required command not found on PATH: ${cmd}"
        return 1
    fi
}

ensure_prerequisites() {
    banner "Step 0: Checking prerequisites"
    local missing=0
    for c in git python3; do
        if require_cmd "${c}"; then
            log_ok "${c} is available"
        else
            missing=1
        fi
    done

    if ! python3 -m pip --version >/dev/null 2>&1; then
        log_error "python3 -m pip is not available"
        missing=1
    else
        log_ok "pip is available"
    fi

    if [ "${missing}" -ne 0 ]; then
        log_error "Prerequisite check failed. Install missing tools and retry."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# External directory bootstrap
# ---------------------------------------------------------------------------
create_external_dir() {
    banner "Step 1: Preparing external directory"
    if [ ! -d "${EXTERNAL_DIR}" ]; then
        mkdir -p "${EXTERNAL_DIR}"
        log_ok "Created ${EXTERNAL_DIR}"
    else
        log_info "Directory already exists: ${EXTERNAL_DIR}"
    fi
}

# ---------------------------------------------------------------------------
# Clone (or stub) the upstream TAMAS repository
# ---------------------------------------------------------------------------
try_clone_tamas() {
    banner "Step 2: Fetching TAMAS upstream repository"

    if [ -d "${TAMAS_DIR}" ]; then
        log_info "TAMAS directory already present: ${TAMAS_DIR}"
        log_info "Skipping clone (idempotent mode)."
        return 0
    fi

    local success=0
    for repo in "${CANDIDATE_REPOS[@]}"; do
        log_info "Trying candidate: ${repo}"
        if git ls-remote --exit-code "${repo}" >/dev/null 2>&1; then
            log_info "Candidate reachable, attempting clone..."
            if git clone --depth 1 "${repo}" "${TAMAS_DIR}" 2>&1; then
                log_ok "Cloned ${repo} to ${TAMAS_DIR}"
                success=1
                break
            else
                log_warn "Clone failed for ${repo}; cleaning up partial directory."
                rm -rf "${TAMAS_DIR}"
            fi
        else
            log_warn "Candidate not reachable: ${repo}"
        fi
    done

    if [ "${success}" -ne 1 ]; then
        log_warn "No upstream TAMAS repository could be cloned."
        create_placeholder
    fi
}

create_placeholder() {
    log_info "Creating placeholder TAMAS directory."
    mkdir -p "${TAMAS_DIR}"
    cat > "${TAMAS_DIR}/README_PLACEHOLDER.md" <<'PLACEHOLDER_EOF'
# TAMAS Placeholder

This directory is a placeholder created by `benchmarks/_unused_tamas/setup.sh`
because no public upstream TAMAS repository could be located at
benchmark setup time.

## What to do

The TAMAS benchmark (Targeting Agentic Multi-Agent Systems, arxiv
2506.02635) will be implemented from the paper specification in
`benchmarks/_unused_tamas/`. The following six attack families must be
reproduced:

1. Direct prompt injection
2. Indirect prompt injection (via tool output / memory)
3. Role impersonation
4. Inter-agent tool confusion
5. Data exfiltration via agent relay
6. Goal hijacking through long-horizon memory poisoning

## How DEFER uses this

The `P12345Middleware` wraps every AutoGen agent with the P1-P5 defense
stack (manifest enforcement, authenticated interface, consensus,
velocity/impact checks, memory isolation). Trials are driven by
`run_baseline.py` (no defenses) and `run_defended.py` (full stack),
then compared by `compare.py`.

Re-run `setup.sh` once an upstream release becomes available to replace
this placeholder with the real repository.
PLACEHOLDER_EOF
    log_ok "Placeholder written to ${TAMAS_DIR}/README_PLACEHOLDER.md"
}

# ---------------------------------------------------------------------------
# pyautogen installation
# ---------------------------------------------------------------------------
version_ge() {
    # version_ge A B  => returns 0 if A >= B
    # Uses sort -V for portable version comparison.
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

ensure_pyautogen() {
    banner "Step 3: Ensuring pyautogen>=${REQUIRED_PYAUTOGEN}"

    local current
    current="$(python3 -c 'import importlib.metadata as m; print(m.version("pyautogen"))' 2>/dev/null || true)"

    if [ -n "${current}" ] && version_ge "${current}" "${REQUIRED_PYAUTOGEN}"; then
        log_ok "pyautogen ${current} already satisfies >=${REQUIRED_PYAUTOGEN}"
        return 0
    fi

    if [ -n "${current}" ]; then
        log_info "pyautogen ${current} is below required ${REQUIRED_PYAUTOGEN}; upgrading."
    else
        log_info "pyautogen is not installed; installing."
    fi

    if python3 -m pip install --quiet "pyautogen>=${REQUIRED_PYAUTOGEN}"; then
        log_ok "pyautogen installation completed."
    else
        log_error "pyautogen installation failed. See pip output above."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Basic import sanity check
# ---------------------------------------------------------------------------
verify_imports() {
    banner "Step 4: Verifying imports"
    if python3 - <<'PY_EOF'
import importlib
import sys

modules = ["autogen"]
failed = []

for mod in modules:
    try:
        m = importlib.import_module(mod)
        version = getattr(m, "__version__", "unknown")
        print(f"[OK]    import {mod} (version={version})")
    except Exception as exc:  # pragma: no cover - diagnostic
        print(f"[FAIL]  import {mod}: {exc}")
        failed.append(mod)

sys.exit(1 if failed else 0)
PY_EOF
    then
        log_ok "Import verification passed."
    else
        log_error "Import verification failed."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    banner "TAMAS benchmark setup starting"
    log_info "Working directory: ${SCRIPT_DIR}"

    ensure_prerequisites
    create_external_dir
    try_clone_tamas
    ensure_pyautogen
    verify_imports

    banner "TAMAS benchmark setup complete"
    log_info "Next steps:"
    log_info "  1) python benchmarks/_unused_tamas/run_baseline.py"
    log_info "  2) python benchmarks/_unused_tamas/run_defended.py"
    log_info "  3) python benchmarks/_unused_tamas/compare.py"
}

main "$@"
