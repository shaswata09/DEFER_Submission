#!/bin/bash
# ============================================================
# DEFER -- ASB upstream data ingest
#
# Clones the upstream Agent Security Bench (ASB) repository
# (agiresearch/ASB, MIT-licensed) into a temp dir, then copies
# the YAML configs and scenario data we need into
#   benchmarks/asb/data/upstream/
# This is the ONLY place upstream artifacts live; the static
# evaluator works from a converted JSON form under
#   benchmarks/asb/data/cases/   (produced by convert_cases.py)
#
# Usage:
#   ./benchmarks/asb/scripts/ingest_upstream.sh
#
# Idempotent: re-running refreshes the upstream snapshot but
# keeps the converted cases and the LICENSE / ATTRIBUTION
# files untouched.
# ============================================================

set -eE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../../.."     # repo root

UPSTREAM_REPO="https://github.com/agiresearch/ASB.git"
DATA_ROOT="benchmarks/asb/data"
UPSTREAM_DIR="$DATA_ROOT/upstream"
TMP_DIR="$(mktemp -d)"

echo "[ingest] Cloning $UPSTREAM_REPO -> $TMP_DIR"
git clone --depth 1 "$UPSTREAM_REPO" "$TMP_DIR/ASB"

mkdir -p "$UPSTREAM_DIR"

# --- Copy the parts we actually need ---
# 1. config/ -- YAML scenario+attack matrices
# 2. data/   -- per-scenario test cases
# 3. LICENSE / README -- provenance
for sub in config data LICENSE README.md; do
    if [ -e "$TMP_DIR/ASB/$sub" ]; then
        echo "[ingest] copying $sub"
        cp -r "$TMP_DIR/ASB/$sub" "$UPSTREAM_DIR/"
    fi
done

# --- Snapshot the commit hash for reproducibility ---
(cd "$TMP_DIR/ASB" && git rev-parse HEAD) > "$UPSTREAM_DIR/UPSTREAM_COMMIT.txt"

rm -rf "$TMP_DIR"

echo ""
echo "[done] Upstream ASB snapshot at $UPSTREAM_DIR/"
echo "       Pinned commit: $(cat $UPSTREAM_DIR/UPSTREAM_COMMIT.txt)"
echo ""
echo "Next:"
echo "  python -m benchmarks.asb.scripts.convert_cases   # YAML -> per-case JSON"
echo "  python -m benchmarks.asb.run_static --groups A    # run through P1-P5"
