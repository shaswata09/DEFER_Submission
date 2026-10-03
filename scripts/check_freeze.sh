#!/bin/bash
# ============================================================
# Defense freeze check (H11).
#
# The defense code is frozen at the git tag defense-freeze-v2 (see
#.  Every experiment run must be made from
# exactly that commit with a clean tree in the frozen directories, so
# the numbers in the paper can be tied to one version of the defense.
#
#   scripts/check_freeze.sh            # exit 0 iff HEAD == tag and frozen dirs are clean
#   scripts/check_freeze.sh --diff     # also show what differs from the tag
#
# Frozen: host/ consensus/ memory/ configs/ domains/*/configs/ mcp_servers/
#         agents/ attacks/effects.py attacks/harness.py logging_utils/
# ============================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TAG="${FREEZE_TAG:-defense-freeze-v3.2}"
FROZEN=(host consensus memory configs mcp_servers agents logging_utils attacks/effects.py attacks/harness.py)
for d in domains/*/configs; do FROZEN+=("$d"); done

if ! git rev-parse -q --verify "refs/tags/$TAG" > /dev/null; then
    echo "[FAIL] tag $TAG does not exist"; exit 1
fi
head=$(git rev-parse HEAD); tagc=$(git rev-parse "$TAG^{commit}")
status=0
if [ "$head" != "$tagc" ]; then
    if git diff --quiet "$tagc" HEAD -- "${FROZEN[@]}"; then
        echo "[  ok] HEAD $(git rev-parse --short HEAD) is after $TAG; frozen directories are identical to the tag"
        status=0
    else
        echo "[FAIL] HEAD $(git rev-parse --short HEAD): frozen files differ from $TAG:"
        git diff --stat "$tagc" HEAD -- "${FROZEN[@]}" | tail -20
        status=1
    fi
else
    echo "[  ok] HEAD is $TAG ($(git rev-parse --short HEAD))"
fi
if ! git diff --quiet HEAD -- "${FROZEN[@]}" || ! git diff --cached --quiet HEAD -- "${FROZEN[@]}"; then
    echo "[FAIL] uncommitted changes in frozen directories:"
    git status --short -- "${FROZEN[@]}"
    status=1
else
    echo "[  ok] frozen directories are clean"
fi
[ "${1:-}" = "--diff" ] && git diff "$tagc" HEAD -- "${FROZEN[@]}"
exit $status
