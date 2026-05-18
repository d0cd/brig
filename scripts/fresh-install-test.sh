#!/bin/bash
# fresh-install-test.sh — A4 from docs/plans/0.3-validation-plan.md.
#
# Validates the user's actual first-run experience: clean slate, then
# `make setup` + `brig up` + `brig run alpine` succeed in one go. Catches
# the kind of bugs that surfaced during 0.3.0 validation: missing
# directories, wrong path constants, slow sudo, perm mismatches, etc.
#
# Required environment:
#   - macOS host with Lima already installed (brew install lima).
#   - This repo cloned and the working dir set to its root.
#
# Side effects:
#   - Stops + deletes the `brig` Lima VM if it exists.
#   - Removes ~/.brig entirely.
#   - Creates a fresh VM and runs a throwaway cell.
#
# Exit codes:
#   0 — all checks passed
#   non-zero — first failure (script stops on `set -e`)

set -euo pipefail

# -------- guard against accidentally nuking a real install --------
if [[ "${BRIG_FRESH_INSTALL_TEST_OK:-}" != "1" ]]; then
    cat <<'EOF' >&2
ERROR: this script wipes the brig VM and ~/.brig. To confirm, re-run with:
  BRIG_FRESH_INSTALL_TEST_OK=1 ./scripts/fresh-install-test.sh
EOF
    exit 2
fi

step() { echo; echo "=== $* ==="; }

step "0. Reset state"
limactl stop brig 2>/dev/null || true
limactl delete brig -f 2>/dev/null || true
rm -rf ~/.brig

step "1. make setup"
make setup

step "2. brig system doctor --quick is fast and green"
START=$(date +%s)
if ! brig system doctor --quick; then
    echo "ERROR: brig system doctor --quick reported failure on a fresh install" >&2
    exit 1
fi
ELAPSED=$(($(date +%s) - START))
echo "  wall time: ${ELAPSED}s"
if [[ "$ELAPSED" -gt 5 ]]; then
    echo "ERROR: doctor --quick took ${ELAPSED}s (>5s). The sudo/DNS-timeout regression is back." >&2
    exit 1
fi

step "3. brig run alpine -- echo hello"
OUT=$(brig run --name fresh-test-$$ alpine -- echo "hello-from-fresh-install")
echo "  output: $OUT"
if ! grep -q "hello-from-fresh-install" <<< "$OUT"; then
    echo "ERROR: cell output missing the expected line" >&2
    exit 1
fi

step "4. brig cell rm -f fresh-test-*"
# Use a name pattern based on PID so concurrent runs don't collide.
brig cell list --format json | python3 -c '
import json, sys
cells = json.load(sys.stdin) if sys.stdin.isatty() is False else []
for c in cells:
    if c["name"].startswith("fresh-test-"):
        print(c["name"])
' | while read -r name; do
    [ -n "$name" ] && brig cell rm -f "$name"
done

step "5. Smoke: brig system doctor reports nothing wrong"
if ! brig system doctor; then
    echo "ERROR: brig system doctor failed on a fresh install" >&2
    exit 1
fi

echo
echo "=== fresh-install-test PASSED ==="
