# e2e_common.sh - Shared harness for Brig shell e2e suites.
#
# Source this from a suite: `source "$(dirname "$0")/lib/e2e_common.sh"`.
#
# Model: brig is driven from the HOST (it orchestrates the VM over lima +
# podman). Suites call `$BRIG <cmd>` for CLI operations and `run_in_vm` /
# `in_cell` only to INSPECT VM-internal state (container config, mounts, the
# per-cell network log). This matches how the cell runs in production —
# unlike the retired in-VM-install model (`run_in_vm /usr/local/bin/brig`).
#
# Provides: color vars, PASSED/FAILED/SKIPPED counters, pass/fail/skip,
# run_in_vm, in_cell, require_brig_up (preflight), finish (summary + exit).
#
# Config (env):
#   BRIG          - how to invoke brig on the host (default: "uv run brig")
#   BRIG_VM_NAME  - lima VM name (default: "brig"; legacy CELL_VM_NAME honored)

# shellcheck disable=SC2034  # color vars are used by sourcing scripts
set -uo pipefail

BRIG="${BRIG:-uv run brig}"
WARDEN="${WARDEN:-uv run warden}"
VM_NAME="${BRIG_VM_NAME:-${CELL_VM_NAME:-brig}}"
PASSED=0
FAILED=0
SKIPPED=0

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BOLD=''; NC=''
fi

log_pass() { echo -e "${GREEN}PASS${NC}: $1"; PASSED=$((PASSED + 1)); }
log_fail() { echo -e "${RED}FAIL${NC}: $1"; FAILED=$((FAILED + 1)); }
log_skip() { echo -e "${YELLOW}SKIP${NC}: $1"; SKIPPED=$((SKIPPED + 1)); }

# Run a command inside the VM (for inspecting VM-internal state).
run_in_vm() { limactl shell "$VM_NAME" -- "$@"; }

# Run a command inside a cell's container. Cells are named brig-<cell>.
in_cell() { local cell="$1"; shift; run_in_vm sudo podman exec "brig-${cell}" "$@"; }

# Preflight: VM running + host brig usable. Exits 1 (not a silent skip) so a
# misconfigured environment is loud, never mistaken for "all passed".
require_brig_up() {
    if ! limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null \
            | grep -q "^${VM_NAME} Running"; then
        echo "ERROR: VM '$VM_NAME' is not running — run \`brig system up\` first." >&2
        echo "       (override the VM name with BRIG_VM_NAME=...)" >&2
        exit 1
    fi
    if ! $BRIG system verify >/dev/null 2>&1 && ! $BRIG ps >/dev/null 2>&1; then
        echo "ERROR: host brig ('$BRIG') is not working — check your install." >&2
        exit 1
    fi
}

# Print the summary block the aggregator (test_all.sh) parses, and exit
# nonzero if anything failed.
finish() {
    echo
    echo "============================================"
    echo "Summary"
    echo "============================================"
    echo -e "Passed: ${GREEN}$PASSED${NC}"
    echo -e "Failed: ${RED}$FAILED${NC}"
    [ "$SKIPPED" -gt 0 ] && echo -e "Skipped: ${YELLOW}$SKIPPED${NC}"
    echo
    if [ "$FAILED" -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed. Review output above.${NC}"
        exit 1
    fi
}
