#!/bin/bash
# shellcheck disable=SC2034,SC2153
# test_invariants_7_8.sh — real podman state for invariants 7 (no
# privileged services on cell networks) and 8 (cells single-homed).
#
# The unit tests for these invariants feed hand-crafted JSON to the
# verifier; this test plants an actual foreign container on a brig-*
# network (resp. attaches a cell to a second network) and asserts
# `brig system verify` flags it. Without this, the verifier can pass
# unit tests while production drift goes unnoticed.
#
# Usage: ./tests/test_invariants_7_8.sh
#
# Prerequisites: Lima VM running, brig installed, warden up.
#
# Exit codes:
#   0 — both invariants correctly detected the violation
#   1 — at least one invariant failed to detect

set -euo pipefail

VM_NAME="${CELL_VM_NAME:-cell}"
PASSED=0
FAILED=0
CELL_NAME="inv-test-$$"
FOREIGN_NAME="foreign-${CELL_NAME}"
SECOND_NET="brig-inv-second-$$"

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    NC=''
fi

log_pass() { echo -e "${GREEN}PASS${NC}: $1"; PASSED=$((PASSED + 1)); }
log_fail() { echo -e "${RED}FAIL${NC}: $1"; FAILED=$((FAILED + 1)); }

vm() {
    limactl shell "$VM_NAME" -- sudo "$@"
}

cleanup() {
    vm podman rm -f "$FOREIGN_NAME"           2>/dev/null || true
    vm podman network rm "$SECOND_NET"        2>/dev/null || true
    brig cell rm -f "$CELL_NAME"              2>/dev/null || true
}
trap cleanup EXIT

# ----- Stand up a cell to violate-against -----
echo "Creating test cell..."
brig run --name "$CELL_NAME" --detach alpine -- sleep 600 >/dev/null
sleep 1

# ===========================================================================
# Invariant 7 — No privileged services on cell networks.
# Attach a foreign container (not via brig) to the cell's network and
# assert brig system verify flags it.
# ===========================================================================
echo
echo "Invariant 7: attaching foreign container to brig-${CELL_NAME}..."
vm podman run -d --name "$FOREIGN_NAME" \
    --network "brig-${CELL_NAME}" \
    docker.io/library/alpine:latest sleep 600 >/dev/null

if brig system verify 2>&1 | tee /tmp/inv7-verify.log | grep -qi "$FOREIGN_NAME\|foreign\|non-brig\|unexpected"; then
    log_pass "invariant 7: brig system verify detected the foreign container"
else
    log_fail "invariant 7: brig system verify did NOT detect the foreign container"
    echo "--- verify output ---"
    cat /tmp/inv7-verify.log
fi

# Clean up the inv 7 setup before testing inv 8.
vm podman rm -f "$FOREIGN_NAME" >/dev/null 2>&1 || true

# ===========================================================================
# Invariant 8 — Cells must be single-homed (one network only).
# Connect the cell's container to a second network and assert brig
# system verify flags it.
# ===========================================================================
echo
echo "Invariant 8: attaching cell to a second network..."
vm podman network create "$SECOND_NET" >/dev/null
vm podman network connect "$SECOND_NET" "brig-${CELL_NAME}" >/dev/null

if brig system verify 2>&1 | tee /tmp/inv8-verify.log | grep -qi "single.homed\|multi.network\|multiple networks\|second network\|$SECOND_NET"; then
    log_pass "invariant 8: brig system verify detected the multi-homed cell"
else
    log_fail "invariant 8: brig system verify did NOT detect the multi-homed cell"
    echo "--- verify output ---"
    cat /tmp/inv8-verify.log
fi

# ----- Summary -----
echo
echo "Results: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
