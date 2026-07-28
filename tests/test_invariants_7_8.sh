#!/bin/bash
# shellcheck disable=SC2034,SC2153
# test_invariants_7_8.sh — real podman state for invariants 7 (no privileged
# services on cell networks) and 8 (cells single-homed).
#
# The unit tests feed hand-crafted JSON to the verifier; this test plants an
# actual foreign container on a brig-* network (resp. attaches a cell to a
# second network) and asserts `brig system verify` flags it — catching
# production drift the unit tests can't.
#
# Usage: ./tests/test_invariants_7_8.sh   (requires `brig system up` first)
# Exit: 0 both violations detected, 1 otherwise.

source "$(dirname "$0")/lib/e2e_common.sh"

CELL_NAME="inv-test-$$"
FOREIGN_NAME="foreign-${CELL_NAME}"
SECOND_NET="brig-inv-second-$$"

vm() { run_in_vm sudo "$@"; }

cleanup() {
    vm podman rm -f "$FOREIGN_NAME"    2>/dev/null || true
    vm podman network rm "$SECOND_NET" 2>/dev/null || true
    $BRIG cell rm -f "$CELL_NAME"      2>/dev/null || true
}
trap cleanup EXIT

echo "============================================"
echo "Invariants 7 & 8 (live podman state)"
echo "============================================"
echo

require_brig_up

echo "Creating test cell..."
$BRIG run --name "$CELL_NAME" --detach alpine -- sleep 600 >/dev/null 2>&1
sleep 1

# Invariant 7 — no privileged/foreign services on a cell network.
echo
echo "--- Invariant 7: foreign container on a cell network is flagged ---"
vm podman run -d --name "$FOREIGN_NAME" --network "brig-${CELL_NAME}" \
    docker.io/library/alpine:latest sleep 600 >/dev/null 2>&1
# Capture first: `brig system verify` exits nonzero on a detected violation,
# which under `set -o pipefail` would clobber grep's match if piped directly.
VERIFY_OUT=$($BRIG system verify 2>&1 || true)
if echo "$VERIFY_OUT" | grep -qiE "member violation|non-warden|non-cell|${FOREIGN_NAME}"; then
    log_pass "invariant 7: verify detected the foreign container"
else
    log_fail "invariant 7: verify did NOT detect the foreign container"
fi
vm podman rm -f "$FOREIGN_NAME" >/dev/null 2>&1 || true

# Invariant 8 — cells must be single-homed.
echo
echo "--- Invariant 8: multi-homed cell is flagged ---"
vm podman network create --internal "$SECOND_NET" >/dev/null 2>&1
vm podman network connect "$SECOND_NET" "brig-${CELL_NAME}" >/dev/null 2>&1
VERIFY_OUT=$($BRIG system verify 2>&1 || true)
if echo "$VERIFY_OUT" | grep -qiE "single.hom|multi.hom|has [0-9]+ networks|${SECOND_NET}"; then
    log_pass "invariant 8: verify detected the multi-homed cell"
else
    log_fail "invariant 8: verify did NOT detect the multi-homed cell"
fi

finish
