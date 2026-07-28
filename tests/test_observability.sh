#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_observability.sh - Observability and diagnostic command tests
#
# Verifies diagnostic and monitoring commands:
#   - brig cell exec: run commands in a running cell
#   - brig cell inspect: show cell details
#   - brig cell network: read the per-cell network activity log
#   - brig cell diagnose: run diagnostic checks
#   - brig system verify: verify security invariants
#
# Usage: ./tests/test_observability.sh   (requires `brig system up` first)
# Exit: 0 all passed, 1 any failed.

source "$(dirname "$0")/lib/e2e_common.sh"

cleanup_test_cells() {
    echo "Cleaning up test cells..."
    $BRIG cell rm -f obs-test-1 2>/dev/null || true
    $BRIG cell rm -f obs-test-2 2>/dev/null || true
}

echo "============================================"
echo "Observability Tests"
echo "============================================"
echo

echo "--- Pre-flight checks ---"
require_brig_up
echo "VM '$VM_NAME' is running; host brig OK"
echo

cleanup_test_cells

echo "--- Setting up test cell ---"
$BRIG run -d --name obs-test-1 --policy-allow example.com alpine sleep 600 >/dev/null 2>&1 || true
sleep 2

# Test 1: brig cell exec runs a command in the cell.
echo
echo "--- Test 1: brig cell exec runs command in cell ---"
EXEC_OUTPUT=$($BRIG cell exec obs-test-1 -- echo "hello from exec" 2>/dev/null || echo "")
if [ "$EXEC_OUTPUT" = "hello from exec" ]; then
    log_pass "brig cell exec runs command successfully"
else
    log_fail "brig cell exec failed: got '$EXEC_OUTPUT'"
fi

# Test 2: brig cell exec with a complex command.
echo
echo "--- Test 2: brig cell exec with complex command ---"
EXEC_OUTPUT=$($BRIG cell exec obs-test-1 -- sh -c 'echo $HOSTNAME' 2>/dev/null || echo "")
if [ -n "$EXEC_OUTPUT" ]; then
    log_pass "brig cell exec runs complex command"
else
    log_fail "brig cell exec complex command failed"
fi

# Test 3: brig cell inspect shows the cell name.
echo
echo "--- Test 3: brig cell inspect shows cell details ---"
INSPECT_OUTPUT=$($BRIG cell inspect obs-test-1 2>/dev/null || echo "")
if echo "$INSPECT_OUTPUT" | grep -q "obs-test-1"; then
    log_pass "brig cell inspect shows cell name"
else
    log_fail "brig cell inspect missing cell name"
fi

# Test 4: inspect shows runtime info.
echo
echo "--- Test 4: brig cell inspect shows runtime ---"
if echo "$INSPECT_OUTPUT" | grep -qi "runsc\|gvisor\|runtime"; then
    log_pass "brig cell inspect shows runtime info"
else
    log_fail "brig cell inspect missing runtime info"
fi

# Test 5: inspect shows network info.
echo
echo "--- Test 5: brig cell inspect shows network ---"
if echo "$INSPECT_OUTPUT" | grep -qi "network\|brig-obs-test-1"; then
    log_pass "brig cell inspect shows network info"
else
    log_fail "brig cell inspect missing network info"
fi

# Test 6: brig cell network reads the activity log.
echo
echo "--- Test 6: brig cell network reads network log ---"
in_cell obs-test-1 wget -q -O /dev/null --timeout=10 http://example.com 2>/dev/null || true
sleep 2
NETWORK_OUTPUT=$($BRIG cell network obs-test-1 2>/dev/null || echo "")
if echo "$NETWORK_OUTPUT" | grep -qi "example.com\|host\|method"; then
    log_pass "brig cell network shows network activity"
else
    log_fail "brig cell network missing data: $NETWORK_OUTPUT"
fi

# Test 7: brig cell network --blocked surfaces blocked requests.
echo
echo "--- Test 7: brig cell network --blocked shows blocked requests ---"
in_cell obs-test-1 wget -q -O /dev/null --timeout=8 http://neverssl.com 2>/dev/null || true
sleep 2
BLOCKED_OUTPUT=$($BRIG cell network obs-test-1 --blocked 2>/dev/null || echo "")
if echo "$BLOCKED_OUTPUT" | grep -qi "neverssl.com\|block"; then
    log_pass "brig cell network --blocked shows blocked requests"
else
    log_fail "brig cell network --blocked missing data: $BLOCKED_OUTPUT"
fi

# Test 8: brig cell diagnose runs checks.
echo
echo "--- Test 8: brig cell diagnose runs diagnostic checks ---"
DIAGNOSE_OUTPUT=$($BRIG cell diagnose obs-test-1 2>/dev/null || echo "")
if echo "$DIAGNOSE_OUTPUT" | grep -qi "proxy\|network\|check\|ok\|pass"; then
    log_pass "brig cell diagnose runs checks"
else
    log_fail "brig cell diagnose output unexpected: $DIAGNOSE_OUTPUT"
fi

# Test 9: diagnose reports cell status + runtime.
echo
echo "--- Test 9: brig cell diagnose reports status and runtime ---"
if echo "$DIAGNOSE_OUTPUT" | grep -qi "status" && echo "$DIAGNOSE_OUTPUT" | grep -qi "runtime"; then
    log_pass "brig cell diagnose reports status and runtime"
else
    log_fail "brig cell diagnose missing status/runtime: $DIAGNOSE_OUTPUT"
fi

# Test 10: brig system verify runs security checks.
echo
echo "--- Test 10: brig system verify checks security invariants ---"
VERIFY_OUTPUT=$($BRIG system verify 2>/dev/null || echo "")
if echo "$VERIFY_OUTPUT" | grep -qi "pass\|ok\|verif\|invariant"; then
    log_pass "brig system verify runs security checks"
else
    log_fail "brig system verify output unexpected"
fi

# Test 11: verify covers gVisor.
echo
echo "--- Test 11: brig system verify checks gVisor runtime ---"
if echo "$VERIFY_OUTPUT" | grep -qi "gvisor\|runtime\|runsc"; then
    log_pass "brig system verify checks gVisor"
else
    log_fail "brig system verify missing gVisor check"
fi

# Test 12: verify covers network isolation.
echo
echo "--- Test 12: brig system verify checks network isolation ---"
if echo "$VERIFY_OUTPUT" | grep -qi "network\|isolat\|internal"; then
    log_pass "brig system verify checks network isolation"
else
    log_fail "brig system verify missing network check"
fi

# Test 13: brig cell exec fails on a stopped cell.
echo
echo "--- Test 13: brig cell exec fails on stopped cell ---"
$BRIG cell stop obs-test-1 >/dev/null 2>&1 || true
if $BRIG cell exec obs-test-1 -- echo "test" >/dev/null 2>&1; then
    log_fail "brig cell exec should fail on stopped cell"
else
    log_pass "brig cell exec correctly fails on stopped cell"
fi

# Test 14: brig cell inspect works on a stopped cell.
echo
echo "--- Test 14: brig cell inspect works on stopped cell ---"
INSPECT_OUTPUT=$($BRIG cell inspect obs-test-1 2>/dev/null || echo "")
if echo "$INSPECT_OUTPUT" | grep -qi "obs-test-1\|stop\|exit"; then
    log_pass "brig cell inspect works on stopped cell"
else
    log_fail "brig cell inspect failed on stopped cell"
fi

echo
echo "--- Cleanup ---"
cleanup_test_cells

finish
