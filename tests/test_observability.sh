#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_observability.sh - Observability and diagnostic command tests
#
# Verifies diagnostic and monitoring commands:
#   - brig network: View network activity logs
#   - brig exec: Execute commands in running cells
#   - brig inspect: Show cell details
#   - brig diagnose: Run diagnostic checks
#   - brig verify: Verify security invariants
#
# Usage: ./tests/test_observability.sh
#
# Prerequisites:
#   - Lima VM running: limactl start cell
#   - Warden running: warden start
#   - Brig CLI installed: /usr/local/bin/brig
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed

set -euo pipefail

VM_NAME="${CELL_VM_NAME:-cell}"
PASSED=0
FAILED=0

# Colors for output.
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

log_pass() {
    echo -e "${GREEN}PASS${NC}: $1"
    PASSED=$((PASSED + 1))
}

log_fail() {
    echo -e "${RED}FAIL${NC}: $1"
    FAILED=$((FAILED + 1))
}

run_in_vm() {
    limactl shell "$VM_NAME" -- "$@"
}

# Check VM is running.
check_vm_running() {
    local vm_info
    vm_info=$(limactl list --format json 2>/dev/null || echo "{}")
    local status
    status=$(echo "$vm_info" | sed 's/.*"status":"\([^"]*\)".*/\1/')
    if [ "$status" != "Running" ]; then
        echo "ERROR: VM '$VM_NAME' is not running"
        exit 1
    fi
    echo "VM '$VM_NAME' is running"
}

# Clean up test cells.
cleanup_test_cells() {
    echo "Cleaning up test cells..."
    run_in_vm sudo /usr/local/bin/brig rm -f --purge obs-test-1 2>/dev/null || true
    run_in_vm sudo /usr/local/bin/brig rm -f --purge obs-test-2 2>/dev/null || true
}

echo "============================================"
echo "Observability Tests"
echo "============================================"
echo

# Pre-flight checks.
echo "--- Pre-flight checks ---"
check_vm_running

# Check cell CLI is installed.
if ! run_in_vm test -f /usr/local/bin/brig; then
    echo "ERROR: Cell CLI not installed at /usr/local/bin/brig"
    exit 1
fi
echo "Cell CLI installed"

# Check proxy is running.
if ! run_in_vm sudo podman ps --format '{{.Names}}' 2>/dev/null | grep -q "warden"; then
    echo "Starting proxy..."
    run_in_vm sudo /usr/local/bin/brig-proxy start 2>/dev/null || true
    sleep 3
fi
echo "Proxy is running"
echo

# Clean up before tests.
cleanup_test_cells

# Create a test cell.
echo "--- Setting up test cell ---"
run_in_vm sudo /usr/local/bin/brig run -d --name obs-test-1 alpine sleep 600 2>/dev/null || true
sleep 2

# Test 1: cell exec runs command in cell.
echo
echo "--- Test 1: cell exec runs command in cell ---"
EXEC_OUTPUT=$(run_in_vm sudo /usr/local/bin/brig exec obs-test-1 -- echo "hello from exec" 2>/dev/null || echo "")
if [ "$EXEC_OUTPUT" = "hello from exec" ]; then
    log_pass "brig exec runs command successfully"
else
    log_fail "brig exec failed: got '$EXEC_OUTPUT'"
fi

# Test 2: cell exec with complex command.
echo
echo "--- Test 2: cell exec with complex command ---"
EXEC_OUTPUT=$(run_in_vm sudo /usr/local/bin/brig exec obs-test-1 -- sh -c 'echo $HOSTNAME' 2>/dev/null || echo "")
if [ -n "$EXEC_OUTPUT" ]; then
    log_pass "brig exec runs complex command"
else
    log_fail "brig exec complex command failed"
fi

# Test 3: cell inspect shows cell details.
echo
echo "--- Test 3: cell inspect shows cell details ---"
INSPECT_OUTPUT=$(run_in_vm sudo /usr/local/bin/brig inspect obs-test-1 2>/dev/null || echo "")
if echo "$INSPECT_OUTPUT" | grep -q "obs-test-1"; then
    log_pass "brig inspect shows cell name"
else
    log_fail "brig inspect missing cell name"
fi

# Test 4: cell inspect shows runtime.
echo
echo "--- Test 4: cell inspect shows runtime ---"
if echo "$INSPECT_OUTPUT" | grep -qi "runsc\|gvisor\|runtime"; then
    log_pass "brig inspect shows runtime info"
else
    log_fail "brig inspect missing runtime info"
fi

# Test 5: cell inspect shows network.
echo
echo "--- Test 5: cell inspect shows network ---"
if echo "$INSPECT_OUTPUT" | grep -qi "network\|brig-obs-test-1"; then
    log_pass "brig inspect shows network info"
else
    log_fail "brig inspect missing network info"
fi

# Test 6: cell network shows log file.
echo
echo "--- Test 6: cell network reads network log ---"
# Generate some network traffic first.
run_in_vm sudo podman exec brig-obs-test-1 wget -q -O /dev/null --timeout=10 http://example.com 2>/dev/null || true
sleep 2

NETWORK_OUTPUT=$(run_in_vm sudo /usr/local/bin/brig network obs-test-1 2>/dev/null || echo "")
if echo "$NETWORK_OUTPUT" | grep -qi "example.com\|host\|method"; then
    log_pass "brig network shows network activity"
else
    log_fail "brig network missing data: $NETWORK_OUTPUT"
fi

# Test 7: cell network shows JSON format.
echo
echo "--- Test 7: cell network --json shows raw JSONL ---"
NETWORK_JSON=$(run_in_vm sudo /usr/local/bin/brig network obs-test-1 --json 2>/dev/null || echo "")
if echo "$NETWORK_JSON" | grep -q '"host"'; then
    log_pass "brig network --json shows JSONL format"
else
    log_fail "brig network --json not showing JSON"
fi

# Test 8: cell diagnose runs checks.
echo
echo "--- Test 8: cell diagnose runs diagnostic checks ---"
DIAGNOSE_OUTPUT=$(run_in_vm sudo /usr/local/bin/brig diagnose obs-test-1 2>/dev/null || echo "")
if echo "$DIAGNOSE_OUTPUT" | grep -qi "proxy\|network\|check\|ok\|pass"; then
    log_pass "brig diagnose runs checks"
else
    log_fail "brig diagnose output unexpected: $DIAGNOSE_OUTPUT"
fi

# Test 9: cell diagnose shows proxy status.
echo
echo "--- Test 9: cell diagnose shows proxy status ---"
if echo "$DIAGNOSE_OUTPUT" | grep -qi "proxy"; then
    log_pass "brig diagnose checks proxy"
else
    log_fail "brig diagnose missing proxy check"
fi

# Test 10: cell verify checks security invariants.
echo
echo "--- Test 10: cell verify checks security invariants ---"
VERIFY_OUTPUT=$(run_in_vm sudo /usr/local/bin/brig verify 2>/dev/null || echo "")
if echo "$VERIFY_OUTPUT" | grep -qi "pass\|ok\|check"; then
    log_pass "brig verify runs security checks"
else
    log_fail "brig verify output unexpected"
fi

# Test 11: cell verify checks gVisor.
echo
echo "--- Test 11: cell verify checks gVisor runtime ---"
if echo "$VERIFY_OUTPUT" | grep -qi "gvisor\|runtime"; then
    log_pass "brig verify checks gVisor"
else
    log_fail "brig verify missing gVisor check"
fi

# Test 12: cell verify checks network isolation.
echo
echo "--- Test 12: cell verify checks network isolation ---"
if echo "$VERIFY_OUTPUT" | grep -qi "network\|isolat"; then
    log_pass "brig verify checks network isolation"
else
    log_fail "brig verify missing network check"
fi

# Test 13: cell exec fails on stopped cell.
echo
echo "--- Test 13: cell exec fails on stopped cell ---"
run_in_vm sudo /usr/local/bin/brig stop obs-test-1 2>/dev/null || true
if run_in_vm sudo /usr/local/bin/brig exec obs-test-1 -- echo "test" 2>/dev/null; then
    log_fail "brig exec should fail on stopped cell"
else
    log_pass "brig exec correctly fails on stopped cell"
fi

# Test 14: cell inspect works on stopped cell.
echo
echo "--- Test 14: cell inspect works on stopped cell ---"
INSPECT_OUTPUT=$(run_in_vm sudo /usr/local/bin/brig inspect obs-test-1 2>/dev/null || echo "")
if echo "$INSPECT_OUTPUT" | grep -qi "obs-test-1\|stop\|exit"; then
    log_pass "brig inspect works on stopped cell"
else
    log_fail "brig inspect failed on stopped cell"
fi

# Cleanup.
echo
echo "--- Cleanup ---"
cleanup_test_cells

# Summary.
echo
echo "============================================"
echo "Summary"
echo "============================================"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Review output above.${NC}"
    exit 1
fi
