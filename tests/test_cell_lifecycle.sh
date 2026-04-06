#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_cell_lifecycle.sh - Cell lifecycle management tests
#
# Verifies core cell operations:
#   - brig run creates isolated container with gVisor
#   - brig stop gracefully terminates container
#   - brig kill immediately terminates container
#   - brig rm cleans up network and subnet
#   - brig list shows all cells with status
#   - brig logs streams container output
#   - Warden proxy integration (env vars, network connectivity)
#
# Usage: ./tests/test_cell_lifecycle.sh
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

# Cleanup test cells.
cleanup_test_cells() {
    echo "Cleaning up test cells..."
    run_in_vm sudo /usr/local/bin/brig rm -f test-cell-1 2>/dev/null || true
    run_in_vm sudo /usr/local/bin/brig rm -f test-cell-2 2>/dev/null || true
    run_in_vm sudo /usr/local/bin/brig rm -f test-lifecycle 2>/dev/null || true
}

echo "============================================"
echo "Cell Lifecycle Tests"
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

# Test 1: cell run creates container with gVisor.
echo "--- Test 1: cell run creates container with gVisor ---"
if run_in_vm sudo /usr/local/bin/brig run -d --name test-cell-1 alpine sleep 300 2>/dev/null; then
    log_pass "Cell started successfully"
else
    log_fail "Failed to start cell"
fi

# Test 2: Container runs with gVisor runtime.
echo
echo "--- Test 2: Container uses gVisor runtime ---"
# Check dmesg for gVisor signature since podman inspect shows "oci" not "runsc".
if run_in_vm sudo podman exec brig-test-cell-1 dmesg 2>/dev/null | grep -q "Starting gVisor"; then
    log_pass "Cell uses gVisor (runsc) runtime"
else
    log_fail "Cell not running with gVisor"
fi

# Test 3: Cell has isolated network.
echo
echo "--- Test 3: Cell has isolated internal network ---"
if run_in_vm sudo podman network exists brig-test-cell-1 2>/dev/null; then
    log_pass "Cell network exists"
else
    log_fail "Cell network not created"
fi

# Verify network is internal.
if run_in_vm sudo podman network inspect brig-test-cell-1 2>/dev/null | grep -q '"internal": true'; then
    log_pass "Cell network is internal"
else
    log_fail "Cell network is not internal"
fi

# Test 4: Proxy connected to cell network.
echo
echo "--- Test 4: Proxy connected to cell network ---"
if run_in_vm sudo podman inspect warden --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | grep -q "brig-test-cell-1"; then
    log_pass "Proxy connected to cell network"
else
    log_fail "Proxy not connected to cell network"
fi

# Test 5: Cell has proxy environment variables.
echo
echo "--- Test 5: Cell has proxy environment variables ---"
if run_in_vm sudo podman exec brig-test-cell-1 printenv http_proxy 2>/dev/null | grep -q "8080"; then
    log_pass "http_proxy env var set"
else
    log_fail "http_proxy env var not set"
fi

# Test 6: Cell can reach internet via proxy.
echo
echo "--- Test 6: Cell can reach allowed domain via proxy ---"
if run_in_vm sudo podman exec brig-test-cell-1 wget -q -O /dev/null --timeout=15 http://example.com 2>/dev/null; then
    log_pass "Cell can reach example.com via proxy"
else
    log_fail "Cell cannot reach internet via proxy"
fi

# Test 7: Cell cannot reach internet directly (without proxy).
echo
echo "--- Test 7: Cell cannot reach internet directly ---"
# Temporarily unset proxy and try direct connection.
if run_in_vm sudo podman exec brig-test-cell-1 sh -c 'unset http_proxy https_proxy; wget -q -O /dev/null --timeout=5 http://example.com' 2>/dev/null; then
    log_fail "Cell can reach internet directly (should be blocked)"
else
    log_pass "Cell correctly blocked from direct internet access"
fi

# Test 8: cell list shows the cell.
echo
echo "--- Test 8: cell list shows running cell ---"
LIST_OUTPUT=$(run_in_vm sudo /usr/local/bin/brig list 2>/dev/null)
if echo "$LIST_OUTPUT" | grep -q "test-cell-1"; then
    log_pass "brig list shows test-cell-1"
else
    log_fail "brig list missing test-cell-1"
fi

if echo "$LIST_OUTPUT" | grep -qi "running\|up"; then
    log_pass "brig list shows running status"
else
    log_fail "brig list not showing running status"
fi

# Test 9: cell stop gracefully stops container.
echo
echo "--- Test 9: cell stop gracefully stops container ---"
if run_in_vm sudo /usr/local/bin/brig stop test-cell-1 2>/dev/null; then
    log_pass "brig stop succeeded"
else
    log_fail "brig stop failed"
fi

# Verify container stopped.
sleep 1
STATUS=$(run_in_vm sudo podman inspect brig-test-cell-1 --format '{{.State.Status}}' 2>/dev/null || echo "removed")
if [ "$STATUS" = "exited" ] || [ "$STATUS" = "stopped" ]; then
    log_pass "Container is stopped"
else
    log_fail "Container not stopped, status: $STATUS"
fi

# Test 10: cell start restarts stopped cell.
echo
echo "--- Test 10: cell start restarts stopped cell ---"
if run_in_vm sudo /usr/local/bin/brig start test-cell-1 2>/dev/null; then
    log_pass "brig start succeeded"
else
    log_fail "brig start failed"
fi

sleep 1
STATUS=$(run_in_vm sudo podman inspect brig-test-cell-1 --format '{{.State.Status}}' 2>/dev/null || echo "unknown")
if [ "$STATUS" = "running" ]; then
    log_pass "Container is running again"
else
    log_fail "Container not running, status: $STATUS"
fi

# Test 11: cell kill immediately terminates.
echo
echo "--- Test 11: cell kill immediately terminates container ---"
if run_in_vm sudo /usr/local/bin/brig kill test-cell-1 2>/dev/null; then
    log_pass "brig kill succeeded"
else
    log_fail "brig kill failed"
fi

STATUS=$(run_in_vm sudo podman inspect brig-test-cell-1 --format '{{.State.Status}}' 2>/dev/null || echo "removed")
if [ "$STATUS" = "exited" ] || [ "$STATUS" = "stopped" ]; then
    log_pass "Container terminated immediately"
else
    log_fail "Container not terminated, status: $STATUS"
fi

# Test 12: cell rm cleans up everything.
echo
echo "--- Test 12: cell rm cleans up container, network, and subnet ---"
if run_in_vm sudo /usr/local/bin/brig rm test-cell-1 2>/dev/null; then
    log_pass "brig rm succeeded"
else
    log_fail "brig rm failed"
fi

# Verify container removed.
if run_in_vm sudo podman inspect brig-test-cell-1 2>/dev/null; then
    log_fail "Container still exists after rm"
else
    log_pass "Container removed"
fi

# Verify network removed.
if run_in_vm sudo podman network exists brig-test-cell-1 2>/dev/null; then
    log_fail "Network still exists after rm"
else
    log_pass "Network removed"
fi

# Verify subnet freed.
if run_in_vm sudo /usr/local/bin/brig-subnet get test-cell-1 2>/dev/null; then
    log_fail "Subnet still allocated after rm"
else
    log_pass "Subnet freed"
fi

# Test 13: Run second cell to verify isolation.
echo
echo "--- Test 13: Multiple cells are isolated from each other ---"
run_in_vm sudo /usr/local/bin/brig run -d --name test-cell-1 alpine sleep 300 2>/dev/null || true
run_in_vm sudo /usr/local/bin/brig run -d --name test-cell-2 alpine sleep 300 2>/dev/null || true
sleep 2

# Get cell-2's IP.
CELL2_IP=$(run_in_vm sudo podman inspect brig-test-cell-2 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null | head -1)

# Try to ping cell-2 from cell-1 (should fail - different networks).
if run_in_vm sudo podman exec brig-test-cell-1 ping -c1 -W2 "$CELL2_IP" 2>/dev/null; then
    log_fail "Cells can communicate (should be isolated)"
else
    log_pass "Cells are isolated from each other"
fi

# Test 14: cell logs shows output.
echo
echo "--- Test 14: cell logs shows container output ---"
# Run a cell that produces output.
# Use -- separator to prevent sh -c from being parsed as cell flags.
run_in_vm sudo /usr/local/bin/brig rm -f test-lifecycle 2>/dev/null || true
run_in_vm sudo /usr/local/bin/brig run -d --name test-lifecycle alpine -- sh -c 'echo hello_from_cell; sleep 60' 2>/dev/null || true
sleep 2

LOGS=$(run_in_vm sudo /usr/local/bin/brig logs test-lifecycle 2>/dev/null)
if echo "$LOGS" | grep -q "hello_from_cell"; then
    log_pass "brig logs shows container output"
else
    log_fail "brig logs not showing output: $LOGS"
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
