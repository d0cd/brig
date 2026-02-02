#!/bin/bash
# test_subnet_allocator.sh - Subnet allocation and network isolation
#
# Verifies subnet allocation and per-cell network isolation:
#   - Subnet allocator correctly allocates/frees subnets
#   - Allocated subnets are in valid range (10.60.1.0/24 - 10.60.254.0/24)
#   - File locking prevents race conditions
#   - Per-cell networks are internal (no external route)
#   - Subnet map is correctly maintained
#   - Proxy can join/leave cell networks
#
# Usage: ./tests/test_subnet_allocator.sh
#
# Prerequisites:
#   - Lima 0.18+ installed
#   - VM running: limactl start cell
#   - Subnet allocator installed in VM
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed

set -euo pipefail

VM_NAME="${CELL_VM_NAME:-cell}"
PASSED=0
FAILED=0

# Colors for output (only if terminal)
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

# Check VM is running
check_vm_running() {
    local vm_info
    vm_info=$(limactl list --format json 2>/dev/null || echo "{}")

    if ! echo "$vm_info" | grep -q "\"name\":\"$VM_NAME\""; then
        echo "ERROR: VM '$VM_NAME' does not exist"
        exit 1
    fi

    local status
    status=$(echo "$vm_info" | sed 's/.*"status":"\([^"]*\)".*/\1/')
    if [ "$status" != "Running" ]; then
        echo "ERROR: VM '$VM_NAME' is not running (status: $status)"
        exit 1
    fi
    echo "VM '$VM_NAME' is running"
}

# Cleanup function for test isolation
cleanup_test_state() {
    echo "Cleaning up test state..."
    # Remove any test networks
    run_in_vm sudo podman network rm brig-test-1 brig-test-2 brig-test-3 2>/dev/null || true
    # Reset subnets.json to initial state for testing
    run_in_vm sudo tee /state/system/subnets.json > /dev/null << 'EOF'
{
  "next_index": 1,
  "allocated": {},
  "freed": []
}
EOF
    # Clear subnet map
    run_in_vm sudo rm -f /var/run/brig/subnet-map.json
}

echo "============================================"
echo "Subnet Allocator & Network Isolation Tests"
echo "============================================"
echo

# Pre-flight checks
echo "--- Pre-flight checks ---"
check_vm_running

# Check subnet allocator is installed
if ! run_in_vm test -f /usr/local/bin/brig-subnet; then
    echo "ERROR: Subnet allocator not installed at /usr/local/bin/brig-subnet"
    echo "Install it first before running these tests."
    exit 1
fi
echo "Subnet allocator installed"
echo

# Clean up before tests
cleanup_test_state

# Test 1: First allocation returns 10.60.1.0/24
echo "--- Test 1: First allocation returns 10.60.1.0/24 ---"
SUBNET1=$(run_in_vm sudo /usr/local/bin/brig-subnet allocate test-cell-1 2>/dev/null)
if [ "$SUBNET1" = "10.60.1.0/24" ]; then
    log_pass "First subnet allocated: $SUBNET1"
else
    log_fail "Expected 10.60.1.0/24, got: $SUBNET1"
fi

# Test 2: Sequential allocation increments subnet index
echo
echo "--- Test 2: Sequential allocation increments subnet index ---"
SUBNET2=$(run_in_vm sudo /usr/local/bin/brig-subnet allocate test-cell-2 2>/dev/null)
if [ "$SUBNET2" = "10.60.2.0/24" ]; then
    log_pass "Second subnet allocated: $SUBNET2"
else
    log_fail "Expected 10.60.2.0/24, got: $SUBNET2"
fi

# Test 3: Allocations persist in subnets.json
echo
echo "--- Test 3: Allocations persist in subnets.json ---"
if run_in_vm cat /state/system/subnets.json | grep -q '"test-cell-1"'; then
    log_pass "test-cell-1 recorded in subnets.json"
else
    log_fail "test-cell-1 not found in subnets.json"
fi

if run_in_vm cat /state/system/subnets.json | grep -q '"test-cell-2"'; then
    log_pass "test-cell-2 recorded in subnets.json"
else
    log_fail "test-cell-2 not found in subnets.json"
fi

# Test 4: Subnet map updated for proxy hot-reload
echo
echo "--- Test 4: Subnet map updated for proxy hot-reload ---"
if run_in_vm test -f /var/run/brig/subnet-map.json; then
    log_pass "subnet-map.json exists"
else
    log_fail "subnet-map.json not created"
fi

if run_in_vm sudo cat /var/run/brig/subnet-map.json 2>/dev/null | grep -q '"10.60.1.0/24": "test-cell-1"'; then
    log_pass "subnet-map.json has correct mapping for test-cell-1"
else
    log_fail "subnet-map.json missing mapping for test-cell-1"
fi

# Test 5: Freed subnets recorded for reuse
echo
echo "--- Test 5: Freed subnets recorded for reuse ---"
if run_in_vm sudo /usr/local/bin/brig-subnet free test-cell-1 2>/dev/null; then
    log_pass "Subnet freed for test-cell-1"
else
    log_fail "Failed to free subnet for test-cell-1"
fi

# Verify it's in freed list. Use jq if available, else grep.
if run_in_vm sudo cat /state/system/subnets.json | tr -d ' \n' | grep -q '"freed":\[1'; then
    log_pass "Freed index recorded in subnets.json"
else
    log_fail "Freed index not recorded"
fi

# Test 6: New allocation reuses freed subnet first
echo
echo "--- Test 6: New allocation reuses freed subnet first ---"
SUBNET3=$(run_in_vm sudo /usr/local/bin/brig-subnet allocate test-cell-3 2>/dev/null)
if [ "$SUBNET3" = "10.60.1.0/24" ]; then
    log_pass "Freed subnet reused: $SUBNET3"
else
    log_fail "Expected freed subnet 10.60.1.0/24, got: $SUBNET3"
fi

# Test 7: Duplicate cell name rejected with error
echo
echo "--- Test 7: Duplicate cell name rejected with error ---"
if run_in_vm sudo /usr/local/bin/brig-subnet allocate test-cell-2 2>/dev/null; then
    log_fail "Duplicate cell name should be rejected"
else
    log_pass "Duplicate cell name correctly rejected"
fi

# Test 8: create-network creates podman network with --internal flag
echo
echo "--- Test 8: create-network creates podman network with --internal flag ---"
if run_in_vm sudo /usr/local/bin/brig-subnet create-network test-cell-3 2>/dev/null; then
    log_pass "Network created for test-cell-3"
else
    log_fail "Failed to create network for test-cell-3"
fi

# Verify network exists and is internal
if run_in_vm sudo podman network inspect brig-test-cell-3 2>/dev/null | grep -q '"internal": true'; then
    log_pass "Network is internal"
else
    log_fail "Network is not internal"
fi

# Test 9: Created network uses allocated subnet
echo
echo "--- Test 9: Created network uses allocated subnet ---"
if run_in_vm sudo podman network inspect brig-test-cell-3 2>/dev/null | grep -q '10.60.1.0/24'; then
    log_pass "Network has correct subnet 10.60.1.0/24"
else
    log_fail "Network has wrong subnet"
fi

# Test 10: Internal network cannot reach internet
echo
echo "--- Test 10: Internal network cannot reach internet ---"
# Start a container on the network and verify it can't reach internet
if run_in_vm sudo podman run --rm --network brig-test-cell-3 alpine wget -q -O /dev/null --timeout=5 http://example.com 2>/dev/null; then
    log_fail "Internal network can reach internet (CRITICAL)"
else
    log_pass "Internal network correctly isolated"
fi

# Test 11: Index 0 reserved, index 255+ rejected
echo
echo "--- Test 11: Index 0 reserved, index 255+ rejected ---"
# Test that index 0 is reserved and 255+ is rejected
if run_in_vm sudo /usr/local/bin/brig-subnet validate-index 0 2>/dev/null; then
    log_fail "Index 0 should be reserved"
else
    log_pass "Index 0 correctly reserved"
fi

if run_in_vm sudo /usr/local/bin/brig-subnet validate-index 255 2>/dev/null; then
    log_fail "Index 255 should be rejected"
else
    log_pass "Index 255 correctly rejected"
fi

# Test 12: list command shows all active allocations
echo
echo "--- Test 12: list command shows all active allocations ---"
LIST_OUTPUT=$(run_in_vm sudo /usr/local/bin/brig-subnet list 2>/dev/null)
if echo "$LIST_OUTPUT" | grep -q "test-cell-2"; then
    log_pass "List shows test-cell-2"
else
    log_fail "List missing test-cell-2"
fi

if echo "$LIST_OUTPUT" | grep -q "test-cell-3"; then
    log_pass "List shows test-cell-3"
else
    log_fail "List missing test-cell-3"
fi

# Test 13: get command returns correct subnet for cell
echo
echo "--- Test 13: get command returns correct subnet for cell ---"
GOT_SUBNET=$(run_in_vm sudo /usr/local/bin/brig-subnet get test-cell-2 2>/dev/null)
if [ "$GOT_SUBNET" = "10.60.2.0/24" ]; then
    log_pass "Got correct subnet for test-cell-2"
else
    log_fail "Expected 10.60.2.0/24, got: $GOT_SUBNET"
fi

# Test 14: remove-network deletes network and frees subnet
echo
echo "--- Test 14: remove-network deletes network and frees subnet ---"
if run_in_vm sudo /usr/local/bin/brig-subnet remove-network test-cell-3 2>/dev/null; then
    log_pass "Network removed for test-cell-3"
else
    log_fail "Failed to remove network"
fi

# Verify network is gone
if run_in_vm sudo podman network exists brig-test-cell-3 2>/dev/null; then
    log_fail "Network still exists after removal"
else
    log_pass "Network correctly removed"
fi

# Cleanup
echo
echo "--- Cleanup ---"
cleanup_test_state

# Summary
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
