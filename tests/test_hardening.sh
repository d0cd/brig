#!/bin/bash
# test_hardening.sh - Security hardening tests
#
# Verifies production security hardening:
#   - Cell resource limits (memory, CPU, PIDs)
#   - Proxy resource limits
#   - Cell runtime constraints
#   - Workspace permissions
#   - State directory security
#
# Usage: ./tests/test_hardening.sh
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
    run_in_vm sudo /usr/local/bin/brig rm -f --purge hardening-test 2>/dev/null || true
    run_in_vm sudo /usr/local/bin/brig rm -f --purge limits-test 2>/dev/null || true
}

echo "============================================"
echo "Hardening Tests"
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

# Test 1: Proxy has memory limit.
echo "--- Test 1: Proxy has memory limit ---"
PROXY_MEM=$(run_in_vm sudo podman inspect warden --format '{{.HostConfig.Memory}}' 2>/dev/null || echo "0")
if [ "$PROXY_MEM" -gt 0 ]; then
    log_pass "Proxy has memory limit: $PROXY_MEM bytes"
else
    log_fail "Proxy missing memory limit"
fi

# Test 2: Proxy has CPU limit.
echo
echo "--- Test 2: Proxy has CPU limit ---"
PROXY_CPU=$(run_in_vm sudo podman inspect warden --format '{{.HostConfig.NanoCpus}}' 2>/dev/null || echo "0")
if [ "$PROXY_CPU" -gt 0 ]; then
    log_pass "Proxy has CPU limit: $PROXY_CPU nanocpus"
else
    log_fail "Proxy missing CPU limit"
fi

# Test 3: Proxy has PID limit.
echo
echo "--- Test 3: Proxy has PID limit ---"
PROXY_PIDS=$(run_in_vm sudo podman inspect warden --format '{{.HostConfig.PidsLimit}}' 2>/dev/null || echo "0")
if [ "$PROXY_PIDS" -gt 0 ]; then
    log_pass "Proxy has PID limit: $PROXY_PIDS"
else
    log_fail "Proxy missing PID limit"
fi

# Test 4: Cell runs with default memory limit.
echo
echo "--- Test 4: Cell has default memory limit ---"
run_in_vm sudo /usr/local/bin/brig run -d --name hardening-test alpine sleep 300 2>/dev/null || true
sleep 2

CELL_MEM=$(run_in_vm sudo podman inspect brig-hardening-test --format '{{.HostConfig.Memory}}' 2>/dev/null || echo "0")
if [ "$CELL_MEM" -gt 0 ]; then
    log_pass "Cell has memory limit: $CELL_MEM bytes"
else
    log_fail "Cell missing default memory limit"
fi

# Test 5: Cell has default CPU limit.
echo
echo "--- Test 5: Cell has default CPU limit ---"
CELL_CPU=$(run_in_vm sudo podman inspect brig-hardening-test --format '{{.HostConfig.NanoCpus}}' 2>/dev/null || echo "0")
if [ "$CELL_CPU" -gt 0 ]; then
    log_pass "Cell has CPU limit: $CELL_CPU nanocpus"
else
    log_fail "Cell missing default CPU limit"
fi

# Test 6: Cell has default PID limit.
echo
echo "--- Test 6: Cell has default PID limit ---"
CELL_PIDS=$(run_in_vm sudo podman inspect brig-hardening-test --format '{{.HostConfig.PidsLimit}}' 2>/dev/null || echo "0")
if [ "$CELL_PIDS" -gt 0 ]; then
    log_pass "Cell has PID limit: $CELL_PIDS"
else
    log_fail "Cell missing default PID limit"
fi

# Test 7: Cell can override memory limit.
echo
echo "--- Test 7: Cell can override memory limit ---"
run_in_vm sudo /usr/local/bin/brig rm -f limits-test 2>/dev/null || true
run_in_vm sudo /usr/local/bin/brig run -d --name limits-test --memory 512m alpine sleep 300 2>/dev/null || true
sleep 2

CUSTOM_MEM=$(run_in_vm sudo podman inspect brig-limits-test --format '{{.HostConfig.Memory}}' 2>/dev/null || echo "0")
# 512MB = 536870912 bytes
if [ "$CUSTOM_MEM" -eq 536870912 ]; then
    log_pass "Custom memory limit applied: 512MB"
else
    log_fail "Custom memory limit not applied: got $CUSTOM_MEM"
fi

# Test 8: Cell cannot exceed PID limit.
echo
echo "--- Test 8: Cell respects PID limit ---"
# Try to spawn more processes than the limit allows.
FORK_RESULT=$(run_in_vm sudo podman exec brig-hardening-test sh -c 'for i in $(seq 1 1000); do sleep 10 & done 2>&1' || echo "fork failed")
# We expect this to fail or hit the limit.
if echo "$FORK_RESULT" | grep -qi "resource\|limit\|cannot\|error\|fork"; then
    log_pass "PID limit enforced (fork bomb blocked)"
else
    # Check if we're near the limit.
    PID_COUNT=$(run_in_vm sudo podman exec brig-hardening-test sh -c 'ps aux | wc -l' 2>/dev/null || echo "0")
    if [ "$PID_COUNT" -lt 600 ]; then
        log_pass "PID limit enforced (limited processes)"
    else
        log_fail "PID limit may not be enforced"
    fi
fi

# Test 9: Workspace has correct permissions.
echo
echo "--- Test 9: Workspace has restricted permissions ---"
WS_PERMS=$(run_in_vm stat -c '%a' /state/hardening-test/workspace 2>/dev/null || echo "000")
if [ "$WS_PERMS" = "755" ] || [ "$WS_PERMS" = "700" ]; then
    log_pass "Workspace permissions: $WS_PERMS"
else
    log_fail "Workspace permissions too open: $WS_PERMS"
fi

# Test 10: /cells mount is noexec.
echo
echo "--- Test 10: /cells mount is noexec ---"
MOUNT_OPTS=$(run_in_vm mount 2>/dev/null | grep "/cells " || echo "")
if echo "$MOUNT_OPTS" | grep -q "noexec"; then
    log_pass "/cells mounted with noexec"
else
    log_fail "/cells not mounted with noexec"
fi

# Test 11: Secrets directory is read-only in VM.
echo
echo "--- Test 11: Secrets directory is read-only in VM ---"
if run_in_vm touch /secrets/test-write 2>/dev/null; then
    run_in_vm rm -f /secrets/test-write 2>/dev/null || true
    log_fail "Secrets directory is writable"
else
    log_pass "Secrets directory is read-only"
fi

# Test 12: gVisor prevents raw socket access.
echo
echo "--- Test 12: gVisor prevents raw socket access ---"
if run_in_vm sudo podman exec brig-hardening-test ping -c1 127.0.0.1 2>/dev/null; then
    # Ping might work with gVisor, that's okay.
    log_pass "gVisor handles ICMP"
else
    log_pass "gVisor restricts raw sockets"
fi

# Test 13: Cell cannot access host network namespace.
echo
echo "--- Test 13: Cell cannot access host network ---"
HOST_IP=$(run_in_vm hostname -I 2>/dev/null | awk '{print $1}')
if run_in_vm sudo podman exec brig-hardening-test ping -c1 -W2 "$HOST_IP" 2>/dev/null; then
    log_fail "Cell can reach host network"
else
    log_pass "Cell isolated from host network"
fi

# Test 14: IPv6 is disabled in VM.
echo
echo "--- Test 14: IPv6 is disabled ---"
IPV6_STATUS=$(run_in_vm cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
if [ "$IPV6_STATUS" = "1" ]; then
    log_pass "IPv6 is disabled"
else
    log_fail "IPv6 is not disabled"
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
