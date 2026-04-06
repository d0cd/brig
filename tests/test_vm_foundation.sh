#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_vm_foundation.sh - VM infrastructure verification
#
# Verifies the base infrastructure is correctly configured:
#   - macOS directory structure exists
#   - VM mounts are present and secured
#   - Podman and gVisor installed and working
#   - Network isolation (east-west blocked, internal isolated, external connected)
#   - Egress firewall configured
#   - Subnet allocator state initialized
#
# Usage: ./tests/test_vm_foundation.sh
#
# Prerequisites:
#   - Lima 0.18+ installed
#   - VM created: limactl start ~/.brig/lima.yaml --name=cell
#   - VM running: limactl start cell
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

log_skip() {
    echo -e "${YELLOW}SKIP${NC}: $1"
}

run_in_vm() {
    limactl shell "$VM_NAME" -- "$@"
}

# Check Lima is installed
check_lima() {
    if ! command -v limactl &> /dev/null; then
        echo "ERROR: limactl not found. Install with: brew install lima"
        exit 1
    fi

    local version
    version=$(limactl --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    if [ "$major" -eq 0 ] && [ "$minor" -lt 18 ]; then
        echo "ERROR: Lima version $version is too old. Need 0.18+"
        exit 1
    fi
    echo "Lima version: $version"
}

# Check VM is running
check_vm_running() {
    local vm_info
    vm_info=$(limactl list --format json 2>/dev/null || echo "{}")

    if ! echo "$vm_info" | grep -q "\"name\":\"$VM_NAME\""; then
        echo "ERROR: VM '$VM_NAME' does not exist"
        echo "Create it with: limactl start ~/.brig/lima.yaml --name=$VM_NAME"
        exit 1
    fi

    local status
    # Parse status from JSON - handle both single object and array formats
    status=$(echo "$vm_info" | sed 's/.*"status":"\([^"]*\)".*/\1/')
    if [ "$status" != "Running" ]; then
        echo "ERROR: VM '$VM_NAME' is not running (status: $status)"
        echo "Start it with: limactl start $VM_NAME"
        exit 1
    fi
    echo "VM '$VM_NAME' is running"
}

echo "============================================"
echo "VM Foundation Tests"
echo "============================================"
echo

# Pre-flight checks
echo "--- Pre-flight checks ---"
check_lima
check_vm_running
echo

# Test 1: Directory structure on macOS
echo "--- Test 1: macOS directory structure ---"
if [ -d "$HOME/.brig" ] && [ -d "$HOME/.brig/cells" ] && [ -d "$HOME/.brig/secrets" ] && [ -d "$HOME/.brig/state" ]; then
    log_pass "Directory structure exists"
else
    log_fail "Missing directories in ~/.brig/"
fi

if [ -f "$HOME/.brig/lima.yaml" ]; then
    log_pass "lima.yaml exists"
else
    log_fail "lima.yaml missing"
fi

# Test 2: Mounts are present in VM
echo
echo "--- Test 2: VM mounts ---"
if run_in_vm test -d /state; then
    log_pass "/state mount exists"
else
    log_fail "/state mount missing"
fi

if run_in_vm test -d /secrets; then
    log_pass "/secrets mount exists"
else
    log_fail "/secrets mount missing"
fi

if run_in_vm test -d /cells; then
    log_pass "/cells mount exists"
else
    log_fail "/cells mount missing"
fi

# Test 3: /cells mount has noexec
echo
echo "--- Test 3: /cells mount security ---"
if run_in_vm mount | grep '/cells' | grep -q 'noexec'; then
    log_pass "/cells mounted with noexec"
else
    log_fail "/cells not mounted with noexec"
fi

# Test 4: Podman installed
echo
echo "--- Test 4: Podman ---"
if run_in_vm command -v podman &> /dev/null; then
    log_pass "Podman installed"
else
    log_fail "Podman not installed"
fi

# Test 5: gVisor installed
echo
echo "--- Test 5: gVisor ---"
if run_in_vm command -v runsc &> /dev/null; then
    log_pass "runsc installed"
else
    log_fail "runsc not installed"
fi

# Test 6: gVisor is default runtime
echo
echo "--- Test 6: gVisor default runtime ---"
if run_in_vm test -f /etc/containers/containers.conf.d/gvisor.conf; then
    log_pass "gVisor config exists"
else
    log_fail "gVisor config missing"
fi

if run_in_vm grep -q 'runtime = "runsc"' /etc/containers/containers.conf.d/gvisor.conf 2>/dev/null; then
    log_pass "gVisor set as default runtime"
else
    log_fail "gVisor not set as default runtime"
fi

# Test 7: IPv6 disabled
echo
echo "--- Test 7: IPv6 disabled ---"
if run_in_vm sysctl net.ipv6.conf.all.disable_ipv6 | grep -q '= 1'; then
    log_pass "IPv6 disabled"
else
    log_fail "IPv6 not disabled"
fi

# Test 8: proxy-external network exists
echo
echo "--- Test 8: proxy-external network ---"
if run_in_vm sudo podman network exists proxy-external; then
    log_pass "proxy-external network exists"
else
    log_fail "proxy-external network missing"
fi

# Test 9: proxy-external has correct subnet
echo
echo "--- Test 9: proxy-external subnet ---"
if run_in_vm sudo podman network inspect proxy-external 2>/dev/null | grep -q '10.51.0.0/24'; then
    log_pass "proxy-external has correct subnet (10.51.0.0/24)"
else
    log_fail "proxy-external has wrong subnet"
fi

# Test 10: PROXY_EGRESS iptables chain exists
echo
echo "--- Test 10: Egress firewall ---"
if run_in_vm sudo iptables -L PROXY_EGRESS -n &> /dev/null; then
    log_pass "PROXY_EGRESS chain exists"
else
    log_fail "PROXY_EGRESS chain missing"
fi

# Test 11: Runtime directories exist
echo
echo "--- Test 11: Runtime directories ---"
if run_in_vm test -d /var/run/brig; then
    log_pass "/var/run/brig exists"
else
    log_fail "/var/run/brig missing"
fi

if run_in_vm test -d /var/log/brig/network; then
    log_pass "/var/log/brig/network exists"
else
    log_fail "/var/log/brig/network missing"
fi

# Test 12: Subnet allocator state exists
echo
echo "--- Test 12: Subnet allocator state ---"
if run_in_vm test -f /state/system/subnets.json; then
    log_pass "subnets.json exists"
else
    log_fail "subnets.json missing"
fi

if run_in_vm cat /state/system/subnets.json | grep -q '"next_index"'; then
    log_pass "subnets.json has valid structure"
else
    log_fail "subnets.json has invalid structure"
fi

# Test 13: East-west isolation
echo
echo "--- Test 13: East-west isolation ---"
echo "Creating test networks..."
run_in_vm sudo podman network create --internal test-net-a-verify 2>/dev/null || true
run_in_vm sudo podman network create --internal test-net-b-verify 2>/dev/null || true

echo "Starting test container on network A..."
run_in_vm sudo podman run --rm -d --network test-net-a-verify --name test-a-verify alpine sleep 30 2>/dev/null || true

echo "Testing if container on network B can reach container on network A..."
if run_in_vm sudo podman run --rm --network test-net-b-verify alpine ping -c1 -W2 test-a-verify 2>/dev/null; then
    log_fail "East-west traffic allowed (CRITICAL)"
else
    log_pass "East-west traffic blocked"
fi

# Cleanup
run_in_vm sudo podman rm -f test-a-verify 2>/dev/null || true
run_in_vm sudo podman network rm test-net-a-verify test-net-b-verify 2>/dev/null || true

# Test 14: Internal network has no internet
echo
echo "--- Test 14: Internal network isolation ---"
run_in_vm sudo podman network create --internal test-internal-verify 2>/dev/null || true

echo "Testing if internal network can reach internet..."
if run_in_vm sudo podman run --rm --network test-internal-verify alpine wget -q -O /dev/null --timeout=5 http://example.com 2>/dev/null; then
    log_fail "Internal network can reach internet (CRITICAL)"
else
    log_pass "Internal network isolated from internet"
fi

run_in_vm sudo podman network rm test-internal-verify 2>/dev/null || true

# Test 15: External network has internet
echo
echo "--- Test 15: External network connectivity ---"
echo "Testing if proxy-external network can reach internet..."
if run_in_vm sudo podman run --rm --network proxy-external alpine wget -q -O /dev/null --timeout=10 http://example.com 2>/dev/null; then
    log_pass "proxy-external can reach internet"
else
    log_fail "proxy-external cannot reach internet"
fi

# Test 16: gVisor runtime works
echo
echo "--- Test 16: gVisor runtime functional ---"
echo "Running container with gVisor..."
# gVisor shows "Starting gVisor..." in dmesg, not in /proc/version
if run_in_vm sudo podman run --rm --runtime=runsc alpine dmesg 2>/dev/null | grep -qi "starting gvisor"; then
    log_pass "gVisor runtime is functional"
else
    log_fail "gVisor runtime not working"
fi

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
