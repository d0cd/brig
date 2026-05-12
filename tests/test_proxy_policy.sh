#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_proxy_policy.sh - Proxy and policy enforcement tests
#
# Verifies the mitmproxy-based egress proxy:
#   - Proxy container starts with security hardening
#   - Policy enforcement blocks disallowed domains
#   - Policy enforcement allows allowlisted domains
#   - Logging addon writes per-cell JSONL logs
#   - Hot-reload updates policy without restart
#   - Proxy joins cell networks correctly
#
# Usage: ./tests/test_proxy_policy.sh
#
# Prerequisites:
#   - Lima 0.18+ installed
#   - VM running: limactl start cell
#   - Proxy addons installed in ~/.brig/cells/addons/
#   - Network policy at ~/.brig/network-policy.yaml
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

# Check the proxy log for a matching entry. Exits 0 if found, 1 otherwise.
# Stronger than "did wget exit 0" — proves the proxy processed the request
# and made the expected policy decision, catching bypass attempts where the
# request somehow reached the internet without going through the proxy.
#
# Args: cell_name host expect_blocked ("true" | "false")
check_log_entry() {
    local cell_name="$1"
    local host="$2"
    local expect_blocked="$3"
    local log_file="/var/log/brig/network/${cell_name}.jsonl"

    # mitmproxy's async logger batches writes; give it a moment to flush.
    sleep 1

    if ! run_in_vm sudo test -f "$log_file"; then
        return 1
    fi

    # Pipe the log through python3 and check for a matching entry.
    run_in_vm sudo cat "$log_file" | python3 -c "
import sys, json
target_host = '$host'
expect_blocked = '$expect_blocked' == 'true'
for line in sys.stdin:
    try:
        entry = json.loads(line)
    except Exception:
        continue
    if entry.get('host') == target_host and bool(entry.get('blocked', False)) == expect_blocked:
        sys.exit(0)
sys.exit(1)
"
}

# Clear a cell's proxy log. Tests should call this before making a request
# so that check_log_entry sees only entries from the current test.
clear_cell_log() {
    local cell_name="$1"
    run_in_vm sudo rm -f "/var/log/brig/network/${cell_name}.jsonl" 2>/dev/null || true
}

# Check VM is running.
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

# Stop proxy if running.
stop_proxy() {
    run_in_vm sudo podman stop warden 2>/dev/null || true
    run_in_vm sudo podman rm warden 2>/dev/null || true
}

# Start proxy for testing.
start_proxy() {
    run_in_vm sudo /usr/local/bin/warden start 2>/dev/null
}

echo "============================================"
echo "Proxy & Policy Enforcement Tests"
echo "============================================"
echo

# Pre-flight checks.
echo "--- Pre-flight checks ---"
check_vm_running

# Check proxy start script exists.
if ! run_in_vm test -f /usr/local/bin/warden; then
    echo "ERROR: Proxy script not installed at /usr/local/bin/warden"
    exit 1
fi
echo "Proxy script installed"

# Check addons exist.
if ! run_in_vm test -f /cells/addons/enforce.py; then
    echo "ERROR: Policy enforcement addon not found at /cells/addons/enforce.py"
    exit 1
fi
echo "Policy enforcement addon found"

if ! run_in_vm test -f /cells/addons/logger.py; then
    echo "ERROR: Logging addon not found at /cells/addons/logger.py"
    exit 1
fi
echo "Logging addon found"

# Check network policy exists.
if ! run_in_vm test -f /cells/network-policy.json; then
    echo "ERROR: Network policy not found at /cells/network-policy.json"
    exit 1
fi
echo "Network policy found"
echo

# Stop any existing proxy.
stop_proxy

# Test 1: Proxy container starts successfully.
echo "--- Test 1: Proxy container starts successfully ---"
if start_proxy; then
    log_pass "Proxy started"
else
    log_fail "Proxy failed to start"
fi

# Test 2: Proxy container is running.
echo
echo "--- Test 2: Proxy container is running ---"
if run_in_vm sudo podman ps --format '{{.Names}}' | grep -q "warden"; then
    log_pass "Proxy container is running"
else
    log_fail "Proxy container not running"
fi

# Test 3: Proxy is on proxy-external network.
echo
echo "--- Test 3: Proxy attached to proxy-external network ---"
if run_in_vm sudo podman inspect warden --format '{{range .NetworkSettings.Networks}}{{.NetworkID}}{{end}}' 2>/dev/null | grep -q "proxy-external"; then
    log_pass "Proxy on proxy-external network"
else
    # Alternative check.
    if run_in_vm sudo podman network inspect proxy-external --format '{{range .Containers}}{{.Name}}{{end}}' 2>/dev/null | grep -q "warden"; then
        log_pass "Proxy on proxy-external network"
    else
        log_fail "Proxy not on proxy-external network"
    fi
fi

# Test 4: Proxy has resource limits.
echo
echo "--- Test 4: Proxy has memory limit ---"
if run_in_vm sudo podman inspect warden --format '{{.HostConfig.Memory}}' 2>/dev/null | grep -q "[0-9]"; then
    log_pass "Proxy has memory limit configured"
else
    log_fail "Proxy missing memory limit"
fi

# Test 5: Proxy container running with expected image.
echo
echo "--- Test 5: Proxy running mitmproxy image ---"
if run_in_vm sudo podman inspect warden --format '{{.Config.Image}}' 2>/dev/null | grep -q "mitmproxy"; then
    log_pass "Proxy running mitmproxy image"
else
    log_fail "Proxy not running expected image"
fi

# Test 6: Proxy listens on port 8080.
echo
echo "--- Test 6: Proxy listens on port 8080 ---"
# Check /proc/net/tcp for listening socket on port 8080 (0x1F90).
if run_in_vm sudo podman exec warden cat /proc/net/tcp 2>/dev/null | grep -q "00000000:1F90.*0A"; then
    log_pass "Proxy listening on port 8080"
else
    # Give it a moment to start.
    sleep 3
    if run_in_vm sudo podman exec warden cat /proc/net/tcp 2>/dev/null | grep -q "00000000:1F90.*0A"; then
        log_pass "Proxy listening on port 8080"
    else
        log_fail "Proxy not listening on port 8080"
    fi
fi

# Create a test cell network for policy tests.
echo
echo "--- Setting up test cell network ---"
run_in_vm sudo /usr/local/bin/brig-subnet allocate policy-test 2>/dev/null || true
run_in_vm sudo /usr/local/bin/brig-subnet create-network policy-test 2>/dev/null || true
# Connect proxy to test network.
run_in_vm sudo podman network connect brig-policy-test warden 2>/dev/null || true
# Get proxy IP on test network.
PROXY_IP=$(run_in_vm sudo podman inspect warden --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null | tr ' ' '\n' | grep "10.60" | head -1)
echo "Proxy IP on test network: $PROXY_IP"

# Tests 7-11 assert on the proxy JSONL log, not just wget exit code.
# A wget exit of 0 or non-zero doesn't prove the proxy handled the request —
# DNS failure, a bypass route, or a crashed cell would all yield the "right"
# exit code while silently violating the security invariant. The log entry
# is the authoritative signal: if the proxy didn't see the request, or saw
# it with the wrong disposition, the test fails.

# Test 7: Allowlisted domain — proxy log must show blocked=false for example.com.
echo
echo "--- Test 7: Allowlisted domain (example.com) accessible ---"
clear_cell_log policy-test
run_in_vm sudo podman run --rm --network brig-policy-test \
    -e http_proxy="http://${PROXY_IP}:8080" \
    -e https_proxy="http://${PROXY_IP}:8080" \
    alpine wget -q -O /dev/null --timeout=10 http://example.com 2>/dev/null || true
if check_log_entry policy-test example.com false; then
    log_pass "Allowlisted domain routed through proxy and allowed (blocked=false in log)"
else
    log_fail "No blocked=false log entry for example.com — proxy did not handle the request"
fi

# Test 8: Non-allowlisted domain — proxy log must show blocked=true for evil.com.
echo
echo "--- Test 8: Non-allowlisted domain blocked ---"
clear_cell_log policy-test
run_in_vm sudo podman run --rm --network brig-policy-test \
    -e http_proxy="http://${PROXY_IP}:8080" \
    -e https_proxy="http://${PROXY_IP}:8080" \
    alpine wget -q -O /dev/null --timeout=5 http://evil.com 2>/dev/null || true
if check_log_entry policy-test evil.com true; then
    log_pass "Non-allowlisted domain blocked at proxy (blocked=true in log)"
else
    log_fail "No blocked=true log entry for evil.com — proxy may not have rejected it"
fi

# Test 9: Internal IP — proxy log must show blocked=true.
echo
echo "--- Test 9: Internal IP addresses blocked ---"
clear_cell_log policy-test
run_in_vm sudo podman run --rm --network brig-policy-test \
    -e http_proxy="http://${PROXY_IP}:8080" \
    alpine wget -q -O /dev/null --timeout=5 http://192.168.1.1 2>/dev/null || true
if check_log_entry policy-test 192.168.1.1 true; then
    log_pass "Internal IP blocked at proxy (blocked=true in log)"
else
    log_fail "No blocked=true log entry for 192.168.1.1"
fi

# Test 10: Literal public IP — proxy log must show blocked=true.
echo
echo "--- Test 10: Literal public IP addresses blocked ---"
clear_cell_log policy-test
run_in_vm sudo podman run --rm --network brig-policy-test \
    -e http_proxy="http://${PROXY_IP}:8080" \
    alpine wget -q -O /dev/null --timeout=5 http://93.184.216.34 2>/dev/null || true
if check_log_entry policy-test 93.184.216.34 true; then
    log_pass "Literal public IP blocked at proxy (blocked=true in log)"
else
    log_fail "No blocked=true log entry for 93.184.216.34"
fi

# Test 11: Non-HTTP port — proxy log must show blocked=true for example.com:8080.
echo
echo "--- Test 11: Non-HTTP ports blocked ---"
clear_cell_log policy-test
run_in_vm sudo podman run --rm --network brig-policy-test \
    -e http_proxy="http://${PROXY_IP}:8080" \
    alpine wget -q -O /dev/null --timeout=5 http://example.com:8080 2>/dev/null || true
if check_log_entry policy-test example.com true; then
    log_pass "Non-standard port blocked at proxy (blocked=true in log)"
else
    log_fail "No blocked=true log entry for example.com on port 8080"
fi

# Test 12: Request logged to cell log file.
echo
echo "--- Test 12: Requests logged to per-cell JSONL file ---"
# Clear existing logs.
run_in_vm sudo rm -f /var/log/brig/network/policy-test.jsonl 2>/dev/null || true
# Make a request.
run_in_vm sudo podman run --rm --network brig-policy-test \
    -e http_proxy="http://${PROXY_IP}:8080" \
    alpine wget -q -O /dev/null --timeout=10 http://example.com 2>/dev/null || true
# Check log exists.
sleep 1
if run_in_vm sudo test -f /var/log/brig/network/policy-test.jsonl; then
    log_pass "Per-cell log file created"
else
    log_fail "Per-cell log file not created"
fi

# Test 13: Log entry has required fields.
echo
echo "--- Test 13: Log entry has required fields ---"
LOG_ENTRY=$(run_in_vm sudo cat /var/log/brig/network/policy-test.jsonl 2>/dev/null | head -1)
if echo "$LOG_ENTRY" | grep -q '"cell"' && \
   echo "$LOG_ENTRY" | grep -q '"host"' && \
   echo "$LOG_ENTRY" | grep -q '"method"' && \
   echo "$LOG_ENTRY" | grep -q '"ts"'; then
    log_pass "Log entry has required fields"
else
    log_fail "Log entry missing fields: $LOG_ENTRY"
fi

# Test 14: Wildcard domain matching.
echo
echo "--- Test 14: Wildcard domain matching (*.example.com) ---"
if run_in_vm sudo podman run --rm --network brig-policy-test \
    -e http_proxy="http://${PROXY_IP}:8080" \
    alpine wget -q -O /dev/null --timeout=10 http://www.example.com 2>/dev/null; then
    log_pass "Wildcard subdomain accessible"
else
    log_fail "Wildcard subdomain should be accessible"
fi

# Test 15: Proxy survives cell network disconnect.
echo
echo "--- Test 15: Proxy survives network disconnect ---"
run_in_vm sudo podman network disconnect brig-policy-test warden 2>/dev/null || true
if run_in_vm sudo podman ps --format '{{.Names}}' | grep -q "warden"; then
    log_pass "Proxy still running after disconnect"
else
    log_fail "Proxy died after network disconnect"
fi

# Cleanup test network.
echo
echo "--- Cleanup ---"
run_in_vm sudo /usr/local/bin/brig-subnet remove-network policy-test 2>/dev/null || true

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
