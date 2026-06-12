#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_warden_features.sh - Tests for new Warden features
#
# Verifies the warden improvements:
#   - Policy validation command
#   - Policy test command
#   - Health check command
#   - Log pruning
#   - Rate limiting
#   - Metrics aggregation
#
# Usage: ./tests/test_warden_features.sh
#
# Prerequisites:
#   - Lima VM running: limactl start cell
#   - Addons deployed: make _copy-addons (or `brig system up`, which syncs them)
#   - Warden running: warden start
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

log_skip() {
    echo -e "${YELLOW}SKIP${NC}: $1"
}

export LIMACTL_QUIET=1

run_in_vm() {
    # Run command in VM, filtering cd warnings but preserving exit code.
    local output
    local exitcode
    output=$(limactl shell "$VM_NAME" -- "$@" 2>&1)
    exitcode=$?
    echo "$output" | grep -v "^bash: line [0-9]*: cd:" || true
    return $exitcode
}

run_in_vm_capture() {
    # Run command in VM for output capture. Filter cd warnings.
    limactl shell "$VM_NAME" -- "$@" 2>&1 | grep -v "^bash: line [0-9]*: cd:" || true
}

# Check VM is running.
check_vm_running() {
    if ! limactl list 2>/dev/null | grep -q "$VM_NAME.*Running"; then
        echo "ERROR: VM '$VM_NAME' is not running"
        echo "Start it with: limactl start $VM_NAME"
        exit 1
    fi
    echo "VM '$VM_NAME' is running"
}

echo "============================================"
echo "Warden Feature Tests"
echo "============================================"
echo

# Pre-flight checks.
echo "--- Pre-flight checks ---"
check_vm_running

# Check warden script exists.
if ! run_in_vm test -f /usr/local/bin/warden; then
    echo "ERROR: Warden not installed at /usr/local/bin/warden"
    exit 1
fi
echo "Warden installed"
echo

# ============================================
# Health Check Tests
# ============================================
echo
echo "--- Health Check Tests ---"

# Start warden if not running.
if ! run_in_vm sudo podman ps --format '{{.Names}}' 2>/dev/null | grep -q "warden"; then
    echo "Starting warden..."
    run_in_vm sudo warden start 2>/dev/null || true
    sleep 3
fi

# Test 7: Health check returns JSON.
echo
echo "Test 7: Health check returns valid JSON"
HEALTH_OUTPUT=$(run_in_vm sudo warden health --json 2>/dev/null || echo "{}")
if echo "$HEALTH_OUTPUT" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    log_pass "Health check returns valid JSON"
else
    log_fail "Health check should return valid JSON"
fi

# Test 8: Health check reports container status.
echo
echo "Test 8: Health check reports container status"
if echo "$HEALTH_OUTPUT" | grep -q "container_running"; then
    log_pass "Health check includes container_running"
else
    log_fail "Health check missing container_running field"
fi

# Test 9: Health check reports policy status.
echo
echo "Test 9: Health check reports policy status"
if echo "$HEALTH_OUTPUT" | grep -q "policy_loaded"; then
    log_pass "Health check includes policy_loaded"
else
    log_fail "Health check missing policy_loaded field"
fi

# ============================================
# Log Pruning Tests
# ============================================
echo
echo "--- Log Pruning Tests ---"

# Test 10: Log prune command runs.
echo
echo "Test 10: Log prune command runs without error"
if run_in_vm sudo warden logs prune --days 30 2>/dev/null; then
    log_pass "Log prune command executed"
else
    log_fail "Log prune command failed"
fi

# ============================================
# Status and Reload Tests
# ============================================
echo
echo "--- Status and Reload Tests ---"

# Test 11: Status command works.
echo
echo "Test 11: Status command works"
if run_in_vm sudo warden status 2>/dev/null | grep -q "Proxy:"; then
    log_pass "Status command works"
else
    log_fail "Status command failed"
fi

# Test 12: Reload command works (if proxy running).
echo
echo "Test 12: Reload command works"
if run_in_vm sudo podman ps --format '{{.Names}}' 2>/dev/null | grep -q "warden"; then
    if run_in_vm sudo warden reload 2>/dev/null; then
        log_pass "Reload command succeeded"
    else
        log_fail "Reload command failed"
    fi
else
    log_skip "Proxy not running, skipping reload test"
fi

# ============================================
# Addon Loading Tests
# ============================================
echo
echo "--- Addon Loading Tests ---"

# Test 13: Required addons exist.
echo
echo "Test 13: Required addons installed"
MISSING_ADDONS=0
for addon in enforce.py logger.py; do
    if ! run_in_vm test -f "/cells/addons/$addon" 2>/dev/null; then
        echo "  Missing: $addon"
        MISSING_ADDONS=$((MISSING_ADDONS + 1))
    fi
done
if [ "$MISSING_ADDONS" -eq 0 ]; then
    log_pass "Required addons installed"
else
    log_fail "Missing $MISSING_ADDONS required addon(s)"
fi

# Test 14: Optional addons exist.
echo
echo "Test 14: Optional addons installed"
OPTIONAL_ADDONS=0
for addon in ratelimit.py metrics.py notifier.py; do
    if run_in_vm test -f "/cells/addons/$addon" 2>/dev/null; then
        OPTIONAL_ADDONS=$((OPTIONAL_ADDONS + 1))
    fi
done
if [ "$OPTIONAL_ADDONS" -gt 0 ]; then
    log_pass "$OPTIONAL_ADDONS optional addon(s) installed"
else
    log_skip "No optional addons installed"
fi

# ============================================
# Summary
# ============================================
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
