#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_secrets.sh - Secrets handling and workspace isolation tests
#
# Verifies:
#   - Secrets are mounted from files, never in env vars
#   - Secrets env vars point to file paths, not values
#   - Each cell has isolated workspace at /work
#   - Cells cannot see other cells' workspaces
#   - Workspace persists across cell restarts
#   - State survives cell removal (unless --purge)
#
# Usage: ./tests/test_secrets.sh
#
# Prerequisites:
#   - Lima VM running: limactl start cell
#   - Proxy running: warden start
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

# Create test secret files.
create_test_secrets() {
    echo "Creating test secrets..."
    mkdir -p ~/.brig/secrets
    echo "test-api-key-12345" > ~/.brig/secrets/test-api-key.txt
    echo "test-token-67890" > ~/.brig/secrets/test-token.txt
    chmod 600 ~/.brig/secrets/test-api-key.txt
    chmod 600 ~/.brig/secrets/test-token.txt
}

# Clean up test secrets.
cleanup_test_secrets() {
    rm -f ~/.brig/secrets/test-api-key.txt
    rm -f ~/.brig/secrets/test-token.txt
}

# Clean up test cells.
cleanup_test_cells() {
    echo "Cleaning up test cells..."
    run_in_vm sudo /usr/local/bin/brig rm -f --purge secrets-test-1 2>/dev/null || true
    run_in_vm sudo /usr/local/bin/brig rm -f --purge secrets-test-2 2>/dev/null || true
    run_in_vm sudo /usr/local/bin/brig rm -f --purge workspace-test 2>/dev/null || true
}

echo "============================================"
echo "Secrets & State Tests"
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

# Set up test fixtures.
create_test_secrets
cleanup_test_cells

# Test 1: Secrets directory mounted in VM.
echo "--- Test 1: Secrets directory mounted in VM ---"
if run_in_vm test -d /secrets; then
    log_pass "Secrets directory mounted at /secrets"
else
    log_fail "Secrets directory not mounted"
fi

# Test 2: Secret files visible in VM.
echo
echo "--- Test 2: Secret files visible in VM ---"
if run_in_vm test -f /secrets/test-api-key.txt; then
    log_pass "Secret file test-api-key.txt visible"
else
    log_fail "Secret file not visible in VM"
fi

# Test 3: Cell can mount secrets via --secret flag.
echo
echo "--- Test 3: Cell mounts secrets at /run/secrets/ ---"
run_in_vm sudo /usr/local/bin/brig run -d --name secrets-test-1 \
    --secret test-api-key.txt \
    alpine sleep 300 2>/dev/null || true
sleep 2

if run_in_vm sudo podman exec brig-secrets-test-1 test -f /run/secrets/test-api-key.txt 2>/dev/null; then
    log_pass "Secret mounted at /run/secrets/test-api-key.txt"
else
    log_fail "Secret not mounted in container"
fi

# Test 4: Secret content matches source.
echo
echo "--- Test 4: Secret content matches source ---"
CONTAINER_SECRET=$(run_in_vm sudo podman exec brig-secrets-test-1 cat /run/secrets/test-api-key.txt 2>/dev/null || echo "")
if [ "$CONTAINER_SECRET" = "test-api-key-12345" ]; then
    log_pass "Secret content matches"
else
    log_fail "Secret content mismatch: got '$CONTAINER_SECRET'"
fi

# Test 5: Secret path env var set (not value).
echo
echo "--- Test 5: Secret path env var set (NAME_FILE format) ---"
if run_in_vm sudo podman exec brig-secrets-test-1 printenv TEST_API_KEY_FILE 2>/dev/null | grep -q "/run/secrets"; then
    log_pass "TEST_API_KEY_FILE env var points to path"
else
    log_fail "Secret path env var not set"
fi

# Test 6: Secret value NOT in env var.
echo
echo "--- Test 6: Secret value NOT exposed in env vars ---"
if run_in_vm sudo podman exec brig-secrets-test-1 env 2>/dev/null | grep -q "test-api-key-12345"; then
    log_fail "Secret value exposed in environment"
else
    log_pass "Secret value not exposed in environment"
fi

# Test 7: Workspace directory created.
echo
echo "--- Test 7: Cell has workspace at /work ---"
if run_in_vm sudo podman exec brig-secrets-test-1 test -d /work 2>/dev/null; then
    log_pass "Workspace directory exists at /work"
else
    log_fail "Workspace directory missing"
fi

# Test 8: Workspace is writable.
echo
echo "--- Test 8: Workspace is writable ---"
if run_in_vm sudo podman exec brig-secrets-test-1 touch /work/test-file.txt 2>/dev/null; then
    log_pass "Workspace is writable"
else
    log_fail "Workspace is not writable"
fi

# Test 9: Workspace persists to host.
echo
echo "--- Test 9: Workspace persists to host state directory ---"
if run_in_vm test -f /state/secrets-test-1/workspace/test-file.txt 2>/dev/null; then
    log_pass "Workspace file visible on host"
else
    log_fail "Workspace not persisted to host"
fi

# Test 10: Cells have isolated workspaces.
echo
echo "--- Test 10: Cells have isolated workspaces ---"
run_in_vm sudo /usr/local/bin/brig run -d --name secrets-test-2 alpine sleep 300 2>/dev/null || true
sleep 2

# Create file in cell 1.
run_in_vm sudo podman exec brig-secrets-test-1 sh -c 'echo "cell1-data" > /work/cell1-file.txt' 2>/dev/null || true

# Check cell 2 cannot see it.
if run_in_vm sudo podman exec brig-secrets-test-2 test -f /work/cell1-file.txt 2>/dev/null; then
    log_fail "Cell 2 can see Cell 1's workspace files"
else
    log_pass "Cells have isolated workspaces"
fi

# Test 11: Workspace persists across restart.
echo
echo "--- Test 11: Workspace persists across cell restart ---"
run_in_vm sudo /usr/local/bin/brig stop secrets-test-1 2>/dev/null || true
run_in_vm sudo /usr/local/bin/brig start secrets-test-1 2>/dev/null || true
sleep 2

if run_in_vm sudo podman exec brig-secrets-test-1 test -f /work/cell1-file.txt 2>/dev/null; then
    log_pass "Workspace persists across restart"
else
    log_fail "Workspace data lost on restart"
fi

# Test 12: Cell rm without --purge keeps workspace.
echo
echo "--- Test 12: Cell rm without --purge keeps workspace ---"
run_in_vm sudo /usr/local/bin/brig rm -f secrets-test-1 2>/dev/null || true
if run_in_vm test -f /state/secrets-test-1/workspace/cell1-file.txt 2>/dev/null; then
    log_pass "Workspace preserved after rm"
else
    log_fail "Workspace deleted without --purge"
fi

# Test 13: Cell rm with --purge removes workspace.
echo
echo "--- Test 13: Cell rm --purge removes workspace ---"
run_in_vm sudo /usr/local/bin/brig rm -f --purge secrets-test-2 2>/dev/null || true
if run_in_vm test -d /state/secrets-test-2 2>/dev/null; then
    log_fail "Workspace not removed with --purge"
else
    log_pass "Workspace removed with --purge"
fi

# Test 14: Multiple secrets can be mounted.
echo
echo "--- Test 14: Multiple secrets can be mounted ---"
run_in_vm sudo /usr/local/bin/brig rm -f workspace-test 2>/dev/null || true
run_in_vm sudo /usr/local/bin/brig run -d --name workspace-test \
    --secret test-api-key.txt \
    --secret test-token.txt \
    alpine sleep 300 2>/dev/null || true
sleep 2

if run_in_vm sudo podman exec brig-workspace-test test -f /run/secrets/test-api-key.txt 2>/dev/null && \
   run_in_vm sudo podman exec brig-workspace-test test -f /run/secrets/test-token.txt 2>/dev/null; then
    log_pass "Multiple secrets mounted"
else
    log_fail "Not all secrets mounted"
fi

# Test 15: Secrets are read-only in container.
echo
echo "--- Test 15: Secrets are read-only in container ---"
if run_in_vm sudo podman exec brig-workspace-test sh -c 'echo "hack" > /run/secrets/test-api-key.txt' 2>/dev/null; then
    log_fail "Secrets are writable (should be read-only)"
else
    log_pass "Secrets are read-only"
fi

# Cleanup.
echo
echo "--- Cleanup ---"
cleanup_test_cells
cleanup_test_secrets

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
