#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_secrets.sh - Secrets handling and workspace isolation tests
#
# Verifies:
#   - Secrets are mounted from files at /run/secrets/<name>, never in env vars
#   - The secret's NAME_FILE env var points to the path, not the value
#   - Each cell has an isolated, writable, host-persisted workspace at /work
#   - Cells cannot see each other's workspaces
#   - Workspace survives restart; `cell rm` removes it (default) but
#     `--keep-workspace` preserves it
#   - Secrets are read-only in the container
#
# Usage: ./tests/test_secrets.sh   (requires `brig system up` first)
# Exit: 0 all passed, 1 any failed.

source "$(dirname "$0")/lib/e2e_common.sh"

# Secrets live in the brig home brig actually reads (host-side). Names carry no
# extension so the derived env var is TEST_API_KEY_FILE (not ..._TXT_FILE).
BRIG_HOME="${BRIG_HOME:-$HOME/.brig}"
SECRETS_DIR="$BRIG_HOME/secrets"

create_test_secrets() {
    echo "Creating test secrets in $SECRETS_DIR ..."
    mkdir -p "$SECRETS_DIR"
    echo "test-api-key-12345" > "$SECRETS_DIR/test-api-key"
    echo "test-token-67890" > "$SECRETS_DIR/test-token"
    chmod 600 "$SECRETS_DIR/test-api-key" "$SECRETS_DIR/test-token"
}
cleanup_test_secrets() { rm -f "$SECRETS_DIR/test-api-key" "$SECRETS_DIR/test-token"; }
cleanup_test_cells() {
    echo "Cleaning up test cells..."
    $BRIG cell rm -f secrets-test-1 2>/dev/null || true
    $BRIG cell rm -f secrets-test-2 2>/dev/null || true
    $BRIG cell rm -f workspace-test 2>/dev/null || true
}

echo "============================================"
echo "Secrets & State Tests"
echo "============================================"
echo

echo "--- Pre-flight checks ---"
require_brig_up
echo "VM '$VM_NAME' is running; host brig OK"
echo

create_test_secrets
cleanup_test_cells

# Test 1: secrets directory mounted into the VM.
echo "--- Test 1: Secrets directory mounted in VM ---"
if run_in_vm test -d /secrets; then
    log_pass "Secrets directory mounted at /secrets"
else
    log_fail "Secrets directory not mounted"
fi

# Test 2: secret files visible in the VM.
echo
echo "--- Test 2: Secret files visible in VM ---"
if run_in_vm test -f /secrets/test-api-key; then
    log_pass "Secret file test-api-key visible"
else
    log_fail "Secret file not visible in VM"
fi

# Test 3: cell mounts secrets at /run/secrets/.
echo
echo "--- Test 3: Cell mounts secrets at /run/secrets/ ---"
$BRIG run -d --name secrets-test-1 --secret test-api-key alpine sleep 300 >/dev/null 2>&1 || true
sleep 2
if in_cell secrets-test-1 test -f /run/secrets/test-api-key 2>/dev/null; then
    log_pass "Secret mounted at /run/secrets/test-api-key"
else
    log_fail "Secret not mounted in container"
fi

# Test 4: secret content matches source.
echo
echo "--- Test 4: Secret content matches source ---"
CONTAINER_SECRET=$(in_cell secrets-test-1 cat /run/secrets/test-api-key 2>/dev/null || echo "")
if [ "$CONTAINER_SECRET" = "test-api-key-12345" ]; then
    log_pass "Secret content matches"
else
    log_fail "Secret content mismatch: got '$CONTAINER_SECRET'"
fi

# Test 5: secret path env var set (NAME_FILE), not the value.
echo
echo "--- Test 5: Secret path env var set (NAME_FILE format) ---"
if in_cell secrets-test-1 printenv TEST_API_KEY_FILE 2>/dev/null | grep -q "/run/secrets"; then
    log_pass "TEST_API_KEY_FILE env var points to path"
else
    log_fail "Secret path env var not set"
fi

# Test 6: secret value NOT in any env var.
echo
echo "--- Test 6: Secret value NOT exposed in env vars ---"
if in_cell secrets-test-1 env 2>/dev/null | grep -q "test-api-key-12345"; then
    log_fail "Secret value exposed in environment"
else
    log_pass "Secret value not exposed in environment"
fi

# Test 7: workspace exists at /work.
echo
echo "--- Test 7: Cell has workspace at /work ---"
if in_cell secrets-test-1 test -d /work 2>/dev/null; then
    log_pass "Workspace directory exists at /work"
else
    log_fail "Workspace directory missing"
fi

# Test 8: workspace is writable.
echo
echo "--- Test 8: Workspace is writable ---"
if in_cell secrets-test-1 touch /work/test-file.txt 2>/dev/null; then
    log_pass "Workspace is writable"
else
    log_fail "Workspace is not writable"
fi

# Test 9: workspace persists to the host state directory (visible in VM).
echo
echo "--- Test 9: Workspace persists to host state directory ---"
if run_in_vm test -f /state/secrets-test-1/workspace/test-file.txt 2>/dev/null; then
    log_pass "Workspace file visible on host"
else
    log_fail "Workspace not persisted to host"
fi

# Test 10: cells have isolated workspaces.
echo
echo "--- Test 10: Cells have isolated workspaces ---"
$BRIG run -d --name secrets-test-2 alpine sleep 300 >/dev/null 2>&1 || true
sleep 2
in_cell secrets-test-1 sh -c 'echo "cell1-data" > /work/cell1-file.txt' 2>/dev/null || true
if in_cell secrets-test-2 test -f /work/cell1-file.txt 2>/dev/null; then
    log_fail "Cell 2 can see Cell 1's workspace files"
else
    log_pass "Cells have isolated workspaces"
fi

# Test 11: workspace persists across restart.
echo
echo "--- Test 11: Workspace persists across cell restart ---"
$BRIG cell stop secrets-test-1 >/dev/null 2>&1 || true
$BRIG cell start secrets-test-1 >/dev/null 2>&1 || true
sleep 2
if in_cell secrets-test-1 test -f /work/cell1-file.txt 2>/dev/null; then
    log_pass "Workspace persists across restart"
else
    log_fail "Workspace data lost on restart"
fi

# Test 12: `cell rm --keep-workspace` preserves the workspace.
echo
echo "--- Test 12: cell rm --keep-workspace preserves workspace ---"
$BRIG cell rm -f --keep-workspace secrets-test-1 >/dev/null 2>&1 || true
if run_in_vm test -f /state/secrets-test-1/workspace/cell1-file.txt 2>/dev/null; then
    log_pass "Workspace preserved with --keep-workspace"
else
    log_fail "Workspace deleted despite --keep-workspace"
fi

# Test 13: `cell rm` (default) removes the workspace.
echo
echo "--- Test 13: cell rm (default) removes workspace ---"
$BRIG cell rm -f secrets-test-2 >/dev/null 2>&1 || true
if run_in_vm test -d /state/secrets-test-2 2>/dev/null; then
    log_fail "Workspace not removed by default rm"
else
    log_pass "Workspace removed by default rm"
fi

# Test 14: multiple secrets can be mounted.
echo
echo "--- Test 14: Multiple secrets can be mounted ---"
$BRIG cell rm -f workspace-test 2>/dev/null || true
$BRIG run -d --name workspace-test --secret test-api-key --secret test-token alpine sleep 300 >/dev/null 2>&1 || true
sleep 2
if in_cell workspace-test test -f /run/secrets/test-api-key 2>/dev/null && \
   in_cell workspace-test test -f /run/secrets/test-token 2>/dev/null; then
    log_pass "Multiple secrets mounted"
else
    log_fail "Not all secrets mounted"
fi

# Test 15: secrets are read-only in the container.
echo
echo "--- Test 15: Secrets are read-only in container ---"
if in_cell workspace-test sh -c 'echo "hack" > /run/secrets/test-api-key' 2>/dev/null; then
    log_fail "Secrets are writable (should be read-only)"
else
    log_pass "Secrets are read-only"
fi

echo
echo "--- Cleanup ---"
cleanup_test_cells
cleanup_test_secrets

finish
