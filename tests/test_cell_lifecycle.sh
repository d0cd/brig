#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_cell_lifecycle.sh - Cell lifecycle management tests
#
# Verifies core cell operations driven from the host CLI:
#   - brig run creates an isolated gVisor container on an internal network
#   - brig cell stop/start/kill transition the container
#   - brig cell rm cleans up container + network
#   - brig cell list / logs reflect state and output
#   - Warden proxy integration (proxy env, allowed vs direct egress)
#   - Two cells are isolated from each other (no east-west)
#
# Usage: ./tests/test_cell_lifecycle.sh   (requires `brig system up` first)
# Exit: 0 all passed, 1 any failed.

source "$(dirname "$0")/lib/e2e_common.sh"

cleanup_test_cells() {
    echo "Cleaning up test cells..."
    $BRIG cell rm -f test-cell-1 2>/dev/null || true
    $BRIG cell rm -f test-cell-2 2>/dev/null || true
    $BRIG cell rm -f test-lifecycle 2>/dev/null || true
}

echo "============================================"
echo "Cell Lifecycle Tests"
echo "============================================"
echo

echo "--- Pre-flight checks ---"
require_brig_up
echo "VM '$VM_NAME' is running; host brig OK"
echo

cleanup_test_cells

# Test 1: brig run creates a container.
echo "--- Test 1: brig run creates a cell ---"
if $BRIG run -d --name test-cell-1 --policy-allow example.com alpine sleep 300 >/dev/null 2>&1; then
    log_pass "Cell started successfully"
else
    log_fail "Failed to start cell"
fi

# Test 2: container runs under gVisor (runsc shows in the guest dmesg).
echo
echo "--- Test 2: Container uses gVisor runtime ---"
if in_cell test-cell-1 dmesg 2>/dev/null | grep -q "Starting gVisor"; then
    log_pass "Cell uses gVisor (runsc) runtime"
else
    log_fail "Cell not running with gVisor"
fi

# Test 3: cell has an isolated internal network.
echo
echo "--- Test 3: Cell has isolated internal network ---"
if run_in_vm sudo podman network exists brig-test-cell-1 2>/dev/null; then
    log_pass "Cell network exists"
else
    log_fail "Cell network not created"
fi
if run_in_vm sudo podman network inspect brig-test-cell-1 2>/dev/null | grep -q '"internal": true'; then
    log_pass "Cell network is internal"
else
    log_fail "Cell network is not internal"
fi

# Test 4: warden is connected to the cell network.
echo
echo "--- Test 4: Warden connected to cell network ---"
if run_in_vm sudo podman inspect warden --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | grep -q "brig-test-cell-1"; then
    log_pass "Warden connected to cell network"
else
    log_fail "Warden not connected to cell network"
fi

# Test 5: cell has the proxy env pointed at warden.
echo
echo "--- Test 5: Cell has proxy environment variables ---"
if in_cell test-cell-1 printenv http_proxy 2>/dev/null | grep -q "8080"; then
    log_pass "http_proxy env var set"
else
    log_fail "http_proxy env var not set"
fi

# Test 6: cell can reach an allowed domain via the proxy.
echo
echo "--- Test 6: Cell can reach allowed domain via proxy ---"
if in_cell test-cell-1 wget -q -O /dev/null --timeout=15 http://example.com 2>/dev/null; then
    log_pass "Cell can reach example.com via proxy"
else
    log_fail "Cell cannot reach internet via proxy"
fi

# Test 7: cell cannot reach the internet directly (bypassing the proxy).
echo
echo "--- Test 7: Cell cannot reach internet directly ---"
if in_cell test-cell-1 sh -c 'unset http_proxy https_proxy; wget -q -O /dev/null --timeout=5 http://example.com' 2>/dev/null; then
    log_fail "Cell can reach internet directly (should be blocked)"
else
    log_pass "Cell correctly blocked from direct internet access"
fi

# Test 8: brig cell list shows the cell + status.
echo
echo "--- Test 8: brig cell list shows running cell ---"
LIST_OUTPUT=$($BRIG cell list 2>/dev/null)
if echo "$LIST_OUTPUT" | grep -q "test-cell-1"; then
    log_pass "brig cell list shows test-cell-1"
else
    log_fail "brig cell list missing test-cell-1"
fi
if echo "$LIST_OUTPUT" | grep -qi "running\|up"; then
    log_pass "brig cell list shows running status"
else
    log_fail "brig cell list not showing running status"
fi

# Test 9: brig cell stop gracefully stops the container.
echo
echo "--- Test 9: brig cell stop ---"
if $BRIG cell stop test-cell-1 >/dev/null 2>&1; then
    log_pass "brig cell stop succeeded"
else
    log_fail "brig cell stop failed"
fi
sleep 1
STATUS=$(run_in_vm sudo podman inspect brig-test-cell-1 --format '{{.State.Status}}' 2>/dev/null || echo "removed")
if [ "$STATUS" = "exited" ] || [ "$STATUS" = "stopped" ]; then
    log_pass "Container is stopped"
else
    log_fail "Container not stopped, status: $STATUS"
fi

# Test 10: brig cell start restarts a stopped cell.
echo
echo "--- Test 10: brig cell start ---"
if $BRIG cell start test-cell-1 >/dev/null 2>&1; then
    log_pass "brig cell start succeeded"
else
    log_fail "brig cell start failed"
fi
sleep 1
STATUS=$(run_in_vm sudo podman inspect brig-test-cell-1 --format '{{.State.Status}}' 2>/dev/null || echo "unknown")
if [ "$STATUS" = "running" ]; then
    log_pass "Container is running again"
else
    log_fail "Container not running, status: $STATUS"
fi

# Test 11: brig cell kill immediately terminates.
echo
echo "--- Test 11: brig cell kill ---"
if $BRIG cell kill test-cell-1 >/dev/null 2>&1; then
    log_pass "brig cell kill succeeded"
else
    log_fail "brig cell kill failed"
fi
STATUS=$(run_in_vm sudo podman inspect brig-test-cell-1 --format '{{.State.Status}}' 2>/dev/null || echo "removed")
if [ "$STATUS" = "exited" ] || [ "$STATUS" = "stopped" ]; then
    log_pass "Container terminated immediately"
else
    log_fail "Container not terminated, status: $STATUS"
fi

# Test 12: brig cell rm cleans up container + network.
echo
echo "--- Test 12: brig cell rm cleans up container and network ---"
if $BRIG cell rm test-cell-1 >/dev/null 2>&1; then
    log_pass "brig cell rm succeeded"
else
    log_fail "brig cell rm failed"
fi
if run_in_vm sudo podman container exists brig-test-cell-1 2>/dev/null; then
    log_fail "Container still exists after rm"
else
    log_pass "Container removed"
fi
if run_in_vm sudo podman network exists brig-test-cell-1 2>/dev/null; then
    log_fail "Network still exists after rm"
else
    log_pass "Network removed (subnet freed)"
fi

# Test 13: two cells are isolated from each other (no east-west).
echo
echo "--- Test 13: Multiple cells are isolated from each other ---"
$BRIG run -d --name test-cell-1 alpine sleep 300 >/dev/null 2>&1 || true
$BRIG run -d --name test-cell-2 alpine sleep 300 >/dev/null 2>&1 || true
sleep 2
CELL2_IP=$(run_in_vm sudo podman inspect brig-test-cell-2 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null | head -1)
if in_cell test-cell-1 ping -c1 -W2 "$CELL2_IP" 2>/dev/null; then
    log_fail "Cells can communicate (should be isolated)"
else
    log_pass "Cells are isolated from each other"
fi

# Test 14: brig cell logs shows container output.
echo
echo "--- Test 14: brig cell logs ---"
$BRIG cell rm -f test-lifecycle 2>/dev/null || true
$BRIG run -d --name test-lifecycle alpine -- sh -c 'echo hello_from_cell; sleep 60' >/dev/null 2>&1 || true
sleep 2
LOGS=$($BRIG cell logs test-lifecycle 2>/dev/null)
if echo "$LOGS" | grep -q "hello_from_cell"; then
    log_pass "brig cell logs shows container output"
else
    log_fail "brig cell logs not showing output: $LOGS"
fi

echo
echo "--- Cleanup ---"
cleanup_test_cells

finish
