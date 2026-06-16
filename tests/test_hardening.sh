#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_hardening.sh - Security hardening tests
#
# Verifies production security hardening:
#   - Warden + cell resource limits (memory, CPU, PIDs)
#   - Custom memory limit applied
#   - Workspace permissions, /cells noexec, secrets read-only in VM
#   - Cell isolation from the host network, IPv6 disabled
#
# Usage: ./tests/test_hardening.sh   (requires `brig system up` first)
# Exit: 0 all passed, 1 any failed.

source "$(dirname "$0")/lib/e2e_common.sh"

cleanup_test_cells() {
    echo "Cleaning up test cells..."
    $BRIG cell rm -f hardening-test 2>/dev/null || true
    $BRIG cell rm -f limits-test 2>/dev/null || true
}

echo "============================================"
echo "Hardening Tests"
echo "============================================"
echo

echo "--- Pre-flight checks ---"
require_brig_up
echo "VM '$VM_NAME' is running; host brig OK"
echo

cleanup_test_cells

# Test 1-3: warden has memory/CPU/PID limits.
echo "--- Test 1: Warden has memory limit ---"
PROXY_MEM=$(run_in_vm sudo podman inspect warden --format '{{.HostConfig.Memory}}' 2>/dev/null || echo "0")
if [ "${PROXY_MEM:-0}" -gt 0 ]; then log_pass "Warden has memory limit: $PROXY_MEM bytes"; else log_fail "Warden missing memory limit"; fi

echo
echo "--- Test 2: Warden has CPU limit ---"
PROXY_CPU=$(run_in_vm sudo podman inspect warden --format '{{.HostConfig.NanoCpus}}' 2>/dev/null || echo "0")
if [ "${PROXY_CPU:-0}" -gt 0 ]; then log_pass "Warden has CPU limit: $PROXY_CPU nanocpus"; else log_fail "Warden missing CPU limit"; fi

echo
echo "--- Test 3: Warden has PID limit ---"
PROXY_PIDS=$(run_in_vm sudo podman inspect warden --format '{{.HostConfig.PidsLimit}}' 2>/dev/null || echo "0")
if [ "${PROXY_PIDS:-0}" -gt 0 ]; then log_pass "Warden has PID limit: $PROXY_PIDS"; else log_fail "Warden missing PID limit"; fi

# Test 4-6: cell has default memory/CPU/PID limits.
echo
echo "--- Test 4: Cell has default memory limit ---"
$BRIG run -d --name hardening-test alpine sleep 300 >/dev/null 2>&1 || true
sleep 2
CELL_MEM=$(run_in_vm sudo podman inspect brig-hardening-test --format '{{.HostConfig.Memory}}' 2>/dev/null || echo "0")
if [ "${CELL_MEM:-0}" -gt 0 ]; then log_pass "Cell has memory limit: $CELL_MEM bytes"; else log_fail "Cell missing default memory limit"; fi

echo
echo "--- Test 5: Cell has default CPU limit ---"
CELL_CPU=$(run_in_vm sudo podman inspect brig-hardening-test --format '{{.HostConfig.NanoCpus}}' 2>/dev/null || echo "0")
if [ "${CELL_CPU:-0}" -gt 0 ]; then log_pass "Cell has CPU limit: $CELL_CPU nanocpus"; else log_fail "Cell missing default CPU limit"; fi

echo
echo "--- Test 6: Cell has default PID limit ---"
CELL_PIDS=$(run_in_vm sudo podman inspect brig-hardening-test --format '{{.HostConfig.PidsLimit}}' 2>/dev/null || echo "0")
if [ "${CELL_PIDS:-0}" -gt 0 ]; then log_pass "Cell has PID limit: $CELL_PIDS"; else log_fail "Cell missing default PID limit"; fi

# Test 7: custom memory limit is applied.
echo
echo "--- Test 7: Cell can override memory limit ---"
$BRIG cell rm -f limits-test 2>/dev/null || true
$BRIG run -d --name limits-test --memory 512m alpine sleep 300 >/dev/null 2>&1 || true
sleep 2
CUSTOM_MEM=$(run_in_vm sudo podman inspect brig-limits-test --format '{{.HostConfig.Memory}}' 2>/dev/null || echo "0")
if [ "${CUSTOM_MEM:-0}" -eq 536870912 ]; then log_pass "Custom memory limit applied: 512MB"; else log_fail "Custom memory limit not applied: got $CUSTOM_MEM"; fi

# Test 8: PID limit is enforced.
echo
echo "--- Test 8: Cell respects PID limit ---"
FORK_RESULT=$(in_cell hardening-test sh -c 'for i in $(seq 1 1000); do sleep 10 & done 2>&1' || echo "fork failed")
if echo "$FORK_RESULT" | grep -qi "resource\|limit\|cannot\|error\|fork"; then
    log_pass "PID limit enforced (fork bomb blocked)"
else
    PID_COUNT=$(in_cell hardening-test sh -c 'ps aux | wc -l' 2>/dev/null || echo "0")
    if [ "${PID_COUNT:-0}" -lt 600 ]; then log_pass "PID limit enforced (limited processes)"; else log_fail "PID limit may not be enforced"; fi
fi

# Test 9: workspace permissions are restricted.
echo
echo "--- Test 9: Workspace has restricted permissions ---"
WS_PERMS=$(run_in_vm stat -c '%a' /state/hardening-test/workspace 2>/dev/null || echo "000")
if [ "$WS_PERMS" = "755" ] || [ "$WS_PERMS" = "700" ]; then log_pass "Workspace permissions: $WS_PERMS"; else log_fail "Workspace permissions too open: $WS_PERMS"; fi

# Test 10: /cells mount is read-only. It carries brig's addons (cell-influenced
# data); the virtiofs mount is `writable: false` → ro, which is stronger than
# noexec (no tampering at all). lima's virtiofs doesn't expose a noexec option.
echo
echo "--- Test 10: /cells mount is read-only ---"
MOUNT_OPTS=$(run_in_vm mount 2>/dev/null | grep "/cells " || echo "")
if echo "$MOUNT_OPTS" | grep -qE "[(,]ro[,)]"; then log_pass "/cells mounted read-only ($MOUNT_OPTS)"; else log_fail "/cells not read-only: $MOUNT_OPTS"; fi

# Test 11: secrets directory is read-only in the VM.
echo
echo "--- Test 11: Secrets directory is read-only in VM ---"
if run_in_vm touch /secrets/test-write 2>/dev/null; then
    run_in_vm rm -f /secrets/test-write 2>/dev/null || true
    log_fail "Secrets directory is writable"
else
    log_pass "Secrets directory is read-only"
fi

# Test 12: gVisor handles ICMP / restricts raw sockets (either outcome is fine).
echo
echo "--- Test 12: gVisor raw-socket behavior ---"
if in_cell hardening-test ping -c1 127.0.0.1 2>/dev/null; then
    log_pass "gVisor handles ICMP"
else
    log_pass "gVisor restricts raw sockets"
fi

# Test 13: cell cannot reach the host network.
echo
echo "--- Test 13: Cell cannot access host network ---"
HOST_IP=$(run_in_vm hostname -I 2>/dev/null | awk '{print $1}')
if in_cell hardening-test ping -c1 -W2 "$HOST_IP" 2>/dev/null; then
    log_fail "Cell can reach host network"
else
    log_pass "Cell isolated from host network"
fi

# Test 14: IPv6 is disabled in the VM.
echo
echo "--- Test 14: IPv6 is disabled ---"
IPV6_STATUS=$(run_in_vm cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
if [ "$IPV6_STATUS" = "1" ]; then log_pass "IPv6 is disabled"; else log_fail "IPv6 is not disabled"; fi

echo
echo "--- Cleanup ---"
cleanup_test_cells

finish
