#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_vm_foundation.sh - VM infrastructure verification
#
# Verifies the base infrastructure:
#   - macOS directory structure + lima.yaml
#   - VM mounts present (/state rw, /cells + /secrets read-only)
#   - podman + gVisor installed; runsc is the default runtime
#   - IPv6 disabled; proxy-external network present
#   - Network isolation: east-west blocked, internal nets have no internet,
#     proxy-external reaches the internet
#   - gVisor runtime is functional
#
# Usage: ./tests/test_vm_foundation.sh   (requires `brig system up` first)
# Exit: 0 all passed, 1 any failed.

source "$(dirname "$0")/lib/e2e_common.sh"

echo "============================================"
echo "VM Foundation Tests"
echo "============================================"
echo

echo "--- Pre-flight checks ---"
require_brig_up
echo "VM '$VM_NAME' is running"
echo

# Test 1: macOS directory structure.
echo "--- Test 1: macOS directory structure ---"
if [ -d "$HOME/.brig/cells" ] && [ -d "$HOME/.brig/secrets" ] && [ -d "$HOME/.brig/state" ]; then
    log_pass "Directory structure exists"
else
    log_fail "Missing directories in ~/.brig/"
fi
if [ -f "$HOME/.brig/lima.yaml" ]; then log_pass "lima.yaml exists"; else log_fail "lima.yaml missing"; fi

# Test 2: VM mounts present.
echo
echo "--- Test 2: VM mounts ---"
for m in /state /secrets /cells; do
    if run_in_vm test -d "$m"; then log_pass "$m mount exists"; else log_fail "$m mount missing"; fi
done

# Test 3: /cells (and /secrets) mounted read-only. virtiofs mounts host dirs
# `writable: false` → ro, which is stronger than noexec (no tampering at all).
echo
echo "--- Test 3: /cells mount is read-only ---"
if run_in_vm mount 2>/dev/null | grep "/cells " | grep -qE "[(,]ro[,)]"; then
    log_pass "/cells mounted read-only"
else
    log_fail "/cells not read-only"
fi

# Test 4: podman installed.
echo
echo "--- Test 4: Podman ---"
if run_in_vm command -v podman >/dev/null 2>&1; then log_pass "Podman installed"; else log_fail "Podman not installed"; fi

# Test 5: gVisor (runsc) installed.
echo
echo "--- Test 5: gVisor ---"
if run_in_vm command -v runsc >/dev/null 2>&1; then log_pass "runsc installed"; else log_fail "runsc not installed"; fi

# Test 6: runsc is podman's default runtime (configured in containers.conf;
# brig also passes --runtime runsc explicitly per cell).
echo
echo "--- Test 6: gVisor is the default runtime ---"
if run_in_vm sudo podman info --format '{{.Host.OCIRuntime.Name}}' 2>/dev/null | grep -q "runsc"; then
    log_pass "runsc is the default OCI runtime"
else
    log_fail "default runtime is not runsc"
fi

# Test 7: IPv6 disabled.
echo
echo "--- Test 7: IPv6 disabled ---"
if run_in_vm sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q '= 1'; then
    log_pass "IPv6 disabled"
else
    log_fail "IPv6 not disabled"
fi

# Test 8: proxy-external network exists with a subnet.
echo
echo "--- Test 8: proxy-external network ---"
if run_in_vm sudo podman network exists proxy-external; then log_pass "proxy-external network exists"; else log_fail "proxy-external network missing"; fi
if run_in_vm sudo podman network inspect proxy-external 2>/dev/null | grep -q '"subnet"'; then
    log_pass "proxy-external has a subnet"
else
    log_fail "proxy-external has no subnet"
fi

# Test 9: log directory exists.
echo
echo "--- Test 9: Log directory ---"
if run_in_vm test -d /var/log/brig/network; then log_pass "/var/log/brig/network exists"; else log_fail "/var/log/brig/network missing"; fi

# Test 10: subnet allocator state exists and is well-formed.
echo
echo "--- Test 10: Subnet allocator state ---"
if run_in_vm test -f /state/system/subnets.json; then log_pass "subnets.json exists"; else log_fail "subnets.json missing"; fi
if run_in_vm cat /state/system/subnets.json 2>/dev/null | grep -q '"next_index"'; then
    log_pass "subnets.json has valid structure"
else
    log_fail "subnets.json has invalid structure"
fi

# Test 11: east-west isolation between two internal networks (invariant 1).
echo
echo "--- Test 11: East-west isolation ---"
run_in_vm sudo podman network create --internal test-net-a-verify 2>/dev/null || true
run_in_vm sudo podman network create --internal test-net-b-verify 2>/dev/null || true
run_in_vm sudo podman run --rm -d --network test-net-a-verify --name test-a-verify alpine sleep 30 2>/dev/null || true
if run_in_vm sudo podman run --rm --network test-net-b-verify alpine ping -c1 -W2 test-a-verify 2>/dev/null; then
    log_fail "East-west traffic allowed (CRITICAL)"
else
    log_pass "East-west traffic blocked"
fi
run_in_vm sudo podman rm -f test-a-verify 2>/dev/null || true
run_in_vm sudo podman network rm test-net-a-verify test-net-b-verify 2>/dev/null || true

# Test 12: internal network has no internet.
echo
echo "--- Test 12: Internal network isolation ---"
run_in_vm sudo podman network create --internal test-internal-verify 2>/dev/null || true
if run_in_vm sudo podman run --rm --network test-internal-verify alpine wget -q -O /dev/null --timeout=5 http://example.com 2>/dev/null; then
    log_fail "Internal network can reach internet (CRITICAL)"
else
    log_pass "Internal network isolated from internet"
fi
run_in_vm sudo podman network rm test-internal-verify 2>/dev/null || true

# Test 13: proxy-external reaches the internet.
echo
echo "--- Test 13: External network connectivity ---"
if run_in_vm sudo podman run --rm --network proxy-external alpine wget -q -O /dev/null --timeout=10 http://example.com 2>/dev/null; then
    log_pass "proxy-external can reach internet"
else
    log_fail "proxy-external cannot reach internet"
fi

# Test 14: gVisor runtime is functional.
echo
echo "--- Test 14: gVisor runtime functional ---"
if run_in_vm sudo podman run --rm --runtime=runsc alpine dmesg 2>/dev/null | grep -qi "starting gvisor"; then
    log_pass "gVisor runtime is functional"
else
    log_fail "gVisor runtime not working"
fi

finish
