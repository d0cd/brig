#!/bin/bash
# local-smoke-test.sh — Run on your Mac to validate brig end-to-end.
#
# Prerequisites:
#   brew install lima
#   make install  (or: uv pip install -e .)
#
# Usage: make smoke
#   or:  ./scripts/local-smoke-test.sh

set -uo pipefail

# Use uv run to ensure we pick up the local venv, not a stale global install.
BRIG="uv run brig"
WARDEN="uv run warden"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASSED=$((PASSED + 1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1"; FAILED=$((FAILED + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC} $1"; SKIPPED=$((SKIPPED + 1)); }
info() { echo -e "${BOLD}$1${NC}"; }

# ---------------------------------------------------------------------------
info "Phase 1: Host prerequisites"
# ---------------------------------------------------------------------------

echo -n "  Checking python3... "
if python3 --version 2>/dev/null; then
    pass "python3"
else
    fail "python3 not found"
fi

echo -n "  Checking limactl... "
if limactl --version 2>/dev/null; then
    pass "limactl"
else
    fail "limactl not found (brew install lima)"
fi

echo -n "  Checking brig CLI... "
if $BRIG --version 2>/dev/null; then
    pass "brig CLI"
else
    fail "brig not on PATH (pip install -e .)"
fi

echo -n "  Checking warden CLI... "
if $WARDEN --help >/dev/null 2>&1; then
    pass "warden CLI"
else
    fail "warden not on PATH"
fi

# ---------------------------------------------------------------------------
info ""
info "Phase 2: brig system init"
# ---------------------------------------------------------------------------

if [ ! -d "$HOME/.brig" ]; then
    echo "  Running brig system init..."
    $BRIG system init
    if [ -f "$HOME/.brig/lima.yaml" ]; then
        pass "brig system init created ~/.brig/lima.yaml"
    else
        fail "brig system init did not create lima.yaml"
    fi
    if [ -f "$HOME/.brig/cells/network-policy.json" ]; then
        pass "brig system init created default policy"
    else
        fail "brig system init did not create policy"
    fi
else
    pass "~/.brig already exists"
fi

# Check secrets dir permissions.
PERMS=$(stat -f "%Lp" "$HOME/.brig/secrets" 2>/dev/null || stat -c "%a" "$HOME/.brig/secrets" 2>/dev/null)
if [ "$PERMS" = "700" ]; then
    pass "secrets dir permissions 700"
else
    fail "secrets dir permissions: $PERMS (expected 700)"
fi

# ---------------------------------------------------------------------------
info ""
info "Phase 3: Lima VM"
# ---------------------------------------------------------------------------

if limactl list --format '{{.Name}}' 2>/dev/null | grep -q "^brig$"; then
    pass "Lima VM 'brig' exists"
else
    skip "Lima VM 'brig' not created — run: limactl create --name=brig ~/.brig/lima.yaml"
    info ""
    info "Remaining tests require the VM. Stopping here."
    info "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}, ${YELLOW}$SKIPPED skipped${NC}"
    exit "$FAILED"
fi

VM_STATUS=$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep "^brig " | awk '{print $2}')
if [ "$VM_STATUS" = "Running" ]; then
    pass "Lima VM is running"
else
    skip "Lima VM not running — run: limactl start brig"
    info ""
    info "Remaining tests require a running VM. Stopping here."
    info "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}, ${YELLOW}$SKIPPED skipped${NC}"
    exit "$FAILED"
fi

# Test VM connectivity.
if limactl shell --workdir / brig -- echo "hello from VM" >/dev/null 2>&1; then
    pass "limactl shell works"
else
    fail "limactl shell failed"
fi

# Test podman inside VM.
if limactl shell --workdir / brig -- sudo podman --version >/dev/null 2>&1; then
    PODMAN_VER=$(limactl shell --workdir / brig -- sudo podman --version 2>/dev/null)
    pass "podman in VM: $PODMAN_VER"
else
    fail "podman not available in VM"
fi

# Test gVisor (use --workdir / to avoid cwd issues when host path doesn't exist in VM).
if limactl shell --workdir / brig -- sudo test -x /usr/local/bin/runsc; then
    pass "gVisor (runsc) installed in VM"
else
    fail "gVisor not found in VM (provision VM with: limactl delete brig && make vm)"
fi

# ---------------------------------------------------------------------------
info ""
info "Phase 4: Warden proxy"
# ---------------------------------------------------------------------------

# Check if warden is running.
WARDEN_STATUS=$(limactl shell --workdir / brig -- sudo podman inspect warden --format '{{.State.Status}}' 2>/dev/null || echo "not found")
if [ "$WARDEN_STATUS" = "running" ]; then
    pass "Warden proxy is running"
else
    echo "  Warden not running, attempting start via brig up..."
    if $BRIG up 2>/dev/null; then
        pass "Warden started (via brig up)"
    else
        fail "Warden failed to start — run: make up"
    fi
fi

# ---------------------------------------------------------------------------
info ""
info "Phase 5: Cell lifecycle (the real test)"
# ---------------------------------------------------------------------------

CELL_NAME="smoke-test-$$"

# Test 1: brig run.
echo "  Running: $BRIG run --name $CELL_NAME -d alpine sleep 30"
if $BRIG run --name "$CELL_NAME" -d alpine sleep 30 2>&1; then
    pass "brig run"
else
    fail "brig run"
fi

# Test 2: brig list.
LIST_OUT=$($BRIG list 2>/dev/null)
if echo "$LIST_OUT" | grep -q "$CELL_NAME"; then
    pass "brig list shows cell"
else
    fail "brig list does not show cell (output: $LIST_OUT)"
fi

# Test 3: brig inspect.
if $BRIG inspect "$CELL_NAME" >/dev/null 2>&1; then
    pass "brig inspect"
else
    fail "brig inspect"
fi

# Test 4: Verify gVisor runtime.
# Podman 4.x doesn't populate HostConfig.Runtime reliably. Verify by
# checking dmesg inside the running container for gVisor's boot message.
DMESG=$(limactl shell --workdir / brig -- sudo podman exec "brig-$CELL_NAME" dmesg 2>/dev/null || echo "")
if echo "$DMESG" | grep -qi "gvisor\|Starting gVisor"; then
    pass "cell uses gVisor runtime (invariant 5)"
else
    # Fallback: check if the default runtime IS runsc.
    DEFAULT_RT=$(limactl shell --workdir / brig -- sudo podman info --format '{{.Host.OCIRuntime.Name}}' 2>/dev/null)
    if [ "$DEFAULT_RT" = "runsc" ]; then
        pass "cell uses gVisor runtime (invariant 5, via default)"
    else
        fail "cell runtime not gVisor (default: '$DEFAULT_RT')"
    fi
fi

# Test 5: Verify network isolation.
NETWORKS=$(limactl shell --workdir / brig -- sudo podman inspect "brig-$CELL_NAME" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null)
NET_COUNT=$(echo "$NETWORKS" | wc -w)
if [ "$NET_COUNT" -eq 1 ]; then
    pass "cell is single-homed (invariant 8): $NETWORKS"
else
    fail "cell has $NET_COUNT networks: $NETWORKS"
fi

# Test 6: Verify proxy env vars.
HTTP_PROXY=$(limactl shell --workdir / brig -- sudo podman inspect "brig-$CELL_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep "^http_proxy=" || echo "")
if echo "$HTTP_PROXY" | grep -q "8080"; then
    pass "proxy env vars set"
else
    fail "proxy env vars not set: $HTTP_PROXY"
fi

# Test 7: brig exec.
EXEC_OUT=$($BRIG exec "$CELL_NAME" echo "hello from cell" 2>/dev/null)
if echo "$EXEC_OUT" | grep -q "hello from cell"; then
    pass "brig exec"
else
    fail "brig exec output: $EXEC_OUT"
fi

# Test 8: brig stop.
if $BRIG stop "$CELL_NAME" 2>/dev/null; then
    pass "brig stop"
else
    fail "brig stop"
fi

# Test 9: brig rm.
if $BRIG rm "$CELL_NAME" 2>/dev/null; then
    pass "brig rm"
else
    fail "brig rm"
fi

# Test 10: Verify cleanup.
if ! $BRIG list 2>/dev/null | grep -q "$CELL_NAME"; then
    pass "cell removed from list"
else
    fail "cell still in list after rm"
fi

# ---------------------------------------------------------------------------
info ""
info "Phase 6: brig verify (security invariants)"
# ---------------------------------------------------------------------------

if $BRIG verify 2>&1; then
    pass "brig verify — all invariants"
else
    fail "brig verify reported issues"
fi

# ---------------------------------------------------------------------------
info ""
info "Phase 7: Airgapped cell"
# ---------------------------------------------------------------------------

AIR_NAME="smoke-air-$$"
echo "  Running airgapped cell..."
if $BRIG run --name "$AIR_NAME" --network none alpine echo "isolated" 2>&1; then
    pass "airgapped cell ran"
else
    fail "airgapped cell failed"
fi
$BRIG rm -f "$AIR_NAME" 2>/dev/null

# ---------------------------------------------------------------------------
info ""
info "Phase 8: Profile-based run"
# ---------------------------------------------------------------------------

PROF_NAME="smoke-prof-$$"
echo "  Running with untrusted profile..."
if $BRIG run --name "$PROF_NAME" --profile untrusted -d alpine sleep 10 2>&1; then
    pass "profile-based run"
    MEM=$(limactl shell --workdir / brig -- sudo podman inspect "brig-$PROF_NAME" --format '{{.HostConfig.Memory}}' 2>/dev/null)
    if [ "$MEM" = "536870912" ]; then
        pass "untrusted profile memory limit (512m)"
    else
        fail "memory limit: $MEM (expected 536870912 for 512m)"
    fi
    $BRIG rm -f "$PROF_NAME" 2>/dev/null
else
    fail "profile-based run"
fi

# ---------------------------------------------------------------------------
info ""
info "Phase 9: Proxy enforcement (policy test)"
# ---------------------------------------------------------------------------

POLICY_NAME="smoke-policy-$$"
echo "  Testing proxy blocks disallowed domain..."
if $BRIG run --name "$POLICY_NAME" -d alpine sleep 30 2>&1; then
    # Try to reach a domain NOT in the allowlist — should be blocked.
    # Use a domain that no reasonable policy would allowlist.
    BLOCKED_OUT=$(limactl shell --workdir / brig -- sudo podman exec "brig-$POLICY_NAME" \
        wget -q -O- --timeout=5 http://neverssl.com 2>&1 || echo "BLOCKED")
    if echo "$BLOCKED_OUT" | grep -qi "blocked\|forbidden\|refused\|timed out\|error\|403\|502"; then
        pass "proxy blocks disallowed domain (neverssl.com)"
    else
        fail "proxy did NOT block disallowed domain (output: $(echo "$BLOCKED_OUT" | head -c 200))"
    fi

    # Try to reach a domain IN the allowlist — should get through the proxy.
    # Use HTTP (not HTTPS) since alpine wget lacks CA certs by default.
    # A 301 redirect or 200 means the proxy allowed the request through.
    ALLOWED_CODE=$(limactl shell --workdir / brig -- sudo podman exec "brig-$POLICY_NAME" \
        wget --spider -S --timeout=10 http://github.com 2>&1 | grep -o "HTTP/[0-9.]* [0-9]*" | head -1 || echo "FAILED")
    if echo "$ALLOWED_CODE" | grep -q "HTTP"; then
        pass "proxy allows allowlisted domain (github.com → $ALLOWED_CODE)"
    else
        fail "proxy blocked allowed domain github.com"
    fi

    $BRIG rm -f "$POLICY_NAME" 2>/dev/null
else
    fail "policy test cell failed to start"
fi

# ---------------------------------------------------------------------------
info ""
info "=========================================="
info "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}, ${YELLOW}$SKIPPED skipped${NC}"
info "=========================================="

exit "$FAILED"
