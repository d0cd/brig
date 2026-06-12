#!/bin/bash
# test_containment_e2e.sh — adversarial-cell containment red-team (Tier-1).
#
# Codifies the "agent tries to break a brig cell" probe as a repeatable e2e
# test. An adversarial workload inside a cell attempts the Tier-1 escapes that
# map to brig's network invariants, and we assert brig both PREVENTS the escape
# AND DETECTS it (Warden logged the policy decision) — for brig, "contained but
# invisible" is a partial failure, so every block must show in the per-cell log.
#
# Covered (Tier-1 — policy/topology claims):
#   - Egress to a non-allowlisted host is blocked + logged.       (Warden default-deny)
#   - Egress to a private / cloud-metadata IP is blocked + logged. (SSRF / rebinding guard)
#   - A second cell is unreachable (no east-west).                 (invariant 1)
#   - An airgapped cell has no egress at all.                      (invariant 8 / network: none)
#   - `brig verify` still passes (invariants intact after the assault).
#
# NOT covered here (see docs/ROADMAP.md): gVisor->VM escape (Tier-2, expected-
# possible defense-in-depth), VM->macOS escape (Tier-3, the real boundary), and
# the host-side symlink confused-deputy (unit-tested in test_mount_scan.py;
# full mount-escape e2e needs mount_roots + a VM restart to wire).
#
# Usage: ./tests/test_containment_e2e.sh   (requires `brig system up` first)
# Exit: 0 all passed, 1 any failed.

set -uo pipefail

BRIG="${BRIG:-uv run brig}"
VM_NAME="${BRIG_VM_NAME:-brig}"
PASSED=0
FAILED=0

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi
pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASSED=$((PASSED + 1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1"; FAILED=$((FAILED + 1)); }
info() { echo -e "${YELLOW}$1${NC}"; }

run_in_vm() { limactl shell "$VM_NAME" -- "$@"; }

# Run a command inside a cell's container (cells reach the net only via Warden,
# since brig injects http(s)_proxy pointing at the proxy).
in_cell() {
    local cell="$1"; shift
    run_in_vm sudo podman exec "brig-${cell}" "$@"
}

# Detection half: prove Warden processed the request and recorded the expected
# decision for `host`. Stronger than "the request failed" — catches a bypass
# where traffic reached the net without Warden seeing it.
log_has_decision() {
    local cell="$1" host="$2" want_blocked="$3"
    local log="/var/log/brig/network/${cell}.jsonl"
    sleep 1  # mitmproxy batches log writes.
    run_in_vm sudo test -f "$log" || return 1
    run_in_vm sudo cat "$log" | python3 -c "
import sys, json
host, want = '$host', '$want_blocked' == 'true'
for line in sys.stdin:
    try: e = json.loads(line)
    except Exception: continue
    if e.get('host') == host and bool(e.get('blocked', False)) == want:
        sys.exit(0)
sys.exit(1)
"
}

cleanup() {
    $BRIG cell rm -f attacker 2>/dev/null || true
    $BRIG cell rm -f bystander 2>/dev/null || true
    $BRIG cell rm -f airgap-probe 2>/dev/null || true
}
trap cleanup EXIT

echo "============================================"
echo "Containment red-team (Tier-1)"
echo "============================================"

# Pre-flight: VM must be up.
if ! limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -q "^${VM_NAME} Running"; then
    echo "ERROR: VM '$VM_NAME' is not running — run \`brig system up\` first." >&2
    exit 1
fi

# An adversarial cell with a deliberately narrow allowlist (github.com only).
info "--- Launching adversarial cell (allow: github.com) ---"
if ! $BRIG run --name attacker -d --policy-allow github.com alpine sleep 120 2>&1; then
    echo "ERROR: could not launch attacker cell" >&2
    exit 1
fi

# T1 — egress to a non-allowlisted host: blocked + logged.
info "--- T1: egress bypass (non-allowlisted host) ---"
OUT=$(in_cell attacker wget -q -O- --timeout=5 http://neverssl.com 2>&1 || echo BLOCKED)
if echo "$OUT" | grep -qiE "blocked|forbidden|refused|timed out|error|403|502|BLOCKED"; then
    pass "T1a prevent: egress to neverssl.com refused"
else
    fail "T1a prevent: egress NOT blocked (got: $(echo "$OUT" | head -c 120))"
fi
if log_has_decision attacker neverssl.com true; then
    pass "T1b detect: Warden logged the block for neverssl.com"
else
    fail "T1b detect: no blocked log entry for neverssl.com (bypassed Warden?)"
fi

# T2 — SSRF / private + cloud-metadata IP: blocked + logged.
info "--- T2: SSRF to cloud-metadata IP (169.254.169.254) ---"
OUT=$(in_cell attacker wget -q -O- --timeout=5 http://169.254.169.254/ 2>&1 || echo BLOCKED)
if echo "$OUT" | grep -qiE "blocked|forbidden|refused|timed out|error|403|502|BLOCKED"; then
    pass "T2a prevent: egress to 169.254.169.254 refused"
else
    fail "T2a prevent: metadata IP NOT blocked (got: $(echo "$OUT" | head -c 120))"
fi
if log_has_decision attacker 169.254.169.254 true; then
    pass "T2b detect: Warden logged the block for 169.254.169.254"
else
    fail "T2b detect: no blocked log entry for 169.254.169.254"
fi

# T3 — east-west: a second cell must be unreachable (invariant 1).
info "--- T3: east-west to a second cell ---"
$BRIG run --name bystander -d alpine sleep 120 >/dev/null 2>&1 || true
BYSTANDER_IP=$(run_in_vm sudo podman inspect brig-bystander \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null | tr -d '\r')
if [ -n "$BYSTANDER_IP" ]; then
    OUT=$(in_cell attacker wget -q -O- --timeout=5 "http://${BYSTANDER_IP}/" 2>&1 || echo UNREACHABLE)
    if echo "$OUT" | grep -qiE "unreachable|refused|timed out|no route|error|UNREACHABLE"; then
        pass "T3 prevent: second cell ($BYSTANDER_IP) is unreachable (no east-west)"
    else
        fail "T3 prevent: reached another cell! (got: $(echo "$OUT" | head -c 120))"
    fi
else
    fail "T3 setup: could not determine bystander cell IP"
fi

# T4 — airgapped cell has no egress at all.
info "--- T4: airgapped cell (network: none) ---"
$BRIG run --name airgap-probe -d --network none alpine sleep 60 >/dev/null 2>&1 || true
OUT=$(in_cell airgap-probe wget -q -O- --timeout=5 http://github.com 2>&1 || echo NOEGRESS)
if echo "$OUT" | grep -qiE "bad address|unreachable|refused|timed out|error|NOEGRESS"; then
    pass "T4 prevent: airgapped cell has no egress"
else
    fail "T4 prevent: airgapped cell reached the network! (got: $(echo "$OUT" | head -c 120))"
fi

# T5 — invariants intact after the assault.
info "--- T5: brig verify (invariants intact) ---"
if $BRIG system verify >/dev/null 2>&1; then
    pass "T5: brig verify passes after the red-team"
else
    fail "T5: brig verify FAILED after the red-team"
fi

echo
echo "============================================"
echo -e "Containment: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}"
echo "============================================"
[ "$FAILED" -eq 0 ]
