#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_per_cell_policy.sh - Per-cell network policy tests
#
# Cells are default-deny; egress is allowed per cell via --policy-allow (at
# create) or `brig policy set --allow` (at runtime). Verifies:
#   - A per-cell allow lets the cell reach that domain
#   - A domain not in the cell's allowlist is blocked (default-deny)
#   - deny takes precedence over allow
#   - policy show reflects the effective allow/deny
#   - Runtime policy updates take effect
#   - Wildcards and multiple domains are stored
#
# Usage: ./tests/test_per_cell_policy.sh   (requires `brig system up` first)
# Exit: 0 all passed, 1 any failed.

source "$(dirname "$0")/lib/e2e_common.sh"

POLICIES_DIR="${BRIG_HOME:-$HOME/.brig}/state/system/policies"

cleanup_test_cells() {
    echo "Cleaning up test cells..."
    for c in policy-cell-1 policy-cell-2 restricted-cell wildcard-cell multi-cell; do
        $BRIG cell rm -f "$c" 2>/dev/null || true
    done
}

echo "============================================"
echo "Per-Cell Network Policy Tests"
echo "============================================"
echo

echo "--- Pre-flight checks ---"
require_brig_up
echo "VM '$VM_NAME' is running; host brig OK"
echo

cleanup_test_cells

# Test 1: a per-cell allow lets the cell reach that domain.
echo "--- Test 1: Per-cell allow permits the domain ---"
$BRIG run -d --name policy-cell-1 --policy-allow example.com alpine sleep 600 >/dev/null 2>&1 || true
sleep 2
if in_cell policy-cell-1 wget -q -O /dev/null --timeout=10 http://example.com 2>/dev/null; then
    log_pass "Cell can reach allowed example.com"
else
    log_fail "Cell cannot reach allowed example.com"
fi

# Test 2: a different cell with its own allow reaches its domain.
echo
echo "--- Test 2: Custom allow permits example.org ---"
$BRIG run -d --name policy-cell-2 --policy-allow example.org alpine sleep 600 >/dev/null 2>&1 || true
sleep 2
if in_cell policy-cell-2 wget -q -O /dev/null --timeout=10 http://example.org/ 2>/dev/null; then
    log_pass "Cell with custom allow can reach example.org"
else
    log_fail "Cell with custom allow cannot reach example.org"
fi

# Test 3: a domain not in the cell's allowlist is blocked (default-deny).
echo
echo "--- Test 3: Default-deny blocks non-allowed domain ---"
if in_cell policy-cell-1 wget -q -O /dev/null --timeout=5 http://example.org/ 2>/dev/null; then
    log_fail "Cell reached example.org despite not allowing it"
else
    log_pass "Default-deny correctly blocks example.org"
fi

# Test 4: policy show reflects the cell's allowlist.
echo
echo "--- Test 4: brig policy show displays the allowlist ---"
POLICY_OUTPUT=$($BRIG policy show policy-cell-2 2>/dev/null || echo "")
if echo "$POLICY_OUTPUT" | grep -q "example.org"; then
    log_pass "brig policy show displays custom allowlist"
else
    log_fail "brig policy show missing custom domain"
fi

# Test 5: a runtime policy update takes effect.
echo
echo "--- Test 5: brig policy set updates policy at runtime ---"
$BRIG policy set policy-cell-1 --allow example.org >/dev/null 2>&1 || true
sleep 2
if in_cell policy-cell-1 wget -q -O /dev/null --timeout=10 http://example.org/ 2>/dev/null; then
    log_pass "Runtime policy update allows the new domain"
else
    log_fail "Runtime policy update not working"
fi

# Test 6: deny takes precedence over allow.
echo
echo "--- Test 6: deny overrides allow ---"
$BRIG run -d --name restricted-cell --policy-allow example.com --policy-deny example.com alpine sleep 600 >/dev/null 2>&1 || true
sleep 2
if in_cell restricted-cell wget -q -O /dev/null --timeout=5 http://example.com 2>/dev/null; then
    log_fail "deny did not override allow"
else
    log_pass "deny correctly overrides allow"
fi

# Test 7: per-cell policy file exists.
echo
echo "--- Test 7: Per-cell policy file created ---"
if [ -f "$POLICIES_DIR/policy-cell-2.json" ]; then
    log_pass "Per-cell policy file exists"
else
    log_fail "Per-cell policy file not created at $POLICIES_DIR/policy-cell-2.json"
fi

# Test 8: policy file removed when the cell is removed.
echo
echo "--- Test 8: Policy cleaned up on cell removal ---"
$BRIG cell rm -f policy-cell-2 >/dev/null 2>&1 || true
if [ -f "$POLICIES_DIR/policy-cell-2.json" ]; then
    log_fail "Policy file not cleaned up on rm"
else
    log_pass "Policy file cleaned up on cell removal"
fi

# Test 9: wildcard domains are stored in the per-cell policy.
echo
echo "--- Test 9: Wildcard domains stored in per-cell policy ---"
$BRIG run -d --name wildcard-cell --policy-allow "*.github.com" alpine sleep 600 >/dev/null 2>&1 || true
sleep 1
if $BRIG policy show wildcard-cell 2>/dev/null | grep -q '\*.github.com'; then
    log_pass "Wildcard domain stored in per-cell policy"
else
    log_fail "Wildcard domain not stored"
fi

# Test 10: multiple domains can be allowed on one cell.
echo
echo "--- Test 10: Multiple domains can be allowed ---"
$BRIG run -d --name multi-cell --policy-allow example.com --policy-allow github.com alpine sleep 600 >/dev/null 2>&1 || true
sleep 1
MULTI_OUTPUT=$($BRIG policy show multi-cell 2>/dev/null || echo "")
if echo "$MULTI_OUTPUT" | grep -q "example.com" && echo "$MULTI_OUTPUT" | grep -q "github.com"; then
    log_pass "Multiple domains supported in policy"
else
    log_fail "Multiple domains not in policy output: $MULTI_OUTPUT"
fi

echo
echo "--- Cleanup ---"
cleanup_test_cells

finish
