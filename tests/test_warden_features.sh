#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_warden_features.sh - Warden lifecycle + feature tests
#
# Driven from the host warden CLI (which orchestrates the VM's warden
# container), plus VM inspection of the deployed addon set. Verifies:
#   - warden status reports the proxy running
#   - the warden container is actually up
#   - warden reload succeeds (live addon/policy reload)
#   - brig system prune --logs runs (host-orchestrated log pruning)
#   - the required + feature addons are deployed
#
# Usage: ./tests/test_warden_features.sh   (requires `brig system up` first)
# Exit: 0 all passed, 1 any failed.

source "$(dirname "$0")/lib/e2e_common.sh"

echo "============================================"
echo "Warden Feature Tests"
echo "============================================"
echo

echo "--- Pre-flight checks ---"
require_brig_up
echo "VM '$VM_NAME' is running; host brig OK"
echo

# Test 1: warden status reports the proxy running.
echo "--- Test 1: warden status reports proxy running ---"
if $WARDEN status 2>/dev/null | grep -qi "running"; then
    log_pass "warden status reports proxy running"
else
    log_fail "warden status does not report running"
fi

# Test 2: the warden container is actually up (liveness/health).
echo
echo "--- Test 2: warden container is up ---"
WARDEN_STATUS=$(run_in_vm sudo podman ps --filter name=^warden$ --format '{{.Status}}' 2>/dev/null || echo "")
if echo "$WARDEN_STATUS" | grep -qi "up"; then
    log_pass "warden container is up ($WARDEN_STATUS)"
else
    log_fail "warden container not up: '$WARDEN_STATUS'"
fi

# Test 3: warden reload succeeds (live addon/policy reload).
echo
echo "--- Test 3: warden reload ---"
if $WARDEN reload >/dev/null 2>&1; then
    log_pass "warden reload succeeded"
else
    log_fail "warden reload failed"
fi

# Test 4: host-orchestrated log pruning runs.
echo
echo "--- Test 4: brig system prune --logs (dry run) ---"
if $BRIG system prune --logs --log-days 30 --dry-run >/dev/null 2>&1; then
    log_pass "log prune (dry run) executed"
else
    log_fail "log prune failed"
fi

# Test 5: required addons are deployed.
echo
echo "--- Test 5: Required addons deployed ---"
MISSING=0
for addon in enforce.py logger.py ops.py; do
    if ! run_in_vm test -f "/cells/addons/$addon" 2>/dev/null; then
        echo "  Missing: $addon"; MISSING=$((MISSING + 1))
    fi
done
if [ "$MISSING" -eq 0 ]; then
    log_pass "Required addons (enforce, logger, ops) deployed"
else
    log_fail "Missing $MISSING required addon(s)"
fi

# Test 6: feature addons are deployed.
echo
echo "--- Test 6: Feature addons deployed ---"
FEATURE=0
for addon in ingress.py notifier.py otel_export.py; do
    if run_in_vm test -f "/cells/addons/$addon" 2>/dev/null; then
        FEATURE=$((FEATURE + 1))
    fi
done
if [ "$FEATURE" -eq 3 ]; then
    log_pass "Feature addons (ingress, notifier, otel_export) deployed"
else
    log_fail "Only $FEATURE/3 feature addons deployed"
fi

finish
