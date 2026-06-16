#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_proxy_policy.sh - Proxy and policy enforcement tests
#
# Verifies the mitmproxy-based egress proxy and per-cell policy:
#   - Warden runs hardened, on proxy-external, listening on 8080
#   - Allowlisted domains are allowed; everything else is blocked
#   - Internal IPs, literal public IPs, and non-80/443 ports are blocked
#   - Per-cell JSONL logs are written with the expected fields
#   - Wildcard domains match
#
# Decisions are asserted on the per-cell JSONL log (not just wget's exit code):
# the log is the authoritative proof the proxy saw the request and made the
# expected call, catching a bypass that "succeeds" without going through Warden.
#
# Usage: ./tests/test_proxy_policy.sh   (requires `brig system up` first)
# Exit: 0 all passed, 1 any failed.

source "$(dirname "$0")/lib/e2e_common.sh"

CELL=policy-test

# Assert the per-cell log has an entry for `host` with the expected disposition.
# Args: host expect_blocked ("true"|"false")
check_log_entry() {
    local host="$1" expect_blocked="$2"
    local log_file="/var/log/brig/network/${CELL}.jsonl"
    sleep 1  # async logger batches writes.
    run_in_vm sudo test -f "$log_file" || return 1
    run_in_vm sudo cat "$log_file" | python3 -c "
import sys, json
target, want = '$host', '$expect_blocked' == 'true'
for line in sys.stdin:
    try: e = json.loads(line)
    except Exception: continue
    if e.get('host') == target and bool(e.get('blocked', False)) == want:
        sys.exit(0)
sys.exit(1)
"
}
clear_cell_log() { run_in_vm sudo rm -f "/var/log/brig/network/${CELL}.jsonl" 2>/dev/null || true; }

echo "============================================"
echo "Proxy & Policy Enforcement Tests"
echo "============================================"
echo

echo "--- Pre-flight checks ---"
require_brig_up
run_in_vm test -f /cells/addons/enforce.py || { echo "ERROR: enforce addon missing"; exit 1; }
run_in_vm test -f /cells/addons/logger.py || { echo "ERROR: logger addon missing"; exit 1; }
echo "VM '$VM_NAME' is running; addons present"
echo

# Test 1: warden is running.
echo "--- Test 1: Warden proxy is running ---"
if $WARDEN status 2>/dev/null | grep -qi "running"; then log_pass "Warden running"; else log_fail "Warden not running"; fi

# Test 2: warden container shows up.
echo
echo "--- Test 2: Warden container is up ---"
if run_in_vm sudo podman ps --format '{{.Names}}' | grep -q "warden"; then log_pass "Warden container up"; else log_fail "Warden container not up"; fi

# Test 3: warden on proxy-external network.
echo
echo "--- Test 3: Warden attached to proxy-external network ---"
if run_in_vm sudo podman inspect warden --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | grep -q "proxy-external"; then
    log_pass "Warden on proxy-external network"
else
    log_fail "Warden not on proxy-external network"
fi

# Test 4: warden has a memory limit.
echo
echo "--- Test 4: Warden has memory limit ---"
WMEM=$(run_in_vm sudo podman inspect warden --format '{{.HostConfig.Memory}}' 2>/dev/null || echo 0)
if [ "${WMEM:-0}" -gt 0 ]; then log_pass "Warden memory limit: $WMEM"; else log_fail "Warden missing memory limit"; fi

# Test 5: warden runs the brig-warden image (built from the pinned mitmproxy base).
echo
echo "--- Test 5: Warden runs the brig-warden image ---"
if run_in_vm sudo podman inspect warden --format '{{.Config.Image}}' 2>/dev/null | grep -qE "warden|mitmproxy"; then log_pass "warden image"; else log_fail "unexpected image"; fi

# Test 6: warden listens on 8080 (0x1F90, LISTEN=0A).
echo
echo "--- Test 6: Warden listens on port 8080 ---"
if run_in_vm sudo podman exec warden cat /proc/net/tcp 2>/dev/null | grep -q "00000000:1F90.*0A"; then
    log_pass "Warden listening on 8080"
else
    log_fail "Warden not listening on 8080"
fi

# Set up a policy-test cell that allows example.com (+ wildcard).
echo
echo "--- Setting up policy-test cell ---"
$BRIG cell rm -f "$CELL" 2>/dev/null || true
$BRIG run -d --name "$CELL" --policy-allow example.com --policy-allow "*.example.com" alpine sleep 600 >/dev/null 2>&1 || true
sleep 2

# Test 7: allowlisted domain is allowed (blocked=false in log).
echo
echo "--- Test 7: Allowlisted domain (example.com) allowed ---"
clear_cell_log
in_cell "$CELL" wget -q -O /dev/null --timeout=10 http://example.com 2>/dev/null || true
if check_log_entry example.com false; then log_pass "example.com allowed (blocked=false logged)"; else log_fail "no blocked=false entry for example.com"; fi

# Test 8: non-allowlisted domain blocked.
echo
echo "--- Test 8: Non-allowlisted domain (evil.com) blocked ---"
clear_cell_log
in_cell "$CELL" wget -q -O /dev/null --timeout=5 http://evil.com 2>/dev/null || true
if check_log_entry evil.com true; then log_pass "evil.com blocked (blocked=true logged)"; else log_fail "no blocked=true entry for evil.com"; fi

# Test 9: internal IP blocked.
echo
echo "--- Test 9: Internal IP (192.168.1.1) blocked ---"
clear_cell_log
in_cell "$CELL" wget -q -O /dev/null --timeout=5 http://192.168.1.1 2>/dev/null || true
if check_log_entry 192.168.1.1 true; then log_pass "internal IP blocked"; else log_fail "no blocked=true entry for 192.168.1.1"; fi

# Test 10: literal public IP blocked.
echo
echo "--- Test 10: Literal public IP (93.184.216.34) blocked ---"
clear_cell_log
in_cell "$CELL" wget -q -O /dev/null --timeout=5 http://93.184.216.34 2>/dev/null || true
if check_log_entry 93.184.216.34 true; then log_pass "literal public IP blocked"; else log_fail "no blocked=true entry for 93.184.216.34"; fi

# Test 11: non-80/443 port blocked.
echo
echo "--- Test 11: Non-HTTP port (example.com:8080) blocked ---"
clear_cell_log
in_cell "$CELL" wget -q -O /dev/null --timeout=5 http://example.com:8080 2>/dev/null || true
if check_log_entry example.com true; then log_pass "non-standard port blocked"; else log_fail "no blocked=true entry for example.com:8080"; fi

# Test 12: per-cell log file is created.
echo
echo "--- Test 12: Per-cell JSONL log created ---"
if run_in_vm sudo test -f "/var/log/brig/network/${CELL}.jsonl"; then log_pass "per-cell log exists"; else log_fail "per-cell log missing"; fi

# Test 13: log entry has the required fields.
echo
echo "--- Test 13: Log entry has required fields ---"
LOG_ENTRY=$(run_in_vm sudo cat "/var/log/brig/network/${CELL}.jsonl" 2>/dev/null | head -1)
if echo "$LOG_ENTRY" | grep -q '"cell"' && echo "$LOG_ENTRY" | grep -q '"host"' && \
   echo "$LOG_ENTRY" | grep -q '"method"' && echo "$LOG_ENTRY" | grep -q '"ts"'; then
    log_pass "log entry has cell/host/method/ts"
else
    log_fail "log entry missing fields: $LOG_ENTRY"
fi

# Test 14: wildcard subdomain allowed.
echo
echo "--- Test 14: Wildcard subdomain (www.example.com) allowed ---"
clear_cell_log
in_cell "$CELL" wget -q -O /dev/null --timeout=10 http://www.example.com 2>/dev/null || true
if check_log_entry www.example.com false; then log_pass "wildcard subdomain allowed"; else log_fail "wildcard subdomain not allowed"; fi

# Test 15: warden survived all the policy traffic.
echo
echo "--- Test 15: Warden still running after policy traffic ---"
if run_in_vm sudo podman ps --format '{{.Names}}' | grep -q "warden"; then log_pass "Warden still running"; else log_fail "Warden died"; fi

echo
echo "--- Cleanup ---"
$BRIG cell rm -f "$CELL" 2>/dev/null || true

finish
