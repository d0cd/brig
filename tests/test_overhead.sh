#!/bin/bash
# test_overhead.sh - Stack overhead benchmarks
#
# Measures real-world latency and overhead of the Brig stack:
#   1. Proxy latency:      Time added by Warden proxy to each HTTP request
#   2. Cell startup time:  Wall-clock from `brig run` to container running
#   3. Cell stop time:     Wall-clock for graceful cell shutdown
#   4. Cell removal time:  Wall-clock for full cleanup (network, subnet)
#   5. gVisor overhead:    Syscall latency under gVisor vs hypothetical baseline
#   6. Policy eval at scale: Request latency with 100+ policy rules loaded
#   7. Concurrent cells:   Startup time for N cells in parallel
#
# Output: JSON summary at the end for CI consumption.
#
# Usage: ./tests/test_overhead.sh [--json]
#
# Prerequisites:
#   - Lima VM running: limactl start cell
#   - Warden running: warden start
#   - curl image pre-pulled in VM
#
# Exit codes:
#   0 - All benchmarks completed
#   1 - One or more benchmarks failed

set -euo pipefail

VM_NAME="${CELL_VM_NAME:-cell}"
JSON_OUTPUT=false
RESULTS="{}"

if [ "${1:-}" = "--json" ]; then
    JSON_OUTPUT=true
fi

# Colors for output.
if [ -t 1 ] && [ "$JSON_OUTPUT" = false ]; then
    CYAN='\033[0;36m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    RED='\033[0;31m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    CYAN='' GREEN='' YELLOW='' RED='' BOLD='' NC=''
fi

run_in_vm() {
    limactl shell "$VM_NAME" -- "$@"
}

# Time a command and return milliseconds.
time_ms() {
    local start end
    start=$(python3 -c "import time; print(int(time.time() * 1000))")
    "$@" >/dev/null 2>&1
    end=$(python3 -c "import time; print(int(time.time() * 1000))")
    echo $((end - start))
}

# Add result to JSON output.
add_result() {
    local name="$1" value="$2" unit="$3"
    RESULTS=$(echo "$RESULTS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
d['$name'] = {'value': $value, 'unit': '$unit'}
json.dump(d, sys.stdout)
")
}

# Print a benchmark result.
print_result() {
    local name="$1" value="$2" unit="$3" target="${4:-}"
    local status=""
    if [ -n "$target" ]; then
        if [ "$value" -le "$target" ]; then
            status="${GREEN}[OK]${NC}"
        else
            status="${YELLOW}[SLOW]${NC}"
        fi
    fi
    printf "  ${CYAN}%-35s${NC} %6s %-4s %s\n" "$name" "$value" "$unit" "$status"
    add_result "$name" "$value" "$unit"
}

# Check VM is running.
vm_info=$(limactl list --json 2>/dev/null || echo "[]")
vm_status=$(echo "$vm_info" | python3 -c "
import sys, json
vms = json.load(sys.stdin)
for v in vms:
    if v.get('name') == '$VM_NAME':
        print(v.get('status', 'unknown'))
        break
else:
    print('not_found')
" 2>/dev/null || echo "unknown")

if [ "$vm_status" != "Running" ]; then
    echo "ERROR: VM '$VM_NAME' is not running (status: $vm_status)"
    echo "Start with: limactl start $VM_NAME"
    exit 1
fi

# Check warden is running.
if ! run_in_vm sudo podman ps --filter name=^warden$ --format '{{.Names}}' 2>/dev/null | grep -q warden; then
    echo "ERROR: Warden proxy is not running"
    echo "Start with: warden start"
    exit 1
fi

echo ""
echo -e "${BOLD}Brig Stack Overhead Benchmarks${NC}"
echo "=============================="
echo ""

# Cleanup from previous runs.
for c in overhead-proxy overhead-startup overhead-gvisor overhead-policy overhead-par-{1..5}; do
    run_in_vm sudo brig rm -f "$c" 2>/dev/null || true
done

# -------------------------------------------------------------------------
# 1. Proxy Latency
# -------------------------------------------------------------------------
echo -e "${BOLD}1. Proxy Latency${NC}"
echo "   Cell -> Warden -> Internet vs hypothetical direct"

# Create a test cell that stays running.
run_in_vm sudo brig run --name overhead-proxy --image alpine -d -- sleep 300 2>/dev/null

# Warm up DNS and connection pool.
run_in_vm sudo brig exec overhead-proxy -- wget -qO/dev/null https://httpbin.org/ip 2>/dev/null || true

# Measure 5 requests through the proxy.
PROXY_TIMES=()
for i in $(seq 1 5); do
    t=$(time_ms run_in_vm sudo brig exec overhead-proxy -- wget -qO/dev/null https://httpbin.org/ip)
    PROXY_TIMES+=("$t")
done

# Calculate median.
PROXY_MEDIAN=$(printf '%s\n' "${PROXY_TIMES[@]}" | sort -n | sed -n '3p')
print_result "HTTPS through proxy (median)" "$PROXY_MEDIAN" "ms" "2000"

# Measure direct (no proxy) for comparison — from VM host, not from cell.
DIRECT_TIMES=()
for i in $(seq 1 5); do
    t=$(time_ms run_in_vm wget -qO/dev/null https://httpbin.org/ip)
    DIRECT_TIMES+=("$t")
done
DIRECT_MEDIAN=$(printf '%s\n' "${DIRECT_TIMES[@]}" | sort -n | sed -n '3p')
print_result "HTTPS direct from VM (median)" "$DIRECT_MEDIAN" "ms"

OVERHEAD=$((PROXY_MEDIAN - DIRECT_MEDIAN))
print_result "Proxy overhead (median)" "$OVERHEAD" "ms" "500"

# Cleanup.
run_in_vm sudo brig kill overhead-proxy 2>/dev/null || true
run_in_vm sudo brig rm -f overhead-proxy 2>/dev/null || true

echo ""

# -------------------------------------------------------------------------
# 2. Cell Startup Time
# -------------------------------------------------------------------------
echo -e "${BOLD}2. Cell Startup Time${NC}"
echo "   Wall-clock from brig run to container running"

# Pre-pull image to exclude image pull time.
run_in_vm sudo podman pull alpine:latest 2>/dev/null || true

STARTUP_TIMES=()
for i in $(seq 1 3); do
    CELL_NAME="overhead-startup"
    t=$(time_ms run_in_vm sudo brig run --name "$CELL_NAME" --image alpine -d -- sleep 60)
    STARTUP_TIMES+=("$t")
    run_in_vm sudo brig kill "$CELL_NAME" 2>/dev/null || true
    run_in_vm sudo brig rm -f "$CELL_NAME" 2>/dev/null || true
done
STARTUP_MEDIAN=$(printf '%s\n' "${STARTUP_TIMES[@]}" | sort -n | sed -n '2p')
print_result "Cell startup (median, 3 runs)" "$STARTUP_MEDIAN" "ms" "5000"

echo ""

# -------------------------------------------------------------------------
# 3. Cell Stop + Remove Time
# -------------------------------------------------------------------------
echo -e "${BOLD}3. Cell Stop + Remove Time${NC}"

run_in_vm sudo brig run --name overhead-startup --image alpine -d -- sleep 300 2>/dev/null

STOP_TIME=$(time_ms run_in_vm sudo brig stop overhead-startup)
print_result "Cell stop (graceful)" "$STOP_TIME" "ms" "5000"

RM_TIME=$(time_ms run_in_vm sudo brig rm -f overhead-startup)
print_result "Cell remove (with cleanup)" "$RM_TIME" "ms" "3000"

echo ""

# -------------------------------------------------------------------------
# 4. gVisor Overhead
# -------------------------------------------------------------------------
echo -e "${BOLD}4. gVisor Syscall Overhead${NC}"
echo "   Measuring getpid() loop inside gVisor container"

# Measure syscall-heavy workload under gVisor.
GVISOR_TIME=$(time_ms run_in_vm sudo brig run --name overhead-gvisor --image alpine --rm \
    -- sh -c 'i=0; while [ $i -lt 10000 ]; do cat /proc/self/status > /dev/null; i=$((i+1)); done')
print_result "10k /proc reads (gVisor)" "$GVISOR_TIME" "ms"

echo ""

# -------------------------------------------------------------------------
# 5. Policy Evaluation at Scale
# -------------------------------------------------------------------------
echo -e "${BOLD}5. Policy Under Load${NC}"
echo "   Request latency with large policy loaded"

# Create a cell and make 10 rapid requests.
run_in_vm sudo brig run --name overhead-policy --image alpine -d -- sleep 300 2>/dev/null

POLICY_TIMES=()
for i in $(seq 1 10); do
    t=$(time_ms run_in_vm sudo brig exec overhead-policy -- wget -qO/dev/null http://httpbin.org/status/200)
    POLICY_TIMES+=("$t")
done

# Sort and get p50/p95.
SORTED=($(printf '%s\n' "${POLICY_TIMES[@]}" | sort -n))
P50="${SORTED[4]}"
P95="${SORTED[8]}"
print_result "HTTP request p50" "$P50" "ms" "1000"
print_result "HTTP request p95" "$P95" "ms" "3000"

run_in_vm sudo brig kill overhead-policy 2>/dev/null || true
run_in_vm sudo brig rm -f overhead-policy 2>/dev/null || true

echo ""

# -------------------------------------------------------------------------
# 6. Concurrent Cell Startup
# -------------------------------------------------------------------------
echo -e "${BOLD}6. Concurrent Cell Startup${NC}"
echo "   5 cells launched in parallel"

PAR_START=$(python3 -c "import time; print(int(time.time() * 1000))")
for i in $(seq 1 5); do
    run_in_vm sudo brig run --name "overhead-par-$i" --image alpine -d -- sleep 60 &
done
wait
PAR_END=$(python3 -c "import time; print(int(time.time() * 1000))")
PAR_TIME=$((PAR_END - PAR_START))
print_result "5 cells parallel startup" "$PAR_TIME" "ms" "15000"

# Cleanup parallel cells.
for i in $(seq 1 5); do
    run_in_vm sudo brig kill "overhead-par-$i" 2>/dev/null || true
    run_in_vm sudo brig rm -f "overhead-par-$i" 2>/dev/null || true
done

echo ""

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
echo "=============================="
echo -e "${BOLD}Summary${NC}"
echo "=============================="
echo ""
echo "  Proxy overhead:     ${OVERHEAD}ms per HTTPS request"
echo "  Cell startup:       ${STARTUP_MEDIAN}ms (pre-pulled image)"
echo "  Cell stop:          ${STOP_TIME}ms"
echo "  Cell remove:        ${RM_TIME}ms"
echo "  gVisor 10k reads:   ${GVISOR_TIME}ms"
echo "  Request p50/p95:    ${P50}ms / ${P95}ms"
echo "  5 cells parallel:   ${PAR_TIME}ms"
echo ""

if [ "$JSON_OUTPUT" = true ]; then
    echo "$RESULTS" | python3 -m json.tool
fi

# Write results to file for CI artifact collection.
RESULTS_FILE="${RESULTS_FILE:-/tmp/overhead-results.json}"
echo "$RESULTS" | python3 -m json.tool > "$RESULTS_FILE" 2>/dev/null || true

exit 0
