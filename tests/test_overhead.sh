#!/bin/bash
# test_overhead.sh - Stack overhead benchmarks
#
# Measures real-world latency and overhead of the Brig stack with
# statistical rigor: 10+ samples, warmup, median with IQR, outlier
# filtering via 1.5*IQR fence.
#
# Benchmarks:
#   1. Proxy latency:      Time added by Warden to each HTTP request
#   2. Cell startup time:  Wall-clock from `brig run` to container running
#   3. Cell stop/rm time:  Graceful shutdown + full cleanup
#   4. gVisor overhead:    Syscall-heavy workload under runsc
#   5. Request latency:    Per-request p50/p95 through full stack
#   6. Startup breakdown:  Network create, proxy connect, container start
#   7. Concurrent cells:   5 cells launched in parallel
#
# Usage: ./tests/test_overhead.sh [--json]
#
# Prerequisites:
#   - Lima VM running with brig installed
#   - Warden running: warden start
#
# Exit codes:
#   0 - All benchmarks completed
#   1 - Prerequisites not met

set -euo pipefail

VM_NAME="${CELL_VM_NAME:-cell}"
JSON_OUTPUT=false
RESULTS="{}"
WARMUP_RUNS=2
SAMPLE_RUNS=10
STARTUP_RUNS=5  # Fewer for startup to stay under rate limit (10/60s).

if [ "${1:-}" = "--json" ]; then
    JSON_OUTPUT=true
fi

# Colors.
if [ -t 1 ] && [ "$JSON_OUTPUT" = false ]; then
    C='\033[0;36m' G='\033[0;32m' Y='\033[0;33m' B='\033[1m' N='\033[0m'
else
    C='' G='' Y='' B='' N=''
fi

run_in_vm() {
    limactl shell "$VM_NAME" -- "$@"
}

# Return epoch milliseconds.
now_ms() {
    python3 -c "import time; print(int(time.time() * 1000))"
}

# Time a command, return milliseconds.
time_ms() {
    local start end
    start=$(now_ms)
    "$@" >/dev/null 2>&1 || true
    end=$(now_ms)
    echo $((end - start))
}

# Compute statistics from a space-separated list of numbers.
# Outputs: median q1 q3 iqr min max n_filtered
compute_stats() {
    python3 -c "
import sys
values = sorted(map(int, '$1'.split()))
n = len(values)
if n == 0:
    print('0 0 0 0 0 0 0')
    sys.exit()
q1 = values[n // 4]
median = values[n // 2]
q3 = values[3 * n // 4]
iqr = q3 - q1
fence_lo = q1 - 1.5 * iqr
fence_hi = q3 + 1.5 * iqr
filtered = [v for v in values if fence_lo <= v <= fence_hi]
f_median = filtered[len(filtered) // 2] if filtered else median
f_min = min(filtered) if filtered else min(values)
f_max = max(filtered) if filtered else max(values)
outliers = n - len(filtered)
print(f'{f_median} {q1} {q3} {iqr} {f_min} {f_max} {outliers}')
"
}

add_result() {
    local name="$1" median="$2" q1="$3" q3="$4" unit="$5"
    RESULTS=$(python3 -c "
import sys, json
d = json.loads('$RESULTS' if '$RESULTS' != '{}' else '{}')
d['$name'] = {'median': $median, 'q1': $q1, 'q3': $q3, 'unit': '$unit'}
print(json.dumps(d))
")
}

print_result() {
    local name="$1" median="$2" q1="$3" q3="$4" unit="$5" outliers="${6:-0}"
    local extra=""
    [ "$outliers" -gt 0 ] && extra=" (${outliers} outliers removed)"
    printf "  ${C}%-35s${N} %6s %-3s  [q1=%s q3=%s]%s\n" \
        "$name" "$median" "$unit" "$q1" "$q3" "$extra"
    add_result "$name" "$median" "$q1" "$q3" "$unit"
}

# --- Prerequisites ---

vm_status=$(limactl list --json 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        v = json.loads(line)
        if v.get('name') == '$VM_NAME':
            print(v.get('status', 'unknown')); break
    except json.JSONDecodeError: continue
else: print('not_found')
" 2>/dev/null || echo "unknown")

if [ "$vm_status" != "Running" ]; then
    echo "ERROR: VM '$VM_NAME' not running (status: $vm_status)"
    exit 1
fi

if ! run_in_vm sudo podman ps --filter name=^warden$ --format '{{.Names}}' 2>/dev/null | grep -q warden; then
    echo "ERROR: Warden not running. Start with: warden start"
    exit 1
fi

echo ""
echo -e "${B}Brig Stack Overhead Benchmarks${N}"
echo -e "${B}Samples: $SAMPLE_RUNS | Warmup: $WARMUP_RUNS | Outlier fence: 1.5*IQR${N}"
echo "=============================="
echo ""

# Cleanup.
for c in overhead-proxy overhead-start overhead-gvisor overhead-policy overhead-par-{1..5}; do
    run_in_vm sudo brig rm -f "$c" 2>/dev/null || true
done

# Pre-pull.
run_in_vm sudo podman pull alpine:latest >/dev/null 2>&1 || true

# Copy container benchmark script to VM.
BENCH_SCRIPT="$(dirname "${BASH_SOURCE[0]}")/benchmarks/container_bench.py"
if [ -f "$BENCH_SCRIPT" ]; then
    limactl cp "$BENCH_SCRIPT" "$VM_NAME":/tmp/container_bench.py 2>/dev/null || true
fi

# =========================================================================
# 1. PROXY LATENCY
# =========================================================================
echo -e "${B}1. Proxy Latency${N}"

run_in_vm sudo brig run --name overhead-proxy -d alpine sleep 600 2>/dev/null
sleep 2

# Warmup.
for i in $(seq 1 $WARMUP_RUNS); do
    run_in_vm sudo brig exec overhead-proxy -- wget -qO/dev/null http://httpbin.org/ip 2>/dev/null || true
done

# Sample proxied requests.
PROXY_SAMPLES=""
for i in $(seq 1 $SAMPLE_RUNS); do
    t=$(time_ms run_in_vm sudo brig exec overhead-proxy -- wget -qO/dev/null http://httpbin.org/ip)
    PROXY_SAMPLES="$PROXY_SAMPLES $t"
done
read -r P_MED P_Q1 P_Q3 P_IQR P_MIN P_MAX P_OUT <<< "$(compute_stats "$PROXY_SAMPLES")"
print_result "HTTPS through proxy" "$P_MED" "$P_Q1" "$P_Q3" "ms" "$P_OUT"

# Sample direct (from VM, no proxy).
for i in $(seq 1 $WARMUP_RUNS); do
    run_in_vm wget -qO/dev/null http://httpbin.org/ip 2>/dev/null || true
done
DIRECT_SAMPLES=""
for i in $(seq 1 $SAMPLE_RUNS); do
    t=$(time_ms run_in_vm wget -qO/dev/null http://httpbin.org/ip)
    DIRECT_SAMPLES="$DIRECT_SAMPLES $t"
done
read -r D_MED D_Q1 D_Q3 _ _ _ D_OUT <<< "$(compute_stats "$DIRECT_SAMPLES")"
print_result "HTTPS direct from VM" "$D_MED" "$D_Q1" "$D_Q3" "ms" "$D_OUT"

OVERHEAD=$((P_MED - D_MED))
echo -e "  ${G}Proxy overhead (median):${N}         ${OVERHEAD}ms"

run_in_vm sudo brig kill overhead-proxy 2>/dev/null || true
run_in_vm sudo brig rm -f overhead-proxy 2>/dev/null || true
echo ""

# =========================================================================
# 2. CELL STARTUP TIME
# =========================================================================
echo -e "${B}2. Cell Startup Time${N}"

START_SAMPLES=""
for i in $(seq 1 $STARTUP_RUNS); do
    t=$(time_ms run_in_vm sudo brig run --name overhead-start --rm alpine echo done)
    START_SAMPLES="$START_SAMPLES $t"
done
read -r S_MED S_Q1 S_Q3 _ _ _ S_OUT <<< "$(compute_stats "$START_SAMPLES")"
print_result "Cell startup (run+rm)" "$S_MED" "$S_Q1" "$S_Q3" "ms" "$S_OUT"
echo ""

# =========================================================================
# 3. CELL STOP + REMOVE
# =========================================================================
echo -e "${B}3. Cell Stop + Remove${N}"

run_in_vm sudo brig run --name overhead-start -d alpine sleep 600 2>/dev/null
sleep 1

STOP_T=$(time_ms run_in_vm sudo brig stop overhead-start)
RM_T=$(time_ms run_in_vm sudo brig rm -f overhead-start)
printf "  ${C}%-35s${N} %6s ms\n" "Cell stop (graceful)" "$STOP_T"
printf "  ${C}%-35s${N} %6s ms\n" "Cell remove (with cleanup)" "$RM_T"
add_result "cell_stop" "$STOP_T" "$STOP_T" "$STOP_T" "ms"
add_result "cell_remove" "$RM_T" "$RM_T" "$RM_T" "ms"
echo ""

# =========================================================================
# 4. RUNTIME COMPARISON: gVisor vs crun
# =========================================================================
echo -e "${B}4. Runtime Comparison: gVisor (runsc) vs Native (crun)${N}"
echo "   Measures the actual cost of gVisor's syscall interception."
echo "   Both run inside the same Lima VM with identical isolation."
echo ""

# Pre-start persistent containers to measure steady-state (not startup).
run_in_vm sudo podman run -d --runtime runsc --name bench-runsc alpine sleep 600 2>/dev/null
run_in_vm sudo podman run -d --runtime crun --name bench-crun alpine sleep 600 2>/dev/null
sleep 2

# 4a. Syscall overhead (steady-state).
echo "  Syscall-heavy (1000x open+read+close /proc/self/status):"
SHCMD='i=0; while [ $i -lt 1000 ]; do cat /proc/self/status > /dev/null; i=$((i+1)); done'

GS_SAMPLES=""
for i in $(seq 1 5); do
    t=$(time_ms run_in_vm sudo podman exec bench-runsc sh -c "$SHCMD")
    GS_SAMPLES="$GS_SAMPLES $t"
done
read -r GS_MED GS_Q1 GS_Q3 _ _ _ GS_OUT <<< "$(compute_stats "$GS_SAMPLES")"

CS_SAMPLES=""
for i in $(seq 1 5); do
    t=$(time_ms run_in_vm sudo podman exec bench-crun sh -c "$SHCMD")
    CS_SAMPLES="$CS_SAMPLES $t"
done
read -r CS_MED CS_Q1 CS_Q3 _ _ _ CS_OUT <<< "$(compute_stats "$CS_SAMPLES")"

print_result "  gVisor (runsc)" "$GS_MED" "$GS_Q1" "$GS_Q3" "ms" "$GS_OUT"
print_result "  Native (crun)" "$CS_MED" "$CS_Q1" "$CS_Q3" "ms" "$CS_OUT"
SC_RATIO=$(python3 -c "print(f'{$GS_MED / max($CS_MED, 1):.1f}')")
echo -e "  ${G}Overhead: ${SC_RATIO}x per syscall${N}"
add_result "runtime_syscall_gvisor" "$GS_MED" "$GS_Q1" "$GS_Q3" "ms"
add_result "runtime_syscall_crun" "$CS_MED" "$CS_Q1" "$CS_Q3" "ms"
echo ""

# 4b. Compute overhead (steady-state, no syscalls).
echo "  Compute-only (Python 100k iterations, no I/O):"

# Copy test script to both containers.
run_in_vm sudo bash -c 'echo "import time; s=time.perf_counter(); x=sum(i*i for i in range(100000)); print(int((time.perf_counter()-s)*1000))" > /tmp/compute.py'
run_in_vm sudo podman cp /tmp/compute.py bench-runsc:/compute.py 2>/dev/null || true
run_in_vm sudo podman cp /tmp/compute.py bench-crun:/compute.py 2>/dev/null || true

# Only run if python3 is available in the container.
GC_MS=$(run_in_vm sudo podman exec bench-runsc python3 /compute.py 2>/dev/null || echo "")
CC_MS=$(run_in_vm sudo podman exec bench-crun python3 /compute.py 2>/dev/null || echo "")

if [ -n "$GC_MS" ] && [ -n "$CC_MS" ]; then
    printf "  ${C}%-35s${N} %6s ms\n" "  gVisor (runsc)" "$GC_MS"
    printf "  ${C}%-35s${N} %6s ms\n" "  Native (crun)" "$CC_MS"
    COMP_RATIO=$(python3 -c "print(f'{int($GC_MS) / max(int($CC_MS), 1):.1f}')")
    echo -e "  ${G}Overhead: ${COMP_RATIO}x for pure compute${N}"
    add_result "runtime_compute_gvisor" "$GC_MS" "$GC_MS" "$GC_MS" "ms"
    add_result "runtime_compute_crun" "$CC_MS" "$CC_MS" "$CC_MS" "ms"
else
    echo "  (skipped — python3 not in alpine image)"
fi
echo ""

# 4c. Cold startup comparison.
echo "  Cold startup (podman run --rm echo):"

GR_SAMPLES=""
for i in $(seq 1 3); do
    t=$(time_ms run_in_vm sudo podman run --rm --runtime runsc alpine echo done)
    GR_SAMPLES="$GR_SAMPLES $t"
done
GR_MED=$(median "$GR_SAMPLES")

CR_SAMPLES=""
for i in $(seq 1 3); do
    t=$(time_ms run_in_vm sudo podman run --rm --runtime crun alpine echo done)
    CR_SAMPLES="$CR_SAMPLES $t"
done
CR_MED=$(median "$CR_SAMPLES")

printf "  ${C}%-35s${N} %6s ms\n" "  gVisor (runsc)" "$GR_MED"
printf "  ${C}%-35s${N} %6s ms\n" "  Native (crun)" "$CR_MED"
START_RATIO=$(python3 -c "print(f'{$GR_MED / max($CR_MED, 1):.1f}')")
echo -e "  ${G}Overhead: ${START_RATIO}x for cold start${N}"
add_result "runtime_startup_gvisor" "$GR_MED" "$GR_MED" "$GR_MED" "ms"
add_result "runtime_startup_crun" "$CR_MED" "$CR_MED" "$CR_MED" "ms"

run_in_vm sudo podman kill bench-runsc bench-crun 2>/dev/null || true
run_in_vm sudo podman rm -f bench-runsc bench-crun 2>/dev/null || true
echo ""

# =========================================================================
# 5. REQUEST LATENCY DISTRIBUTION
# =========================================================================
echo -e "${B}5. Request Latency Distribution${N}"

run_in_vm sudo brig run --name overhead-policy -d alpine sleep 600 2>/dev/null
sleep 2

# Warmup.
for i in $(seq 1 $WARMUP_RUNS); do
    run_in_vm sudo brig exec overhead-policy -- wget -qO/dev/null http://httpbin.org/status/200 2>/dev/null || true
done

REQ_SAMPLES=""
for i in $(seq 1 $SAMPLE_RUNS); do
    t=$(time_ms run_in_vm sudo brig exec overhead-policy -- wget -qO/dev/null http://httpbin.org/status/200)
    REQ_SAMPLES="$REQ_SAMPLES $t"
done

# Compute p50 and p95 from sorted filtered samples.
read -r R_P50 R_Q1 R_Q3 _ _ _ R_OUT <<< "$(compute_stats "$REQ_SAMPLES")"
R_P95=$(echo "$REQ_SAMPLES" | python3 -c "
import sys
v = sorted(map(int, sys.stdin.read().split()))
print(v[int(len(v) * 0.95)])
")
print_result "HTTP request p50" "$R_P50" "$R_Q1" "$R_Q3" "ms" "$R_OUT"
printf "  ${C}%-35s${N} %6s ms\n" "HTTP request p95" "$R_P95"
add_result "request_p95" "$R_P95" "$R_P95" "$R_P95" "ms"

run_in_vm sudo brig kill overhead-policy 2>/dev/null || true
run_in_vm sudo brig rm -f overhead-policy 2>/dev/null || true
echo ""

# =========================================================================
# 6. STARTUP BREAKDOWN
# =========================================================================
echo -e "${B}6. Startup Breakdown${N}"
echo "   Timing individual steps of cell creation"

# Time each step separately.
CELL="overhead-start"
T_SUBNET=$(time_ms run_in_vm sudo brig-subnet allocate "$CELL")
T_NETCREATE=$(time_ms run_in_vm sudo podman network create --internal "brig-$CELL")
T_CONNECT=$(time_ms run_in_vm sudo podman network connect "brig-$CELL" warden)
T_PODMAN=$(time_ms run_in_vm sudo podman run --rm --runtime runsc --name "brig-$CELL" \
    --network "brig-$CELL" alpine echo done)

# Cleanup.
run_in_vm sudo podman network disconnect "brig-$CELL" warden 2>/dev/null || true
run_in_vm sudo podman network rm "brig-$CELL" 2>/dev/null || true
run_in_vm sudo brig-subnet free "$CELL" 2>/dev/null || true

printf "  ${C}%-35s${N} %6s ms\n" "Subnet allocate" "$T_SUBNET"
printf "  ${C}%-35s${N} %6s ms\n" "Network create" "$T_NETCREATE"
printf "  ${C}%-35s${N} %6s ms\n" "Proxy connect" "$T_CONNECT"
printf "  ${C}%-35s${N} %6s ms\n" "Container run (runsc)" "$T_PODMAN"
TOTAL=$((T_SUBNET + T_NETCREATE + T_CONNECT + T_PODMAN))
printf "  ${G}%-35s${N} %6s ms\n" "Sum" "$TOTAL"
add_result "breakdown_subnet" "$T_SUBNET" "$T_SUBNET" "$T_SUBNET" "ms"
add_result "breakdown_network" "$T_NETCREATE" "$T_NETCREATE" "$T_NETCREATE" "ms"
add_result "breakdown_connect" "$T_CONNECT" "$T_CONNECT" "$T_CONNECT" "ms"
add_result "breakdown_container" "$T_PODMAN" "$T_PODMAN" "$T_PODMAN" "ms"
echo ""

# =========================================================================
# 7. CONCURRENT STARTUP
# =========================================================================
echo -e "${B}7. Concurrent Cell Startup${N}"

PAR_START=$(now_ms)
for i in $(seq 1 5); do
    run_in_vm sudo brig run --name "overhead-par-$i" -d alpine sleep 60 &
done
wait
PAR_END=$(now_ms)
PAR_T=$((PAR_END - PAR_START))
printf "  ${C}%-35s${N} %6s ms\n" "5 cells parallel startup" "$PAR_T"
add_result "concurrent_5" "$PAR_T" "$PAR_T" "$PAR_T" "ms"

for i in $(seq 1 5); do
    run_in_vm sudo brig kill "overhead-par-$i" 2>/dev/null || true
    run_in_vm sudo brig rm -f "overhead-par-$i" 2>/dev/null || true
done
echo ""

# =========================================================================
# SUMMARY
# =========================================================================
echo "=============================="
echo -e "${B}Summary${N}"
echo "=============================="
echo ""
echo "  Proxy overhead:     ${OVERHEAD}ms  (median of $SAMPLE_RUNS samples)"
echo "  Cell startup:       ${S_MED}ms  [q1=${S_Q1} q3=${S_Q3}]"
echo "  Cell stop:          ${STOP_T}ms"
echo "  Cell remove:        ${RM_T}ms"
echo "  gVisor 5k reads:    ${G_MED}ms  [q1=${G_Q1} q3=${G_Q3}]"
echo "  Request p50/p95:    ${R_P50}ms / ${R_P95}ms"
echo "  5 cells parallel:   ${PAR_T}ms"
echo "  Breakdown: subnet=${T_SUBNET} net=${T_NETCREATE} connect=${T_CONNECT} run=${T_PODMAN}ms"
echo ""

# Write JSON results.
RESULTS_FILE="${RESULTS_FILE:-/tmp/overhead-results.json}"
echo "$RESULTS" | python3 -m json.tool > "$RESULTS_FILE" 2>/dev/null || true

if [ "$JSON_OUTPUT" = true ]; then
    echo "$RESULTS" | python3 -m json.tool
fi

exit 0
