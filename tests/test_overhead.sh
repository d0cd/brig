#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_overhead.sh - Stack overhead benchmarks (informational; always exit 0)
#
# Measures real-world latency/overhead of the Brig stack with statistical
# rigor: warmup, multiple samples, median with IQR, 1.5*IQR outlier filtering.
# Host-orchestrated: brig runs on the host (timings include the lima-shell
# round-trip, which is what a real user pays). VM-internal steps (podman) are
# still measured via run_in_vm.
#
# Benchmarks: proxy latency, cell startup, stop/remove, gVisor vs crun,
# request latency distribution, startup breakdown, concurrent startup.
#
# Usage: ./tests/test_overhead.sh [--json]   (requires `brig system up` first)
# Exit: 0 (benchmarks completed) / 1 (prerequisites not met)

set -uo pipefail

BRIG="${BRIG:-uv run brig}"
VM_NAME="${BRIG_VM_NAME:-${CELL_VM_NAME:-brig}}"
JSON_OUTPUT=false
RESULTS="{}"
WARMUP_RUNS=2
SAMPLE_RUNS=10
STARTUP_RUNS=5  # Fewer for startup to stay under the rate limit (10/60s).
ALLOW="--policy-allow httpbin.org"

[ "${1:-}" = "--json" ] && JSON_OUTPUT=true

if [ -t 1 ] && [ "$JSON_OUTPUT" = false ]; then
    C='\033[0;36m' G='\033[0;32m' B='\033[1m' N='\033[0m'
else
    C='' G='' B='' N=''
fi

run_in_vm() { limactl shell "$VM_NAME" -- "$@"; }
now_ms() { python3 -c "import time; print(int(time.time() * 1000))"; }
time_ms() { local s e; s=$(now_ms); "$@" >/dev/null 2>&1 || true; e=$(now_ms); echo $((e - s)); }

# median q1 q3 iqr min max n_filtered  (1.5*IQR outlier fence)
compute_stats() {
    python3 -c "
import sys
values = sorted(map(int, '$1'.split()))
n = len(values)
if n == 0:
    print('0 0 0 0 0 0 0'); sys.exit()
q1 = values[n // 4]; median = values[n // 2]; q3 = values[3 * n // 4]
iqr = q3 - q1
lo, hi = q1 - 1.5 * iqr, q3 + 1.5 * iqr
filt = [v for v in values if lo <= v <= hi]
fm = filt[len(filt) // 2] if filt else median
print(f'{fm} {q1} {q3} {iqr} {min(filt) if filt else min(values)} {max(filt) if filt else max(values)} {n - len(filt)}')
"
}
# Convenience: median only.
median() { read -r m _ <<< "$(compute_stats "$1")"; echo "$m"; }

add_result() {
    RESULTS=$(python3 -c "
import json
d = json.loads('$RESULTS' if '$RESULTS' != '{}' else '{}')
d['$1'] = {'median': $2, 'q1': $3, 'q3': $4, 'unit': '$5'}
print(json.dumps(d))
")
}
print_result() {
    local name="$1" median="$2" q1="$3" q3="$4" unit="$5" outliers="${6:-0}"
    local extra=""; [ "$outliers" -gt 0 ] && extra=" (${outliers} outliers removed)"
    printf "  ${C}%-35s${N} %6s %-3s  [q1=%s q3=%s]%s\n" "$name" "$median" "$unit" "$q1" "$q3" "$extra"
    add_result "$name" "$median" "$q1" "$q3" "$unit"
}

# --- Prerequisites ---
if ! limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -q "^${VM_NAME} Running"; then
    echo "ERROR: VM '$VM_NAME' not running — run \`brig system up\` first."; exit 1
fi
if ! run_in_vm sudo podman ps --filter name=^warden$ --format '{{.Names}}' 2>/dev/null | grep -q warden; then
    echo "ERROR: Warden not running. Start with: brig system up"; exit 1
fi

cleanup_cells() {
    for c in overhead-proxy overhead-start overhead-policy overhead-par-{1..5}; do
        $BRIG cell rm -f "$c" >/dev/null 2>&1 || true
    done
}
cleanup_cells
run_in_vm sudo podman pull alpine:latest >/dev/null 2>&1 || true

echo ""
echo -e "${B}Brig Stack Overhead Benchmarks (host-orchestrated, VM: $VM_NAME)${N}"
echo -e "${B}Samples: $SAMPLE_RUNS | Warmup: $WARMUP_RUNS | Outlier fence: 1.5*IQR${N}"
echo "=============================="
echo ""

# 1. PROXY LATENCY
echo -e "${B}1. Proxy Latency${N}"
$BRIG run --name overhead-proxy $ALLOW -d alpine sleep 600 >/dev/null 2>&1
sleep 2
for i in $(seq 1 $WARMUP_RUNS); do $BRIG cell exec overhead-proxy -- wget -qO/dev/null http://httpbin.org/ip >/dev/null 2>&1 || true; done
PROXY_SAMPLES=""
for i in $(seq 1 $SAMPLE_RUNS); do
    t=$(time_ms $BRIG cell exec overhead-proxy -- wget -qO/dev/null http://httpbin.org/ip); PROXY_SAMPLES="$PROXY_SAMPLES $t"
done
read -r P_MED P_Q1 P_Q3 _ _ _ P_OUT <<< "$(compute_stats "$PROXY_SAMPLES")"
print_result "HTTP through proxy (cell)" "$P_MED" "$P_Q1" "$P_Q3" "ms" "$P_OUT"
for i in $(seq 1 $WARMUP_RUNS); do run_in_vm wget -qO/dev/null http://httpbin.org/ip >/dev/null 2>&1 || true; done
DIRECT_SAMPLES=""
for i in $(seq 1 $SAMPLE_RUNS); do t=$(time_ms run_in_vm wget -qO/dev/null http://httpbin.org/ip); DIRECT_SAMPLES="$DIRECT_SAMPLES $t"; done
read -r D_MED D_Q1 D_Q3 _ _ _ D_OUT <<< "$(compute_stats "$DIRECT_SAMPLES")"
print_result "HTTP direct from VM" "$D_MED" "$D_Q1" "$D_Q3" "ms" "$D_OUT"
OVERHEAD=$((P_MED - D_MED))
echo -e "  ${G}Proxy overhead (median):${N}         ${OVERHEAD}ms"
$BRIG cell rm -f overhead-proxy >/dev/null 2>&1 || true
echo ""

# 2. CELL STARTUP TIME
echo -e "${B}2. Cell Startup Time${N}"
START_SAMPLES=""
for i in $(seq 1 $STARTUP_RUNS); do
    t=$(time_ms $BRIG run --name overhead-start --rm alpine echo done)
    START_SAMPLES="$START_SAMPLES $t"
    $BRIG cell rm -f overhead-start >/dev/null 2>&1 || true
done
read -r S_MED S_Q1 S_Q3 _ _ _ S_OUT <<< "$(compute_stats "$START_SAMPLES")"
print_result "Cell startup (run+rm)" "$S_MED" "$S_Q1" "$S_Q3" "ms" "$S_OUT"
echo ""

# 3. CELL STOP + REMOVE
echo -e "${B}3. Cell Stop + Remove${N}"
$BRIG run --name overhead-start -d alpine sleep 600 >/dev/null 2>&1
sleep 1
STOP_T=$(time_ms $BRIG cell stop overhead-start)
RM_T=$(time_ms $BRIG cell rm -f overhead-start)
printf "  ${C}%-35s${N} %6s ms\n" "Cell stop (graceful)" "$STOP_T"
printf "  ${C}%-35s${N} %6s ms\n" "Cell remove (with cleanup)" "$RM_T"
add_result "cell_stop" "$STOP_T" "$STOP_T" "$STOP_T" "ms"
add_result "cell_remove" "$RM_T" "$RM_T" "$RM_T" "ms"
echo ""

# 4. RUNTIME COMPARISON: gVisor vs crun (VM-internal podman)
echo -e "${B}4. Runtime Comparison: gVisor (runsc) vs Native (crun)${N}"
run_in_vm sudo podman run -d --runtime runsc --name bench-runsc alpine sleep 600 >/dev/null 2>&1
run_in_vm sudo podman run -d --runtime crun --name bench-crun alpine sleep 600 >/dev/null 2>&1
sleep 2
SHCMD='i=0; while [ $i -lt 1000 ]; do cat /proc/self/status > /dev/null; i=$((i+1)); done'
GS_SAMPLES=""; for i in $(seq 1 5); do t=$(time_ms run_in_vm sudo podman exec bench-runsc sh -c "$SHCMD"); GS_SAMPLES="$GS_SAMPLES $t"; done
read -r GS_MED GS_Q1 GS_Q3 _ _ _ GS_OUT <<< "$(compute_stats "$GS_SAMPLES")"
CS_SAMPLES=""; for i in $(seq 1 5); do t=$(time_ms run_in_vm sudo podman exec bench-crun sh -c "$SHCMD"); CS_SAMPLES="$CS_SAMPLES $t"; done
read -r CS_MED CS_Q1 CS_Q3 _ _ _ CS_OUT <<< "$(compute_stats "$CS_SAMPLES")"
print_result "  gVisor (runsc) 1k reads" "$GS_MED" "$GS_Q1" "$GS_Q3" "ms" "$GS_OUT"
print_result "  Native (crun) 1k reads" "$CS_MED" "$CS_Q1" "$CS_Q3" "ms" "$CS_OUT"
echo -e "  ${G}Overhead: $(python3 -c "print(f'{$GS_MED / max($CS_MED, 1):.1f}')")x per syscall batch${N}"
echo "  Cold startup (podman run --rm echo):"
GR_SAMPLES=""; for i in $(seq 1 3); do t=$(time_ms run_in_vm sudo podman run --rm --runtime runsc alpine echo done); GR_SAMPLES="$GR_SAMPLES $t"; done
GR_MED=$(median "$GR_SAMPLES")
CR_SAMPLES=""; for i in $(seq 1 3); do t=$(time_ms run_in_vm sudo podman run --rm --runtime crun alpine echo done); CR_SAMPLES="$CR_SAMPLES $t"; done
CR_MED=$(median "$CR_SAMPLES")
printf "  ${C}%-35s${N} %6s ms\n" "  gVisor (runsc)" "$GR_MED"
printf "  ${C}%-35s${N} %6s ms\n" "  Native (crun)" "$CR_MED"
add_result "runtime_syscall_gvisor" "$GS_MED" "$GS_Q1" "$GS_Q3" "ms"
add_result "runtime_syscall_crun" "$CS_MED" "$CS_Q1" "$CS_Q3" "ms"
run_in_vm sudo podman rm -f bench-runsc bench-crun >/dev/null 2>&1 || true
echo ""

# 5. REQUEST LATENCY DISTRIBUTION
echo -e "${B}5. Request Latency Distribution${N}"
$BRIG run --name overhead-policy $ALLOW -d alpine sleep 600 >/dev/null 2>&1
sleep 2
for i in $(seq 1 $WARMUP_RUNS); do $BRIG cell exec overhead-policy -- wget -qO/dev/null http://httpbin.org/status/200 >/dev/null 2>&1 || true; done
REQ_SAMPLES=""; for i in $(seq 1 $SAMPLE_RUNS); do t=$(time_ms $BRIG cell exec overhead-policy -- wget -qO/dev/null http://httpbin.org/status/200); REQ_SAMPLES="$REQ_SAMPLES $t"; done
read -r R_P50 R_Q1 R_Q3 _ _ _ R_OUT <<< "$(compute_stats "$REQ_SAMPLES")"
R_P95=$(echo "$REQ_SAMPLES" | python3 -c "import sys; v=sorted(map(int, sys.stdin.read().split())); print(v[int(len(v)*0.95)] if v else 0)")
print_result "HTTP request p50" "$R_P50" "$R_Q1" "$R_Q3" "ms" "$R_OUT"
printf "  ${C}%-35s${N} %6s ms\n" "HTTP request p95" "$R_P95"
add_result "request_p95" "$R_P95" "$R_P95" "$R_P95" "ms"
$BRIG cell rm -f overhead-policy >/dev/null 2>&1 || true
echo ""

# 6. STARTUP BREAKDOWN (VM-internal podman steps; subnet alloc is host-side now)
echo -e "${B}6. Startup Breakdown (podman steps)${N}"
CELL="overhead-start"
T_NETCREATE=$(time_ms run_in_vm sudo podman network create --internal "brig-$CELL")
T_CONNECT=$(time_ms run_in_vm sudo podman network connect "brig-$CELL" warden)
T_PODMAN=$(time_ms run_in_vm sudo podman run --rm --runtime runsc --name "brig-$CELL" --network "brig-$CELL" alpine echo done)
run_in_vm sudo podman network disconnect "brig-$CELL" warden >/dev/null 2>&1 || true
run_in_vm sudo podman network rm "brig-$CELL" >/dev/null 2>&1 || true
printf "  ${C}%-35s${N} %6s ms\n" "Network create" "$T_NETCREATE"
printf "  ${C}%-35s${N} %6s ms\n" "Proxy connect" "$T_CONNECT"
printf "  ${C}%-35s${N} %6s ms\n" "Container run (runsc)" "$T_PODMAN"
add_result "breakdown_network" "$T_NETCREATE" "$T_NETCREATE" "$T_NETCREATE" "ms"
add_result "breakdown_connect" "$T_CONNECT" "$T_CONNECT" "$T_CONNECT" "ms"
add_result "breakdown_container" "$T_PODMAN" "$T_PODMAN" "$T_PODMAN" "ms"
echo ""

# 7. CONCURRENT STARTUP
echo -e "${B}7. Concurrent Cell Startup${N}"
PAR_START=$(now_ms)
for i in $(seq 1 5); do $BRIG run --name "overhead-par-$i" -d alpine sleep 60 >/dev/null 2>&1 & done
wait
PAR_END=$(now_ms); PAR_T=$((PAR_END - PAR_START))
printf "  ${C}%-35s${N} %6s ms\n" "5 cells parallel startup" "$PAR_T"
add_result "concurrent_5" "$PAR_T" "$PAR_T" "$PAR_T" "ms"
for i in $(seq 1 5); do $BRIG cell rm -f "overhead-par-$i" >/dev/null 2>&1 || true; done
echo ""

# SUMMARY
echo "=============================="
echo -e "${B}Summary${N}"
echo "=============================="
echo "  Proxy overhead:   ${OVERHEAD}ms  (median of $SAMPLE_RUNS samples)"
echo "  Cell startup:     ${S_MED}ms  [q1=${S_Q1} q3=${S_Q3}]"
echo "  Cell stop/remove: ${STOP_T}ms / ${RM_T}ms"
echo "  gVisor 1k reads:  ${GS_MED}ms  [q1=${GS_Q1} q3=${GS_Q3}] (crun ${CS_MED}ms)"
echo "  Request p50/p95:  ${R_P50}ms / ${R_P95}ms"
echo "  5 cells parallel: ${PAR_T}ms"
echo "  Breakdown: net=${T_NETCREATE} connect=${T_CONNECT} run=${T_PODMAN}ms"
echo ""

RESULTS_FILE="${RESULTS_FILE:-/tmp/overhead-results.json}"
echo "$RESULTS" | python3 -m json.tool > "$RESULTS_FILE" 2>/dev/null || true
[ "$JSON_OUTPUT" = true ] && echo "$RESULTS" | python3 -m json.tool
exit 0
