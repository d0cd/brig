#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_all.sh - Run all Brig shell verification suites
#
# Runs every shell e2e suite in order and aggregates the result. Each suite
# exits 0 only when it ran AND all its checks passed; any other outcome
# (preflight bail, missing tooling, a failed check) is a NONZERO exit. This
# runner keys off that exit code — so a suite that bails before printing a
# summary is reported as ERROR, never silently counted as "0 passed" (which
# previously let a no-op run print "All tests passed!").
#
# Requires brig to be up (`brig system up`). VM name defaults to `brig`;
# override with BRIG_VM_NAME (or the legacy CELL_VM_NAME).
#
# Usage: ./tests/test_all.sh
#
# Exit codes:
#   0 - Every suite ran and passed
#   1 - One or more suites failed or did not complete

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_PASSED=0
TOTAL_FAILED=0
FAILED_SUITES=()
SKIPPED_SUITES=()

# Resolve the VM name once and propagate to the suites, so a local run works
# without the caller exporting anything. An explicitly-set value (e.g. CI's
# CELL_VM_NAME=cell) is respected.
VM_NAME="${BRIG_VM_NAME:-${CELL_VM_NAME:-brig}}"
export BRIG_VM_NAME="$VM_NAME"
export CELL_VM_NAME="$VM_NAME"

# Colors for output.
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BOLD=''
    NC=''
fi

echo -e "${BOLD}================================================"
echo "Brig - Full Shell Verification Suite (VM: $VM_NAME)"
echo -e "================================================${NC}"
echo
echo "Running all test suites..."
echo

# Core verification suites — all host-orchestrated (drive the host `brig`
# CLI; inspect VM state via lima). These are expected to pass on a healthy
# `brig system up`.
SUITES=(
    "test_vm_foundation:VM Foundation"
    "test_proxy_policy:Proxy & Policy"
    "test_cell_lifecycle:Cell Lifecycle"
    "test_secrets:Secrets & State"
    "test_observability:Observability"
    "test_hardening:Hardening"
    "test_per_cell_policy:Per-Cell Policy"
    "test_warden_features:Warden Features"
    "test_invariants_7_8:Invariants 7 & 8"
    "test_stream_passthrough:Stream Passthrough (ingress SSE)"
)

# Run on their own (also wired into CI's e2e.yml), NOT here:
#   - test_ingress_replay_e2e.sh (does `brig system down/up` — disruptive)
#   - test_overhead.sh           (perf benchmarks, minutes-long, informational)
#
# A suite may exit 2 to SKIP (e.g. wrong platform / missing dep); a skip is
# reported, not failed.

# Pull "Passed:/Failed:" counts from a suite's output, stripping ANSI codes.
extract_count() {
    printf '%s\n' "$1" | grep -E "^$2:" | head -1 \
        | sed -E 's/.*: //; s/\x1b\[[0-9;]*m//g' | tr -d '[:space:]'
}

for suite in "${SUITES[@]}"; do
    script="${suite%%:*}"
    name="${suite##*:}"

    echo -e "${BOLD}--- Running: $name ---${NC}"

    # Run the suite, capturing output and (crucially) its exit code.
    output=$("$SCRIPT_DIR/${script}.sh" 2>&1)
    rc=$?

    passed=$(extract_count "$output" "Passed"); [ -z "$passed" ] && passed=0
    failed=$(extract_count "$output" "Failed"); [ -z "$failed" ] && failed=0
    TOTAL_PASSED=$((TOTAL_PASSED + passed))
    TOTAL_FAILED=$((TOTAL_FAILED + failed))

    if [ "$rc" -eq 2 ]; then
        # Suite opted out (wrong platform / missing dep / known limitation).
        reason=$(printf '%s\n' "$output" | grep -iE "^SKIP" | head -1 | sed 's/^SKIP:[[:space:]]*//')
        echo -e "  ${YELLOW}SKIPPED${NC}: ${reason:-suite skipped}"
        SKIPPED_SUITES+=("$name")
    elif [ "$rc" -eq 0 ]; then
        echo -e "  ${GREEN}PASSED${NC}: $passed tests"
    elif printf '%s\n' "$output" | grep -qE "^Passed:"; then
        # Ran to its summary but reported failing checks.
        echo -e "  ${RED}FAILED${NC}: $passed passed, $failed failed"
        FAILED_SUITES+=("$name ($failed failed)")
        printf '%s\n' "$output" | tail -n 20 | sed 's/^/    | /'
    else
        # Exited nonzero before any summary — preflight bail, missing tooling,
        # or a crash. NOT a pass; surface it loudly.
        echo -e "  ${RED}ERROR${NC}: suite did not complete (exit $rc, no summary) — preflight bail or missing tooling"
        FAILED_SUITES+=("$name (did not complete)")
        printf '%s\n' "$output" | tail -n 8 | sed 's/^/    | /'
    fi
    echo
done

# Summary.
echo -e "${BOLD}================================================"
echo "Final Summary"
echo -e "================================================${NC}"
echo -e "Total checks passed: ${GREEN}$TOTAL_PASSED${NC}"
echo -e "Total checks failed: ${RED}$TOTAL_FAILED${NC}"
[ "${#SKIPPED_SUITES[@]}" -gt 0 ] && echo -e "Skipped suites: ${YELLOW}${SKIPPED_SUITES[*]}${NC}"
echo

if [ "${#FAILED_SUITES[@]}" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All suites passed!${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}Suites with problems:${NC}"
    for suite in "${FAILED_SUITES[@]}"; do
        echo -e "  ${RED}- $suite${NC}"
    done
    exit 1
fi
