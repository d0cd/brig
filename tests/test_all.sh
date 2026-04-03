#!/bin/bash
# test_all.sh - Run all Cell test suites
#
# Runs all verification test suites in order:
#   1. VM Foundation - Basic infrastructure
#   2. Subnet Allocator - Network allocation
#   3. Proxy Policy - Egress enforcement
#   4. Cell Lifecycle - Core operations
#   5. Secrets - Secrets handling
#   6. Observability - Diagnostic commands
#   7. Hardening - Security hardening
#
# Usage: ./tests/test_all.sh
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_PASSED=0
TOTAL_FAILED=0
FAILED_SUITES=()

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
echo "Cell - Full Verification Test Suite"
echo -e "================================================${NC}"
echo
echo "Running all test suites..."
echo

# Test suites to run in order.
SUITES=(
    "test_vm_foundation:VM Foundation"
    "test_subnet_allocator:Subnet Allocator"
    "test_proxy_policy:Proxy & Policy"
    "test_cell_lifecycle:Cell Lifecycle"
    "test_secrets:Secrets & State"
    "test_observability:Observability"
    "test_hardening:Hardening"
    "test_per_cell_policy:Per-Cell Policy"
    "test_warden_features:Warden Features"
    "test_overhead:Stack Overhead Benchmarks"
)

for suite in "${SUITES[@]}"; do
    script="${suite%%:*}"
    name="${suite##*:}"

    echo -e "${BOLD}--- Running: $name ---${NC}"

    # Run the test suite and capture output.
    output=$("$SCRIPT_DIR/${script}.sh" 2>&1) || true

    # Extract passed/failed counts.
    passed=$(echo "$output" | grep -E "^Passed:" | sed 's/.*: //' | tr -d ' ' || echo "0")
    failed=$(echo "$output" | grep -E "^Failed:" | sed 's/.*: //' | tr -d ' ' || echo "0")

    # Handle ANSI color codes in numbers.
    passed=$(echo "$passed" | sed 's/\x1b\[[0-9;]*m//g')
    failed=$(echo "$failed" | sed 's/\x1b\[[0-9;]*m//g')

    if [ -z "$passed" ]; then passed=0; fi
    if [ -z "$failed" ]; then failed=0; fi

    TOTAL_PASSED=$((TOTAL_PASSED + passed))
    TOTAL_FAILED=$((TOTAL_FAILED + failed))

    if [ "$failed" -eq 0 ]; then
        echo -e "  ${GREEN}PASSED${NC}: $passed tests"
    else
        echo -e "  ${RED}FAILED${NC}: $passed passed, $failed failed"
        FAILED_SUITES+=("$name")
    fi
    echo
done

# Summary.
echo -e "${BOLD}================================================"
echo "Final Summary"
echo -e "================================================${NC}"
echo -e "Total Passed: ${GREEN}$TOTAL_PASSED${NC}"
echo -e "Total Failed: ${RED}$TOTAL_FAILED${NC}"
echo

if [ "$TOTAL_FAILED" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}Some tests failed:${NC}"
    for suite in "${FAILED_SUITES[@]}"; do
        echo -e "  ${RED}- $suite${NC}"
    done
    exit 1
fi
