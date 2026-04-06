#!/bin/bash
# check.sh - Run the same checks as CI, locally.
#
# Usage: ./scripts/check.sh
#
# Runs: ruff, mypy, shellcheck, bandit, pytest with coverage.
# Exit code is non-zero if any check fails.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

FAILED=0

run_check() {
    local name="$1"
    shift
    printf "${BOLD}%-20s${NC} " "$name..."
    if "$@" > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        "$@" 2>&1 | tail -5
        FAILED=$((FAILED + 1))
    fi
}

echo ""
echo -e "${BOLD}Running CI checks locally${NC}"
echo "========================="
echo ""

run_check "ruff" ruff check src/ tests/
run_check "mypy" mypy src/brig/ --ignore-missing-imports --follow-imports=silent
run_check "shellcheck" shellcheck tests/*.sh
run_check "bandit" bandit -r src/ -ll --skip B101,B104,B108 -q
run_check "pytest" pytest --cov=src --cov-fail-under=70 -q --ignore=tests/benchmarks -m "not slow"

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All checks passed${NC}"
else
    echo -e "${RED}${FAILED} check(s) failed${NC}"
fi
exit "$FAILED"
