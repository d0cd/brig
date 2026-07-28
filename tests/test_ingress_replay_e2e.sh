#!/bin/bash
# shellcheck disable=SC2034,SC2016
# test_ingress_replay_e2e.sh — End-to-end test for ingress survival
# across `brig system down` / `brig system up`.
#
# The scenario aitelier reported: a cell with ingress is running, the
# operator does `brig system down && brig system up`, then
# `brig cell start <name>`. Before the fix, the cell's routes pointed
# at a stale cell IP and every external request through warden's :8443
# reverse proxy returned 502 indefinitely.
#
# This test verifies that flow returns 200 after `brig cell start`
# without an intervening `brig cell rm + brig run --file` workaround.
#
# Usage: ./tests/test_ingress_replay_e2e.sh
#
# Prerequisites:
#   - Lima VM running: limactl start brig (or the CELL_VM_NAME-named VM)
#   - Warden up: brig system up
#   - brig CLI on PATH
#   - python3 in the cell image (busybox httpd would also work)
#
# Exit codes:
#   0 - All assertions passed
#   1 - One or more assertions failed
#   2 - Skipped (missing dependency)

set -euo pipefail

CELL_NAME="brigtest-ingress-replay"
WORK_DIR="$(mktemp -d)"
YAML="$WORK_DIR/cell.yaml"
TOKEN_VALUE="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

PASSED=0
FAILED=0

log_pass() { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
log_fail() { echo "FAIL: $1"; FAILED=$((FAILED + 1)); }

cleanup() {
    set +e
    brig cell rm -f "$CELL_NAME" >/dev/null 2>&1
    brig secrets rm "${CELL_NAME}-ingress-token" --yes >/dev/null 2>&1
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# --- Skip gate ---
if ! command -v brig >/dev/null 2>&1; then
    echo "SKIP: brig not on PATH"
    exit 2
fi
if ! brig system doctor --quick >/dev/null 2>&1; then
    echo "SKIP: brig system not ready (run: brig system up)"
    exit 2
fi

# --- Stage the ingress token secret ---
echo "$TOKEN_VALUE" | brig secrets add "${CELL_NAME}-ingress-token" --force >/dev/null

# --- Cell yaml: a tiny python http.server publishing one ingress route ---
# Serve a dir that has content at BOTH / and /api/ so the assertion is 200
# whether warden forwards the /api prefix to the cell or strips it. The rootfs
# is read-only except /tmp, so build the docroot there.
cat > "$YAML" <<'EOF'
name: brigtest-ingress-replay
image: python:3.12-alpine
command: ["sh", "-c", "mkdir -p /tmp/srv/api && echo ok > /tmp/srv/api/index.html && echo root > /tmp/srv/index.html && cd /tmp/srv && exec python -m http.server 8000"]
memory: 256m
ingress:
  - name: api
    port: 8000
    path_prefix: /api
    auth: token
EOF

# Replace name placeholder so the trap cleanup matches.
sed -i.bak "s/name: brigtest-ingress-replay/name: $CELL_NAME/" "$YAML"

# --- Start the cell from yaml. Confirms ingress works in the
# happy-path baseline before we exercise the replay scenario. ---
brig run --file "$YAML" -d >/dev/null
sleep 2

baseline=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN_VALUE" \
    "http://127.0.0.1:8443/$CELL_NAME/api/" || echo "000")
if [ "$baseline" = "200" ]; then
    log_pass "baseline ingress reaches cell (HTTP $baseline)"
else
    log_fail "baseline ingress failed (HTTP $baseline)"
    exit 1
fi

# --- The actual regression test: down + up + start, then curl ---
brig system down >/dev/null
brig system up >/dev/null
sleep 2

brig cell start "$CELL_NAME" >/dev/null
# Give warden a moment to pick up the refreshed routes file
# (mtime-throttled at ~1s in the ingress addon).
sleep 3

# Poll up to 15s — warden's route reload runs on its own clock and we
# don't want a spurious failure from racing the first attempt.
final="000"
for _ in $(seq 1 15); do
    final=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN_VALUE" \
        "http://127.0.0.1:8443/$CELL_NAME/api/" || echo "000")
    if [ "$final" = "200" ]; then
        break
    fi
    sleep 1
done

if [ "$final" = "200" ]; then
    log_pass "ingress reachable after brig system down/up + cell start (HTTP $final)"
else
    log_fail "ingress unreachable after brig system down/up + cell start (HTTP $final)"
fi

echo ""
echo "Passed: $PASSED, Failed: $FAILED"
[ "$FAILED" -eq 0 ]
