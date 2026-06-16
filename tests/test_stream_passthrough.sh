#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_stream_passthrough.sh — warden must not buffer streaming responses on
# the INGRESS path.
#
# mitmproxy buffers response bodies by default. For Server-Sent Events
# (Content-Type: text/event-stream) buffering is fatal: keepalives emitted
# every ~Ns during a silent phase would all arrive at once at stream close,
# tripping the consumer's read timeout. warden's ingress addon sets
# `flow.response.stream = True` for event-stream responses so they pass through
# unbuffered (see ingress.py responseheaders).
#
# Scope: this is the INGRESS guarantee (external client -> warden :8443 -> cell)
# — the path aitelier uses for streaming agents. Egress responses (cell ->
# outside) are buffered BY DESIGN (ingress.py docstring), so this does not test
# that direction.
#
# A cell runs a tiny stdlib SSE server (no extra deps), exposes it via ingress,
# and the host streams it through warden :8443, asserting keepalives arrive
# incrementally (gaps ~1s) rather than all at once.
#
# Usage: ./tests/test_stream_passthrough.sh   (requires `brig system up` first)
# Exit: 0 all passed, 1 any failed.

source "$(dirname "$0")/lib/e2e_common.sh"

PYRUN="${PYRUN:-uv run python}"
TEST_CELL="stream-passthrough-$$"
TOKEN_VALUE="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
WORK_DIR="$(mktemp -d)"
YAML="$WORK_DIR/cell.yaml"

cleanup() {
    $BRIG cell rm -f "$TEST_CELL" 2>/dev/null || true
    $BRIG secrets rm "${TEST_CELL}-ingress-token" --yes 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "============================================"
echo "Stream Passthrough (ingress SSE) Test"
echo "============================================"
echo

require_brig_up

# --- Ingress token + a cell running a stdlib SSE server ----------------------
echo "$TOKEN_VALUE" | $BRIG secrets add "${TEST_CELL}-ingress-token" --force >/dev/null 2>&1

cat > "$YAML" <<EOF
name: $TEST_CELL
image: python:3.12-alpine
memory: 256m
ingress:
  - name: sse
    port: 8000
    path_prefix: /sse
    auth: token
command:
  - python
  - -c
  - |
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import time
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            for _ in range(5):
                self.wfile.write(b":keepalive\n\n"); self.wfile.flush(); time.sleep(1)
            self.wfile.write(b"data: done\n\n"); self.wfile.flush()
        def log_message(self, *a): pass
    HTTPServer(("0.0.0.0", 8000), H).serve_forever()
EOF

echo "Starting cell with an SSE endpoint behind ingress ..."
$BRIG run --file "$YAML" -d >/dev/null 2>&1 || true
sleep 3

# --- Stream it from the host through warden :8443 and measure inter-line gaps -
GAP_OUT=$($PYRUN - "$TEST_CELL" "$TOKEN_VALUE" <<'PY'
import sys, urllib.request, time
cell, token = sys.argv[1], sys.argv[2]
req = urllib.request.Request(
    f"http://127.0.0.1:8443/{cell}/sse/",
    headers={"Authorization": f"Bearer {token}"},
)
last = time.time(); gaps = []; keepalives = 0
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        for raw in r:
            now = time.time(); gaps.append(now - last); last = now
            if raw.decode(errors="replace").rstrip() == ":keepalive":
                keepalives += 1
except Exception as e:
    print("ERROR:%s" % e); sys.exit(0)
print("KEEPALIVES:%d" % keepalives)
print("GAPS:" + " ".join("%.2f" % g for g in gaps))
PY
)

if echo "$GAP_OUT" | grep -q "^ERROR:"; then
    log_fail "ingress SSE request failed: $(echo "$GAP_OUT" | sed -n 's/^ERROR://p')"
    finish
fi

KEEPALIVES=$(echo "$GAP_OUT" | sed -n 's/^KEEPALIVES:\([0-9]*\)/\1/p' | tail -1)
KEEPALIVES="${KEEPALIVES:-0}"
if [ "$KEEPALIVES" -ge 5 ]; then
    log_pass "received $KEEPALIVES SSE keepalive lines through ingress"
else
    log_fail "expected >=5 :keepalive lines, got $KEEPALIVES ($GAP_OUT)"
fi

GAPS=$(echo "$GAP_OUT" | sed -n 's/^GAPS://p' | tail -1)
if [ -n "$GAPS" ]; then
    BIG=$(echo "$GAPS" | tr ' ' '\n' | awk '$1 > 2.0 {c++} END{print c+0}')
    if [ "$BIG" -eq 0 ]; then
        log_pass "all inter-line gaps <= 2.0s (ingress streams SSE, no buffering)"
    else
        log_fail "$BIG gap(s) > 2.0s — warden is buffering ingress SSE"
        echo "  gaps: $GAPS"
    fi
else
    log_fail "no GAPS line ($GAP_OUT)"
fi

finish
