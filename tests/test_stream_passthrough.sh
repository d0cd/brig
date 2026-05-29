#!/bin/bash
# shellcheck disable=SC2034,SC2016,SC2153,SC2329,SC2001
# test_stream_passthrough.sh — B4 + B5 from docs/plans/0.3-validation-plan.md.
#
# Both tests verify that warden (mitmproxy) doesn't buffer streaming
# responses. Buffering would break:
#   B4 — WebSocket gateways (Telegram long-poll, Discord WSS, Slack
#        Socket Mode) that any agent / bot in a cell may use.
#   B5 — Server-Sent Events keepalives. Long-running LLM-style endpoints
#        commonly emit `:keepalive` SSE comments every ~25s during
#        silent phases; buffering would trip the consumer's stream-read
#        timeout and kill long tasks.
#
# Usage: ./tests/test_stream_passthrough.sh
#
# Prerequisites:
#   - Lima VM running, brig installed, warden up.
#   - Network policy allows `stream-test.host.brig` as a host service.
#
# Exit codes:
#   0 — all checks passed
#   1 — at least one failure

set -euo pipefail

VM_NAME="${CELL_VM_NAME:-cell}"
PASSED=0
FAILED=0
TEST_PORT="${STREAM_TEST_PORT:-7700}"
TEST_CELL="stream-passthrough-$$"
SERVER_PID=""

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    NC=''
fi

log_pass() { echo -e "${GREEN}PASS${NC}: $1"; PASSED=$((PASSED + 1)); }
log_fail() { echo -e "${RED}FAIL${NC}: $1"; FAILED=$((FAILED + 1)); }

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    brig rm -f "$TEST_CELL" 2>/dev/null || true
    brig policy rm "$TEST_CELL" 2>/dev/null || true
    # Best-effort: drop the host service entry we added.
    brig policy set global --remove-host-service stream-test 2>/dev/null || true
}
trap cleanup EXIT

# --- Set up the in-VM stream server -----------------------------------------
# A tiny Python server that:
#   GET /sse  → text/event-stream, emits `:keepalive\n\n` every 1s for 5s
#              then sends `data: done\n\n` and closes
#   GET /ws   → WebSocket upgrade; echoes each message; emits ping/pong
#
# Run it on the macOS host (the same place any host-service lives) and
# route the cell to it via the host-service mechanism. Host port = $TEST_PORT.

mkdir -p /tmp/brig-stream-test
cat > /tmp/brig-stream-test/server.py <<'PY'
import asyncio
import sys
from aiohttp import web

async def sse(request):
    resp = web.StreamResponse(
        status=200,
        headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"},
    )
    await resp.prepare(request)
    for _ in range(5):
        await resp.write(b":keepalive\n\n")
        await asyncio.sleep(1)
    await resp.write(b"data: done\n\n")
    return resp

async def ws(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    async for msg in ws:
        if msg.type == web.WSMsgType.TEXT:
            await ws.send_str(f"echo:{msg.data}")
            if msg.data == "bye":
                break
    return ws

app = web.Application()
app.router.add_get("/sse", sse)
app.router.add_get("/ws", ws)
port = int(sys.argv[1]) if len(sys.argv) > 1 else 7700
web.run_app(app, host="127.0.0.1", port=port, print=lambda *a, **k: None)
PY

echo "Starting stream server on host 127.0.0.1:$TEST_PORT..."
python3 /tmp/brig-stream-test/server.py "$TEST_PORT" >/tmp/brig-stream-test/server.log 2>&1 &
SERVER_PID=$!
sleep 1
if ! ps -p "$SERVER_PID" > /dev/null; then
    log_fail "stream server failed to start (see /tmp/brig-stream-test/server.log)"
    cat /tmp/brig-stream-test/server.log
    exit 1
fi
log_pass "stream server up on host port $TEST_PORT"

# --- Wire the host service + per-cell ACL -----------------------------------
brig policy set global --host-service "stream-test:$TEST_PORT" >/dev/null
brig policy set "$TEST_CELL" --host-service stream-test >/dev/null
log_pass "stream-test.host.brig wired through warden"

# --- B5: SSE keepalive passthrough ------------------------------------------
# Spin up a cell that curls /sse and records the timestamp of each line.
# We need each `:keepalive` to arrive within <2s of emission (server sleeps
# 1s between lines). If mitmproxy buffers, all 5 keepalives arrive together
# at end of stream and the test fails.

echo
echo "B5: SSE keepalive passthrough"
brig run --name "$TEST_CELL" --detach alpine -- sh -c '
    apk add --no-cache curl python3 >/dev/null 2>&1 || true
    curl -sN http://stream-test.host.brig/sse | python3 -c "
import sys, time
last = time.time()
gaps = []
for line in sys.stdin:
    now = time.time()
    gaps.append(now - last); last = now
    print(line.rstrip(), flush=True)
print(\"GAPS:\" + \" \".join(f\"{g:.2f}\" for g in gaps), file=sys.stderr)
"
' >/dev/null

# Wait up to 10s for the cell to exit.
for _ in $(seq 1 10); do
    if ! brig list --format json | python3 -c 'import json,sys; print(any(c["name"]=="'"$TEST_CELL"'" and c["status"]=="running" for c in json.load(sys.stdin)))' | grep -q True; then
        break
    fi
    sleep 1
done

# Pull cell logs; assert at least 5 :keepalive lines and gaps < 2s.
LOGS=$(brig logs "$TEST_CELL" 2>&1)
KEEPALIVES=$(echo "$LOGS" | grep -c "^:keepalive$" || true)
if [ "$KEEPALIVES" -ge 5 ]; then
    log_pass "received $KEEPALIVES SSE keepalive lines"
else
    log_fail "expected ≥5 :keepalive lines, got $KEEPALIVES"
    echo "--- cell logs ---"
    echo "$LOGS"
fi

# Check the inter-line gaps to confirm streaming behavior (no buffering).
GAPS=$(echo "$LOGS" | grep "^GAPS:" | sed 's/^GAPS://')
if [ -n "$GAPS" ]; then
    BIG_GAPS=$(echo "$GAPS" | tr ' ' '\n' | awk '$1 > 2.0 { print }' | wc -l | tr -d ' ')
    if [ "$BIG_GAPS" -eq 0 ]; then
        log_pass "all inter-line gaps ≤ 2.0s (no buffering)"
    else
        log_fail "$BIG_GAPS gaps > 2.0s suggests mitmproxy is buffering SSE"
        echo "  gaps: $GAPS"
    fi
fi

# --- B4: WebSocket echo through warden --------------------------------------
echo
echo "B4: WebSocket through warden"
brig rm -f "$TEST_CELL" >/dev/null 2>&1 || true

# mitmproxy needs explicit websocket handling; the addon enables it by
# default in regular mode. Verify by opening a ws:// connection through
# http_proxy via Python's websockets lib.
brig run --name "$TEST_CELL" --detach alpine -- sh -c '
    apk add --no-cache python3 py3-pip >/dev/null 2>&1 || true
    pip install --quiet websockets httpx-ws 2>/dev/null || true
    python3 -c "
import asyncio, os, sys
from websockets.client import connect
proxy = os.environ.get(\"http_proxy\", \"\")
# Connect through the proxy if the lib supports it; otherwise direct
# (warden will intercept the CONNECT regardless).
async def go():
    async with connect(\"ws://stream-test.host.brig/ws\") as ws:
        await ws.send(\"hello\")
        reply = await asyncio.wait_for(ws.recv(), timeout=5)
        print(f\"reply={reply}\")
        await ws.send(\"bye\")
asyncio.run(go())
"
' >/dev/null

for _ in $(seq 1 10); do
    if ! brig list --format json | python3 -c 'import json,sys; print(any(c["name"]=="'"$TEST_CELL"'" and c["status"]=="running" for c in json.load(sys.stdin)))' | grep -q True; then
        break
    fi
    sleep 1
done

LOGS=$(brig logs "$TEST_CELL" 2>&1)
if echo "$LOGS" | grep -q "reply=echo:hello"; then
    log_pass "WebSocket echo through warden works"
else
    log_fail "WebSocket echo failed (see cell logs)"
    echo "--- cell logs ---"
    echo "$LOGS"
fi

# --- Summary ---------------------------------------------------------------
echo
echo "Results: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
