"""Web dashboard for Brig.

Lightweight HTTP server with Server-Sent Events (SSE) for real-time updates.
Serves a single HTML page with embedded JS — no build step, no external dependencies.

Usage:
    brig dashboard [--port 8080]
"""

import json
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Reuse data functions from tui.py (they have no textual dependency).
from tui import get_cells, get_metrics, get_cell_stats, is_warden_running

# Cell name validation pattern.
import re
CELL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the Brig dashboard."""

    def log_message(self, format, *args):
        """Suppress default access logs."""
        pass

    def _set_headers(self, content_type="application/json", status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

    def _json_response(self, data, status=200):
        self._set_headers("application/json", status)
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        if self.path == "/":
            self._serve_html()
        elif self.path == "/api/cells":
            self._api_cells()
        elif self.path == "/api/metrics":
            self._api_metrics()
        elif self.path == "/api/health":
            self._api_health()
        elif self.path.startswith("/api/stats/"):
            self._api_cell_stats()
        elif self.path == "/events":
            self._sse_stream()
        else:
            self._set_headers("text/plain", 404)
            self.wfile.write(b"Not Found")

    def _serve_html(self):
        self._set_headers("text/html")
        self.wfile.write(_DASHBOARD_HTML.encode("utf-8"))

    def _api_cells(self):
        self._json_response(get_cells())

    def _api_metrics(self):
        self._json_response(get_metrics())

    def _api_health(self):
        self._json_response({
            "warden_running": is_warden_running(),
            "timestamp": time.time(),
        })

    def _api_cell_stats(self):
        cell_name = self.path.split("/api/stats/", 1)[-1]
        if not CELL_NAME_RE.match(cell_name):
            self._json_response({"error": "Invalid cell name"}, 400)
            return
        self._json_response(get_cell_stats(cell_name))

    def _sse_stream(self):
        """Server-Sent Events stream pushing state every 2 seconds."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        try:
            while True:
                data = {
                    "cells": get_cells(),
                    "metrics": get_metrics(),
                    "warden_running": is_warden_running(),
                    "timestamp": time.time(),
                }
                payload = f"data: {json.dumps(data)}\n\n"
                self.wfile.write(payload.encode("utf-8"))
                self.wfile.flush()
                time.sleep(2)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


# ---------------------------------------------------------------------------
# Embedded HTML page
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Brig Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
         background: #0d1117; color: #c9d1d9; }
  .header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px;
            display: flex; align-items: center; justify-content: space-between; }
  .header h1 { font-size: 18px; color: #58a6ff; }
  .status { display: flex; gap: 16px; align-items: center; font-size: 13px; }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .status-dot.up { background: #3fb950; }
  .status-dot.down { background: #f85149; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 16px; margin-bottom: 24px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; }
  .card h3 { font-size: 12px; color: #8b949e; text-transform: uppercase; margin-bottom: 8px; }
  .card .value { font-size: 28px; font-weight: 600; color: #e6edf3; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 8px 12px; font-size: 12px; color: #8b949e;
       text-transform: uppercase; border-bottom: 1px solid #30363d; }
  td { padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 13px; }
  tr:hover { background: #1c2128; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px;
           font-weight: 600; }
  .badge.running { background: #23312e; color: #3fb950; }
  .badge.exited { background: #2d1f1f; color: #f85149; }
  .badge.created { background: #2d2a1f; color: #d29922; }
  .footer { text-align: center; padding: 24px; font-size: 12px; color: #484f58; }
</style>
</head>
<body>
<div class="header">
  <h1>Brig Dashboard</h1>
  <div class="status">
    <span>Warden: <span class="status-dot" id="warden-dot"></span> <span id="warden-status">...</span></span>
    <span id="last-update"></span>
  </div>
</div>
<div class="container">
  <div class="grid" id="metrics-grid">
    <div class="card"><h3>Total Cells</h3><div class="value" id="m-cells">-</div></div>
    <div class="card"><h3>Total Requests</h3><div class="value" id="m-requests">-</div></div>
    <div class="card"><h3>Blocked</h3><div class="value" id="m-blocked">-</div></div>
    <div class="card"><h3>Rate Limited</h3><div class="value" id="m-ratelimited">-</div></div>
  </div>
  <div class="card" style="margin-bottom: 24px;">
    <h3>Cells</h3>
    <table>
      <thead><tr><th>Name</th><th>Status</th><th>Image</th><th>Requests</th><th>Blocked</th></tr></thead>
      <tbody id="cell-table"></tbody>
    </table>
  </div>
</div>
<div class="footer">Brig &mdash; Secure Workload Harness</div>
<script>
function update(data) {
  // Warden status.
  const dot = document.getElementById('warden-dot');
  const ws = document.getElementById('warden-status');
  if (data.warden_running) {
    dot.className = 'status-dot up'; ws.textContent = 'Running';
  } else {
    dot.className = 'status-dot down'; ws.textContent = 'Stopped';
  }
  document.getElementById('last-update').textContent =
    'Updated: ' + new Date(data.timestamp * 1000).toLocaleTimeString();

  // Cells count.
  const cells = data.cells || [];
  document.getElementById('m-cells').textContent = cells.length;

  // Metrics.
  const m = data.metrics || {};
  const g = m.global_metrics || {};
  document.getElementById('m-requests').textContent = g.total_requests || 0;
  document.getElementById('m-blocked').textContent = g.total_blocked || 0;
  document.getElementById('m-ratelimited').textContent = g.total_rate_limited || 0;

  // Cell table.
  const tbody = document.getElementById('cell-table');
  const cellMetrics = m.cells || {};
  tbody.innerHTML = cells.map(c => {
    const cm = cellMetrics[c.name] || {};
    const cls = c.status === 'running' ? 'running' : c.status === 'exited' ? 'exited' : 'created';
    return '<tr>' +
      '<td>' + esc(c.name) + '</td>' +
      '<td><span class="badge ' + cls + '">' + esc(c.status) + '</span></td>' +
      '<td>' + esc(c.image) + '</td>' +
      '<td>' + (cm.total_requests || 0) + '</td>' +
      '<td>' + (cm.blocked_requests || 0) + '</td>' +
      '</tr>';
  }).join('');
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// Connect via SSE, fall back to polling.
let evtSource;
try {
  evtSource = new EventSource('/events');
  evtSource.onmessage = function(e) { update(JSON.parse(e.data)); };
  evtSource.onerror = function() { evtSource.close(); startPolling(); };
} catch(e) { startPolling(); }

function startPolling() {
  setInterval(async () => {
    try {
      const [cells, metrics, health] = await Promise.all([
        fetch('/api/cells').then(r => r.json()),
        fetch('/api/metrics').then(r => r.json()),
        fetch('/api/health').then(r => r.json()),
      ]);
      update({ cells, metrics, warden_running: health.warden_running, timestamp: health.timestamp });
    } catch(e) {}
  }, 2000);
}
</script>
</body>
</html>"""


def run_dashboard(port: int = 8080) -> int:
    """Start the dashboard HTTP server."""
    server = HTTPServer(("127.0.0.1", port), DashboardHandler)
    print(f"Dashboard running at http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped")
    finally:
        server.server_close()
    return 0
