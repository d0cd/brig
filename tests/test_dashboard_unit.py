"""Unit tests for the web dashboard."""

import importlib.util
import json
import sys
import threading
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add src to path.
SRC_DIR = Path(__file__).parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Mock subprocess before importing dashboard (tui.py calls subprocess).
_mock_subprocess = MagicMock()
_mock_subprocess.run.return_value = MagicMock(returncode=1, stdout="", stderr="")


MOCK_CELLS = [
    {"name": "test-cell", "status": "running", "image": "alpine", "created": "2026-01-01"},
]
MOCK_METRICS = {
    "global_metrics": {"total_requests": 42, "total_blocked": 3, "total_rate_limited": 0},
    "cells": {"test-cell": {"total_requests": 42, "blocked_requests": 3}},
}


def _setup_dashboard_module():
    """Import dashboard module with mocked dependencies."""
    with patch.dict(sys.modules, {"subprocess": _mock_subprocess}):
        # Re-import tui data functions will use mocked subprocess.
        if "tui" in sys.modules:
            del sys.modules["tui"]
        if "dashboard" in sys.modules:
            del sys.modules["dashboard"]
        import dashboard
        return dashboard


dashboard_mod = _setup_dashboard_module()
# Ensure the module is in sys.modules so @patch("dashboard.get_cells") targets the
# same object the server handler uses — patch.dict restores sys.modules on exit,
# removing dashboard from it.
sys.modules["dashboard"] = dashboard_mod


class TestDashboardAPI(unittest.TestCase):
    """Test API endpoints."""

    @classmethod
    def setUpClass(cls):
        """Start dashboard server on random port."""
        from http.server import HTTPServer
        cls.server = HTTPServer(("127.0.0.1", 0), dashboard_mod.DashboardHandler)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _get(self, path):
        req = urllib.request.Request(f"{self.base}{path}")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def test_root_returns_html(self):
        """/ returns HTML page."""
        status, headers, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"Brig Dashboard", body)

    def test_html_contains_eventsource(self):
        """HTML page has EventSource JS for SSE."""
        _, _, body = self._get("/")
        self.assertIn(b"EventSource", body)

    def test_html_contains_cell_table(self):
        """HTML page has cell table structure."""
        _, _, body = self._get("/")
        self.assertIn(b"cell-table", body)

    @patch("dashboard.get_cells", return_value=MOCK_CELLS)
    def test_api_cells_returns_json(self, mock_cells):
        """GET /api/cells returns JSON array."""
        status, headers, body = self._get("/api/cells")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers["Content-Type"])
        data = json.loads(body)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["name"], "test-cell")

    @patch("dashboard.get_metrics", return_value=MOCK_METRICS)
    def test_api_metrics_returns_json(self, mock_metrics):
        """GET /api/metrics returns JSON."""
        status, headers, body = self._get("/api/metrics")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("global_metrics", data)

    @patch("dashboard.is_warden_running", return_value=True)
    def test_api_health_returns_json(self, mock_warden):
        """GET /api/health returns warden status."""
        status, headers, body = self._get("/api/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["warden_running"])
        self.assertIn("timestamp", data)

    @patch("dashboard.get_cell_stats", return_value={"cpu": "0.5%", "mem": "10MB"})
    def test_api_stats_valid_cell(self, mock_stats):
        """GET /api/stats/<cell> returns stats."""
        status, headers, body = self._get("/api/stats/test-cell")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("cpu", data)

    def test_api_stats_invalid_cell_name(self):
        """GET /api/stats/../etc rejects traversal."""
        status, headers, body = self._get("/api/stats/../etc/passwd")
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn("error", data)

    def test_api_stats_reject_uppercase(self):
        """GET /api/stats/INVALID rejects uppercase."""
        status, headers, body = self._get("/api/stats/INVALID")
        self.assertEqual(status, 400)

    def test_404_for_unknown_route(self):
        """Unknown routes return 404."""
        status, _, _ = self._get("/nonexistent")
        self.assertEqual(status, 404)

    def test_server_binds_localhost_only(self):
        """Server binds to 127.0.0.1, not 0.0.0.0."""
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    @patch("dashboard.get_cells", return_value=MOCK_CELLS)
    @patch("dashboard.get_metrics", return_value=MOCK_METRICS)
    @patch("dashboard.is_warden_running", return_value=True)
    def test_sse_data_format(self, mock_warden, mock_metrics, mock_cells):
        """SSE endpoint sends data: frames."""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", self.port))
        sock.sendall(b"GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n")
        # Read enough to get headers + first data frame.
        response = b""
        while b"data:" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        self.assertIn(b"text/event-stream", response)
        # Extract data line.
        for line in response.decode("utf-8", errors="replace").split("\n"):
            if line.startswith("data:"):
                payload = json.loads(line[5:].strip())
                self.assertIn("cells", payload)
                self.assertIn("warden_running", payload)
                break
        else:
            self.fail("No data: frame found in SSE response")


if __name__ == "__main__":
    unittest.main()
