"""
Health check HTTP endpoint addon for mitmproxy.

Exposes health status on a dedicated port for monitoring systems.

Endpoints:
    GET /health    - Overall health status
    GET /ready     - Readiness check (dependencies available)
    GET /live      - Liveness check (process running)

Default port: 8089 (configurable via HEALTH_PORT env var)

Usage:
    mitmdump -s health.py

Response format:
    {
        "status": "healthy" | "unhealthy",
        "checks": {
            "proxy_running": true,
            "policy_loaded": true,
            "logging_available": true
        },
        "timestamp": "2024-01-01T12:00:00Z"
    }
"""

import http.server
import json
import os
import socketserver
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import ctx

# Health server configuration.
HEALTH_PORT = int(os.environ.get("HEALTH_PORT", "8089"))
POLICY_FILE = Path(os.environ.get("POLICY_FILE", "/cells/network-policy.json"))
LOG_DIR = Path("/var/log/brig/network")

# Global health state (updated by addon).
_health_state = {
    "proxy_running": True,  # If addon is loaded, proxy is running.
    "policy_loaded": False,
    "logging_available": False,
    "last_request_ts": 0.0,
    "request_count": 0,
    "error_count": 0,
}
_health_lock = threading.Lock()


def _update_health_state():
    """Update health state checks."""
    with _health_lock:
        # Check policy file.
        _health_state["policy_loaded"] = POLICY_FILE.exists()

        # Check logging.
        try:
            test_file = LOG_DIR / ".health_check"
            test_file.touch()
            test_file.unlink()
            _health_state["logging_available"] = True
        except Exception:
            _health_state["logging_available"] = False


def _get_health_response(check_type: str = "health") -> tuple:
    """Get health response for given check type.

    Returns:
        Tuple of (status_code, response_dict)
    """
    _update_health_state()

    with _health_lock:
        state = _health_state.copy()

    timestamp = datetime.now(timezone.utc).isoformat()

    if check_type == "live":
        # Liveness: process is running.
        return 200, {
            "status": "alive",
            "timestamp": timestamp,
        }

    if check_type == "ready":
        # Readiness: dependencies available.
        ready = state["policy_loaded"]
        status_code = 200 if ready else 503
        return status_code, {
            "status": "ready" if ready else "not_ready",
            "checks": {
                "policy_loaded": state["policy_loaded"],
            },
            "timestamp": timestamp,
        }

    # Full health check.
    healthy = all([
        state["proxy_running"],
        state["policy_loaded"],
        state["logging_available"],
    ])

    status_code = 200 if healthy else 503
    return status_code, {
        "status": "healthy" if healthy else "unhealthy",
        "checks": {
            "proxy_running": state["proxy_running"],
            "policy_loaded": state["policy_loaded"],
            "logging_available": state["logging_available"],
        },
        "stats": {
            "request_count": state["request_count"],
            "error_count": state["error_count"],
            "last_request_ts": state["last_request_ts"],
        },
        "timestamp": timestamp,
    }


class HealthHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for health checks."""

    def log_message(self, format, *args):
        """Suppress access logs."""
        pass

    def do_GET(self):
        """Handle GET requests."""
        path = self.path.rstrip("/")

        if path == "/health" or path == "/healthz" or path == "":
            status_code, response = _get_health_response("health")
        elif path == "/ready" or path == "/readyz":
            status_code, response = _get_health_response("ready")
        elif path == "/live" or path == "/livez":
            status_code, response = _get_health_response("live")
        else:
            status_code = 404
            response = {"error": "not_found", "path": self.path}

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode("utf-8"))


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP server for health checks."""
    daemon_threads = True
    allow_reuse_address = True


class HealthAddon:
    """Mitmproxy addon for health checks.

    Runs HTTP server on dedicated port for health endpoints.
    """

    def __init__(self):
        self.server = None
        self.server_thread = None

    def load(self, loader):
        """Called when addon is loaded."""
        # Start health server in background.
        try:
            self.server = ThreadedHTTPServer(("0.0.0.0", HEALTH_PORT), HealthHandler)
            self.server_thread = threading.Thread(
                target=self.server.serve_forever,
                daemon=True
            )
            self.server_thread.start()
            ctx.log.info(f"Health server started on port {HEALTH_PORT}")
        except Exception as e:
            ctx.log.error(f"Failed to start health server: {e}")

    def done(self):
        """Called when addon is shutting down."""
        if self.server:
            self.server.shutdown()
            ctx.log.info("Health server stopped")

    def response(self, flow):
        """Track requests for health stats."""
        with _health_lock:
            _health_state["request_count"] += 1
            _health_state["last_request_ts"] = time.time()
            if flow.response and flow.response.status_code >= 500:
                _health_state["error_count"] += 1

    def error(self, flow):
        """Track errors."""
        with _health_lock:
            _health_state["error_count"] += 1


# Mitmproxy addon instance.
addons = [HealthAddon()]
