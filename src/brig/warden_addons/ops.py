"""
Merged operational addon for mitmproxy: metrics, rate limiting, and a health
endpoint, behind one configure() hook for coordinated state management.

This addon is loaded alongside enforce.py and logger.py.

Note: Do NOT use `from __future__ import annotations` here.
mitmproxy loads addons in a way that doesn't register them in sys.modules,
which breaks dataclass introspection with deferred annotations on Python 3.11.
"""

import collections
import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional

from mitmproxy import ctx, http

from _common import stat_signature


# --- Configuration ---

POLICY_FILE = Path("/policy.json")
MAX_TRACKED_CELLS = 1000
DEFAULT_RATE = 100.0
DEFAULT_BURST = 500
HEALTH_PORT = 8089


# --- Rate Limiting (Token Bucket) ---

@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    rate: float = DEFAULT_RATE
    burst: int = DEFAULT_BURST


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.last_refill = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


# --- Metrics ---

@dataclass
class CellMetrics:
    """Metrics for a single cell."""
    requests: int = 0
    blocked: int = 0
    rate_limited: int = 0
    errors: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    last_request_ts: float = 0.0


# --- Health Check Server ---

_health_state: Dict[str, Any] = {
    "proxy_running": True,
    "request_count": 0,
    "error_count": 0,
    "last_request_ts": 0.0,
}
_health_lock = threading.Lock()


class _HealthHandler(BaseHTTPRequestHandler):
    """HTTP handler for health check endpoints."""

    def do_GET(self) -> None:
        path = self.path.rstrip("/")
        if path in ("/health", "/healthz"):
            self._respond_health()
        elif path in ("/ready", "/readyz"):
            self._respond_ready()
        elif path in ("/live", "/livez"):
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, {"error": "not found"})

    def _respond_health(self) -> None:
        with _health_lock:
            state = dict(_health_state)
        status = 200 if state.get("proxy_running") else 503
        self._respond(status, state)

    def _respond_ready(self) -> None:
        with _health_lock:
            state = dict(_health_state)
        ready = state.get("proxy_running", False) and state.get("request_count", 0) > 0
        self._respond(200 if ready else 503, {"ready": ready})

    def _respond(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress default logging.


class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# --- Main Addon ---

class OpsAddon:
    """Combined metrics, rate limiting, and health addon."""

    def __init__(self) -> None:
        # Rate limiting.
        self.default_rate_config = RateLimitConfig()
        self.cell_rate_configs: Dict[str, RateLimitConfig] = {}
        self.buckets: collections.OrderedDict[str, TokenBucket] = collections.OrderedDict()
        self.buckets_lock = threading.Lock()
        self.policy_mtime: tuple[int, int] = (0, 0)

        # Metrics.
        self.metrics: collections.OrderedDict[str, CellMetrics] = collections.OrderedDict()
        self.metrics_lock = threading.Lock()

        # Health server.
        self.health_server: Optional[_ThreadedHTTPServer] = None
        self.health_thread: Optional[threading.Thread] = None

    def load(self, loader: Any) -> None:
        """Initialize addon: load config, start health server."""
        self._load_rate_config()
        self._start_health_server()
        ctx.log.info("OpsAddon: Loaded (metrics + rate limiting + health)")

    def done(self) -> None:
        """Shutdown: stop health server."""
        if self.health_server:
            self.health_server.shutdown()

    def configure(self, updated: set[str]) -> None:
        """Reload rate limit config if policy file changed.

        Called by mitmproxy on configure events. Replaces SIGHUP dispatcher.
        """
        try:
            if POLICY_FILE.exists():
                if stat_signature(POLICY_FILE) != self.policy_mtime:
                    self._load_rate_config()
        except OSError:
            pass

    def request(self, flow: http.HTTPFlow) -> None:
        """Check rate limit and record request metrics."""
        # Identify cell from source IP.
        cell_name = self._cell_from_flow(flow)

        # Rate limiting.
        if cell_name:
            bucket = self._get_bucket(cell_name)
            if bucket and not bucket.consume():
                flow.response = http.Response.make(
                    429, b"Rate limit exceeded", {"Content-Type": "text/plain"},
                )
                with self.metrics_lock:
                    m = self._get_metrics(cell_name)
                    m.rate_limited += 1
                return

        # Record request.
        if cell_name:
            with self.metrics_lock:
                m = self._get_metrics(cell_name)
                m.requests += 1
                m.last_request_ts = time.time()

        with _health_lock:
            _health_state["request_count"] = _health_state.get("request_count", 0) + 1
            _health_state["last_request_ts"] = time.time()

        # Store start time for latency tracking.
        flow.metadata["ops_start_time"] = time.monotonic()

    def response(self, flow: http.HTTPFlow) -> None:
        """Record response metrics."""
        cell_name = self._cell_from_flow(flow)
        if cell_name and flow.response:
            with self.metrics_lock:
                m = self._get_metrics(cell_name)
                m.bytes_received += len(flow.response.content or b"")

    def error(self, flow: http.HTTPFlow) -> None:
        """Record error metrics."""
        cell_name = self._cell_from_flow(flow)
        if cell_name:
            with self.metrics_lock:
                m = self._get_metrics(cell_name)
                m.errors += 1

        with _health_lock:
            _health_state["error_count"] = _health_state.get("error_count", 0) + 1

    # --- Internal methods ---

    def _cell_from_flow(self, flow: http.HTTPFlow) -> str:
        """Extract cell name from flow metadata (set by enforce.py)."""
        return flow.metadata.get("cell", "")

    def _get_bucket(self, cell_name: str) -> Optional[TokenBucket]:
        """Get or create a token bucket for a cell."""
        with self.buckets_lock:
            if cell_name in self.buckets:
                self.buckets.move_to_end(cell_name)
                return self.buckets[cell_name]

            config = self.cell_rate_configs.get(cell_name, self.default_rate_config)
            bucket = TokenBucket(config.rate, config.burst)
            self.buckets[cell_name] = bucket

            # LRU eviction.
            while len(self.buckets) > MAX_TRACKED_CELLS:
                self.buckets.popitem(last=False)

            return bucket

    def _get_metrics(self, cell_name: str) -> CellMetrics:
        """Get or create metrics for a cell. Must hold metrics_lock."""
        if cell_name in self.metrics:
            self.metrics.move_to_end(cell_name)
            return self.metrics[cell_name]

        m = CellMetrics()
        self.metrics[cell_name] = m

        while len(self.metrics) > MAX_TRACKED_CELLS:
            self.metrics.popitem(last=False)

        return m

    def _load_rate_config(self) -> None:
        """Load rate limit configuration from policy file."""
        try:
            if not POLICY_FILE.exists():
                return
            sig = stat_signature(POLICY_FILE)
            with open(POLICY_FILE) as f:
                policy = json.load(f)
            rate_limits = policy.get("rate_limits", {})
            default = rate_limits.get("default", {})
            self.default_rate_config = RateLimitConfig(
                rate=float(default.get("rate", DEFAULT_RATE)),
                burst=int(default.get("burst", DEFAULT_BURST)),
            )
            cells = rate_limits.get("cells", {})
            self.cell_rate_configs = {}
            for cell, config in cells.items():
                self.cell_rate_configs[cell] = RateLimitConfig(
                    rate=float(config.get("rate", self.default_rate_config.rate)),
                    burst=int(config.get("burst", self.default_rate_config.burst)),
                )
            # Advance the fingerprint only after a fully successful parse, so a
            # bad edit is retried on the next configure() rather than skipped
            # until the file changes again (matches enforce.py / notifier.py).
            self.policy_mtime = sig
        except (json.JSONDecodeError, IOError, OSError, ValueError) as e:
            ctx.log.warn(f"OpsAddon: Failed to load rate config: {e}")

    def _start_health_server(self) -> None:
        """Start the health check HTTP server.

        Bind address defaults to 127.0.0.1 — warden is multi-homed onto
        every per-cell network, so a 0.0.0.0 bind would expose the
        aggregate metrics (request counts, last_request_ts) to every
        cell that probes warden's IP on its joined network. Tenancy
        isolation requires the health endpoint to stay inside the
        warden container; consumers on the host can reach it via
        `podman exec` or by publishing the port explicitly.
        """
        import os
        port = int(os.environ.get("HEALTH_PORT", str(HEALTH_PORT)))
        bind_host = os.environ.get("HEALTH_BIND", "127.0.0.1")
        try:
            self.health_server = _ThreadedHTTPServer((bind_host, port), _HealthHandler)
            self.health_thread = threading.Thread(target=self.health_server.serve_forever, daemon=True)
            self.health_thread.start()
            ctx.log.info(f"OpsAddon: Health server started on {bind_host}:{port}")
        except OSError as e:
            ctx.log.warn(f"OpsAddon: Failed to start health server: {e}")


# mitmproxy entry point.
addons = [OpsAddon()]
