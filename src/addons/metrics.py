"""
Metrics aggregation addon for mitmproxy.

Collects per-cell metrics for the warden stats command:
    - Total requests
    - Blocked requests
    - Bytes transferred
    - Error count
    - Latency percentiles (p50, p95, p99)

Exposes metrics via Unix socket for warden stats command.

Usage:
    mitmdump -s metrics.py
"""

import bisect
import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mitmproxy import http, ctx

# Metrics socket path.
METRICS_SOCKET = Path("/var/run/cells/metrics.sock")

# Maximum latencies to keep for percentile calculation.
MAX_LATENCIES = 10000


@dataclass
class CellMetrics:
    """Metrics for a single cell."""
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limited_requests: int = 0
    error_requests: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    latencies_ms: list = field(default_factory=list)
    last_request_ts: float = 0.0

    def record_request(
        self,
        blocked: bool,
        rate_limited: bool,
        error: bool,
        request_bytes: int,
        response_bytes: int,
        latency_ms: float
    ) -> None:
        """Record a request's metrics."""
        self.total_requests += 1
        self.last_request_ts = time.time()

        if blocked:
            self.blocked_requests += 1
        if rate_limited:
            self.rate_limited_requests += 1
        if error:
            self.error_requests += 1

        self.bytes_sent += request_bytes
        self.bytes_received += response_bytes

        # Keep sorted list of latencies for percentile calculation.
        if len(self.latencies_ms) >= MAX_LATENCIES:
            # Remove oldest entries by sampling.
            self.latencies_ms = self.latencies_ms[::2]

        bisect.insort(self.latencies_ms, latency_ms)

    def get_percentile(self, p: float) -> float:
        """Get latency percentile (0-100)."""
        if not self.latencies_ms:
            return 0.0
        idx = int(len(self.latencies_ms) * p / 100)
        idx = min(idx, len(self.latencies_ms) - 1)
        return self.latencies_ms[idx]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "rate_limited_requests": self.rate_limited_requests,
            "error_requests": self.error_requests,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "latency_p50_ms": round(self.get_percentile(50), 2),
            "latency_p95_ms": round(self.get_percentile(95), 2),
            "latency_p99_ms": round(self.get_percentile(99), 2),
            "last_request_ts": self.last_request_ts,
        }


class MetricsCollector:
    """mitmproxy addon for metrics collection."""

    def __init__(self):
        self.metrics: dict[str, CellMetrics] = {}
        self.metrics_lock = threading.Lock()
        self.server_thread: Optional[threading.Thread] = None
        self.running = False

    def load(self, loader):
        """Called when addon is loaded."""
        ctx.log.info("MetricsCollector: Loading...")
        self._start_server()

    def done(self):
        """Called when addon is unloaded."""
        self._stop_server()

    def _start_server(self) -> None:
        """Start Unix socket server for metrics queries."""
        self.running = True
        self.server_thread = threading.Thread(target=self._serve, daemon=True)
        self.server_thread.start()
        ctx.log.info(f"MetricsCollector: Server started on {METRICS_SOCKET}")

    def _stop_server(self) -> None:
        """Stop Unix socket server."""
        self.running = False
        if METRICS_SOCKET.exists():
            METRICS_SOCKET.unlink()

    def _serve(self) -> None:
        """Serve metrics queries over Unix socket."""
        # Ensure parent directory exists.
        METRICS_SOCKET.parent.mkdir(parents=True, exist_ok=True)

        # Remove stale socket.
        if METRICS_SOCKET.exists():
            METRICS_SOCKET.unlink()

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(METRICS_SOCKET))
            sock.listen(5)
            sock.settimeout(1.0)  # Allow periodic check for shutdown.

            while self.running:
                try:
                    conn, _ = sock.accept()
                    self._handle_connection(conn)
                except socket.timeout:
                    continue
                except Exception as e:
                    ctx.log.error(f"MetricsCollector: Server error: {e}")

        except Exception as e:
            ctx.log.error(f"MetricsCollector: Failed to start server: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass
            if METRICS_SOCKET.exists():
                METRICS_SOCKET.unlink()

    def _handle_connection(self, conn: socket.socket) -> None:
        """Handle a metrics query connection."""
        try:
            conn.settimeout(5.0)
            data = conn.recv(1024).decode("utf-8").strip()

            if data == "all":
                # Return all cell metrics.
                response = self._get_all_metrics()
            elif data.startswith("cell:"):
                # Return specific cell metrics.
                cell_name = data[5:]
                response = self._get_cell_metrics(cell_name)
            else:
                response = {"error": "Unknown command"}

            conn.send(json.dumps(response).encode("utf-8"))

        except Exception as e:
            ctx.log.debug(f"MetricsCollector: Connection error: {e}")
        finally:
            conn.close()

    def _get_all_metrics(self) -> dict:
        """Get metrics for all cells."""
        with self.metrics_lock:
            return {
                "cells": {
                    name: metrics.to_dict()
                    for name, metrics in self.metrics.items()
                },
                "timestamp": time.time(),
            }

    def _get_cell_metrics(self, cell_name: str) -> dict:
        """Get metrics for a specific cell."""
        with self.metrics_lock:
            if cell_name in self.metrics:
                return {
                    "cell": cell_name,
                    "metrics": self.metrics[cell_name].to_dict(),
                    "timestamp": time.time(),
                }
            return {"error": f"Cell not found: {cell_name}"}

    def _get_or_create_metrics(self, cell_name: str) -> CellMetrics:
        """Get or create metrics for a cell."""
        with self.metrics_lock:
            if cell_name not in self.metrics:
                self.metrics[cell_name] = CellMetrics()
            return self.metrics[cell_name]

    def request(self, flow: http.HTTPFlow) -> None:
        """Record request start time."""
        flow.metadata["metrics_start"] = time.time()

    def response(self, flow: http.HTTPFlow) -> None:
        """Record completed request metrics."""
        cell_name = flow.metadata.get("cell", "unknown")
        metrics = self._get_or_create_metrics(cell_name)

        # Calculate latency.
        start_time = flow.metadata.get("metrics_start", time.time())
        latency_ms = (time.time() - start_time) * 1000

        # Get sizes.
        request_bytes = len(flow.request.content) if flow.request.content else 0
        response_bytes = len(flow.response.content) if flow.response.content else 0

        # Record metrics.
        metrics.record_request(
            blocked=flow.metadata.get("blocked", False),
            rate_limited=flow.metadata.get("rate_limited", False),
            error=False,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            latency_ms=latency_ms
        )

    def error(self, flow: http.HTTPFlow) -> None:
        """Record error metrics."""
        cell_name = flow.metadata.get("cell", "unknown")
        metrics = self._get_or_create_metrics(cell_name)

        # Calculate latency.
        start_time = flow.metadata.get("metrics_start", time.time())
        latency_ms = (time.time() - start_time) * 1000

        # Get request size.
        request_bytes = len(flow.request.content) if flow.request and flow.request.content else 0

        # Record error metrics.
        metrics.record_request(
            blocked=flow.metadata.get("blocked", False),
            rate_limited=flow.metadata.get("rate_limited", False),
            error=True,
            request_bytes=request_bytes,
            response_bytes=0,
            latency_ms=latency_ms
        )


addons = [MetricsCollector()]
