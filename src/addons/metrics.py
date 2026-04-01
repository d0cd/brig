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

import collections
import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http

# Metrics socket path.
METRICS_SOCKET = Path("/var/run/cells/metrics.sock")

# Metrics persistence file path.
METRICS_PERSISTENCE_FILE = Path("/var/run/cells/metrics-state.json")

# Maximum latencies to keep for percentile calculation.
MAX_LATENCIES = 10000

# Maximum number of cells to track (LRU eviction beyond this).
MAX_TRACKED_CELLS = 1000


class HistogramLatencyBuffer:
    """O(1) histogram-based latency tracking for fast percentile queries.

    Uses log-scale buckets (1ms to 60s) for bounded memory and O(1) percentiles.
    Trade-off: ~5% error for O(1) insert and O(1) percentile queries.
    """

    # Bucket boundaries in ms: 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 60000
    BUCKET_BOUNDS = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 60000]

    def __init__(self, max_samples: int = MAX_LATENCIES):
        self.buckets = [0] * (len(self.BUCKET_BOUNDS) + 1)
        self.total_count = 0
        self.max_samples = max_samples
        self._decay_threshold = max_samples

    def _get_bucket_index(self, latency_ms: float) -> int:
        """Find bucket index for a latency value."""
        for i, bound in enumerate(self.BUCKET_BOUNDS):
            if latency_ms < bound:
                return i
        return len(self.BUCKET_BOUNDS)

    def add(self, latency_ms: float) -> None:
        """Add a latency value in O(1) time."""
        idx = self._get_bucket_index(latency_ms)
        self.buckets[idx] += 1
        self.total_count += 1

        # Decay old samples to prevent unbounded growth.
        if self.total_count > self._decay_threshold:
            self._decay()

    def _decay(self) -> None:
        """Halve all bucket counts to decay old samples."""
        self.buckets = [c // 2 for c in self.buckets]
        self.total_count = sum(self.buckets)

    def percentile(self, p: float) -> float:
        """Get latency percentile (0-100) in O(1) time.

        Returns the bucket midpoint for the target percentile.
        """
        if self.total_count == 0:
            return 0.0

        target = int(self.total_count * p / 100)
        cumulative = 0

        for i, count in enumerate(self.buckets):
            cumulative += count
            if cumulative >= target:
                # Return bucket midpoint.
                if i == 0:
                    return self.BUCKET_BOUNDS[0] / 2
                elif i >= len(self.BUCKET_BOUNDS):
                    return self.BUCKET_BOUNDS[-1] * 1.5
                else:
                    return (self.BUCKET_BOUNDS[i - 1] + self.BUCKET_BOUNDS[i]) / 2

        return self.BUCKET_BOUNDS[-1]

    def __len__(self) -> int:
        return self.total_count


class CircularLatencyBuffer:
    """O(1) circular buffer for latency tracking.

    Provides efficient insertion while maintaining ability to calculate percentiles.
    Uses histogram for O(1) percentile queries.
    """

    def __init__(self, size: int = MAX_LATENCIES):
        self.buffer = [0.0] * size
        self.size = size
        self.index = 0
        self.count = 0
        # Use histogram for fast percentile queries.
        self._histogram = HistogramLatencyBuffer(size)

    def add(self, latency: float) -> None:
        """Add a latency value in O(1) time."""
        self.buffer[self.index] = latency
        self.index = (self.index + 1) % self.size
        self.count = min(self.count + 1, self.size)
        # Also add to histogram for O(1) percentiles.
        self._histogram.add(latency)

    def percentile(self, p: float) -> float:
        """Get latency percentile (0-100) in O(1) time."""
        return self._histogram.percentile(p)

    def __len__(self) -> int:
        return self.count


@dataclass
class CellMetrics:
    """Metrics for a single cell."""
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limited_requests: int = 0
    error_requests: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    last_request_ts: float = 0.0
    _latency_buffer: CircularLatencyBuffer = field(default_factory=CircularLatencyBuffer)

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

        # O(1) latency recording.
        self._latency_buffer.add(latency_ms)

    def get_percentile(self, p: float) -> float:
        """Get latency percentile (0-100)."""
        return self._latency_buffer.percentile(p)

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
        self.metrics: collections.OrderedDict[str, CellMetrics] = collections.OrderedDict()
        self.metrics_lock = threading.Lock()
        self.server_thread: Optional[threading.Thread] = None
        self.running = False
        self.persistence_enabled = True

    def load(self, loader):
        """Called when addon is loaded."""
        ctx.log.info("MetricsCollector: Loading...")
        self._load_persisted_metrics()
        self._start_server()

    def done(self):
        """Called when addon is unloaded."""
        self._persist_metrics()
        self._stop_server()

    def _persist_metrics(self) -> None:
        """Save metrics to disk for persistence across restarts."""
        if not self.persistence_enabled:
            return

        try:
            METRICS_PERSISTENCE_FILE.parent.mkdir(parents=True, exist_ok=True)

            # Serialize metrics (counters only, latency histogram not persisted).
            with self.metrics_lock:
                data = {}
                for cell_name, cell_metrics in self.metrics.items():
                    data[cell_name] = {
                        "total_requests": cell_metrics.total_requests,
                        "blocked_requests": cell_metrics.blocked_requests,
                        "rate_limited_requests": cell_metrics.rate_limited_requests,
                        "error_requests": cell_metrics.error_requests,
                        "bytes_sent": cell_metrics.bytes_sent,
                        "bytes_received": cell_metrics.bytes_received,
                        "last_request_ts": cell_metrics.last_request_ts,
                    }

            # Atomic write.
            tmp_path = METRICS_PERSISTENCE_FILE.with_suffix(".tmp")
            with open(tmp_path, "w") as f:
                json.dump(data, f, indent=2)
            tmp_path.rename(METRICS_PERSISTENCE_FILE)

            ctx.log.info(f"MetricsCollector: Persisted metrics for {len(data)} cells")

        except (IOError, OSError) as e:
            ctx.log.error(f"MetricsCollector: Failed to persist metrics: {e}")

    def _load_persisted_metrics(self) -> None:
        """Load metrics from disk on startup."""
        if not self.persistence_enabled:
            return

        if not METRICS_PERSISTENCE_FILE.exists():
            return

        try:
            with open(METRICS_PERSISTENCE_FILE, "r") as f:
                data = json.load(f)

            with self.metrics_lock:
                for cell_name, values in data.items():
                    cell_metrics = CellMetrics()
                    cell_metrics.total_requests = values.get("total_requests", 0)
                    cell_metrics.blocked_requests = values.get("blocked_requests", 0)
                    cell_metrics.rate_limited_requests = values.get("rate_limited_requests", 0)
                    cell_metrics.error_requests = values.get("error_requests", 0)
                    cell_metrics.bytes_sent = values.get("bytes_sent", 0)
                    cell_metrics.bytes_received = values.get("bytes_received", 0)
                    cell_metrics.last_request_ts = values.get("last_request_ts", 0.0)
                    self.metrics[cell_name] = cell_metrics

            ctx.log.info(f"MetricsCollector: Loaded persisted metrics for {len(data)} cells")

        except (json.JSONDecodeError, IOError, OSError) as e:
            ctx.log.warn(f"MetricsCollector: Failed to load persisted metrics: {e}")

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

        sock = None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(METRICS_SOCKET))
            os.chmod(str(METRICS_SOCKET), 0o600)
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
            if sock:
                sock.close()
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
                cell_name = data[5:].strip()
                if len(cell_name) > 64:
                    response = {"error": "Cell name too long"}
                else:
                    response = self._get_cell_metrics(cell_name)
            else:
                response = {"error": "Unknown command"}

            # Send response in chunks to handle large payloads.
            response_bytes = json.dumps(response).encode("utf-8")
            total_sent = 0
            while total_sent < len(response_bytes):
                sent = conn.send(response_bytes[total_sent:])
                if sent == 0:
                    ctx.log.warn("MetricsCollector: Socket connection closed while sending")
                    break
                total_sent += sent

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

    def _get_or_create_metrics_unlocked(self, cell_name: str) -> CellMetrics:
        """Get or create metrics for a cell. Caller must hold metrics_lock.

        Applies LRU eviction when exceeding MAX_TRACKED_CELLS to bound memory.
        Uses OrderedDict for O(1) eviction instead of O(n) min() scan.
        """
        if cell_name in self.metrics:
            # Move to end (most recently used).
            self.metrics.move_to_end(cell_name)
            return self.metrics[cell_name]
        # Evict least recently used if at capacity.
        if len(self.metrics) >= MAX_TRACKED_CELLS:
            oldest_key, _ = self.metrics.popitem(last=False)
            ctx.log.debug(f"MetricsCollector: Evicted metrics for '{oldest_key}'")
        self.metrics[cell_name] = CellMetrics()
        return self.metrics[cell_name]

    def _get_or_create_metrics(self, cell_name: str) -> CellMetrics:
        """Get or create metrics for a cell (acquires lock)."""
        with self.metrics_lock:
            return self._get_or_create_metrics_unlocked(cell_name)

    def request(self, flow: http.HTTPFlow) -> None:
        """Record request start time."""
        flow.metadata["metrics_start"] = time.time()

    def response(self, flow: http.HTTPFlow) -> None:
        """Record completed request metrics."""
        cell_name = flow.metadata.get("cell", "unknown")

        # Calculate latency.
        start_time = flow.metadata.get("metrics_start", time.time())
        latency_ms = (time.time() - start_time) * 1000

        # Get sizes.
        request_bytes = len(flow.request.content) if flow.request.content else 0
        response_bytes = len(flow.response.content) if flow.response.content else 0

        # Hold lock for get-or-create + record to avoid torn reads from socket thread.
        with self.metrics_lock:
            metrics = self._get_or_create_metrics_unlocked(cell_name)
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

        # Calculate latency.
        start_time = flow.metadata.get("metrics_start", time.time())
        latency_ms = (time.time() - start_time) * 1000

        # Get request size.
        request_bytes = len(flow.request.content) if flow.request and flow.request.content else 0

        # Hold lock for get-or-create + record to avoid torn reads from socket thread.
        with self.metrics_lock:
            metrics = self._get_or_create_metrics_unlocked(cell_name)
            metrics.record_request(
                blocked=flow.metadata.get("blocked", False),
                rate_limited=flow.metadata.get("rate_limited", False),
                error=True,
                request_bytes=request_bytes,
                response_bytes=0,
                latency_ms=latency_ms
            )


addons = [MetricsCollector()]
