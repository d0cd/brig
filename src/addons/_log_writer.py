"""
Async log writer + log filter for the request-logger addon.

Sibling module of `logger.py` — `_` prefix keeps mitmproxy from registering
this as an addon. `logger.py` imports the classes here. Splitting these out
keeps `logger.py` focused on the mitmproxy lifecycle hooks.

Contents:
  - JSON encoder selector (orjson when available)
  - AsyncLogWriter: queue + background flush thread + per-file rotation
  - LogFilter: pre-compiled glob filters + sample rate + latency/size gates
  - constants the addon needs
  - `_redact_path()` for stripping secrets from query strings
"""

from __future__ import annotations

import fcntl
import fnmatch
import json
import queue
import random
import re
import threading
import time
from pathlib import Path

from mitmproxy import ctx


# Try to use orjson for faster JSON encoding, fall back to standard json.
try:
    import orjson
    def _json_encode(obj: dict) -> str:
        """Fast JSON encoding using orjson."""
        return orjson.dumps(obj).decode("utf-8")
    JSON_ENCODER = "orjson"
except ImportError:
    _json_encoder = json.JSONEncoder(separators=(",", ":"))
    def _json_encode(obj: dict) -> str:
        """JSON encoding using reusable encoder."""
        return _json_encoder.encode(obj)
    JSON_ENCODER = "json"

# Async logging configuration.
ASYNC_QUEUE_SIZE = 10000
ASYNC_FLUSH_INTERVAL_MS = 100
ASYNC_FLUSH_BATCH_SIZE = 100

# Log directory.
LOG_DIR = Path("/logs")

# Default max log file size per cell (100MB).
DEFAULT_MAX_LOG_SIZE = 100 * 1024 * 1024

# Number of rotated log files to keep on top of the live one.
#
# Sizing example: a cell at 100 req/s with 1KB log entries fills 100MB in
# ~17 minutes. 4 generations + live = ~85 minutes of history before the
# oldest rotation is dropped. Tunable per workload — bump if you need a
# longer window, or lower DEFAULT_MAX_LOG_SIZE for more frequent rotation
# at the cost of more inodes.
MAX_ROTATED_FILES = 4

# Default log file for unknown sources.
UNKNOWN_LOG_FILE = LOG_DIR / "unknown.jsonl"


# Pattern matching common secret query parameters.
_SECRET_PARAM_RE = re.compile(
    r'([?&])'
    r'(key|api_key|apikey|token|access_token|secret|password|auth|authorization|'
    r'client_secret|private_key|signing_key|bearer)'
    r'=([^&]*)',
    re.IGNORECASE,
)


def _redact_path(path: str) -> str:
    """Redact sensitive query string parameters from a request path.

    URL-decodes the path in a loop until stable to prevent double-encoding
    bypass (e.g., %2561pi%255Fkey=secret). Limited to 5 iterations to
    prevent pathological inputs from causing excessive CPU use.
    """
    from urllib.parse import unquote
    prev = None
    decoded = path
    for _ in range(5):
        prev = decoded
        decoded = unquote(decoded)
        if decoded == prev:
            break
    return _SECRET_PARAM_RE.sub(r'\1\2=REDACTED', decoded)


class AsyncLogWriter:
    """Asynchronous log writer with batched writes.

    Uses a queue and background thread to avoid blocking on file I/O.
    Hybrid flush: writes batch when either time or count threshold is reached.
    Supports per-cell disk quotas with log rotation.
    """

    def __init__(self, queue_size: int = ASYNC_QUEUE_SIZE,
                 flush_interval_ms: int = ASYNC_FLUSH_INTERVAL_MS,
                 batch_size: int = ASYNC_FLUSH_BATCH_SIZE,
                 max_log_size: int = DEFAULT_MAX_LOG_SIZE):
        self.queue = queue.Queue(maxsize=queue_size)
        self.flush_interval = flush_interval_ms / 1000.0
        self.batch_size = batch_size
        self.max_log_size = max_log_size
        self.running = False
        self.worker = None
        self._lock = threading.Lock()
        self._file_sizes: dict[Path, int] = {}

    def start(self) -> None:
        """Start the background worker thread."""
        if self.running:
            return
        self.running = True
        self.worker = threading.Thread(target=self._flush_worker, daemon=True)
        self.worker.start()

    def stop(self) -> None:
        """Stop the background worker and flush remaining entries."""
        self.running = False
        if self.worker:
            self.worker.join(timeout=1.0)
            self.worker = None
        self._flush_all()

    def log(self, entry: dict, log_file: Path) -> None:
        """Queue a log entry for async writing."""
        try:
            self.queue.put_nowait((entry, log_file))
        except queue.Full:
            self._write_sync(entry, log_file)

    def _flush_worker(self) -> None:
        """Background worker that flushes batches to disk."""
        batch = []
        last_flush = time.time()

        while self.running:
            try:
                item = self.queue.get(timeout=0.01)
                batch.append(item)
                now = time.time()
                should_flush = (
                    len(batch) >= self.batch_size or
                    (now - last_flush) >= self.flush_interval
                )
                if should_flush:
                    try:
                        self._flush_batch(batch)
                    except Exception as e:
                        ctx.log.error(f"AsyncLogWriter: flush failed: {e}")
                    batch = []
                    last_flush = now
            except queue.Empty:
                now = time.time()
                if batch and (now - last_flush) >= self.flush_interval:
                    try:
                        self._flush_batch(batch)
                    except Exception as e:
                        ctx.log.error(f"AsyncLogWriter: flush failed: {e}")
                    batch = []
                    last_flush = now

        if batch:
            try:
                self._flush_batch(batch)
            except Exception as e:
                ctx.log.error(f"AsyncLogWriter: final flush failed: {e}")

    def _flush_batch(self, batch: list) -> None:
        """Write a batch of entries to their respective files."""
        if not batch:
            return
        by_file: dict[Path, list] = {}
        for entry, log_file in batch:
            by_file.setdefault(log_file, []).append(entry)
        for log_file, entries in by_file.items():
            self._write_batch(entries, log_file)

    def _rotate_log(self, log_file: Path) -> None:
        """Rotate log file when size limit exceeded.

        Caller must hold self._lock for _file_sizes access.
        """
        try:
            for i in range(MAX_ROTATED_FILES, 0, -1):
                old = log_file.with_suffix(f".{i}.jsonl")
                if i == MAX_ROTATED_FILES and old.exists():
                    old.unlink()
                elif old.exists():
                    old.rename(log_file.with_suffix(f".{i+1}.jsonl"))
            if log_file.exists():
                log_file.rename(log_file.with_suffix(".1.jsonl"))
            self._file_sizes[log_file] = 0
        except (IOError, OSError) as e:
            ctx.log.warn(f"RequestLogger: Failed to rotate log {log_file}: {e}")

    def _check_rotation(self, log_file: Path, bytes_to_write: int) -> None:
        """Check if log file needs rotation before writing.

        Caller must hold the file lock (fcntl.flock) to prevent races.
        """
        with self._lock:
            if log_file not in self._file_sizes:
                try:
                    self._file_sizes[log_file] = log_file.stat().st_size if log_file.exists() else 0
                except (IOError, OSError):
                    self._file_sizes[log_file] = 0
            if self._file_sizes[log_file] + bytes_to_write > self.max_log_size:
                self._rotate_log(log_file)

    def _write_batch(self, entries: list, log_file: Path) -> None:
        """Write multiple entries to a file with locking and rotation."""
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            encoded = [_json_encode(entry) + "\n" for entry in entries]
            total_bytes = sum(len(e.encode("utf-8")) for e in encoded)

            f = open(log_file, "a")
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                self._check_rotation(log_file, total_bytes)
                if self._file_sizes.get(log_file, 0) == 0 and f.tell() > 0:
                    f.close()
                    f = open(log_file, "a")
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                for line in encoded:
                    f.write(line)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                f.close()

            with self._lock:
                self._file_sizes[log_file] = self._file_sizes.get(log_file, 0) + total_bytes
        except (IOError, OSError) as e:
            ctx.log.warn(f"RequestLogger: Failed to write batch to {log_file}: {e}")

    def _write_sync(self, entry: dict, log_file: Path) -> None:
        """Synchronous write fallback when queue is full."""
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            encoded = _json_encode(entry) + "\n"
            byte_len = len(encoded.encode("utf-8"))

            f = open(log_file, "a")
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                self._check_rotation(log_file, byte_len)
                if self._file_sizes.get(log_file, 0) == 0 and f.tell() > 0:
                    f.close()
                    f = open(log_file, "a")
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                f.write(encoded)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                f.close()

            with self._lock:
                self._file_sizes[log_file] = self._file_sizes.get(log_file, 0) + byte_len
        except (IOError, OSError) as e:
            ctx.log.warn(f"RequestLogger: Failed to write sync to {log_file}: {e}")

    def _flush_all(self) -> None:
        """Flush all remaining entries in queue."""
        batch = []
        while True:
            try:
                item = self.queue.get_nowait()
                batch.append(item)
            except queue.Empty:
                break
        if batch:
            self._flush_batch(batch)


class LogFilter:
    """Log filtering configuration.

    Patterns are pre-compiled to regex at construction time for O(1)
    matching per pattern instead of fnmatch's per-call parsing.
    """

    def __init__(self, config: dict = None):
        config = config or {}
        self.min_status = config.get("min_status", 0)
        self.sample_rate = config.get("sample_rate", 1.0)
        self.only_blocked = config.get("only_blocked", False)
        self.only_errors = config.get("only_errors", False)
        self.min_latency_ms = config.get("min_latency_ms", 0)
        self.max_body_size = config.get("max_body_size", 0)
        self._host_patterns = [
            re.compile(fnmatch.translate(p.lower()))
            for p in config.get("exclude_hosts", [])
        ]
        self._path_patterns = [
            re.compile(fnmatch.translate(p))
            for p in config.get("exclude_paths", [])
        ]

    def should_log(self, host: str, path: str, status: int,
                   blocked: bool = False, latency_ms: float = 0,
                   body_size: int = 0) -> bool:
        """Check if request should be logged based on filter rules."""
        if self._host_patterns:
            host_lower = host.lower()
            for pattern in self._host_patterns:
                if pattern.match(host_lower):
                    return False
        for pattern in self._path_patterns:
            if pattern.match(path):
                return False
        if status < self.min_status:
            return False
        if self.only_blocked and not blocked:
            return False
        if self.only_errors and not (status >= 400 or status == 0):
            return False
        if self.min_latency_ms > 0 and latency_ms < self.min_latency_ms:
            return False
        if self.max_body_size > 0 and body_size > self.max_body_size:
            return False
        if self.sample_rate < 1.0 and random.random() > self.sample_rate:
            return False
        return True
