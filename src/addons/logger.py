"""
Logging addon for mitmproxy.

Logs all HTTP requests to per-cell JSONL files:
    - Resolves client IP to cell name via subnet map
    - Logs request details including timing and size
    - Supports log filtering to reduce noise
    - TLS certificate logging for security visibility
    - Hot-reload of configuration

Log format (JSONL):
    {
        "ts": "2024-01-01T12:00:00Z",
        "cell": "my-cell",
        "src_ip": "10.60.1.2",
        "method": "GET",
        "host": "example.com",
        "path": "/api/v1/data",
        "status": 200,
        "bytes": 1234,
        "request_bytes": 56,
        "ms": 45.2,
        "blocked": false,
        "cert_issuer": "Let's Encrypt",
        "cert_valid": true,
        "cert_flags": []
    }

Usage:
    mitmdump -s logger.py
"""

import fcntl
import fnmatch
import json
import queue
import random
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http


# Try to use orjson for faster JSON encoding, fall back to standard json.
try:
    import orjson
    def _json_encode(obj: dict) -> str:
        """Fast JSON encoding using orjson."""
        return orjson.dumps(obj).decode("utf-8")
    JSON_ENCODER = "orjson"
except ImportError:
    # Reusable JSON encoder for better performance.
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

# Number of rotated log files to keep.
MAX_ROTATED_FILES = 1

# Subnet map for cell identification.
SUBNET_MAP_FILE = Path("/var/run/cells/subnet-map.json")

# Policy file (for log filter configuration).
POLICY_FILE = Path("/policy.json")

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
    # Decode until stable to prevent double-encoding bypass.
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
        self.flush_interval = flush_interval_ms / 1000.0  # Convert to seconds.
        self.batch_size = batch_size
        self.max_log_size = max_log_size
        self.running = False
        self.worker = None
        self._lock = threading.Lock()
        self._file_sizes: dict[Path, int] = {}  # Cached file sizes.

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
        # Flush any remaining entries.
        self._flush_all()

    def log(self, entry: dict, log_file: Path) -> None:
        """Queue a log entry for async writing."""
        try:
            self.queue.put_nowait((entry, log_file))
        except queue.Full:
            # Queue full - fall back to sync write.
            self._write_sync(entry, log_file)

    def _flush_worker(self) -> None:
        """Background worker that flushes batches to disk."""
        batch = []
        last_flush = time.time()

        while self.running:
            try:
                # Non-blocking get with timeout.
                item = self.queue.get(timeout=0.01)
                batch.append(item)

                # Check flush conditions: batch size or time interval.
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
                # Timeout - check if we should flush due to time.
                now = time.time()
                if batch and (now - last_flush) >= self.flush_interval:
                    try:
                        self._flush_batch(batch)
                    except Exception as e:
                        ctx.log.error(f"AsyncLogWriter: flush failed: {e}")
                    batch = []
                    last_flush = now

        # Final flush on shutdown.
        if batch:
            try:
                self._flush_batch(batch)
            except Exception as e:
                ctx.log.error(f"AsyncLogWriter: final flush failed: {e}")

    def _flush_batch(self, batch: list) -> None:
        """Write a batch of entries to their respective files."""
        if not batch:
            return

        # Group entries by log file.
        by_file = {}
        for entry, log_file in batch:
            if log_file not in by_file:
                by_file[log_file] = []
            by_file[log_file].append(entry)

        # Write each file's entries.
        for log_file, entries in by_file.items():
            self._write_batch(entries, log_file)

    def _rotate_log(self, log_file: Path) -> None:
        """Rotate log file when size limit exceeded.

        Caller must hold self._lock for _file_sizes access.
        """
        try:
            # Remove oldest rotated file if it exists.
            for i in range(MAX_ROTATED_FILES, 0, -1):
                old = log_file.with_suffix(f".{i}.jsonl")
                if i == MAX_ROTATED_FILES and old.exists():
                    old.unlink()
                elif old.exists():
                    old.rename(log_file.with_suffix(f".{i+1}.jsonl"))

            # Rotate current log to .1.
            if log_file.exists():
                log_file.rename(log_file.with_suffix(".1.jsonl"))

            # Reset cached size (caller holds self._lock).
            self._file_sizes[log_file] = 0
        except (IOError, OSError) as e:
            # Log rotation is best-effort; continue even on failure.
            ctx.log.warn(f"RequestLogger: Failed to rotate log {log_file}: {e}")

    def _check_rotation(self, log_file: Path, bytes_to_write: int) -> None:
        """Check if log file needs rotation before writing.

        Caller must hold the file lock (fcntl.flock) to prevent races.
        """
        # Get current file size (cached or from disk).
        with self._lock:
            if log_file not in self._file_sizes:
                try:
                    self._file_sizes[log_file] = log_file.stat().st_size if log_file.exists() else 0
                except (IOError, OSError):
                    self._file_sizes[log_file] = 0

            # Rotate if adding these bytes would exceed limit.
            if self._file_sizes[log_file] + bytes_to_write > self.max_log_size:
                self._rotate_log(log_file)

    def _write_batch(self, entries: list, log_file: Path) -> None:
        """Write multiple entries to a file with locking and rotation.

        Acquires file lock before rotation check to ensure atomicity.
        """
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)

            # Encode all entries first to know total size.
            encoded = [_json_encode(entry) + "\n" for entry in entries]
            total_bytes = sum(len(e.encode("utf-8")) for e in encoded)

            # Open and lock before rotation check to prevent races between
            # rotation (which unlinks the file) and writes from other processes.
            f = open(log_file, "a")
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                self._check_rotation(log_file, total_bytes)
                # After rotation, re-open the file to write to the new path.
                if self._file_sizes.get(log_file, 0) == 0 and f.tell() > 0:
                    f.close()
                    f = open(log_file, "a")
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                for line in encoded:
                    f.write(line)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                f.close()

            # Update cached size under the instance lock.
            with self._lock:
                self._file_sizes[log_file] = self._file_sizes.get(log_file, 0) + total_bytes

        except (IOError, OSError) as e:
            # Log errors go to mitmproxy log, not recursively.
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
                # After rotation, re-open the file to write to the new path.
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
        # Enhanced filtering options.
        self.only_blocked = config.get("only_blocked", False)
        self.only_errors = config.get("only_errors", False)
        self.min_latency_ms = config.get("min_latency_ms", 0)
        self.max_body_size = config.get("max_body_size", 0)  # 0 = no limit
        # Pre-compile glob patterns to regex for fast matching.
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
        # Check host exclusions (pre-compiled regex).
        if self._host_patterns:
            host_lower = host.lower()
            for pattern in self._host_patterns:
                if pattern.match(host_lower):
                    return False

        # Check path exclusions (pre-compiled regex).
        for pattern in self._path_patterns:
            if pattern.match(path):
                return False

        # Check minimum status.
        if status < self.min_status:
            return False

        # Check only_blocked filter.
        if self.only_blocked and not blocked:
            return False

        # Check only_errors filter (status >= 400 or status == 0 for connection errors).
        if self.only_errors and not (status >= 400 or status == 0):
            return False

        # Check minimum latency.
        if self.min_latency_ms > 0 and latency_ms < self.min_latency_ms:
            return False

        # Check maximum body size.
        if self.max_body_size > 0 and body_size > self.max_body_size:
            return False

        # Check sample rate.
        if self.sample_rate < 1.0 and random.random() > self.sample_rate:
            return False

        return True


class RequestLogger:
    """mitmproxy addon for request logging."""

    def __init__(self):
        self.subnet_map: dict[str, str] = {}
        self._subnet_index: dict[int, str] = {}  # Third-octet index for O(1) /24 lookup.
        self.subnet_map_mtime = 0.0
        self.log_filter = LogFilter()
        self.policy_mtime = 0.0
        self.max_log_size = DEFAULT_MAX_LOG_SIZE
        self.async_writer = AsyncLogWriter(max_log_size=self.max_log_size)
        self._reload_pending = False  # Deferred reload flag for signal safety.

    def load(self, loader):
        """Called when addon is loaded."""
        ctx.log.info("RequestLogger: Loading...")
        self._reload_subnet_map()
        self._reload_log_filter()
        self.async_writer.start()
        # Register with shared SIGHUP dispatcher.
        ctx.log.info("RequestLogger: Async logging enabled")

    def configure(self, updated):
        """Reload config when files change."""
        self._reload_pending = True

    def _do_reload(self):
        """Perform the actual reload outside of signal context."""
        ctx.log.info("RequestLogger: Reloading config...")
        self.subnet_map_mtime = 0.0
        self.policy_mtime = 0.0
        self._reload_subnet_map()
        self._reload_log_filter()

    def done(self):
        """Called when addon is unloaded."""
        ctx.log.info("RequestLogger: Shutting down async writer...")
        self.async_writer.stop()

    def _reload_subnet_map(self) -> None:
        """Load subnet-to-cell mapping."""
        try:
            if not SUBNET_MAP_FILE.exists():
                return

            mtime = SUBNET_MAP_FILE.stat().st_mtime
            if mtime == self.subnet_map_mtime:
                return  # No change.

            with open(SUBNET_MAP_FILE, "r") as f:
                self.subnet_map = json.load(f)
            self.subnet_map_mtime = mtime
            self._build_subnet_index()

            ctx.log.info(f"RequestLogger: Loaded subnet map - {len(self.subnet_map)} cells")

        except (json.JSONDecodeError, IOError, OSError) as e:
            ctx.log.error(f"RequestLogger: Failed to load subnet map: {e}")

    def _build_subnet_index(self) -> None:
        """Build O(1) lookup index for /24 subnets keyed by top 24 bits.

        Uses the network prefix (top 24 bits) as key to avoid collisions
        between subnets in different /16 ranges.
        """
        import ipaddress
        index = {}
        for subnet_str, cell_name in self.subnet_map.items():
            try:
                net = ipaddress.ip_network(subnet_str, strict=False)
                if net.version == 4 and net.prefixlen == 24:
                    prefix = int(net.network_address) >> 8
                    index[prefix] = cell_name
            except ValueError:
                continue
        self._subnet_index = index

    def _reload_log_filter(self) -> None:
        """Load log filter and quota configuration from policy file."""
        try:
            if not POLICY_FILE.exists():
                return

            mtime = POLICY_FILE.stat().st_mtime
            if mtime == self.policy_mtime:
                return  # No change.

            with open(POLICY_FILE, "r") as f:
                data = json.load(f)

            filter_config = data.get("log_filter", {})
            self.log_filter = LogFilter(filter_config)

            # Load disk quota configuration.
            quota_config = data.get("log_quota", {})
            max_size_mb = quota_config.get("max_size_mb", 100)
            self.max_log_size = max_size_mb * 1024 * 1024
            self.async_writer.max_log_size = self.max_log_size

            self.policy_mtime = mtime

            ctx.log.info(
                f"RequestLogger: Loaded config (filter enabled, "
                f"max log size: {max_size_mb}MB)"
            )

        except (json.JSONDecodeError, IOError, OSError) as e:
            ctx.log.error(f"RequestLogger: Failed to load log filter: {e}")

    def _get_cell_name(self, client_ip: str) -> Optional[str]:
        """Resolve client IP to cell name via subnet map.

        Fast path: O(1) dict lookup by third octet for /24 IPv4 subnets.
        Slow path: linear scan for non-/24 or IPv6 subnets.
        """
        import ipaddress
        try:
            ip = ipaddress.ip_address(client_ip)
            # Fast path: IPv4 with /24 index.
            if isinstance(ip, ipaddress.IPv4Address) and self._subnet_index:
                prefix = int(ip) >> 8
                result = self._subnet_index.get(prefix)
                if result is not None:
                    return result
            # Slow path: linear scan for non-indexed subnets.
            for subnet_str, cell_name in self.subnet_map.items():
                try:
                    subnet = ipaddress.ip_network(subnet_str, strict=False)
                    if ip in subnet:
                        return cell_name
                except ValueError:
                    continue
        except ValueError:
            pass
        return None

    def _get_cert_info(self, flow: http.HTTPFlow) -> dict:
        """Extract TLS certificate information from the server connection."""
        cert_info = {}

        try:
            server_conn = flow.server_conn
            if not server_conn or not server_conn.tls_established:
                return cert_info

            # Get the peer certificate from the server connection.
            # mitmproxy 10.x uses peercert attribute.
            cert = getattr(server_conn, 'peercert', None)
            if cert is None:
                # Fallback for older versions.
                cert_list = getattr(server_conn, 'certificate_list', None)
                if cert_list and len(cert_list) > 0:
                    cert = cert_list[0]

            if cert is None:
                return cert_info

            # Extract certificate details safely.
            issuer = getattr(cert, 'issuer', None)
            cn = getattr(cert, 'cn', None)

            if issuer:
                cert_info["cert_issuer"] = str(issuer)
            if cn:
                cert_info["cert_subject"] = str(cn)

            # Check validity.
            now = datetime.now(timezone.utc)
            not_before = getattr(cert, 'notbefore', None)
            not_after = getattr(cert, 'notafter', None)

            cert_flags = []

            if not_before and now < not_before:
                cert_flags.append("not_yet_valid")
            if not_after and now > not_after:
                cert_flags.append("expired")

            # Check for self-signed.
            if issuer and cn and str(issuer) == str(cn):
                cert_flags.append("self_signed")

            cert_info["cert_valid"] = len(cert_flags) == 0
            cert_info["cert_flags"] = cert_flags

        except Exception as e:
            ctx.log.debug(f"RequestLogger: Failed to extract cert info: {e}")

        return cert_info

    def _write_log(self, cell_name: str, entry: dict) -> None:
        """Queue log entry for async writing."""
        # Validate cell name to prevent path traversal.
        if cell_name and not re.match(r'^[a-z0-9][a-z0-9._-]{0,62}$', cell_name):
            cell_name = None  # Fall back to unknown log.
        if cell_name:
            log_file = LOG_DIR / f"{cell_name}.jsonl"
        else:
            log_file = UNKNOWN_LOG_FILE

        self.async_writer.log(entry, log_file)

    def request(self, flow: http.HTTPFlow) -> None:
        """Record request start time."""
        flow.metadata["request_start"] = time.time()

    def response(self, flow: http.HTTPFlow) -> None:
        """Log completed request."""
        # Check for deferred SIGHUP reload (signal-safe pattern).
        if self._reload_pending:
            self._reload_pending = False
            self._do_reload()

        # Get cell name from metadata (set by enforce.py) or resolve.
        cell_name = flow.metadata.get("cell")
        if not cell_name or cell_name == "unknown":
            client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
            cell_name = self._get_cell_name(client_ip)

        # Calculate timing.
        start_time = flow.metadata.get("request_start", time.time())
        duration_ms = (time.time() - start_time) * 1000

        # Get request/response sizes.
        request_bytes = len(flow.request.content) if flow.request.content else 0
        response_bytes = len(flow.response.content) if flow.response.content else 0

        # Get status code.
        status = flow.response.status_code

        # Check log filter with enhanced parameters.
        blocked = flow.metadata.get("blocked", False)
        if not self.log_filter.should_log(
            flow.request.host, flow.request.path, status,
            blocked=blocked, latency_ms=duration_ms, body_size=response_bytes
        ):
            return

        # Build log entry.
        entry = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cell": cell_name or "unknown",
            "src_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "unknown",
            "method": flow.request.method,
            "host": flow.request.host,
            "path": _redact_path(flow.request.path),
            "status": status,
            "bytes": response_bytes,
            "request_bytes": request_bytes,
            "ms": round(duration_ms, 2),
            "blocked": flow.metadata.get("blocked", False),
        }

        # Add block reason if blocked.
        if entry["blocked"]:
            entry["block_reason"] = flow.metadata.get("block_reason", "unknown")

        # Add rate limit event if rate limited.
        rate_limit_event = flow.metadata.get("rate_limit_event")
        if rate_limit_event:
            entry["rate_limit"] = rate_limit_event

        # Add TLS certificate info for HTTPS.
        if flow.request.scheme == "https":
            cert_info = self._get_cert_info(flow)
            entry.update(cert_info)

        # Add policy trace if available.
        policy_trace = flow.metadata.get("policy_trace")
        if policy_trace:
            entry["policy_trace"] = policy_trace

        # Add host service attribution.
        host_service = flow.metadata.get("host_service")
        if host_service:
            entry["host_service"] = host_service

        # Write log.
        self._write_log(cell_name, entry)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Log WebSocket frame metadata for observability."""
        message = flow.websocket.messages[-1] if flow.websocket and flow.websocket.messages else None
        if message is None:
            return

        cell_name = flow.metadata.get("cell")
        if not cell_name or cell_name == "unknown":
            client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
            cell_name = self._get_cell_name(client_ip)

        entry = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cell": cell_name or "unknown",
            "src_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "unknown",
            "type": "websocket",
            "host": flow.request.host,
            "path": _redact_path(flow.request.path),
            "direction": "client" if message.from_client else "server",
            "frame_type": "text" if message.is_text else "binary",
            "frame_size": len(message.content),
        }

        self._write_log(cell_name, entry)

    def _extract_error_details(self, flow: http.HTTPFlow) -> dict:
        """Extract detailed error information from flow."""
        import errno
        import re

        details = {}
        error_str = str(flow.error) if flow.error else ""

        # Map common error patterns to error codes.
        error_patterns = {
            r"Connection refused": "ECONNREFUSED",
            r"Connection reset": "ECONNRESET",
            r"Connection timed out": "ETIMEDOUT",
            r"No route to host": "EHOSTUNREACH",
            r"Network is unreachable": "ENETUNREACH",
            r"Name or service not known": "NXDOMAIN",
            r"getaddrinfo failed": "NXDOMAIN",
            r"Temporary failure in name resolution": "EAGAIN",
            r"nodename nor servname provided": "NXDOMAIN",
            r"SSL": "SSL_ERROR",
            r"certificate": "CERT_ERROR",
            r"EOF": "EOF",
            r"closed": "CLOSED",
        }

        details["error_code"] = "UNKNOWN"
        for pattern, code in error_patterns.items():
            if re.search(pattern, error_str, re.IGNORECASE):
                details["error_code"] = code
                break

        # DNS resolution status.
        details["dns_resolved"] = details["error_code"] not in ("NXDOMAIN", "EAGAIN")

        # Destination IP if available.
        try:
            if flow.server_conn and flow.server_conn.peername:
                details["destination_ip"] = flow.server_conn.peername[0]
                details["destination_port"] = flow.server_conn.peername[1]
            elif flow.server_conn and flow.server_conn.address:
                # Address is (host, port) tuple.
                details["destination_port"] = flow.server_conn.address[1]
        except (AttributeError, TypeError, IndexError):
            pass

        return details

    def error(self, flow: http.HTTPFlow) -> None:
        """Log request errors with enhanced details."""
        # Get cell name.
        cell_name = flow.metadata.get("cell")
        if not cell_name or cell_name == "unknown":
            client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
            cell_name = self._get_cell_name(client_ip)

        # Calculate timing.
        start_time = flow.metadata.get("request_start", time.time())
        duration_ms = (time.time() - start_time) * 1000

        # Build error log entry.
        entry = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cell": cell_name or "unknown",
            "src_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "unknown",
            "method": flow.request.method if flow.request else "UNKNOWN",
            "host": flow.request.host if flow.request else "unknown",
            "path": _redact_path(flow.request.path) if flow.request else "/",
            "status": 0,
            "bytes": 0,
            "request_bytes": len(flow.request.content) if flow.request and flow.request.content else 0,
            "ms": round(duration_ms, 2),
            "blocked": flow.metadata.get("blocked", False),
            "error": re.sub(r'\d+\.\d+\.\d+\.\d+', '<ip>', str(flow.error)) if flow.error else "unknown error",
        }

        # Add enhanced error details.
        error_details = self._extract_error_details(flow)
        entry.update(error_details)

        # Write log.
        self._write_log(cell_name, entry)


addons = [RequestLogger()]
