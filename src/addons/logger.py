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
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mitmproxy import http, ctx, connection

# Log directory.
LOG_DIR = Path("/logs")

# Subnet map for cell identification.
SUBNET_MAP_FILE = Path("/var/run/cells/subnet-map.json")

# Policy file (for log filter configuration).
POLICY_FILE = Path("/policy.json")

# Default log file for unknown sources.
UNKNOWN_LOG_FILE = LOG_DIR / "unknown.jsonl"


class LogFilter:
    """Log filtering configuration."""

    def __init__(self, config: dict = None):
        config = config or {}
        self.exclude_hosts = config.get("exclude_hosts", [])
        self.exclude_paths = config.get("exclude_paths", [])
        self.min_status = config.get("min_status", 0)
        self.sample_rate = config.get("sample_rate", 1.0)

    def should_log(self, host: str, path: str, status: int) -> bool:
        """Check if request should be logged based on filter rules."""
        # Check host exclusions.
        for pattern in self.exclude_hosts:
            if fnmatch.fnmatch(host.lower(), pattern.lower()):
                return False

        # Check path exclusions.
        for pattern in self.exclude_paths:
            if fnmatch.fnmatch(path, pattern):
                return False

        # Check minimum status.
        if status < self.min_status:
            return False

        # Check sample rate.
        if self.sample_rate < 1.0 and random.random() > self.sample_rate:
            return False

        return True


class RequestLogger:
    """mitmproxy addon for request logging."""

    def __init__(self):
        self.subnet_map: dict[str, str] = {}
        self.subnet_map_mtime = 0.0
        self.log_filter = LogFilter()
        self.policy_mtime = 0.0

    def load(self, loader):
        """Called when addon is loaded."""
        ctx.log.info("RequestLogger: Loading...")
        self._reload_subnet_map()
        self._reload_log_filter()

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

            ctx.log.info(f"RequestLogger: Loaded subnet map - {len(self.subnet_map)} cells")

        except (json.JSONDecodeError, IOError, OSError) as e:
            ctx.log.error(f"RequestLogger: Failed to load subnet map: {e}")

    def _reload_log_filter(self) -> None:
        """Load log filter configuration from policy file."""
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
            self.policy_mtime = mtime

            ctx.log.info("RequestLogger: Loaded log filter configuration")

        except (json.JSONDecodeError, IOError, OSError) as e:
            ctx.log.error(f"RequestLogger: Failed to load log filter: {e}")

    def _get_cell_name(self, client_ip: str) -> Optional[str]:
        """Resolve client IP to cell name via subnet map."""
        import ipaddress
        try:
            ip = ipaddress.ip_address(client_ip)
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
        """Write log entry to cell's log file with locking."""
        LOG_DIR.mkdir(parents=True, exist_ok=True)

        if cell_name:
            log_file = LOG_DIR / f"{cell_name}.jsonl"
        else:
            log_file = UNKNOWN_LOG_FILE

        try:
            with open(log_file, "a") as f:
                # Acquire exclusive lock for concurrent-safe writes.
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(json.dumps(entry) + "\n")
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except (IOError, OSError) as e:
            ctx.log.error(f"RequestLogger: Failed to write log: {e}")

    def request(self, flow: http.HTTPFlow) -> None:
        """Record request start time."""
        flow.metadata["request_start"] = time.time()

    def response(self, flow: http.HTTPFlow) -> None:
        """Log completed request."""
        # Hot-reload configuration.
        self._reload_subnet_map()
        self._reload_log_filter()

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

        # Check log filter.
        if not self.log_filter.should_log(flow.request.host, flow.request.path, status):
            return

        # Build log entry.
        entry = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cell": cell_name or "unknown",
            "src_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "unknown",
            "method": flow.request.method,
            "host": flow.request.host,
            "path": flow.request.path,
            "status": status,
            "bytes": response_bytes,
            "request_bytes": request_bytes,
            "ms": round(duration_ms, 2),
            "blocked": flow.metadata.get("blocked", False),
        }

        # Add block reason if blocked.
        if entry["blocked"]:
            entry["block_reason"] = flow.metadata.get("block_reason", "unknown")

        # Add TLS certificate info for HTTPS.
        if flow.request.scheme == "https":
            cert_info = self._get_cert_info(flow)
            entry.update(cert_info)

        # Write log.
        self._write_log(cell_name, entry)

    def error(self, flow: http.HTTPFlow) -> None:
        """Log request errors."""
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
            "path": flow.request.path if flow.request else "/",
            "status": 0,
            "bytes": 0,
            "request_bytes": len(flow.request.content) if flow.request and flow.request.content else 0,
            "ms": round(duration_ms, 2),
            "blocked": flow.metadata.get("blocked", False),
            "error": str(flow.error) if flow.error else "unknown error",
        }

        # Write log.
        self._write_log(cell_name, entry)


addons = [RequestLogger()]
