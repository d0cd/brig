"""
Logging addon for mitmproxy.

Logs all HTTP requests to per-cell JSONL files:
    - Resolves client IP to cell name via subnet map
    - Logs request details including timing and size
    - Supports log filtering to reduce noise
    - TLS certificate logging for security visibility
    - Hot-reload of configuration

Async writer + log filter logic lives in `_log_writer.py` (sibling module,
not loaded as an addon). This file owns the mitmproxy lifecycle hooks.

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

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http

from _common import SubnetResolver, stat_signature
from _log_writer import (
    AsyncLogWriter,
    DEFAULT_MAX_LOG_SIZE,
    LOG_DIR,
    LogFilter,
    UNKNOWN_LOG_FILE,
    _redact_path,
)


# Subnet map for cell identification.
SUBNET_MAP_FILE = Path("/var/run/cells/subnet-map.json")

# Policy file (for log filter configuration).
POLICY_FILE = Path("/policy.json")


class RequestLogger:
    """mitmproxy addon for request logging."""

    def __init__(self):
        self.subnets = SubnetResolver(SUBNET_MAP_FILE)
        self.log_filter = LogFilter()
        self.policy_mtime: tuple[int, int] = (0, 0)
        self.max_log_size = DEFAULT_MAX_LOG_SIZE
        self.async_writer = AsyncLogWriter(max_log_size=self.max_log_size)
        self._reload_pending = False  # Deferred reload flag for signal safety.

    def load(self, loader):
        """Called when addon is loaded."""
        ctx.log.info("RequestLogger: Loading...")
        self.subnets.reload()
        self._reload_log_filter()
        self.async_writer.start()
        ctx.log.info("RequestLogger: Async logging enabled")

    def configure(self, updated):
        """Reload config when files change."""
        self._reload_pending = True

    def _do_reload(self):
        """Perform the actual reload outside of signal context."""
        ctx.log.info("RequestLogger: Reloading config...")
        self.subnets._sig = (0, 0)
        self.policy_mtime: tuple[int, int] = (0, 0)
        self.subnets.reload()
        self._reload_log_filter()

    def done(self):
        """Called when addon is unloaded."""
        ctx.log.info("RequestLogger: Shutting down async writer...")
        self.async_writer.stop()

    def _reload_log_filter(self) -> None:
        """Load log filter and quota configuration from policy file."""
        try:
            if not POLICY_FILE.exists():
                return

            sig = stat_signature(POLICY_FILE)
            if sig == self.policy_mtime:
                return  # No change.

            with open(POLICY_FILE, "r") as f:
                data = json.load(f)

            filter_config = data.get("log_filter", {})
            self.log_filter = LogFilter(filter_config)

            # Load disk quota configuration. Coerce to int: a string value
            # (e.g. "100") would silently become a repeated string on `* 1024`,
            # making the rotation size comparison raise TypeError and disabling
            # rotation (log loss).
            quota_config = data.get("log_quota", {})
            try:
                max_size_mb = int(quota_config.get("max_size_mb", 100))
            except (TypeError, ValueError):
                max_size_mb = 100
            self.max_log_size = max_size_mb * 1024 * 1024
            self.async_writer.max_log_size = self.max_log_size

            self.policy_mtime = sig

            ctx.log.info(
                f"RequestLogger: Loaded config (filter enabled, "
                f"max log size: {max_size_mb}MB)"
            )

        except (json.JSONDecodeError, IOError, OSError) as e:
            ctx.log.error(f"RequestLogger: Failed to load log filter: {e}")

    def _get_cell_name(self, client_ip: str) -> Optional[str]:
        """Resolve client IP to cell name via subnet map."""
        return self.subnets.get_cell_name(client_ip)

    def _get_cert_info(self, flow: http.HTTPFlow) -> dict:
        """Extract TLS certificate information from the server connection."""
        cert_info: dict = {}

        try:
            server_conn = flow.server_conn
            if not server_conn or not server_conn.tls_established:
                return cert_info

            # mitmproxy 10.x uses peercert attribute.
            cert = getattr(server_conn, 'peercert', None)
            if cert is None:
                cert_list = getattr(server_conn, 'certificate_list', None)
                if cert_list and len(cert_list) > 0:
                    cert = cert_list[0]
            if cert is None:
                return cert_info

            issuer = getattr(cert, 'issuer', None)
            cn = getattr(cert, 'cn', None)
            if issuer:
                cert_info["cert_issuer"] = str(issuer)
            if cn:
                cert_info["cert_subject"] = str(cn)

            now = datetime.now(timezone.utc)
            not_before = getattr(cert, 'notbefore', None)
            not_after = getattr(cert, 'notafter', None)

            cert_flags = []
            if not_before and now < not_before:
                cert_flags.append("not_yet_valid")
            if not_after and now > not_after:
                cert_flags.append("expired")
            if issuer and cn and str(issuer) == str(cn):
                cert_flags.append("self_signed")

            cert_info["cert_valid"] = len(cert_flags) == 0
            cert_info["cert_flags"] = cert_flags

        except Exception as e:
            ctx.log.debug(f"RequestLogger: Failed to extract cert info: {e}")

        return cert_info

    def _write_log(self, cell_name: Optional[str], entry: dict) -> None:
        """Queue log entry for async writing."""
        # Validate cell name to prevent path traversal.
        if cell_name and not re.match(r'^[a-z0-9][a-z0-9._-]{0,62}$', cell_name):
            cell_name = None  # Fall back to unknown log.
        log_file = LOG_DIR / f"{cell_name}.jsonl" if cell_name else UNKNOWN_LOG_FILE
        self.async_writer.log(entry, log_file)

    def request(self, flow: http.HTTPFlow) -> None:
        """Record request start time."""
        flow.metadata["request_start"] = time.time()

    def response(self, flow: http.HTTPFlow) -> None:
        """Log completed request."""
        if self._reload_pending:
            self._reload_pending = False
            self._do_reload()

        # Get cell name from metadata (set by enforce.py) or resolve.
        cell_name = flow.metadata.get("cell")
        if not cell_name or cell_name == "unknown":
            client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
            cell_name = self._get_cell_name(client_ip)

        start_time = flow.metadata.get("request_start", time.time())
        duration_ms = (time.time() - start_time) * 1000

        request_bytes = len(flow.request.content) if flow.request.content else 0
        response_bytes = len(flow.response.content) if flow.response.content else 0
        status = flow.response.status_code

        blocked = flow.metadata.get("blocked", False)
        if not self.log_filter.should_log(
            flow.request.host, flow.request.path, status,
            blocked=blocked, latency_ms=duration_ms, body_size=response_bytes
        ):
            return

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

        if entry["blocked"]:
            entry["block_reason"] = flow.metadata.get("block_reason", "unknown")

        rate_limit_event = flow.metadata.get("rate_limit_event")
        if rate_limit_event:
            entry["rate_limit"] = rate_limit_event

        if flow.request.scheme == "https":
            entry.update(self._get_cert_info(flow))

        policy_trace = flow.metadata.get("policy_trace")
        if policy_trace:
            entry["policy_trace"] = policy_trace

        host_service = flow.metadata.get("host_service")
        if host_service:
            entry["host_service"] = host_service

        # Mark ingress hits so `brig cell network` can tag them.
        ingress_route = flow.metadata.get("ingress_route")
        if ingress_route:
            entry["ingress_route"] = ingress_route
            entry["ingress_src_ip"] = flow.metadata.get(
                "ingress_client_ip", entry["src_ip"],
            )

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
        """Map common error strings to error codes + extract destination."""
        details: dict = {}
        error_str = str(flow.error) if flow.error else ""

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

        details["dns_resolved"] = details["error_code"] not in ("NXDOMAIN", "EAGAIN")

        try:
            if flow.server_conn and flow.server_conn.peername:
                details["destination_ip"] = flow.server_conn.peername[0]
                details["destination_port"] = flow.server_conn.peername[1]
            elif flow.server_conn and flow.server_conn.address:
                details["destination_port"] = flow.server_conn.address[1]
        except (AttributeError, TypeError, IndexError):
            pass

        return details

    def error(self, flow: http.HTTPFlow) -> None:
        """Log request errors with enhanced details."""
        cell_name = flow.metadata.get("cell")
        if not cell_name or cell_name == "unknown":
            client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
            cell_name = self._get_cell_name(client_ip)

        start_time = flow.metadata.get("request_start", time.time())
        duration_ms = (time.time() - start_time) * 1000

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

        entry.update(self._extract_error_details(flow))
        self._write_log(cell_name, entry)


addons = [RequestLogger()]
