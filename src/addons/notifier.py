"""
Webhook notification addon for mitmproxy.

Sends real-time notifications on blocked requests:
    - POST to configured webhook URL
    - Configurable filters (block reasons, cells, domains)
    - Rate-limited to prevent notification spam
    - Async HTTP to avoid blocking proxy
    - Circuit breaker to prevent repeated failures
    - Exponential backoff for retries
    - Dead-letter queue for failed notifications

Configuration in policy file:
    {
        "notifications": {
            "webhook_url": "https://example.com/webhook",
            "filters": {
                "block_reasons": ["denied by rule", "not in allowlist"],
                "cells": ["sensitive-cell"],
                "min_interval_seconds": 60
            },
            "circuit_breaker": {
                "failure_threshold": 5,
                "recovery_timeout": 300,
                "max_retries": 3
            }
        }
    }

Usage:
    mitmdump -s notifier.py
"""

import collections
import ipaddress
import json
import queue
import re
import socket as _socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from mitmproxy import ctx, http

# Try to use urllib3 for connection pooling, fall back to urllib.
try:
    import urllib3
    URLLIB3_AVAILABLE = True
except ImportError:
    import urllib.error
    import urllib.request
    URLLIB3_AVAILABLE = False

# Blocked networks for SSRF prevention.
# Must match enforce.py BLOCKED_NETWORKS to prevent webhook-based SSRF.
BLOCKED_NETWORKS = [
    # RFC1918 private ranges.
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Localhost.
    ipaddress.ip_network("127.0.0.0/8"),
    # Link-local.
    ipaddress.ip_network("169.254.0.0/16"),
    # CGNAT.
    ipaddress.ip_network("100.64.0.0/10"),
    # Benchmarking.
    ipaddress.ip_network("198.18.0.0/15"),
    # Reserved.
    ipaddress.ip_network("240.0.0.0/4"),
    # "This network" (used in SSRF attacks).
    ipaddress.ip_network("0.0.0.0/8"),
    # Multicast.
    ipaddress.ip_network("224.0.0.0/4"),
    # IPv6 equivalents.
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    # IPv4-mapped IPv6 (bypass for all IPv4 blocked ranges).
    ipaddress.ip_network("::ffff:0:0/96"),
    # Documentation prefix (should never appear in production).
    ipaddress.ip_network("2001:db8::/32"),
    # IPv6 multicast.
    ipaddress.ip_network("ff00::/8"),
]


def _resolve_webhook_url(url: str) -> tuple[bool, str, str, int]:
    """Resolve webhook URL and validate against internal networks.

    Returns (safe, resolved_ip, hostname, port). If safe is False the
    remaining fields are empty/zero.
    """
    parsed = urlparse(url)
    if not parsed.hostname:
        return False, "", "", 0
    if parsed.scheme not in ("http", "https"):
        return False, "", "", 0

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addrs = _socket.getaddrinfo(parsed.hostname, port)
        # Collect the first usable address while checking all.
        first_ip_str = ""
        for family, socktype, proto, canonname, sockaddr in addrs:
            ip = ipaddress.ip_address(sockaddr[0])
            for net in BLOCKED_NETWORKS:
                if ip in net:
                    return False, "", "", 0
            if not first_ip_str:
                first_ip_str = sockaddr[0]
        if not first_ip_str:
            return False, "", "", 0
    except (OSError, ValueError):
        return False, "", "", 0

    return True, first_ip_str, parsed.hostname, port


def _is_safe_webhook_url(url: str) -> bool:
    """Validate webhook URL is not targeting internal networks."""
    safe, _, _, _ = _resolve_webhook_url(url)
    return safe


# Regex matching path segments that look like secrets/tokens.
# Matches hex strings >= 20 chars, base64-ish strings >= 20 chars, or
# segments containing common secret indicators.
_SECRET_PATH_RE = re.compile(
    r"(?<=/)"                         # Preceded by /.
    r"(?:"
    r"[A-Fa-f0-9]{20,}"              # Long hex string.
    r"|[A-Za-z0-9_\-]{20,}"          # Long base64-ish string.
    r")"
    r"(?=/|$)"                        # Followed by / or end.
)


def _redact_notification_path(path: str) -> str:
    """Remove query parameters, fragments, and potential secrets from path."""
    # Strip query string.
    path = path.split("?")[0]
    # Strip fragment identifier.
    path = path.split("#")[0]
    # Redact path segments that look like secrets or tokens.
    path = _SECRET_PATH_RE.sub("[REDACTED]", path)
    return path


def _redact_url_for_logging(url: str) -> str:
    """Return scheme + hostname only, stripping path, query, and credentials."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.hostname}"


# Policy file path.
POLICY_FILE = Path("/policy.json")

# Dead letter queue file path.
DEAD_LETTER_FILE = Path("/var/run/cells/dead-letters.json")

# Default minimum interval between notifications (per cell).
DEFAULT_MIN_INTERVAL = 60  # seconds

# Maximum queue size.
MAX_QUEUE_SIZE = 100

# HTTP timeout for webhook requests.
HTTP_TIMEOUT = 10  # seconds

# Maximum number of cells to track for rate limiting (LRU eviction beyond this).
MAX_TRACKED_CELLS = 1000

# Circuit breaker defaults.
DEFAULT_FAILURE_THRESHOLD = 5  # Consecutive failures before opening circuit.
DEFAULT_RECOVERY_TIMEOUT = 300  # Seconds before attempting recovery.
DEFAULT_MAX_RETRIES = 3  # Max retry attempts per notification.
DEFAULT_BASE_BACKOFF = 1.0  # Base backoff in seconds.
DEFAULT_MAX_BACKOFF = 60.0  # Maximum backoff in seconds.

# Maximum dead letters to keep.
MAX_DEAD_LETTERS = 1000


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD
    recovery_timeout: float = DEFAULT_RECOVERY_TIMEOUT
    max_retries: int = DEFAULT_MAX_RETRIES
    base_backoff: float = DEFAULT_BASE_BACKOFF
    max_backoff: float = DEFAULT_MAX_BACKOFF


@dataclass
class CircuitBreakerState:
    """Circuit breaker state tracking."""
    consecutive_failures: int = 0
    last_failure_time: float = 0.0
    state: str = "closed"  # closed, open, half-open
    total_failures: int = 0
    total_successes: int = 0


@dataclass
class NotificationConfig:
    """Notification configuration."""
    webhook_url: str = ""
    block_reasons: Optional[list] = None  # None = all reasons.
    cells: Optional[list] = None  # None = all cells.
    min_interval_seconds: int = DEFAULT_MIN_INTERVAL
    enabled: bool = False
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)


class Notifier:
    """mitmproxy addon for webhook notifications."""

    def __init__(self):
        self.config = NotificationConfig()
        self.policy_mtime = 0.0
        self.last_notification: collections.OrderedDict[str, float] = collections.OrderedDict()
        self.notification_queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.worker_thread: Optional[threading.Thread] = None
        self.running = False
        self.circuit_breaker = CircuitBreakerState()
        self.dead_letters: list[dict] = []
        self._dl_lock = threading.Lock()  # Lock for dead_letters list.
        self._dl_dirty_count = 0  # Pending unsaved dead letters.
        self._cb_lock = threading.Lock()  # Lock for circuit breaker state.
        # Connection pool for HTTP requests (reuses connections).
        self._http_pool: Optional[object] = None
        self._pool_lock = threading.Lock()

    def _get_http_pool(self):
        """Get or create HTTP connection pool for the webhook URL."""
        if not URLLIB3_AVAILABLE:
            return None

        with self._pool_lock:
            if self._http_pool is None and self.config.webhook_url:
                # Create a PoolManager for connection reuse.
                self._http_pool = urllib3.PoolManager(
                    num_pools=1,
                    maxsize=10,
                    timeout=urllib3.Timeout(total=HTTP_TIMEOUT),
                    retries=False,  # We handle retries ourselves.
                )
                ctx.log.info("Notifier: Created HTTP connection pool")
            return self._http_pool

    def load(self, loader):
        """Called when addon is loaded."""
        ctx.log.info("Notifier: Loading...")
        self._reload_config()
        if self.config.enabled:
            self._start_worker()

    def done(self):
        """Called when addon is unloaded."""
        self._stop_worker()
        # Clean up connection pool.
        with self._pool_lock:
            if self._http_pool is not None:
                self._http_pool.clear()
                self._http_pool = None

    def _reload_config(self) -> None:
        """Load notification configuration from policy file."""
        try:
            if not POLICY_FILE.exists():
                return

            mtime = POLICY_FILE.stat().st_mtime
            if mtime == self.policy_mtime:
                return  # No change.

            with open(POLICY_FILE, "r") as f:
                data = json.load(f)

            notifications = data.get("notifications", {})

            webhook_url = notifications.get("webhook_url", "")
            # Validate webhook URL at load time for fast feedback.
            if webhook_url and not _is_safe_webhook_url(webhook_url):
                ctx.log.error("Notifier: webhook URL targets internal network, disabling")
                webhook_url = ""
            filters = notifications.get("filters", {})
            cb_config = notifications.get("circuit_breaker", {})

            self.config = NotificationConfig(
                webhook_url=webhook_url,
                block_reasons=filters.get("block_reasons"),
                cells=filters.get("cells"),
                min_interval_seconds=filters.get("min_interval_seconds", DEFAULT_MIN_INTERVAL),
                enabled=bool(webhook_url),
                circuit_breaker=CircuitBreakerConfig(
                    failure_threshold=cb_config.get("failure_threshold", DEFAULT_FAILURE_THRESHOLD),
                    recovery_timeout=cb_config.get("recovery_timeout", DEFAULT_RECOVERY_TIMEOUT),
                    max_retries=cb_config.get("max_retries", DEFAULT_MAX_RETRIES),
                    base_backoff=cb_config.get("base_backoff", DEFAULT_BASE_BACKOFF),
                    max_backoff=cb_config.get("max_backoff", DEFAULT_MAX_BACKOFF),
                )
            )

            self.policy_mtime = mtime

            if self.config.enabled:
                ctx.log.info(f"Notifier: Enabled - webhook {_redact_url_for_logging(self.config.webhook_url)}")
                if not self.running:
                    self._start_worker()
            else:
                ctx.log.info("Notifier: Disabled (no webhook URL)")
                self._stop_worker()

        except (json.JSONDecodeError, IOError, OSError) as e:
            ctx.log.error(f"Notifier: Failed to load config: {e}")

    def _start_worker(self) -> None:
        """Start background worker for sending notifications."""
        if self.running:
            return
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        ctx.log.info("Notifier: Worker started")

    def _stop_worker(self) -> None:
        """Stop background worker."""
        self.running = False
        # Signal worker to exit.
        try:
            self.notification_queue.put_nowait(None)
        except queue.Full:
            pass

    def _worker(self) -> None:
        """Background worker for sending notifications."""
        while self.running:
            try:
                notification = self.notification_queue.get(timeout=1.0)
                if notification is None:
                    continue  # Shutdown signal or spurious wakeup.
                self._send_notification(notification)
            except queue.Empty:
                continue
            except Exception as e:
                ctx.log.error(f"Notifier: Worker error: {e}")

    def _check_circuit_breaker(self) -> bool:
        """Check if circuit breaker allows requests. Returns True if allowed."""
        with self._cb_lock:
            now = time.time()

            if self.circuit_breaker.state == "closed":
                return True

            if self.circuit_breaker.state == "open":
                # Check if recovery timeout has passed.
                elapsed = now - self.circuit_breaker.last_failure_time
                if elapsed >= self.config.circuit_breaker.recovery_timeout:
                    self.circuit_breaker.state = "half-open"
                    ctx.log.info("Notifier: Circuit breaker half-open, attempting recovery")
                    return True
                return False

            # Half-open: allow one request to test.
            return True

    def _record_success(self) -> None:
        """Record a successful webhook call."""
        with self._cb_lock:
            self.circuit_breaker.consecutive_failures = 0
            self.circuit_breaker.total_successes += 1
            if self.circuit_breaker.state == "half-open":
                self.circuit_breaker.state = "closed"
                ctx.log.info("Notifier: Circuit breaker closed (recovered)")

    def _record_failure(self) -> None:
        """Record a failed webhook call."""
        with self._cb_lock:
            self.circuit_breaker.consecutive_failures += 1
            self.circuit_breaker.total_failures += 1
            self.circuit_breaker.last_failure_time = time.time()

            if self.circuit_breaker.state == "half-open":
                self.circuit_breaker.state = "open"
                ctx.log.warn("Notifier: Circuit breaker re-opened after failed recovery")
            elif self.circuit_breaker.consecutive_failures >= self.config.circuit_breaker.failure_threshold:
                self.circuit_breaker.state = "open"
                ctx.log.warn(
                    f"Notifier: Circuit breaker opened after "
                    f"{self.circuit_breaker.consecutive_failures} consecutive failures"
                )

    def _add_to_dead_letter(self, notification: dict, error: str) -> None:
        """Add failed notification to dead-letter queue."""
        dead_letter = {
            "notification": notification,
            "error": str(error),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "attempts": notification.get("_attempts", 1),
        }

        with self._dl_lock:
            self.dead_letters.append(dead_letter)

            # Trim if over limit.
            if len(self.dead_letters) > MAX_DEAD_LETTERS:
                self.dead_letters = self.dead_letters[-MAX_DEAD_LETTERS:]

            # Batch disk writes: persist every 10 failures or on trim.
            self._dl_dirty_count += 1
            if self._dl_dirty_count >= 10 or len(self.dead_letters) >= MAX_DEAD_LETTERS:
                self._save_dead_letters()
                self._dl_dirty_count = 0

    def _save_dead_letters(self) -> None:
        """Persist dead letters to disk."""
        try:
            DEAD_LETTER_FILE.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = DEAD_LETTER_FILE.with_suffix(".tmp")
            with open(tmp_path, "w") as f:
                json.dump(self.dead_letters, f, indent=2)
            tmp_path.rename(DEAD_LETTER_FILE)
        except (IOError, OSError) as e:
            ctx.log.error(f"Notifier: Failed to save dead letters: {e}")

    def _send_http_request(self, data: bytes, resolved_ip: str, hostname: str, port: int) -> tuple[bool, Optional[str]]:
        """Send HTTP request to the webhook URL. Returns (success, error).

        The caller has already validated the resolved IP against
        BLOCKED_NETWORKS. We connect to the resolved IP directly to
        prevent DNS rebinding between validation and connection. The
        original Host header is set for correct routing/vhost selection.
        """
        parsed = urlparse(self.config.webhook_url)
        # Build URL with resolved IP to prevent DNS rebinding.
        ip_url = f"{parsed.scheme}://{resolved_ip}:{port}{parsed.path or '/'}"
        if parsed.query:
            ip_url += f"?{parsed.query}"

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Warden/1.0",
            "Host": hostname,
        }

        pool = self._get_http_pool()
        if pool is not None:
            # Use urllib3 connection pool.
            try:
                response = pool.request(
                    "POST",
                    ip_url,
                    body=data,
                    headers=headers,
                    assert_hostname=hostname,
                    server_hostname=hostname,
                )
                if response.status < 400:
                    return True, None
                else:
                    return False, f"HTTP {response.status}"
            except urllib3.exceptions.HTTPError as e:
                return False, str(e)
        else:
            # Fallback to urllib.
            try:
                req = urllib.request.Request(
                    ip_url,
                    data=data,
                    headers=headers,
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as response:  # nosec B310
                    if response.status < 400:
                        return True, None
                    else:
                        return False, f"HTTP {response.status}"
            except urllib.error.URLError as e:
                return False, str(e)

    def _send_notification(self, notification: dict) -> None:
        """Send notification to webhook with circuit breaker and retry logic."""
        if not self.config.webhook_url:
            return

        # Resolve DNS once and validate against internal networks.
        # Using the resolved IP for the HTTP request prevents DNS rebinding.
        safe, resolved_ip, hostname, port = _resolve_webhook_url(self.config.webhook_url)
        if not safe:
            ctx.log.warn("Notifier: webhook URL targets internal network, skipping")
            return

        # Check circuit breaker.
        if not self._check_circuit_breaker():
            ctx.log.debug("Notifier: Circuit breaker open, dropping notification")
            self._add_to_dead_letter(notification, "circuit_breaker_open")
            return

        attempts = notification.get("_attempts", 0)
        max_retries = self.config.circuit_breaker.max_retries

        while attempts < max_retries:
            attempts += 1
            notification["_attempts"] = attempts

            try:
                # Strip internal fields before sending to webhook.
                payload = {k: v for k, v in notification.items() if not k.startswith("_")}
                data = json.dumps(payload).encode("utf-8")
                success, error = self._send_http_request(data, resolved_ip, hostname, port)

                if success:
                    self._record_success()
                    return  # Success.
                else:
                    ctx.log.warn(f"Notifier: Webhook failed (attempt {attempts}): {error}")

            except Exception as e:
                ctx.log.error(f"Notifier: Unexpected error (attempt {attempts}): {e}")

            # Calculate exponential backoff.
            if attempts < max_retries:
                backoff = min(
                    self.config.circuit_breaker.base_backoff * (2 ** (attempts - 1)),
                    self.config.circuit_breaker.max_backoff
                )
                time.sleep(backoff)

        # All retries exhausted.
        self._record_failure()
        self._add_to_dead_letter(notification, f"max_retries_exceeded_{max_retries}")

    def _should_notify(self, cell_name: str, block_reason: str) -> bool:
        """Check if we should send a notification."""
        if not self.config.enabled:
            return False

        # Check cell filter.
        if self.config.cells is not None:
            if cell_name not in self.config.cells:
                return False

        # Check block reason filter.
        if self.config.block_reasons is not None:
            matched = False
            for reason_pattern in self.config.block_reasons:
                if reason_pattern in block_reason:
                    matched = True
                    break
            if not matched:
                return False

        # Check rate limit.
        now = time.time()
        last = self.last_notification.get(cell_name, 0)
        if now - last < self.config.min_interval_seconds:
            return False

        return True

    def response(self, flow: http.HTTPFlow) -> None:
        """Check for blocked requests and queue notifications."""
        # Hot-reload config.
        self._reload_config()

        if not flow.metadata.get("blocked", False):
            return

        cell_name = flow.metadata.get("cell", "unknown")
        block_reason = flow.metadata.get("block_reason", "unknown")

        if not self._should_notify(cell_name, block_reason):
            return

        # Update last notification time with LRU eviction.
        if cell_name not in self.last_notification:
            if len(self.last_notification) >= MAX_TRACKED_CELLS:
                self.last_notification.popitem(last=False)
        else:
            self.last_notification.move_to_end(cell_name)
        self.last_notification[cell_name] = time.time()

        # Build notification.
        notification = {
            "event": "request_blocked",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cell": cell_name,
            "host": flow.request.host,
            "path": _redact_notification_path(flow.request.path),
            "method": flow.request.method,
            "block_reason": block_reason,
            "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "unknown",
        }

        # Queue notification.
        try:
            self.notification_queue.put_nowait(notification)
        except queue.Full:
            ctx.log.warn("Notifier: Queue full, adding to dead-letter queue")
            self._add_to_dead_letter(notification, "queue_full")


addons = [Notifier()]
