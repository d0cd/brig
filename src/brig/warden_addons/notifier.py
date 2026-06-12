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

Stateless helpers + config dataclasses live in `_notifier_state.py`. This
file owns the addon class and the mitmproxy lifecycle.

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
import json
import queue
import re
import threading
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from mitmproxy import ctx, http

from _common import BLOCKED_NETWORKS, atomic_write_json, stat_signature  # noqa: F401  (re-exported for tests)
from _notifier_state import (
    DEFAULT_BASE_BACKOFF,
    DEFAULT_FAILURE_THRESHOLD,
    DEFAULT_MAX_BACKOFF,
    DEFAULT_MAX_RETRIES,
    DEFAULT_MIN_INTERVAL,
    DEFAULT_RECOVERY_TIMEOUT,
    HTTP_TIMEOUT,
    MAX_DEAD_LETTERS,
    MAX_QUEUE_SIZE,
    MAX_TRACKED_CELLS,
    CircuitBreakerConfig,
    CircuitBreakerState,
    NotificationConfig,
    NovelAllowedConfig,
    _redact_notification_path,
    _redact_url_for_logging,
    _resolve_webhook_url,
    normalize_path_template,
    query_exfil_signal,
)

# Per-cell network logs the logger addon writes — used to seed the novel_allowed
# baseline so a warden restart doesn't replay every known path as "novel".
NETWORK_LOG_DIR = Path("/var/log/brig/network")
# Cap per-cell baseline templates; if a cell saturates it, novelty detection
# goes quiet for that cell (logged once) rather than storming or growing unbounded.
MAX_NOVEL_KEYS_PER_CELL = 5000

# Try to use urllib3 for connection pooling, fall back to urllib.
try:
    import urllib3
    URLLIB3_AVAILABLE = True
except ImportError:
    import urllib.error
    import urllib.request
    URLLIB3_AVAILABLE = False


POLICY_FILE = Path("/policy.json")
DEAD_LETTER_FILE = Path("/var/run/cells/dead-letters.json")


class Notifier:
    """mitmproxy addon for webhook notifications."""

    def __init__(self):
        self.config = NotificationConfig()
        self.policy_mtime: tuple[int, int] = (0, 0)
        self._last_check_time = 0.0
        self.last_notification: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._last_notification_lock = threading.Lock()
        self.notification_queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.worker_thread: Optional[threading.Thread] = None
        self.running = False
        self.circuit_breaker = CircuitBreakerState()
        self.dead_letters: list[dict] = []
        self._dl_lock = threading.Lock()
        self._dl_dirty_count = 0
        self._cb_lock = threading.Lock()
        self._http_pool: Optional[object] = None
        self._pool_lock = threading.Lock()
        # novel_allowed baselines, per cell. Touched only from response()
        # (mitmproxy runs hooks single-threaded), so no lock needed.
        self._novel_seen: dict[str, set] = {}        # cell -> {host\npath_template}
        self._novel_query_seen: dict[str, set] = {}  # cell -> {host\npath_template} (query-flagged)
        self._novel_seeded: set[str] = set()         # cells whose baseline was seeded
        self._novel_saturated: set[str] = set()      # cells whose baseline hit the cap

    def _get_http_pool(self):
        """Get or create HTTP connection pool for the webhook URL.

        Configures strict TLS verification and a system CA bundle. urllib3
        defaults to CERT_REQUIRED in v2 but we set it explicitly so behavior
        does not silently regress. retries=False because we manage retries
        ourselves with circuit breaker + exponential backoff.
        """
        if not URLLIB3_AVAILABLE:
            return None

        with self._pool_lock:
            if self._http_pool is None and self.config.webhook_url:
                ca_bundle = None
                try:
                    import certifi
                    ca_bundle = certifi.where()
                except ImportError:
                    pass
                pool_kwargs = dict(
                    num_pools=1,
                    maxsize=10,
                    timeout=urllib3.Timeout(total=HTTP_TIMEOUT),
                    retries=False,
                    cert_reqs="CERT_REQUIRED",
                )
                if ca_bundle:
                    pool_kwargs["ca_certs"] = ca_bundle
                self._http_pool = urllib3.PoolManager(**pool_kwargs)
                ctx.log.info("Notifier: Created HTTP connection pool (TLS verify: required)")
            return self._http_pool

    def load(self, loader):
        """Called when addon is loaded."""
        ctx.log.info("Notifier: Loading...")
        self._reload_config(force=True)
        if self.config.enabled:
            self._start_worker()

    def done(self):
        """Called when addon is unloaded."""
        self._stop_worker()
        with self._pool_lock:
            if self._http_pool is not None:
                self._http_pool.clear()
                self._http_pool = None

    _CHECK_INTERVAL: float = 1.0  # Seconds between mtime checks.

    def _reload_config(self, *, force: bool = False) -> None:
        """Load notification configuration from policy file.

        Called from response() on every proxied flow, so throttle the stat
        check to at most once per second (matching enforce.py) — `force=True`
        from load() bypasses the throttle for the initial read.
        """
        now = time.monotonic()
        if not force and now - self._last_check_time < self._CHECK_INTERVAL:
            return
        self._last_check_time = now
        try:
            if not POLICY_FILE.exists():
                return

            sig = stat_signature(POLICY_FILE)
            if sig == self.policy_mtime:
                return  # No change.

            with open(POLICY_FILE, "r") as f:
                data = json.load(f)

            notifications = data.get("notifications", {})
            webhook_url = notifications.get("webhook_url", "")
            resolved_ip = ""
            resolved_hostname = ""
            resolved_port = 0
            if webhook_url:
                safe, resolved_ip, resolved_hostname, resolved_port = (
                    _resolve_webhook_url(webhook_url)
                )
                if not safe:
                    ctx.log.error(
                        "Notifier: webhook URL targets internal network, disabling"
                    )
                    webhook_url = ""
                    resolved_ip = ""
                    resolved_hostname = ""
                    resolved_port = 0
            filters = notifications.get("filters", {})
            cb_config = notifications.get("circuit_breaker", {})

            na = notifications.get("novel_allowed", {})
            novel_allowed = None
            if isinstance(na, dict):
                ignore_paths = []
                for pat in (na.get("ignore_paths") or []):
                    try:
                        ignore_paths.append(re.compile(pat))
                    except re.error as e:
                        ctx.log.warn(f"Notifier: bad novel_allowed ignore_paths regex {pat!r}: {e}")
                novel_allowed = NovelAllowedConfig(
                    enabled=bool(na.get("enabled", False)),
                    cells=na.get("cells"),
                    ignore_hosts=tuple(na.get("ignore_hosts") or ()),
                    ignore_paths=tuple(ignore_paths),
                    dry_run=bool(na.get("dry_run", False)),
                    max_query_len=int(na.get("max_query_len", 512)),
                )

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
                ),
                resolved_ip=resolved_ip,
                resolved_hostname=resolved_hostname,
                resolved_port=resolved_port,
                novel_allowed=novel_allowed,
            )
            self.policy_mtime = sig

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
        """Stop background worker.

        Mirrors the pattern in _log_writer.AsyncLogWriter.stop(): set the
        flag, signal via a sentinel, then join with a bounded timeout so
        warden shutdown can't hang on a stuck worker.
        """
        self.running = False
        try:
            self.notification_queue.put_nowait(None)
        except queue.Full:
            pass
        if self.worker_thread:
            self.worker_thread.join(timeout=1.0)
            self.worker_thread = None

    def _worker(self) -> None:
        """Background worker for sending notifications."""
        while self.running:
            try:
                notification = self.notification_queue.get(timeout=1.0)
                if notification is None:
                    continue
                self._send_notification(notification)
            except queue.Empty:
                continue
            except Exception as e:
                ctx.log.error(f"Notifier: Worker error: {e}")

    def _check_circuit_breaker(self) -> bool:
        """Check if circuit breaker allows requests. Returns True if allowed."""
        with self._cb_lock:
            # monotonic: this is a within-process elapsed timer; a wall-clock
            # step backward (VM sleep/resume + NTP) must not wedge the breaker.
            now = time.monotonic()
            if self.circuit_breaker.state == "closed":
                return True
            if self.circuit_breaker.state == "open":
                elapsed = now - self.circuit_breaker.last_failure_time
                if elapsed >= self.config.circuit_breaker.recovery_timeout:
                    self.circuit_breaker.state = "half-open"
                    ctx.log.info("Notifier: Circuit breaker half-open, attempting recovery")
                    return True
                return False
            return True  # half-open

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
            self.circuit_breaker.last_failure_time = time.monotonic()
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
            if len(self.dead_letters) > MAX_DEAD_LETTERS:
                self.dead_letters = self.dead_letters[-MAX_DEAD_LETTERS:]
            self._dl_dirty_count += 1
            if self._dl_dirty_count >= 10 or len(self.dead_letters) >= MAX_DEAD_LETTERS:
                self._save_dead_letters()
                self._dl_dirty_count = 0

    def _save_dead_letters(self) -> None:
        """Persist dead letters to disk."""
        try:
            atomic_write_json(DEAD_LETTER_FILE, self.dead_letters)
        except (IOError, OSError) as e:
            ctx.log.error(f"Notifier: Failed to save dead letters: {e}")

    def _send_http_request(self, data: bytes, resolved_ip: str, hostname: str, port: int) -> tuple[bool, Optional[str]]:
        """Send HTTP request to the webhook URL. Returns (success, error).

        The caller has already validated the resolved IP against
        BLOCKED_NETWORKS. We connect to the resolved IP directly to
        prevent DNS rebinding between validation and connection.
        """
        parsed = urlparse(self.config.webhook_url)
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
            try:
                response = pool.request(
                    "POST", ip_url, body=data, headers=headers,
                    assert_hostname=hostname, server_hostname=hostname,
                )
                if response.status < 400:
                    return True, None
                return False, f"HTTP {response.status}"
            except urllib3.exceptions.HTTPError as e:
                return False, str(e)
        else:
            # Fallback to urllib. Disable redirect following so a 302 from
            # the webhook cannot point to an internal-by-name host that
            # _resolve_webhook_url did not pre-validate (SSRF / H2).
            try:
                class _NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None
                opener = urllib.request.build_opener(_NoRedirect())
                req = urllib.request.Request(
                    ip_url, data=data, headers=headers, method="POST",
                )
                with opener.open(req, timeout=HTTP_TIMEOUT) as response:  # nosec B310
                    if response.status < 400:
                        return True, None
                    return False, f"HTTP {response.status}"
            except urllib.error.HTTPError as e:
                if 300 <= e.code < 400:
                    return False, f"HTTP {e.code} (redirect refused)"
                return False, str(e)
            except urllib.error.URLError as e:
                return False, str(e)

    def _send_notification(self, notification: dict) -> None:
        """Send notification to webhook with circuit breaker and retry logic.

        Uses the resolved IP/hostname pinned at config-load time rather
        than re-resolving DNS every call — re-resolving would let an
        attacker who controls the webhook DNS return a public IP first
        (passing BLOCKED_NETWORKS) and an internal IP later. Pinning
        means the only way to change the connect target is to reload
        the config, which re-runs the SSRF gate.
        """
        if not self.config.webhook_url:
            return

        resolved_ip = self.config.resolved_ip
        hostname = self.config.resolved_hostname
        port = self.config.resolved_port
        if not resolved_ip or not hostname or not port:
            ctx.log.warn(
                "Notifier: webhook URL has no pinned resolution, skipping "
                "(config reload required)"
            )
            return

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
                payload = {k: v for k, v in notification.items() if not k.startswith("_")}
                data = json.dumps(payload).encode("utf-8")
                success, error = self._send_http_request(data, resolved_ip, hostname, port)
                if success:
                    self._record_success()
                    return
                ctx.log.warn(f"Notifier: Webhook failed (attempt {attempts}): {error}")
            except Exception as e:
                ctx.log.error(f"Notifier: Unexpected error (attempt {attempts}): {e}")

            if attempts < max_retries:
                backoff = min(
                    self.config.circuit_breaker.base_backoff * (2 ** (attempts - 1)),
                    self.config.circuit_breaker.max_backoff,
                )
                time.sleep(backoff)

        self._record_failure()
        self._add_to_dead_letter(notification, f"max_retries_exceeded_{max_retries}")

    def _should_notify(self, cell_name: str, block_reason: str) -> bool:
        """Check if we should send a notification."""
        if not self.config.enabled:
            return False
        if self.config.cells is not None and cell_name not in self.config.cells:
            return False
        if self.config.block_reasons is not None:
            if not any(p in block_reason for p in self.config.block_reasons):
                return False
        # monotonic: per-cell throttle is a within-process elapsed timer.
        now = time.monotonic()
        with self._last_notification_lock:
            last = self.last_notification.get(cell_name, 0)
        if now - last < self.config.min_interval_seconds:
            return False
        return True

    def _enqueue(self, notification: dict) -> None:
        """Hand a notification to the worker, or dead-letter it if the queue is full."""
        try:
            self.notification_queue.put_nowait(notification)
        except queue.Full:
            ctx.log.warn("Notifier: Queue full, adding to dead-letter queue")
            self._add_to_dead_letter(notification, "queue_full")

    def response(self, flow: http.HTTPFlow) -> None:
        """Alert on blocked requests (tried somewhere new) and — if enabled —
        on first-seen allowed requests (used an allowed destination a new way)."""
        self._reload_config()
        if flow.metadata.get("blocked", False):
            self._handle_blocked(flow)
        else:
            self._handle_novel_allowed(flow)

    def _handle_blocked(self, flow: http.HTTPFlow) -> None:
        cell_name = flow.metadata.get("cell", "unknown")
        block_reason = flow.metadata.get("block_reason", "unknown")

        if not self._should_notify(cell_name, block_reason):
            return

        # Update last notification time with LRU eviction (single-writer for
        # the OrderedDict invariant — popitem/move_to_end aren't atomic).
        with self._last_notification_lock:
            if cell_name not in self.last_notification:
                if len(self.last_notification) >= MAX_TRACKED_CELLS:
                    self.last_notification.popitem(last=False)
            else:
                self.last_notification.move_to_end(cell_name)
            self.last_notification[cell_name] = time.monotonic()

        self._enqueue({
            "event": "request_blocked",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cell": cell_name,
            "host": flow.request.host,
            "path": _redact_notification_path(flow.request.path),
            "method": flow.request.method,
            "block_reason": block_reason,
            "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "unknown",
        })

    @staticmethod
    def _host_ignored(host: str, ignore_hosts) -> bool:
        return any(host == h or host.endswith("." + h) for h in ignore_hosts)

    def _seed_novel_baseline(self, cell: str) -> None:
        """Seed a cell's baseline from its existing network log so a warden
        restart doesn't replay every known (host, path) as novel. The log is
        the persistence layer — re-seeding from it on each load is idempotent."""
        if cell in self._novel_seeded:
            return
        self._novel_seeded.add(cell)
        seen = self._novel_seen.setdefault(cell, set())
        try:
            with open(NETWORK_LOG_DIR / f"{cell}.jsonl", "r") as f:
                for line in f:
                    if len(seen) >= MAX_NOVEL_KEYS_PER_CELL:
                        break
                    try:
                        e = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    if e.get("blocked"):
                        continue
                    host, path = e.get("host"), e.get("path")
                    if host and path is not None:
                        seen.add(f"{host}\n{normalize_path_template(path)}")
        except OSError:
            pass  # No prior log — baseline starts empty (all novel from here).

    def _emit_novel(self, flow, cell, host, template, reason, na, query_length=None):
        # Deliberately omit the raw path/query — for suspicious_query the query
        # may BE the exfil payload, so we report its length, never its content.
        notification = {
            "event": "novel_allowed",
            "reason": reason,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cell": cell,
            "host": host,
            "path_template": template,
            "method": flow.request.method,
        }
        if query_length is not None:
            notification["query_length"] = query_length
        if na.dry_run:
            ctx.log.info(
                f"Notifier: [dry-run] novel_allowed {reason}: {cell} {host}{template}"
            )
            return
        self._enqueue(notification)

    def _handle_novel_allowed(self, flow: http.HTTPFlow) -> None:
        na = self.config.novel_allowed
        if not na or not na.enabled:
            return
        cell = flow.metadata.get("cell", "unknown")
        if na.cells is not None and cell not in na.cells:
            return
        host = flow.request.host
        if self._host_ignored(host, na.ignore_hosts):
            return
        template = normalize_path_template(flow.request.path)
        if any(p.search(template) for p in na.ignore_paths):
            return

        self._seed_novel_baseline(cell)
        if cell in self._novel_saturated:
            return
        seen = self._novel_seen.setdefault(cell, set())
        key = f"{host}\n{template}"

        if key not in seen:
            if len(seen) >= MAX_NOVEL_KEYS_PER_CELL:
                self._novel_saturated.add(cell)
                ctx.log.warn(
                    f"Notifier: novel_allowed baseline saturated for cell "
                    f"'{cell}' ({MAX_NOVEL_KEYS_PER_CELL}); pausing novelty alerts"
                )
                return
            seen.add(key)
            self._emit_novel(flow, cell, host, template, "novel_path", na)
            return

        # Known shape — check the query channel path-novelty can't see (fires
        # once per (host, template) so a chatty endpoint doesn't storm).
        if query_exfil_signal(flow.request.path, na.max_query_len):
            qseen = self._novel_query_seen.setdefault(cell, set())
            if key not in qseen:
                qseen.add(key)
                qlen = len(flow.request.path.split("?", 1)[1])
                self._emit_novel(flow, cell, host, template, "suspicious_query",
                                 na, query_length=qlen)


addons = [Notifier()]
