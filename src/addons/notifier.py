"""
Webhook notification addon for mitmproxy.

Sends real-time notifications on blocked requests:
    - POST to configured webhook URL
    - Configurable filters (block reasons, cells, domains)
    - Rate-limited to prevent notification spam
    - Async HTTP to avoid blocking proxy

Configuration in policy file:
    {
        "notifications": {
            "webhook_url": "https://example.com/webhook",
            "filters": {
                "block_reasons": ["denied by rule", "not in allowlist"],
                "cells": ["sensitive-cell"],
                "min_interval_seconds": 60
            }
        }
    }

Usage:
    mitmdump -s notifier.py
"""

import json
import queue
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mitmproxy import http, ctx

# Policy file path.
POLICY_FILE = Path("/policy.json")

# Default minimum interval between notifications (per cell).
DEFAULT_MIN_INTERVAL = 60  # seconds

# Maximum queue size.
MAX_QUEUE_SIZE = 100

# HTTP timeout for webhook requests.
HTTP_TIMEOUT = 10  # seconds


@dataclass
class NotificationConfig:
    """Notification configuration."""
    webhook_url: str = ""
    block_reasons: Optional[list] = None  # None = all reasons.
    cells: Optional[list] = None  # None = all cells.
    min_interval_seconds: int = DEFAULT_MIN_INTERVAL
    enabled: bool = False


class Notifier:
    """mitmproxy addon for webhook notifications."""

    def __init__(self):
        self.config = NotificationConfig()
        self.policy_mtime = 0.0
        self.last_notification: dict[str, float] = {}  # cell -> timestamp
        self.notification_queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.worker_thread: Optional[threading.Thread] = None
        self.running = False

    def load(self, loader):
        """Called when addon is loaded."""
        ctx.log.info("Notifier: Loading...")
        self._reload_config()
        if self.config.enabled:
            self._start_worker()

    def done(self):
        """Called when addon is unloaded."""
        self._stop_worker()

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
            filters = notifications.get("filters", {})

            self.config = NotificationConfig(
                webhook_url=webhook_url,
                block_reasons=filters.get("block_reasons"),
                cells=filters.get("cells"),
                min_interval_seconds=filters.get("min_interval_seconds", DEFAULT_MIN_INTERVAL),
                enabled=bool(webhook_url)
            )

            self.policy_mtime = mtime

            if self.config.enabled:
                ctx.log.info(f"Notifier: Enabled - webhook {self.config.webhook_url}")
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

    def _send_notification(self, notification: dict) -> None:
        """Send notification to webhook."""
        if not self.config.webhook_url:
            return

        try:
            data = json.dumps(notification).encode("utf-8")
            req = urllib.request.Request(
                self.config.webhook_url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Warden/1.0",
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as response:
                if response.status >= 400:
                    ctx.log.warn(f"Notifier: Webhook returned {response.status}")

        except urllib.error.URLError as e:
            ctx.log.error(f"Notifier: Failed to send notification: {e}")
        except Exception as e:
            ctx.log.error(f"Notifier: Unexpected error: {e}")

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

        # Update last notification time.
        self.last_notification[cell_name] = time.time()

        # Build notification.
        notification = {
            "event": "request_blocked",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cell": cell_name,
            "host": flow.request.host,
            "path": flow.request.path,
            "method": flow.request.method,
            "block_reason": block_reason,
            "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "unknown",
        }

        # Queue notification.
        try:
            self.notification_queue.put_nowait(notification)
        except queue.Full:
            ctx.log.warn("Notifier: Queue full, dropping notification")


addons = [Notifier()]
