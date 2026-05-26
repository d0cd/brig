"""
Stateless helpers + dataclasses + circuit-breaker logic for notifier.py.

Sibling module of `notifier.py` — `_` prefix keeps mitmproxy from
registering this as an addon. Splits roughly into:

  - URL safety helpers (`_resolve_webhook_url`, `_is_safe_webhook_url`)
  - Path / URL redaction helpers
  - Tunable constants (HTTP timeout, circuit breaker defaults, etc.)
  - Config dataclasses (`CircuitBreakerConfig`, `NotificationConfig`)
  - Mutable state container (`CircuitBreakerState`) — purely a record
"""

from __future__ import annotations

import ipaddress
import re
import socket as _socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from _common import BLOCKED_NETWORKS


# Default minimum interval between notifications (per cell).
DEFAULT_MIN_INTERVAL = 60  # seconds

# Maximum queue size.
MAX_QUEUE_SIZE = 100

# HTTP timeout for webhook requests.
HTTP_TIMEOUT = 10  # seconds

# Maximum number of cells to track for rate limiting (LRU eviction beyond).
MAX_TRACKED_CELLS = 1000

# Circuit breaker defaults.
DEFAULT_FAILURE_THRESHOLD = 5  # Consecutive failures before opening circuit.
DEFAULT_RECOVERY_TIMEOUT = 300  # Seconds before attempting recovery.
DEFAULT_MAX_RETRIES = 3  # Max retry attempts per notification.
DEFAULT_BASE_BACKOFF = 1.0  # Base backoff in seconds.
DEFAULT_MAX_BACKOFF = 60.0  # Maximum backoff in seconds.

# Maximum dead letters to keep.
MAX_DEAD_LETTERS = 1000


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
_SECRET_PATH_RE = re.compile(
    r"(?<=/)"                         # Preceded by /.
    r"(?:"
    r"[A-Fa-f0-9]{20,}"               # Long hex string.
    r"|[A-Za-z0-9_\-]{20,}"           # Long base64-ish string.
    r")"
    r"(?=/|$)"                        # Followed by / or end.
)


def _redact_notification_path(path: str) -> str:
    """Remove query parameters, fragments, and potential secrets from path."""
    path = path.split("?")[0]
    path = path.split("#")[0]
    path = _SECRET_PATH_RE.sub("[REDACTED]", path)
    return path


def _redact_url_for_logging(url: str) -> str:
    """Return scheme + hostname only, stripping path, query, and credentials."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.hostname}"


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
    """Notification configuration.

    `resolved_ip` / `resolved_hostname` / `resolved_port` are pinned at
    config-load time. Without pinning, every notification re-resolves
    the webhook hostname and accepts the first IP returned. An attacker
    who controls the webhook hostname's DNS could return a public IP on
    the first call (passes the BLOCKED_NETWORKS check) and flip to an
    internal IP later. Pinning closes that mid-flight rebinding window —
    only a config reload (which re-runs the SSRF check) can change the
    connect target.
    """
    webhook_url: str = ""
    block_reasons: Optional[list] = None  # None = all reasons.
    cells: Optional[list] = None  # None = all cells.
    min_interval_seconds: int = DEFAULT_MIN_INTERVAL
    enabled: bool = False
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    resolved_ip: str = ""
    resolved_hostname: str = ""
    resolved_port: int = 0
