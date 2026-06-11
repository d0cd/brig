"""
Stateless helpers + dataclasses + circuit-breaker logic for notifier.py.

Sibling module of `notifier.py` — `_` prefix keeps mitmproxy from
registering this as an addon. Splits roughly into:

  - URL safety helper (`_resolve_webhook_url`)
  - Path / URL redaction helpers
  - Tunable constants (HTTP timeout, circuit breaker defaults, etc.)
  - Config dataclasses (`CircuitBreakerConfig`, `NotificationConfig`)
  - Mutable state container (`CircuitBreakerState`) — purely a record
"""

from __future__ import annotations

import socket as _socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from _common import (  # noqa: F401  (re-exported for notifier.py + tests)
    BLOCKED_NETWORKS,
    _high_entropy_segment,
    collapse_path_template,
    is_blocked_ip,
    redact_path,
)


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
            if is_blocked_ip(sockaddr[0]):
                return False, "", "", 0
            if not first_ip_str:
                first_ip_str = sockaddr[0]
        if not first_ip_str:
            return False, "", "", 0
    except (OSError, ValueError):
        return False, "", "", 0

    return True, first_ip_str, parsed.hostname, port


def _redact_notification_path(path: str) -> str:
    """Blocked-alert path: drop query/fragment (blocked alerts don't carry it),
    then mask secret path segments via the shared _common redactor."""
    return redact_path(path.split("?", 1)[0].split("#", 1)[0])


def _redact_url_for_logging(url: str) -> str:
    """Return scheme + hostname only, stripping path, query, and credentials."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.hostname}"


# Path templating for novel_allowed keys lives in _common (the shared
# classifier all sinks use). Re-exported so notifier.py's import is unchanged.
normalize_path_template = collapse_path_template


def query_exfil_signal(path: str, max_query_len: int) -> bool:
    """True if `path` carries an unusually long query string — a crude but real
    detector for data smuggled in `?param=<payload>` on an otherwise-known path
    (the channel path-template novelty can't see). Length, not content, so we
    never log the (possibly secret) payload itself."""
    parts = path.split("?", 1)
    return len(parts) == 2 and len(parts[1]) > max_query_len


@dataclass
class NovelAllowedConfig:
    """Config for first-seen detection on allow-listed hosts (the detection
    complement to blocked-alerting). Default off; opt in via the notifications
    block. `dry_run` logs would-be alerts without delivering — run it first to
    confirm the baseline + ignore-lists are tight before enabling delivery."""
    enabled: bool = False
    cells: Optional[list] = None        # None = all cells.
    ignore_hosts: tuple = ()            # Exact host or dot-suffix match.
    ignore_paths: tuple = ()            # Compiled regex patterns (templates).
    dry_run: bool = False
    max_query_len: int = 512


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
    novel_allowed: Optional["NovelAllowedConfig"] = None
