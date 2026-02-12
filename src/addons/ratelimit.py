"""
Rate limiting addon for mitmproxy.

Implements per-cell token bucket rate limiting:
    - Configurable sustained rate and burst limit
    - Returns 429 Too Many Requests when exceeded
    - Per-cell limits from policy file

Default limits (permissive):
    - Sustained: 100 requests/second
    - Burst: 500 requests

Policy format:
    {
        "rate_limits": {
            "default": {"rate": 100, "burst": 500},
            "cells": {
                "my-cell": {"rate": 10, "burst": 50}
            }
        }
    }

Usage:
    mitmdump -s ratelimit.py
"""

import json
import math
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mitmproxy import http, ctx

# Import shared SIGHUP dispatcher from enforce addon.
try:
    from enforce import register_sighup
except ImportError:
    # Standalone mode: register our own handler.
    def register_sighup(callback):
        signal.signal(signal.SIGHUP, lambda s, f: callback())

# Policy file path.
POLICY_FILE = Path("/policy.json")

# Default rate limits (permissive as per user preference).
DEFAULT_RATE = 100  # requests per second
DEFAULT_BURST = 500  # max burst size

# Maximum number of cell buckets to track (LRU eviction beyond this).
MAX_TRACKED_CELLS = 1000


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    rate: float  # Tokens per second.
    burst: int  # Maximum tokens (bucket size).

    def validate(self) -> list[str]:
        """Validate configuration values. Returns list of error messages."""
        errors = []
        if math.isnan(self.rate) or math.isinf(self.rate):
            errors.append(f"rate must be a finite number, got {self.rate}")
        elif self.rate <= 0:
            errors.append(f"rate must be positive, got {self.rate}")
        if isinstance(self.burst, float) and (math.isnan(self.burst) or math.isinf(self.burst)):
            errors.append(f"burst must be a finite number, got {self.burst}")
        elif self.burst <= 0:
            errors.append(f"burst must be positive, got {self.burst}")
        return errors

    def warnings(self) -> list[str]:
        """Check for potentially problematic configurations."""
        warnings = []
        if self.rate > self.burst:
            warnings.append(
                f"rate ({self.rate}/s) exceeds burst ({self.burst}), "
                "requests may be unnecessarily rate limited"
            )
        if self.rate > 10000:
            warnings.append(f"very high rate ({self.rate}/s) may indicate misconfiguration")
        if self.burst > 100000:
            warnings.append(f"very high burst ({self.burst}) may indicate misconfiguration")
        return warnings


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, rate: float, burst: int):
        """Initialize bucket with given rate and burst.

        Args:
            rate: Tokens added per second.
            burst: Maximum tokens (bucket capacity).
        """
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.last_update = time.monotonic()
        self.lock = threading.Lock()

    def consume(self) -> bool:
        """Try to consume one token.

        Returns True if token was consumed, False if rate limited.
        """
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now

            # Add tokens based on elapsed time.
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    def update_config(self, rate: float, burst: int) -> None:
        """Update bucket configuration."""
        with self.lock:
            self.rate = rate
            self.burst = burst
            # Don't reset tokens to allow gradual adjustment.
            self.tokens = min(self.tokens, burst)


class RateLimiter:
    """mitmproxy addon for rate limiting."""

    def __init__(self):
        self.default_config = RateLimitConfig(rate=DEFAULT_RATE, burst=DEFAULT_BURST)
        self.cell_configs: dict[str, RateLimitConfig] = {}
        self.buckets: dict[str, TokenBucket] = {}
        self.buckets_lock = threading.Lock()
        self.policy_mtime = 0.0
        self._reload_pending = False  # Deferred reload flag for signal safety.

    def load(self, loader):
        """Called when addon is loaded."""
        ctx.log.info("RateLimiter: Loading...")
        self._reload_config()
        # Register with shared SIGHUP dispatcher.
        register_sighup(self._on_sighup)
        ctx.log.info("RateLimiter: SIGHUP reload handler registered")

    def _on_sighup(self):
        """Set deferred reload flag on SIGHUP. Safe to call from signal context."""
        self._reload_pending = True

    def _do_reload(self):
        """Perform the actual reload outside of signal context."""
        ctx.log.info("RateLimiter: Reloading config...")
        self.policy_mtime = 0.0
        self._reload_config()

    def _reload_config(self) -> None:
        """Load rate limit configuration from policy file.

        Validates all configuration values and logs warnings for potentially
        problematic settings. Invalid configs are rejected.
        """
        try:
            if not POLICY_FILE.exists():
                return

            mtime = POLICY_FILE.stat().st_mtime
            if mtime == self.policy_mtime:
                return  # No change.

            with open(POLICY_FILE, "r") as f:
                data = json.load(f)

            rate_limits = data.get("rate_limits", {})

            # Load and validate default config.
            default = rate_limits.get("default", {})
            new_default = RateLimitConfig(
                rate=default.get("rate", DEFAULT_RATE),
                burst=default.get("burst", DEFAULT_BURST)
            )

            # Validate default config.
            errors = new_default.validate()
            if errors:
                ctx.log.error(f"RateLimiter: Invalid default config: {'; '.join(errors)}")
                return  # Reject invalid config.

            # Log warnings for default config.
            for warning in new_default.warnings():
                ctx.log.warn(f"RateLimiter: default config: {warning}")

            # Load and validate per-cell configs.
            cells = rate_limits.get("cells", {})
            new_cell_configs = {}
            has_errors = False

            for cell_name, config in cells.items():
                cell_config = RateLimitConfig(
                    rate=config.get("rate", new_default.rate),
                    burst=config.get("burst", new_default.burst)
                )

                # Validate cell config.
                errors = cell_config.validate()
                if errors:
                    ctx.log.error(
                        f"RateLimiter: Invalid config for cell '{cell_name}': "
                        f"{'; '.join(errors)}"
                    )
                    has_errors = True
                    continue

                # Log warnings for cell config.
                for warning in cell_config.warnings():
                    ctx.log.warn(f"RateLimiter: cell '{cell_name}': {warning}")

                new_cell_configs[cell_name] = cell_config

            if has_errors:
                ctx.log.error("RateLimiter: Config reload aborted due to validation errors")
                return  # Reject entire config if any cell has errors.

            # Apply validated config.
            self.default_config = new_default
            self.cell_configs = new_cell_configs
            self.policy_mtime = mtime

            ctx.log.info(
                f"RateLimiter: Loaded config - "
                f"default {self.default_config.rate}/s, burst {self.default_config.burst}, "
                f"{len(self.cell_configs)} cell overrides"
            )

            # Update existing buckets with new configs.
            with self.buckets_lock:
                for cell_name, bucket in self.buckets.items():
                    config = self.cell_configs.get(cell_name, self.default_config)
                    bucket.update_config(config.rate, config.burst)

        except (json.JSONDecodeError, IOError, OSError) as e:
            ctx.log.error(f"RateLimiter: Failed to load config: {e}")

    def _get_bucket(self, cell_name: str) -> TokenBucket:
        """Get or create token bucket for a cell.

        Applies LRU eviction when exceeding MAX_TRACKED_CELLS to bound memory.
        """
        with self.buckets_lock:
            if cell_name not in self.buckets:
                # Evict oldest bucket if at capacity.
                if len(self.buckets) >= MAX_TRACKED_CELLS:
                    oldest = min(
                        self.buckets.keys(),
                        key=lambda k: self.buckets[k].last_update
                    )
                    del self.buckets[oldest]
                    ctx.log.debug(f"RateLimiter: Evicted bucket for '{oldest}'")
                config = self.cell_configs.get(cell_name, self.default_config)
                self.buckets[cell_name] = TokenBucket(config.rate, config.burst)
            return self.buckets[cell_name]

    def request(self, flow: http.HTTPFlow) -> None:
        """Check rate limit for each request."""
        # Check for deferred SIGHUP reload (signal-safe pattern).
        if self._reload_pending:
            self._reload_pending = False
            self._do_reload()

        # Get cell name from metadata (set by enforce.py).
        cell_name = flow.metadata.get("cell", "unknown")

        # Get bucket for this cell.
        bucket = self._get_bucket(cell_name)

        # Try to consume a token.
        if not bucket.consume():
            flow.metadata["rate_limited"] = True

            # Store rate limit event details for logger.
            flow.metadata["rate_limit_event"] = {
                "event": "rate_limited",
                "cell": cell_name,
                "limit": bucket.rate,
                "burst": bucket.burst,
                "bucket_tokens": round(bucket.tokens, 2),
            }

            flow.response = http.Response.make(
                429,
                "Rate limit exceeded",
                {
                    "Content-Type": "text/plain",
                    "Retry-After": "1",
                    "X-RateLimit-Limit": str(int(bucket.rate)),
                    "X-RateLimit-Remaining": "0",
                }
            )
            ctx.log.info(f"RATE LIMITED: {cell_name} - {flow.request.host}{flow.request.path}")


addons = [RateLimiter()]
