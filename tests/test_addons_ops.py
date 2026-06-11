"""Tests for addons.ops — merged metrics, rate limiting, and health addon.

Imports the real mitmproxy (installed via the dev extras) so an API
drift in mitmproxy surfaces as a unit-test failure instead of an E2E
surprise. Tests skip if mitmproxy is unavailable — `uv pip install -e
'.[dev]'` to enable.
"""

import unittest

import pytest

pytest.importorskip("mitmproxy", reason="install dev extras: uv pip install -e '.[dev]'")

from ops import OpsAddon, TokenBucket


class TestTokenBucket(unittest.TestCase):
    """Test token bucket rate limiter."""

    def test_consume_until_empty(self):
        bucket = TokenBucket(rate=0.0, burst=3)
        self.assertTrue(bucket.consume())
        self.assertTrue(bucket.consume())
        self.assertTrue(bucket.consume())
        self.assertFalse(bucket.consume())

    @pytest.mark.slow
    def test_refill(self):
        """Timing-dependent: relies on monotonic clock advancing during a
        20ms sleep. Marked slow so CI matrix concurrency doesn't flake
        the bucket consume below the refill threshold.
        """
        bucket = TokenBucket(rate=1000.0, burst=10)
        for _ in range(10):
            bucket.consume()
        import time
        time.sleep(0.02)
        self.assertTrue(bucket.consume())


class TestOpsAddon(unittest.TestCase):
    """Test OpsAddon LRU eviction and bucket identity."""

    def test_get_metrics_returns_same_instance(self):
        addon = OpsAddon()
        with addon.metrics_lock:
            m1 = addon._get_metrics("cell-a")
            m1.requests = 42
            m2 = addon._get_metrics("cell-a")
        self.assertEqual(m2.requests, 42)

    def test_metrics_lru_eviction(self):
        addon = OpsAddon()
        with addon.metrics_lock:
            for i in range(1005):
                addon._get_metrics(f"cell-{i}")
            self.assertLessEqual(len(addon.metrics), 1000)

    def test_get_bucket_returns_same_instance(self):
        addon = OpsAddon()
        b1 = addon._get_bucket("cell-a")
        b2 = addon._get_bucket("cell-a")
        self.assertIs(b1, b2)

    def test_bucket_lru_eviction(self):
        addon = OpsAddon()
        for i in range(1005):
            addon._get_bucket(f"cell-{i}")
        with addon.buckets_lock:
            self.assertLessEqual(len(addon.buckets), 1000)
