#!/usr/bin/env python3
"""
Load and stress tests for Brig.

Tests performance and concurrency:
    - Token bucket under load
    - Cache performance
    - Concurrent operations
    - Memory usage patterns

Run with: python3 tests/test_load.py
"""

import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Import brig.py directly (not the brig/ package).
brig_path = Path(__file__).parent.parent / "src" / "brig.py"
spec = importlib.util.spec_from_file_location("brig_module", brig_path)
brig = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brig)

# Mock mitmproxy for addon imports.
sys.modules['mitmproxy'] = MagicMock()
sys.modules['mitmproxy.http'] = MagicMock()
sys.modules['mitmproxy.ctx'] = MagicMock()

ADDONS_DIR = Path(__file__).parent.parent / "src" / "addons"
sys.path.insert(0, str(ADDONS_DIR))


class TestTokenBucketLoad(unittest.TestCase):
    """Load tests for rate limiting token bucket."""

    def setUp(self):
        """Create a TokenBucket class for testing."""
        class TokenBucket:
            def __init__(self, rate, burst):
                self.rate = rate
                self.burst = burst
                self.tokens = float(burst)
                self.last_update = time.monotonic()
                self.lock = threading.Lock()

            def consume(self):
                with self.lock:
                    now = time.monotonic()
                    elapsed = now - self.last_update
                    self.last_update = now
                    self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
                    if self.tokens >= 1.0:
                        self.tokens -= 1.0
                        return True
                    return False

        self.TokenBucket = TokenBucket

    def test_sustained_load(self):
        """Bucket handles sustained load at rate limit."""
        # 100 req/s rate, 10 burst.
        bucket = self.TokenBucket(rate=100, burst=10)

        # Consume burst.
        for _ in range(10):
            self.assertTrue(bucket.consume())

        # Sustained load at rate limit.
        start = time.monotonic()
        successful = 0
        attempts = 0
        while time.monotonic() - start < 0.1:  # 100ms test.
            if bucket.consume():
                successful += 1
            attempts += 1
            time.sleep(0.001)  # 1ms between attempts.

        # Should have allowed ~10 requests (100/s * 0.1s).
        self.assertGreater(successful, 5)
        self.assertLess(successful, 20)

    def test_concurrent_access(self):
        """Bucket handles concurrent access from multiple threads."""
        bucket = self.TokenBucket(rate=1000, burst=100)
        results = []
        errors = []

        def worker():
            try:
                for _ in range(100):
                    results.append(bucket.consume())
            except Exception as e:
                errors.append(e)

        # 10 threads, 100 attempts each.
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No errors should occur.
        self.assertEqual(len(errors), 0)
        # Should have exactly 1000 results.
        self.assertEqual(len(results), 1000)
        # Should have allowed burst + some refill.
        successful = sum(results)
        self.assertGreaterEqual(successful, 100)  # At least burst.
        self.assertLessEqual(successful, 1000)

    def test_burst_recovery(self):
        """Bucket recovers burst capacity after idle period."""
        bucket = self.TokenBucket(rate=100, burst=10)

        # Exhaust burst.
        for _ in range(10):
            bucket.consume()
        self.assertFalse(bucket.consume())

        # Wait for full recovery.
        time.sleep(0.15)  # 100 tokens/s * 0.15s = 15 tokens, capped at 10.

        # Should have full burst again.
        for _ in range(10):
            self.assertTrue(bucket.consume())


class TestCacheLoad(unittest.TestCase):
    """Load tests for caching system."""

    def setUp(self):
        """Clear cache before each test."""
        brig._cache.clear()

    def test_many_cache_entries(self):
        """Cache handles many entries."""
        # Add 10000 entries.
        for i in range(10000):
            brig._set_cache(f"key_{i}", f"value_{i}")

        # Verify all can be retrieved.
        for i in range(10000):
            hit, value = brig._cached(f"key_{i}")
            self.assertTrue(hit)
            self.assertEqual(value, f"value_{i}")

    def test_cache_update_performance(self):
        """Cache updates are fast."""
        start = time.monotonic()
        for i in range(10000):
            brig._set_cache(f"key_{i % 100}", f"value_{i}")
        elapsed = time.monotonic() - start

        # Should complete in under 1 second.
        self.assertLess(elapsed, 1.0)

    def test_cache_read_performance(self):
        """Cache reads are fast."""
        # Populate cache.
        for i in range(1000):
            brig._set_cache(f"key_{i}", f"value_{i}")

        # Time many reads.
        start = time.monotonic()
        for _ in range(100000):
            brig._cached("key_500")
        elapsed = time.monotonic() - start

        # Should complete 100k reads in under 1 second.
        self.assertLess(elapsed, 1.0)

    def test_concurrent_cache_access(self):
        """Cache handles concurrent access safely."""
        errors = []
        results = []

        def writer():
            try:
                for i in range(1000):
                    brig._set_cache(f"key_{i}", f"value_{i}")
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for i in range(1000):
                    hit, value = brig._cached(f"key_{i}")
                    results.append((hit, value))
            except Exception as e:
                errors.append(e)

        # Start multiple readers and writers.
        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No errors should occur.
        self.assertEqual(len(errors), 0)


class TestPolicyMatchingLoad(unittest.TestCase):
    """Load tests for policy matching."""

    @classmethod
    def setUpClass(cls):
        """Import Policy with mocked mitmproxy."""
        from enforce import Policy
        cls.Policy = Policy

    def test_large_policy(self):
        """Policy handles many rules."""
        # Create policy with 1000 allow rules.
        allow_rules = [f"domain-{i}.example.com" for i in range(1000)]
        policy = self.Policy(allow=allow_rules)

        # Check matching performance.
        start = time.monotonic()
        for i in range(10000):
            policy.is_allowed(f"domain-{i % 1000}.example.com", "/", "GET")
        elapsed = time.monotonic() - start

        # Should complete 10k checks in under 2 seconds.
        self.assertLess(elapsed, 2.0)

    def test_complex_rules(self):
        """Policy handles complex path/method rules efficiently."""
        allow_rules = [
            {"domain": f"api{i}.example.com", "paths": ["/v1/*", "/v2/*"], "methods": ["GET", "POST"]}
            for i in range(100)
        ]
        policy = self.Policy(allow=allow_rules)

        start = time.monotonic()
        for i in range(10000):
            policy.is_allowed(f"api{i % 100}.example.com", f"/v1/resource-{i}", "POST")
        elapsed = time.monotonic() - start

        # Should complete 10k checks in under 2 seconds.
        self.assertLess(elapsed, 2.0)


class TestValidationLoad(unittest.TestCase):
    """Load tests for validation functions."""

    def test_large_cell_definition(self):
        """Validation handles large cell definitions."""
        cell_def = {
            "image": "alpine:latest",
            "command": ["echo"] + ["arg"] * 1000,
            "env": {f"VAR_{i}": f"value_{i}" for i in range(1000)},
            "secrets": [f"secret-{i}" for i in range(100)],
        }

        start = time.monotonic()
        for _ in range(100):
            errors = brig.validate_cell_definition(cell_def)
        elapsed = time.monotonic() - start

        # Should complete 100 validations in under 1 second.
        self.assertLess(elapsed, 1.0)
        self.assertEqual(errors, [])

    def test_many_small_definitions(self):
        """Validation handles many small definitions efficiently."""
        start = time.monotonic()
        for i in range(1000):
            cell_def = {"image": f"alpine:{i}", "name": f"cell-{i}"}
            brig.validate_cell_definition(cell_def)
        elapsed = time.monotonic() - start

        # Should complete 1000 validations in under 1 second.
        self.assertLess(elapsed, 1.0)


class TestRateLimitLoad(unittest.TestCase):
    """Load tests for rate limiting."""

    def setUp(self):
        """Create temp directory for rate limit file."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_rate_limit_file = brig.RATE_LIMIT_FILE
        brig.RATE_LIMIT_FILE = Path(self.temp_dir) / "rate_limit.json"

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.RATE_LIMIT_FILE = self._original_rate_limit_file

    def test_rapid_rate_checks(self):
        """Rate limiting handles rapid checks."""
        start = time.monotonic()
        results = []
        for _ in range(100):
            results.append(brig.check_rate_limit())
        elapsed = time.monotonic() - start

        # Should complete in under 1 second.
        self.assertLess(elapsed, 1.0)
        # First RATE_LIMIT_MAX should succeed.
        self.assertEqual(sum(results[:brig.RATE_LIMIT_MAX]), brig.RATE_LIMIT_MAX)


class TestIPBlockingLoad(unittest.TestCase):
    """Load tests for IP blocking."""

    @classmethod
    def setUpClass(cls):
        """Import BLOCKED_NETWORKS from enforce.py."""
        import ipaddress
        from enforce import BLOCKED_NETWORKS
        cls.BLOCKED_NETWORKS = BLOCKED_NETWORKS
        cls.ipaddress = ipaddress

    def test_ip_check_performance(self):
        """IP blocking checks are fast."""
        ips = [
            "192.168.1.1",
            "10.0.0.1",
            "8.8.8.8",
            "1.1.1.1",
            "127.0.0.1",
            "169.254.169.254",
        ]

        start = time.monotonic()
        for _ in range(10000):
            for ip in ips:
                any(
                    self.ipaddress.ip_address(ip) in net
                    for net in self.BLOCKED_NETWORKS
                )
        elapsed = time.monotonic() - start

        # Should complete 60k checks in under 2 seconds.
        self.assertLess(elapsed, 2.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
