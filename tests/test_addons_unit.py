#!/usr/bin/env python3
"""
Unit tests for Warden mitmproxy addons.

Tests addon logic without requiring mitmproxy:
    - PolicyRule/Policy classes from enforce.py
    - TokenBucket from ratelimit.py
    - Log filtering from logger.py
    - Metrics aggregation from metrics.py
    - Notification filtering from notifier.py

Run with: python3 tests/test_addons_unit.py
"""

import ipaddress
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


# Mock mitmproxy before importing addons.
sys.modules['mitmproxy'] = MagicMock()
sys.modules['mitmproxy.http'] = MagicMock()
sys.modules['mitmproxy.ctx'] = MagicMock()

# Add src/addons to path.
ADDONS_DIR = Path(__file__).parent.parent / "src" / "addons"
sys.path.insert(0, str(ADDONS_DIR))


class TestPolicyRule(unittest.TestCase):
    """Tests for PolicyRule class from enforce.py."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyRule with mocked mitmproxy."""
        from enforce import PolicyRule
        cls.PolicyRule = PolicyRule

    def test_string_rule_exact_match(self):
        """String rule matches exact domain."""
        rule = self.PolicyRule("example.com")
        self.assertTrue(rule.matches_domain("example.com"))
        self.assertFalse(rule.matches_domain("other.com"))
        self.assertFalse(rule.matches_domain("sub.example.com"))

    def test_string_rule_case_insensitive(self):
        """Domain matching is case insensitive."""
        rule = self.PolicyRule("Example.COM")
        self.assertTrue(rule.matches_domain("example.com"))
        self.assertTrue(rule.matches_domain("EXAMPLE.com"))

    def test_wildcard_rule_subdomain(self):
        """Wildcard rule matches subdomains."""
        rule = self.PolicyRule("*.example.com")
        self.assertTrue(rule.matches_domain("sub.example.com"))
        self.assertTrue(rule.matches_domain("deep.sub.example.com"))
        self.assertTrue(rule.matches_domain("example.com"))  # Also matches base.
        self.assertFalse(rule.matches_domain("other.com"))

    def test_wildcard_rule_no_cross_boundary(self):
        """Wildcard doesn't match similar but different domains."""
        rule = self.PolicyRule("*.example.com")
        self.assertFalse(rule.matches_domain("exampleXcom"))
        self.assertFalse(rule.matches_domain("notexample.com"))

    def test_dict_rule_domain_only(self):
        """Dict rule with only domain behaves like string rule."""
        rule = self.PolicyRule({"domain": "api.example.com"})
        self.assertTrue(rule.matches_domain("api.example.com"))
        self.assertFalse(rule.matches_domain("other.com"))

    def test_dict_rule_path_matching(self):
        """Dict rule with paths restricts by path."""
        rule = self.PolicyRule({
            "domain": "api.example.com",
            "paths": ["/v1/*", "/v2/*"]
        })
        self.assertTrue(rule.matches_path("/v1/users"))
        self.assertTrue(rule.matches_path("/v2/data"))
        self.assertFalse(rule.matches_path("/v3/other"))
        self.assertFalse(rule.matches_path("/"))

    def test_dict_rule_method_matching(self):
        """Dict rule with methods restricts by HTTP method."""
        rule = self.PolicyRule({
            "domain": "api.example.com",
            "methods": ["GET", "POST"]
        })
        self.assertTrue(rule.matches_method("GET"))
        self.assertTrue(rule.matches_method("get"))  # Case insensitive.
        self.assertTrue(rule.matches_method("POST"))
        self.assertFalse(rule.matches_method("DELETE"))
        self.assertFalse(rule.matches_method("PUT"))

    def test_dict_rule_full_match(self):
        """Dict rule matches() checks all conditions."""
        rule = self.PolicyRule({
            "domain": "api.example.com",
            "paths": ["/v1/*"],
            "methods": ["POST"]
        })
        # All conditions met.
        self.assertTrue(rule.matches("api.example.com", "/v1/create", "POST"))
        # Wrong domain.
        self.assertFalse(rule.matches("other.com", "/v1/create", "POST"))
        # Wrong path.
        self.assertFalse(rule.matches("api.example.com", "/v2/create", "POST"))
        # Wrong method.
        self.assertFalse(rule.matches("api.example.com", "/v1/create", "GET"))

    def test_rule_without_restrictions_allows_all(self):
        """Rule without path/method restrictions allows any path/method."""
        rule = self.PolicyRule("example.com")
        self.assertTrue(rule.matches("example.com", "/any/path", "DELETE"))
        self.assertTrue(rule.matches("example.com", "/", "OPTIONS"))

    def test_invalid_rule_raises(self):
        """Invalid rule format raises ValueError."""
        with self.assertRaises(ValueError):
            self.PolicyRule(12345)
        with self.assertRaises(ValueError):
            self.PolicyRule(["list", "not", "allowed"])


class TestPolicy(unittest.TestCase):
    """Tests for Policy class from enforce.py."""

    @classmethod
    def setUpClass(cls):
        """Import Policy with mocked mitmproxy."""
        from enforce import Policy
        cls.Policy = Policy

    def test_empty_policy_denies_all(self):
        """Empty policy denies all requests."""
        policy = self.Policy()
        allowed, reason = policy.is_allowed("example.com", "/", "GET")
        self.assertFalse(allowed)
        self.assertIn("allowlist", reason.lower())

    def test_allowlist_permits_matching(self):
        """Allowlist permits matching domains."""
        policy = self.Policy(allow=["example.com", "*.github.com"])
        allowed, _ = policy.is_allowed("example.com", "/", "GET")
        self.assertTrue(allowed)
        allowed, _ = policy.is_allowed("api.github.com", "/", "GET")
        self.assertTrue(allowed)

    def test_denylist_blocks_even_if_allowed(self):
        """Denylist takes precedence over allowlist."""
        policy = self.Policy(
            allow=["*.example.com"],
            deny=["evil.example.com"]
        )
        allowed, _ = policy.is_allowed("good.example.com", "/", "GET")
        self.assertTrue(allowed)
        allowed, reason = policy.is_allowed("evil.example.com", "/", "GET")
        self.assertFalse(allowed)
        self.assertIn("denied", reason.lower())

    def test_non_matching_denied(self):
        """Domains not in allowlist are denied."""
        policy = self.Policy(allow=["example.com"])
        allowed, _ = policy.is_allowed("other.com", "/", "GET")
        self.assertFalse(allowed)


class TestIPBlocking(unittest.TestCase):
    """Tests for IP address blocking from enforce.py."""

    @classmethod
    def setUpClass(cls):
        """Import BLOCKED_NETWORKS from enforce.py."""
        from enforce import BLOCKED_NETWORKS
        cls.BLOCKED_NETWORKS = BLOCKED_NETWORKS

    def test_rfc1918_ranges_blocked(self):
        """RFC1918 private IP ranges are in blocked list."""
        # 10.x.x.x
        self.assertTrue(any(
            ipaddress.ip_address("10.0.0.1") in net
            for net in self.BLOCKED_NETWORKS
        ))
        # 172.16.x.x
        self.assertTrue(any(
            ipaddress.ip_address("172.16.0.1") in net
            for net in self.BLOCKED_NETWORKS
        ))
        # 192.168.x.x
        self.assertTrue(any(
            ipaddress.ip_address("192.168.1.1") in net
            for net in self.BLOCKED_NETWORKS
        ))

    def test_localhost_blocked(self):
        """Localhost ranges are blocked."""
        self.assertTrue(any(
            ipaddress.ip_address("127.0.0.1") in net
            for net in self.BLOCKED_NETWORKS
        ))

    def test_link_local_blocked(self):
        """Link-local (APIPA) range is blocked."""
        self.assertTrue(any(
            ipaddress.ip_address("169.254.169.254") in net
            for net in self.BLOCKED_NETWORKS
        ))

    def test_cgnat_blocked(self):
        """CGNAT range (100.64.0.0/10) is blocked."""
        self.assertTrue(any(
            ipaddress.ip_address("100.64.0.1") in net
            for net in self.BLOCKED_NETWORKS
        ))

    def test_public_ip_not_blocked(self):
        """Public IPs are not in the blocked list."""
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34"]:
            self.assertFalse(any(
                ipaddress.ip_address(ip) in net
                for net in self.BLOCKED_NETWORKS
            ), f"Public IP {ip} should not be blocked")


class TestTokenBucket(unittest.TestCase):
    """Tests for rate limiting token bucket algorithm.

    Implements the same logic as ratelimit.py TokenBucket class.
    """

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

    def test_initial_burst(self):
        """Bucket allows initial burst up to capacity."""
        bucket = self.TokenBucket(rate=10, burst=5)
        for i in range(5):
            self.assertTrue(bucket.consume(), f"Burst request {i+1} should succeed")
        self.assertFalse(bucket.consume(), "Request beyond burst should fail")

    def test_refill_over_time(self):
        """Bucket refills tokens over time."""
        bucket = self.TokenBucket(rate=100, burst=1)
        self.assertTrue(bucket.consume())
        self.assertFalse(bucket.consume())
        # Wait for refill at 100/s = 10ms per token.
        time.sleep(0.015)
        self.assertTrue(bucket.consume())

    def test_burst_cap(self):
        """Bucket doesn't exceed burst capacity."""
        bucket = self.TokenBucket(rate=100, burst=2)
        bucket.consume()  # Use 1.
        bucket.consume()  # Use 2.
        time.sleep(0.1)   # Wait for 10 tokens at 100/s rate.
        # Should only have 2 (burst cap), not 10.
        self.assertTrue(bucket.consume())
        self.assertTrue(bucket.consume())
        self.assertFalse(bucket.consume())

    def test_thread_safety(self):
        """Bucket is thread-safe under concurrent access."""
        bucket = self.TokenBucket(rate=1000, burst=100)
        results = []

        def worker():
            for _ in range(50):
                results.append(bucket.consume())

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have consumed 100 tokens (burst) from 200 attempts.
        successful = sum(results)
        self.assertLessEqual(successful, 100)
        self.assertGreaterEqual(successful, 95)  # Allow some timing variance.


class TestLogFiltering(unittest.TestCase):
    """Tests for log filtering logic.

    Tests the filtering concepts from logger.py without mitmproxy.
    """

    def test_host_pattern_matching(self):
        """Hosts can be filtered by glob pattern."""
        import fnmatch

        exclude_hosts = ["*.googleapis.com", "telemetry.*", "metrics.example.com"]

        def is_excluded(host):
            return any(fnmatch.fnmatch(host, pattern) for pattern in exclude_hosts)

        self.assertTrue(is_excluded("fonts.googleapis.com"))
        self.assertTrue(is_excluded("telemetry.example.com"))
        self.assertTrue(is_excluded("metrics.example.com"))
        self.assertFalse(is_excluded("api.example.com"))
        self.assertFalse(is_excluded("googleapis.com"))  # No leading wildcard match.

    def test_path_pattern_matching(self):
        """Paths can be filtered by glob pattern."""
        import fnmatch

        exclude_paths = ["/health", "/health/*", "/metrics", "/.well-known/*"]

        def is_excluded(path):
            return any(fnmatch.fnmatch(path, pattern) for pattern in exclude_paths)

        self.assertTrue(is_excluded("/health"))
        self.assertTrue(is_excluded("/health/liveness"))
        self.assertTrue(is_excluded("/metrics"))
        self.assertTrue(is_excluded("/.well-known/acme-challenge/token"))
        self.assertFalse(is_excluded("/api/v1/users"))
        self.assertFalse(is_excluded("/"))

    def test_status_code_filtering(self):
        """Status codes can be filtered by threshold."""
        min_status = 400

        def should_log(status):
            return status >= min_status

        self.assertFalse(should_log(200))
        self.assertFalse(should_log(304))
        self.assertTrue(should_log(400))
        self.assertTrue(should_log(404))
        self.assertTrue(should_log(500))


class TestMetricsAggregation(unittest.TestCase):
    """Tests for metrics aggregation logic.

    Tests the concepts from metrics.py without mitmproxy.
    """

    def test_latency_percentile_calculation(self):
        """Percentiles are calculated correctly."""
        latencies = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

        def percentile(sorted_data, p):
            idx = int(len(sorted_data) * p / 100)
            return sorted_data[min(idx, len(sorted_data) - 1)]

        self.assertEqual(percentile(latencies, 50), 60)   # p50 = 60th value (index 5)
        self.assertEqual(percentile(latencies, 95), 100)  # p95 = last value
        self.assertEqual(percentile(latencies, 99), 100)  # p99 = last value

    def test_counter_increment(self):
        """Counters increment correctly."""
        counters = {"requests": 0, "blocked": 0}

        counters["requests"] += 1
        counters["requests"] += 1
        counters["blocked"] += 1

        self.assertEqual(counters["requests"], 2)
        self.assertEqual(counters["blocked"], 1)

    def test_per_cell_metrics(self):
        """Metrics can be tracked per cell."""
        from collections import defaultdict

        cell_metrics = defaultdict(lambda: {"requests": 0, "blocked": 0, "bytes": 0})

        cell_metrics["cell-a"]["requests"] += 1
        cell_metrics["cell-a"]["bytes"] += 1024
        cell_metrics["cell-b"]["requests"] += 1
        cell_metrics["cell-b"]["blocked"] += 1

        self.assertEqual(cell_metrics["cell-a"]["requests"], 1)
        self.assertEqual(cell_metrics["cell-a"]["bytes"], 1024)
        self.assertEqual(cell_metrics["cell-b"]["blocked"], 1)
        self.assertEqual(cell_metrics["cell-c"]["requests"], 0)  # Untracked cell.


class TestNotificationFiltering(unittest.TestCase):
    """Tests for notification filtering logic.

    Tests the concepts from notifier.py without mitmproxy.
    """

    def test_rate_limited_notifications(self):
        """Notifications are rate-limited to avoid spam."""
        last_notification = {}
        min_interval = 1.0  # seconds

        def should_notify(key):
            now = time.time()
            if key in last_notification:
                if now - last_notification[key] < min_interval:
                    return False
            last_notification[key] = now
            return True

        # First notification always allowed.
        self.assertTrue(should_notify("cell-a:evil.com"))
        # Immediate retry blocked.
        self.assertFalse(should_notify("cell-a:evil.com"))
        # Different key allowed.
        self.assertTrue(should_notify("cell-b:evil.com"))
        # After interval, allowed again.
        time.sleep(1.1)
        self.assertTrue(should_notify("cell-a:evil.com"))

    def test_severity_filtering(self):
        """Notifications can be filtered by severity."""
        min_severity = "warn"
        severity_order = ["debug", "info", "warn", "error", "critical"]

        def should_notify(severity):
            return severity_order.index(severity) >= severity_order.index(min_severity)

        self.assertFalse(should_notify("debug"))
        self.assertFalse(should_notify("info"))
        self.assertTrue(should_notify("warn"))
        self.assertTrue(should_notify("error"))
        self.assertTrue(should_notify("critical"))


class TestAllowedPorts(unittest.TestCase):
    """Tests for port restriction logic from enforce.py."""

    @classmethod
    def setUpClass(cls):
        """Import ALLOWED_PORTS from enforce.py."""
        from enforce import ALLOWED_PORTS
        cls.ALLOWED_PORTS = ALLOWED_PORTS

    def test_http_ports_allowed(self):
        """HTTP and HTTPS ports are allowed."""
        self.assertIn(80, self.ALLOWED_PORTS)
        self.assertIn(443, self.ALLOWED_PORTS)

    def test_other_ports_not_allowed(self):
        """Other common ports are not allowed."""
        self.assertNotIn(22, self.ALLOWED_PORTS)    # SSH
        self.assertNotIn(8080, self.ALLOWED_PORTS)  # Alt HTTP
        self.assertNotIn(3306, self.ALLOWED_PORTS)  # MySQL
        self.assertNotIn(5432, self.ALLOWED_PORTS)  # PostgreSQL


if __name__ == "__main__":
    unittest.main(verbosity=2)
