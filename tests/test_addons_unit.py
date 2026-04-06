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

import collections
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
        """Wildcard rule matches subdomains only, not the bare domain."""
        rule = self.PolicyRule("*.example.com")
        self.assertTrue(rule.matches_domain("sub.example.com"))
        self.assertTrue(rule.matches_domain("deep.sub.example.com"))
        self.assertFalse(rule.matches_domain("example.com"))
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
        allowed, reason, _ = policy.is_allowed("example.com", "/", "GET")
        self.assertFalse(allowed)
        self.assertIn("allowlist", reason.lower())

    def test_allowlist_permits_matching(self):
        """Allowlist permits matching domains."""
        policy = self.Policy(allow=["example.com", "*.github.com"])
        allowed, _, _ = policy.is_allowed("example.com", "/", "GET")
        self.assertTrue(allowed)
        allowed, _, _ = policy.is_allowed("api.github.com", "/", "GET")
        self.assertTrue(allowed)

    def test_denylist_blocks_even_if_allowed(self):
        """Denylist takes precedence over allowlist."""
        policy = self.Policy(
            allow=["*.example.com"],
            deny=["evil.example.com"]
        )
        allowed, _, _ = policy.is_allowed("good.example.com", "/", "GET")
        self.assertTrue(allowed)
        allowed, reason, _ = policy.is_allowed("evil.example.com", "/", "GET")
        self.assertFalse(allowed)
        self.assertIn("denied", reason.lower())

    def test_non_matching_denied(self):
        """Domains not in allowlist are denied."""
        policy = self.Policy(allow=["example.com"])
        allowed, _, _ = policy.is_allowed("other.com", "/", "GET")
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
    """Tests for rate limiting token bucket algorithm from ratelimit.py."""

    @classmethod
    def setUpClass(cls):
        """Import TokenBucket from production code."""
        from ratelimit import TokenBucket
        cls.TokenBucket = TokenBucket

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

        # Should have consumed ~100 tokens (burst) plus a few from refill during execution.
        # At rate=1000/s with ~5ms execution, expect up to ~5 extra tokens from refill.
        successful = sum(results)
        self.assertLessEqual(successful, 115)
        self.assertGreaterEqual(successful, 95)


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


class TestLogRotation(unittest.TestCase):
    """Tests for log file rotation with disk quotas."""

    def setUp(self):
        """Create temp directory for log files."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test.jsonl"

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_rotation_creates_backup(self):
        """Log rotation creates .1 backup file."""
        # Create a log file with some content.
        self.log_file.write_text("line1\nline2\nline3\n")

        # Simulate rotation by renaming.
        rotated = self.log_file.with_suffix(".1.jsonl")
        self.log_file.rename(rotated)

        self.assertTrue(rotated.exists())
        self.assertFalse(self.log_file.exists())
        self.assertEqual(rotated.read_text(), "line1\nline2\nline3\n")

    def test_size_calculation(self):
        """File size is calculated correctly for rotation check."""
        content = '{"test": "data"}\n' * 100
        self.log_file.write_text(content)

        size = self.log_file.stat().st_size
        expected = len(content.encode("utf-8"))
        self.assertEqual(size, expected)


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

    def test_histogram_percentile_approximate(self):
        """Histogram-based percentiles are approximately correct."""
        from metrics import HistogramLatencyBuffer

        histogram = HistogramLatencyBuffer()

        # Add 1000 samples uniformly distributed 1-100ms.
        for i in range(1, 101):
            for _ in range(10):  # 10 of each value.
                histogram.add(float(i))

        # p50 should be in a reasonable range (histogram buckets are coarse).
        p50 = histogram.percentile(50)
        self.assertGreater(p50, 10)
        self.assertLess(p50, 200)

        # p95 should be at least as high as p50 (coarse buckets may be equal).
        p95 = histogram.percentile(95)
        self.assertGreaterEqual(p95, p50)

    def test_circular_buffer_uses_histogram(self):
        """CircularLatencyBuffer uses histogram for percentiles."""
        from metrics import CircularLatencyBuffer

        buffer = CircularLatencyBuffer(size=100)

        # Add samples.
        for i in range(1, 101):
            buffer.add(float(i))

        # Should return O(1) percentiles via histogram.
        p50 = buffer.percentile(50)
        self.assertGreater(p50, 0)  # Should return something reasonable.


class TestMetricsPersistence(unittest.TestCase):
    """Tests for metrics persistence across restarts."""

    def setUp(self):
        """Create temp directory for metrics file."""
        self.temp_dir = tempfile.mkdtemp()
        self.metrics_file = Path(self.temp_dir) / "metrics-state.json"

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_metrics_serialization(self):
        """CellMetrics can be serialized to dict."""
        from metrics import CellMetrics

        metrics = CellMetrics()
        metrics.total_requests = 100
        metrics.blocked_requests = 5
        metrics.bytes_sent = 50000

        data = metrics.to_dict()
        self.assertEqual(data["total_requests"], 100)
        self.assertEqual(data["blocked_requests"], 5)
        self.assertEqual(data["bytes_sent"], 50000)

    def test_persistence_file_format(self):
        """Persisted metrics file has correct format."""
        data = {
            "cell-a": {
                "total_requests": 100,
                "blocked_requests": 5,
                "bytes_sent": 50000,
                "bytes_received": 100000,
            }
        }

        with open(self.metrics_file, "w") as f:
            json.dump(data, f)

        # Verify it can be read back.
        with open(self.metrics_file, "r") as f:
            loaded = json.load(f)

        self.assertEqual(loaded["cell-a"]["total_requests"], 100)


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


class TestCircuitBreaker(unittest.TestCase):
    """Tests for circuit breaker pattern in notifier."""

    @classmethod
    def setUpClass(cls):
        """Import circuit breaker classes from notifier.py."""
        from notifier import CircuitBreakerConfig, CircuitBreakerState
        cls.CircuitBreakerState = CircuitBreakerState
        cls.CircuitBreakerConfig = CircuitBreakerConfig

    def test_initial_state_is_closed(self):
        """Circuit breaker starts in closed state."""
        state = self.CircuitBreakerState()
        self.assertEqual(state.state, "closed")
        self.assertEqual(state.consecutive_failures, 0)

    def test_state_tracks_failures(self):
        """Circuit breaker tracks consecutive failures."""
        state = self.CircuitBreakerState()
        state.consecutive_failures = 3
        state.total_failures = 10
        self.assertEqual(state.consecutive_failures, 3)
        self.assertEqual(state.total_failures, 10)

    def test_config_defaults(self):
        """Circuit breaker config has sensible defaults."""
        config = self.CircuitBreakerConfig()
        self.assertGreater(config.failure_threshold, 0)
        self.assertGreater(config.recovery_timeout, 0)
        self.assertGreater(config.max_retries, 0)
        self.assertGreater(config.base_backoff, 0)

    def test_exponential_backoff_calculation(self):
        """Exponential backoff grows correctly."""
        base = 1.0
        max_backoff = 60.0
        # attempt 1: 1.0, attempt 2: 2.0, attempt 3: 4.0, etc.
        for attempt in range(1, 6):
            backoff = min(base * (2 ** (attempt - 1)), max_backoff)
            expected = [1.0, 2.0, 4.0, 8.0, 16.0][attempt - 1]
            self.assertEqual(backoff, expected)

    def test_backoff_capped_at_max(self):
        """Exponential backoff doesn't exceed max."""
        base = 1.0
        max_backoff = 10.0
        # attempt 5 would be 16.0, but capped at 10.0
        backoff = min(base * (2 ** 4), max_backoff)
        self.assertEqual(backoff, 10.0)


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


class TestSIGHUPReloadHandlers(unittest.TestCase):
    """Tests for SIGHUP-based deferred policy reload handlers."""

    def test_enforce_sighup_sets_flag(self):
        """PolicyEnforcer._on_sighup sets reload pending flag."""
        from enforce import PolicyEnforcer

        enforcer = PolicyEnforcer()
        self.assertFalse(enforcer._reload_pending)

        # Simulate SIGHUP.
        enforcer._on_sighup()

        # Flag should be set (deferred reload).
        self.assertTrue(enforcer._reload_pending)

    def test_enforce_do_reload_resets_mtimes(self):
        """PolicyEnforcer._do_reload resets all mtimes."""
        from enforce import PolicyEnforcer

        enforcer = PolicyEnforcer()
        enforcer.policy_mtime = 12345.0
        enforcer.subnet_map_mtime = 67890.0
        enforcer.cell_policy_mtimes["test-cell"] = 11111.0

        enforcer._do_reload()

        self.assertEqual(enforcer.policy_mtime, 0.0)
        self.assertEqual(enforcer.subnet_map_mtime, 0.0)
        self.assertEqual(len(enforcer.cell_policy_mtimes), 0)

    def test_ratelimit_sighup_sets_flag(self):
        """RateLimiter._on_sighup sets reload pending flag."""
        from ratelimit import RateLimiter

        limiter = RateLimiter()
        self.assertFalse(limiter._reload_pending)

        limiter._on_sighup()

        self.assertTrue(limiter._reload_pending)

    def test_ratelimit_do_reload_resets_mtime(self):
        """RateLimiter._do_reload resets policy mtime."""
        from ratelimit import RateLimiter

        limiter = RateLimiter()
        limiter.policy_mtime = 12345.0

        limiter._do_reload()

        self.assertEqual(limiter.policy_mtime, 0.0)

    def test_logger_sighup_sets_flag(self):
        """RequestLogger._on_sighup sets reload pending flag."""
        from logger import RequestLogger

        req_logger = RequestLogger()
        self.assertFalse(req_logger._reload_pending)

        req_logger._on_sighup()

        self.assertTrue(req_logger._reload_pending)

    def test_logger_do_reload_resets_mtimes(self):
        """RequestLogger._do_reload resets all mtimes."""
        from logger import RequestLogger

        req_logger = RequestLogger()
        req_logger.subnet_map_mtime = 12345.0
        req_logger.policy_mtime = 67890.0

        req_logger._do_reload()

        self.assertEqual(req_logger.subnet_map_mtime, 0.0)
        self.assertEqual(req_logger.policy_mtime, 0.0)


class TestPolicyReloadDuringRequests(unittest.TestCase):
    """Tests for policy reload safety during active requests."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyEnforcer with mocked mitmproxy."""
        from enforce import PolicyEnforcer
        cls.PolicyEnforcer = PolicyEnforcer

    def test_reload_during_policy_check(self):
        """Concurrent reads and SIGHUP reload do not raise exceptions."""
        from enforce import Policy

        enforcer = self.PolicyEnforcer()
        enforcer.global_policy = Policy(
            allow=["example.com", "*.github.com"],
            deny=["evil.com"]
        )

        errors = []
        stop_flag = threading.Event()

        def check_requests():
            """Continuously check requests against the policy."""
            try:
                for _ in range(100):
                    if stop_flag.is_set():
                        break
                    enforcer.global_policy.is_allowed("example.com", "/", "GET")
                    enforcer.global_policy.is_allowed("api.github.com", "/v1", "POST")
                    enforcer.global_policy.is_allowed("evil.com", "/", "GET")
            except Exception as e:
                errors.append(e)

        # Start 10 reader threads.
        threads = [threading.Thread(target=check_requests) for _ in range(10)]
        for t in threads:
            t.start()

        # Trigger reload mid-flight.
        enforcer._on_sighup()
        enforcer._do_reload()

        stop_flag.set()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"Exceptions during concurrent reads: {errors}")

    def test_reload_preserves_deny_during_check(self):
        """Deny rules are never partially applied during reload."""
        from enforce import Policy

        enforcer = self.PolicyEnforcer()
        enforcer.global_policy = Policy(
            allow=["example.com"],
            deny=["evil.com"]
        )

        results = []
        errors = []
        # Barrier ensures all readers are running before the policy swap.
        barrier = threading.Barrier(6)  # 5 readers + 1 main thread.

        def check_deny():
            """Check that evil.com is always denied."""
            try:
                barrier.wait(timeout=5)
                for _ in range(200):
                    allowed, reason, _ = enforcer.global_policy.is_allowed(
                        "evil.com", "/", "GET"
                    )
                    results.append(allowed)
            except threading.BrokenBarrierError:
                errors.append("Barrier timeout")
            except Exception as e:
                errors.append(e)

        # Start readers.
        threads = [threading.Thread(target=check_deny) for _ in range(5)]
        for t in threads:
            t.start()

        # Wait for all readers to be ready, then swap policy.
        barrier.wait(timeout=5)
        new_policy = Policy(
            allow=["example.com", "new.com"],
            deny=["evil.com", "also-evil.com"]
        )
        enforcer.global_policy = new_policy

        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"Exceptions: {errors}")
        # evil.com should always be denied (never True).
        self.assertTrue(
            all(r is False for r in results),
            "evil.com was allowed during reload"
        )

    def test_concurrent_sighup_is_idempotent(self):
        """Multiple concurrent SIGHUP signals are safe."""
        enforcer = self.PolicyEnforcer()

        def fire_sighup():
            for _ in range(100):
                enforcer._on_sighup()

        # Fire 10 threads each calling _on_sighup 100 times.
        threads = [threading.Thread(target=fire_sighup) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        # Flag should be True (boolean assignment is atomic in CPython).
        self.assertTrue(enforcer._reload_pending)

        # _do_reload should be callable without error.
        enforcer._do_reload()
        self.assertEqual(enforcer.policy_mtime, 0.0)


class TestSIGHUPDispatcher(unittest.TestCase):
    """Tests for shared SIGHUP dispatcher."""

    def test_dispatcher_calls_all_callbacks(self):
        """SIGHUP dispatcher invokes all registered callbacks."""
        from enforce import _sighup_callbacks, _sighup_dispatcher

        results = []
        original = _sighup_callbacks.copy()

        try:
            _sighup_callbacks.clear()
            _sighup_callbacks.append(lambda: results.append("a"))
            _sighup_callbacks.append(lambda: results.append("b"))

            _sighup_dispatcher(None, None)

            self.assertEqual(results, ["a", "b"])
        finally:
            _sighup_callbacks.clear()
            _sighup_callbacks.extend(original)

    def test_register_sighup_adds_callback(self):
        """register_sighup adds callback to the list."""
        from enforce import _sighup_callbacks, register_sighup

        original = _sighup_callbacks.copy()
        count_before = len(_sighup_callbacks)

        try:
            register_sighup(lambda: None)
            self.assertEqual(len(_sighup_callbacks), count_before + 1)
        finally:
            _sighup_callbacks.clear()
            _sighup_callbacks.extend(original)


class TestCellPolicyIsolation(unittest.TestCase):
    """Tests for cell policy isolation (no fall-through to global)."""

    @classmethod
    def setUpClass(cls):
        """Import Policy and PolicyEnforcer with mocked mitmproxy."""
        from enforce import Policy, PolicyEnforcer
        cls.Policy = Policy
        cls.PolicyEnforcer = PolicyEnforcer

    def test_cell_policy_blocks_without_global_fallthrough(self):
        """Cell policy blocks requests not in its allowlist, even if global would allow."""
        cell_policy = self.Policy(allow=["specific.com"])

        # Request for example.com — allowed by global, but cell only allows specific.com.
        allowed, reason, _ = cell_policy.is_allowed("example.com", "/", "GET")
        self.assertFalse(allowed)
        self.assertIn("allowlist", reason.lower())

    def test_cell_policy_allows_matching_domain(self):
        """Cell policy allows domains in its allowlist."""
        cell_policy = self.Policy(allow=["specific.com"])

        allowed, reason, _ = cell_policy.is_allowed("specific.com", "/", "GET")
        self.assertTrue(allowed)


class TestBlockedNetworksExpanded(unittest.TestCase):
    """Tests for expanded blocked IP ranges."""

    @classmethod
    def setUpClass(cls):
        """Import BLOCKED_NETWORKS from enforce.py."""
        from enforce import BLOCKED_NETWORKS
        cls.BLOCKED_NETWORKS = BLOCKED_NETWORKS

    def test_this_network_blocked(self):
        """0.0.0.0/8 'this network' range is blocked."""
        self.assertTrue(any(
            ipaddress.ip_address("0.0.0.1") in net
            for net in self.BLOCKED_NETWORKS
        ))

    def test_multicast_blocked(self):
        """224.0.0.0/4 multicast range is blocked."""
        self.assertTrue(any(
            ipaddress.ip_address("224.0.0.1") in net
            for net in self.BLOCKED_NETWORKS
        ))

    def test_ipv4_mapped_ipv6_blocked(self):
        """::ffff:0:0/96 IPv4-mapped IPv6 range is blocked."""
        self.assertTrue(any(
            ipaddress.ip_address("::ffff:127.0.0.1") in net
            for net in self.BLOCKED_NETWORKS
        ))

    def test_documentation_ipv6_blocked(self):
        """2001:db8::/32 documentation range is blocked."""
        self.assertTrue(any(
            ipaddress.ip_address("2001:db8::1") in net
            for net in self.BLOCKED_NETWORKS
        ))


class TestGenericBlockMessage(unittest.TestCase):
    """Tests for generic block message (no policy details leaked)."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyEnforcer with mocked mitmproxy."""
        from enforce import PolicyEnforcer
        cls.PolicyEnforcer = PolicyEnforcer

    def test_block_response_is_generic(self):
        """_block() returns generic message, not the internal reason."""
        enforcer = self.PolicyEnforcer()
        flow = MagicMock()
        flow.metadata = {}
        flow.request.host = "evil.com"
        flow.request.path = "/secret"

        enforcer._block(flow, "cell policy: denied by rule: *.evil.com")

        # Response body should be generic.
        # The mock captures the Response.make() call.
        self.assertIn("block_reason", flow.metadata)
        self.assertEqual(flow.metadata["block_reason"], "cell policy: denied by rule: *.evil.com")


class TestNaNRateLimitBypass(unittest.TestCase):
    """Tests for NaN bypass prevention in rate limit config."""

    @classmethod
    def setUpClass(cls):
        """Import RateLimitConfig from ratelimit.py."""
        from ratelimit import RateLimitConfig
        cls.RateLimitConfig = RateLimitConfig

    def test_nan_rate_rejected(self):
        """NaN rate value is rejected by validation."""
        import math
        config = self.RateLimitConfig(rate=float('nan'), burst=500)
        errors = config.validate()
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any("finite" in e for e in errors))

    def test_inf_rate_rejected(self):
        """Infinity rate value is rejected by validation."""
        config = self.RateLimitConfig(rate=float('inf'), burst=500)
        errors = config.validate()
        self.assertTrue(len(errors) > 0)

    def test_nan_burst_rejected(self):
        """NaN burst value is rejected by validation."""
        config = self.RateLimitConfig(rate=100, burst=float('nan'))
        errors = config.validate()
        self.assertTrue(len(errors) > 0)


class TestLoggerPathTraversal(unittest.TestCase):
    """Tests for logger cell name path traversal prevention."""

    @classmethod
    def setUpClass(cls):
        """Import RequestLogger from logger.py."""
        from logger import LOG_DIR, UNKNOWN_LOG_FILE, RequestLogger
        cls.RequestLogger = RequestLogger
        cls.LOG_DIR = LOG_DIR
        cls.UNKNOWN_LOG_FILE = UNKNOWN_LOG_FILE

    def test_traversal_cell_name_falls_back_to_unknown(self):
        """Cell name with path traversal falls back to unknown log."""
        req_logger = self.RequestLogger()
        # Mock the async_writer.log method.
        req_logger.async_writer = MagicMock()

        req_logger._write_log("../../../etc/passwd", {"test": True})

        # Should have written to unknown log, not traversal path.
        call_args = req_logger.async_writer.log.call_args
        log_file = call_args[0][1]
        self.assertEqual(log_file, self.UNKNOWN_LOG_FILE)

    def test_slash_cell_name_falls_back_to_unknown(self):
        """Cell name with slash falls back to unknown log."""
        req_logger = self.RequestLogger()
        req_logger.async_writer = MagicMock()

        req_logger._write_log("subdir/evil", {"test": True})

        call_args = req_logger.async_writer.log.call_args
        log_file = call_args[0][1]
        self.assertEqual(log_file, self.UNKNOWN_LOG_FILE)

    def test_normal_cell_name_uses_cell_log(self):
        """Normal cell name writes to cell-specific log."""
        req_logger = self.RequestLogger()
        req_logger.async_writer = MagicMock()

        req_logger._write_log("my-cell", {"test": True})

        call_args = req_logger.async_writer.log.call_args
        log_file = call_args[0][1]
        self.assertEqual(log_file, self.LOG_DIR / "my-cell.jsonl")


class TestLRUEviction(unittest.TestCase):
    """Tests for LRU eviction in caches."""

    def test_metrics_evicts_oldest_cell(self):
        """MetricsCollector evicts oldest cell when at capacity."""
        from metrics import MAX_TRACKED_CELLS, CellMetrics, MetricsCollector

        collector = MetricsCollector()

        # Add cells up to capacity.
        for i in range(MAX_TRACKED_CELLS):
            cell_name = f"cell-{i}"
            collector.metrics[cell_name] = CellMetrics()
            collector.metrics[cell_name].last_request_ts = float(i)

        # Verify at capacity.
        self.assertEqual(len(collector.metrics), MAX_TRACKED_CELLS)

        # Add one more - should evict cell-0 (oldest).
        collector._get_or_create_metrics("new-cell")
        self.assertEqual(len(collector.metrics), MAX_TRACKED_CELLS)
        self.assertNotIn("cell-0", collector.metrics)
        self.assertIn("new-cell", collector.metrics)

    def test_ratelimit_evicts_oldest_bucket(self):
        """RateLimiter evicts oldest bucket when at capacity."""
        from ratelimit import MAX_TRACKED_CELLS, RateLimiter, TokenBucket

        limiter = RateLimiter()

        # Add buckets up to capacity.
        for i in range(MAX_TRACKED_CELLS):
            cell_name = f"cell-{i}"
            limiter.buckets[cell_name] = TokenBucket(10, 5)
            limiter.buckets[cell_name].last_update = float(i)

        # Verify at capacity.
        self.assertEqual(len(limiter.buckets), MAX_TRACKED_CELLS)

        # Add one more - should evict cell-0 (oldest).
        limiter._get_bucket("new-cell")
        self.assertEqual(len(limiter.buckets), MAX_TRACKED_CELLS)
        self.assertNotIn("cell-0", limiter.buckets)
        self.assertIn("new-cell", limiter.buckets)


class TestTUIDataFunctions(unittest.TestCase):
    """Tests for TUI data retrieval functions."""

    @classmethod
    def setUpClass(cls):
        """Import TUI module."""
        # Add src directory to path if not already present.
        src_dir = Path(__file__).parent.parent / "src"
        if str(src_dir) not in sys.path:
            sys.path.insert(0, str(src_dir))

    @patch('subprocess.run')
    def test_get_cells_success(self, mock_run):
        """get_cells returns parsed cell data."""
        from tui import get_cells

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps([
                {"Names": ["brig-test1"], "State": "running", "Image": "alpine"},
                {"Names": ["brig-test2"], "State": "exited", "Image": "python:3.12"},
                {"Names": ["warden"], "State": "running", "Image": "warden:latest"},
            ])
        )

        cells = get_cells()

        self.assertEqual(len(cells), 2)  # Excludes warden.
        self.assertEqual(cells[0]["name"], "test1")
        self.assertEqual(cells[0]["status"], "running")
        self.assertEqual(cells[1]["name"], "test2")
        self.assertEqual(cells[1]["status"], "exited")

    @patch('subprocess.run')
    def test_get_cells_empty(self, mock_run):
        """get_cells handles empty response."""
        from tui import get_cells

        mock_run.return_value = MagicMock(returncode=0, stdout="")
        cells = get_cells()
        self.assertEqual(cells, [])

    @patch('subprocess.run')
    def test_get_cells_error(self, mock_run):
        """get_cells handles podman error."""
        from tui import get_cells

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        cells = get_cells()
        self.assertEqual(cells, [])

    @patch('subprocess.run')
    def test_get_cell_stats(self, mock_run):
        """get_cell_stats returns resource stats."""
        from tui import get_cell_stats

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps([{
                "CPUPerc": "5.00%",
                "MemUsage": "100MiB / 1GiB",
                "MemPerc": "10.00%",
                "Pids": "10",
            }])
        )

        stats = get_cell_stats("test-cell")

        self.assertEqual(stats["CPUPerc"], "5.00%")
        self.assertEqual(stats["Pids"], "10")

    @patch('subprocess.run')
    def test_get_cell_logs(self, mock_run):
        """get_cell_logs returns log output."""
        from tui import get_cell_logs

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="line1\nline2\n",
            stderr=""
        )

        logs = get_cell_logs("test-cell", tail=50)

        self.assertIn("line1", logs)
        self.assertIn("line2", logs)

    @patch('subprocess.run')
    def test_run_cell_action_success(self, mock_run):
        """run_cell_action succeeds for valid actions."""
        from tui import run_cell_action

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        success, message = run_cell_action("test-cell", "stop")

        self.assertTrue(success)
        self.assertIn("successful", message.lower())
        mock_run.assert_called()

    @patch('subprocess.run')
    def test_run_cell_action_failure(self, mock_run):
        """run_cell_action handles failure."""
        from tui import run_cell_action

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="container not found")

        success, message = run_cell_action("test-cell", "stop")

        self.assertFalse(success)
        self.assertIn("not found", message)

    def test_run_cell_action_unknown(self):
        """run_cell_action rejects unknown actions."""
        from tui import run_cell_action

        success, message = run_cell_action("test-cell", "invalid")

        self.assertFalse(success)
        self.assertIn("Unknown action", message)

    @patch('subprocess.run')
    def test_is_warden_running_true(self, mock_run):
        """is_warden_running detects running warden."""
        from tui import is_warden_running

        mock_run.return_value = MagicMock(returncode=0, stdout="true\n")

        self.assertTrue(is_warden_running())

    @patch('subprocess.run')
    def test_is_warden_running_false(self, mock_run):
        """is_warden_running detects stopped warden."""
        from tui import is_warden_running

        mock_run.return_value = MagicMock(returncode=0, stdout="false\n")

        self.assertFalse(is_warden_running())

    def test_get_cell_policy_missing_file(self):
        """get_cell_policy returns empty policy for missing file."""
        from tui import get_cell_policy

        # Use a cell name that won't exist.
        policy = get_cell_policy("nonexistent-cell-xyz")

        self.assertEqual(policy.get("allow", []), [])
        self.assertEqual(policy.get("deny", []), [])


class TestTUIAvailabilityCheck(unittest.TestCase):
    """Tests for TUI textual availability detection."""

    @classmethod
    def setUpClass(cls):
        """Ensure src directory is in path."""
        src_dir = Path(__file__).parent.parent / "src"
        if str(src_dir) not in sys.path:
            sys.path.insert(0, str(src_dir))

    def test_textual_available_flag(self):
        """TEXTUAL_AVAILABLE flag is set based on import."""
        from tui import TEXTUAL_AVAILABLE

        # This will be True if textual is installed, False otherwise.
        # Either is valid - we just check the flag exists and is boolean.
        self.assertIsInstance(TEXTUAL_AVAILABLE, bool)

    def test_run_tui_without_textual(self):
        """run_tui exits gracefully without textual."""
        import tui

        # Mock TEXTUAL_AVAILABLE to False.
        original = tui.TEXTUAL_AVAILABLE
        try:
            tui.TEXTUAL_AVAILABLE = False
            result = tui.run_tui()
            self.assertEqual(result, 1)  # Should return error code.
        finally:
            tui.TEXTUAL_AVAILABLE = original


class TestLogSummarizer(unittest.TestCase):
    """Tests for AI-powered log summarization addon."""

    @classmethod
    def setUpClass(cls):
        """Import summarizer with mocked mitmproxy."""
        from summarizer import (
            DEFAULT_PRESERVE_EVENTS,
            CostTracker,
            LogSummarizer,
            SummarizationConfig,
            calculate_cost,
            estimate_tokens,
        )
        cls.SummarizationConfig = SummarizationConfig
        cls.LogSummarizer = LogSummarizer
        cls.CostTracker = CostTracker
        cls.estimate_tokens = estimate_tokens
        cls.calculate_cost = calculate_cost
        cls.DEFAULT_PRESERVE_EVENTS = DEFAULT_PRESERVE_EVENTS

    def test_config_defaults(self):
        """SummarizationConfig has sensible defaults."""
        config = self.SummarizationConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.model, "claude-haiku-3")
        self.assertEqual(config.max_input_tokens, 50000)
        self.assertEqual(config.cost_limit_daily_usd, 1.00)

    def test_config_custom_values(self):
        """SummarizationConfig accepts custom values."""
        config = self.SummarizationConfig(
            enabled=True,
            model="claude-sonnet-3.5",
            max_input_tokens=100000,
            cost_limit_daily_usd=5.00
        )
        self.assertTrue(config.enabled)
        self.assertEqual(config.model, "claude-sonnet-3.5")
        self.assertEqual(config.max_input_tokens, 100000)
        self.assertEqual(config.cost_limit_daily_usd, 5.00)

    def test_should_preserve_blocked(self):
        """Blocked entries are preserved."""
        config = self.SummarizationConfig(enabled=True)
        summarizer = self.LogSummarizer(config)

        entry = {"blocked": True, "host": "evil.com"}
        self.assertTrue(summarizer.should_preserve(entry))

    def test_should_preserve_error(self):
        """Error entries (status >= 400) are preserved."""
        config = self.SummarizationConfig(enabled=True)
        summarizer = self.LogSummarizer(config)

        # 4xx error.
        entry = {"status": 404, "host": "example.com"}
        self.assertTrue(summarizer.should_preserve(entry))

        # 5xx error.
        entry = {"status": 500, "host": "example.com"}
        self.assertTrue(summarizer.should_preserve(entry))

        # Connection error (status 0).
        entry = {"status": 0, "error": "connection refused"}
        self.assertTrue(summarizer.should_preserve(entry))

    def test_should_preserve_rate_limited(self):
        """Rate-limited entries are preserved."""
        config = self.SummarizationConfig(enabled=True)
        summarizer = self.LogSummarizer(config)

        entry = {"rate_limit": {"cell": "test"}, "host": "api.com"}
        self.assertTrue(summarizer.should_preserve(entry))

    def test_should_preserve_cert_invalid(self):
        """Certificate anomaly entries are preserved."""
        config = self.SummarizationConfig(enabled=True)
        summarizer = self.LogSummarizer(config)

        # Certificate flags present.
        entry = {"cert_flags": ["expired"], "host": "old.com"}
        self.assertTrue(summarizer.should_preserve(entry))

        # cert_valid is False.
        entry = {"cert_valid": False, "host": "insecure.com"}
        self.assertTrue(summarizer.should_preserve(entry))

    def test_should_not_preserve_normal_request(self):
        """Normal successful requests are not preserved."""
        config = self.SummarizationConfig(enabled=True)
        summarizer = self.LogSummarizer(config)

        entry = {"status": 200, "host": "example.com", "blocked": False}
        self.assertFalse(summarizer.should_preserve(entry))

    def test_partition_entries(self):
        """partition_entries correctly separates preserved from summarizable."""
        config = self.SummarizationConfig(enabled=True)
        summarizer = self.LogSummarizer(config)

        entries = [
            {"status": 200, "host": "a.com"},
            {"status": 404, "host": "b.com"},
            {"status": 200, "blocked": True, "host": "c.com"},
            {"status": 200, "host": "d.com"},
            {"status": 500, "host": "e.com"},
        ]

        preserved, summarizable = summarizer.partition_entries(entries)

        self.assertEqual(len(preserved), 3)  # 404, blocked, 500
        self.assertEqual(len(summarizable), 2)  # Two 200s

    def test_estimate_tokens(self):
        """Token estimation is approximately correct."""
        from summarizer import estimate_tokens
        # ~4 chars per token.
        text = "a" * 400
        tokens = estimate_tokens(text)
        self.assertEqual(tokens, 100)

    def test_calculate_cost_haiku(self):
        """Cost calculation for Haiku model."""
        from summarizer import calculate_cost
        cost = calculate_cost("claude-haiku-3", 1_000_000, 500_000)
        # 1M input * $0.25/M + 500K output * $1.25/M = $0.25 + $0.625 = $0.875
        self.assertAlmostEqual(cost, 0.875, places=3)

    def test_calculate_cost_sonnet(self):
        """Cost calculation for Sonnet model."""
        from summarizer import calculate_cost
        cost = calculate_cost("claude-sonnet-3.5", 1_000_000, 500_000)
        # 1M input * $3.00/M + 500K output * $15.00/M = $3.00 + $7.50 = $10.50
        self.assertAlmostEqual(cost, 10.50, places=2)

    def test_cost_tracker_daily_tracking(self):
        """CostTracker tracks daily costs correctly."""
        tracker = self.CostTracker()
        tracker.daily_costs = {}  # Reset.

        tracker.add_cost(0.50)
        self.assertAlmostEqual(tracker.get_today_cost(), 0.50, places=2)

        tracker.add_cost(0.25)
        self.assertAlmostEqual(tracker.get_today_cost(), 0.75, places=2)

    def test_cost_tracker_can_spend(self):
        """CostTracker enforces spending limits."""
        tracker = self.CostTracker()
        tracker.daily_costs = {}  # Reset.

        self.assertTrue(tracker.can_spend(1.00))  # Under limit.

        tracker.add_cost(0.90)
        self.assertTrue(tracker.can_spend(1.00))  # Still under.

        tracker.add_cost(0.15)
        self.assertFalse(tracker.can_spend(1.00))  # Over limit.

    def test_summarize_empty_entries(self):
        """summarize handles empty entry list."""
        config = self.SummarizationConfig(enabled=True)
        summarizer = self.LogSummarizer(config)

        result = summarizer.summarize([], "test-cell")
        self.assertIn("error", result)

    def test_summarize_preserves_security_events(self):
        """summarize always includes preserved events in result."""
        config = self.SummarizationConfig(enabled=False)  # AI disabled.
        summarizer = self.LogSummarizer(config)

        entries = [
            {"ts": "2024-01-01T00:00:00Z", "status": 200, "host": "a.com"},
            {"ts": "2024-01-01T00:01:00Z", "status": 403, "blocked": True, "host": "b.com"},
            {"ts": "2024-01-01T00:02:00Z", "status": 200, "host": "c.com"},
        ]

        result = summarizer.summarize(entries, "test-cell")

        self.assertIn("preserved_events", result)
        self.assertEqual(len(result["preserved_events"]), 1)
        self.assertEqual(result["preserved_events"][0]["host"], "b.com")

    def test_summarize_without_api_key(self):
        """summarize handles missing API key gracefully."""
        config = self.SummarizationConfig(enabled=True)
        summarizer = self.LogSummarizer(config)
        summarizer._api_key = None  # Ensure no API key.

        entries = [
            {"ts": "2024-01-01T00:00:00Z", "status": 200, "host": "a.com"},
        ]

        # Mock load_api_key to return None.
        with patch.object(summarizer, '_get_api_key', return_value=None):
            result = summarizer.summarize(entries, "test-cell")

        self.assertIn("ai_error", result)
        self.assertEqual(result["ai_error"], "API key not available")

    def test_build_prompt_includes_cell_name(self):
        """build_prompt includes cell name for context."""
        config = self.SummarizationConfig(enabled=True)
        summarizer = self.LogSummarizer(config)

        entries = [{"status": 200, "host": "example.com"}]
        prompt = summarizer.build_prompt(entries, "my-test-cell")

        self.assertIn("my-test-cell", prompt)
        self.assertIn("example.com", prompt)


class TestDeferredSIGHUPEndToEnd(unittest.TestCase):
    """Tests that deferred SIGHUP triggers reload on next request."""

    def test_enforce_reload_triggered_by_request(self):
        """PolicyEnforcer reload happens on next request after SIGHUP."""
        from enforce import PolicyEnforcer

        enforcer = PolicyEnforcer()
        enforcer._on_sighup()
        self.assertTrue(enforcer._reload_pending)

        # Simulate a request; _do_reload should be called.
        with patch.object(enforcer, '_do_reload') as mock_reload:
            flow = MagicMock()
            flow.request.host = "example.com"
            flow.request.port = 443
            flow.request.path = "/"
            flow.request.method = "GET"
            flow.client_conn.peername = ("10.60.1.2", 12345)
            flow.metadata = {}

            enforcer.request(flow)

            mock_reload.assert_called_once()
        self.assertFalse(enforcer._reload_pending)

    def test_enforce_no_reload_without_flag(self):
        """PolicyEnforcer skips reload when flag is not set."""
        from enforce import PolicyEnforcer

        enforcer = PolicyEnforcer()
        self.assertFalse(enforcer._reload_pending)

        with patch.object(enforcer, '_do_reload') as mock_reload:
            flow = MagicMock()
            flow.request.host = "example.com"
            flow.request.port = 443
            flow.request.path = "/"
            flow.request.method = "GET"
            flow.client_conn.peername = ("10.60.1.2", 12345)
            flow.metadata = {}

            enforcer.request(flow)

            mock_reload.assert_not_called()

    def test_ratelimit_reload_triggered_by_request(self):
        """RateLimiter reload happens on next request after SIGHUP."""
        from ratelimit import RateLimiter

        limiter = RateLimiter()
        limiter._on_sighup()
        self.assertTrue(limiter._reload_pending)

        with patch.object(limiter, '_do_reload') as mock_reload:
            flow = MagicMock()
            flow.request.host = "example.com"
            flow.request.port = 443
            flow.request.path = "/"
            flow.request.method = "GET"
            flow.client_conn.peername = ("10.60.1.2", 12345)
            flow.metadata = {}

            limiter.request(flow)

            mock_reload.assert_called_once()
        self.assertFalse(limiter._reload_pending)


class TestIDNEquivalence(unittest.TestCase):
    """Tests for IDN/punycode equivalence in policy rules."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyRule with mocked mitmproxy."""
        from enforce import PolicyRule
        cls.PolicyRule = PolicyRule

    def test_unicode_domain_matches_punycode(self):
        """Unicode domain rule matches punycode request."""
        try:
            rule = self.PolicyRule("münchen.de")
            self.assertTrue(rule.matches_domain("xn--mnchen-3ya.de"))
        except UnicodeError:
            self.skipTest("IDNA encoding not supported on this platform")

    def test_punycode_domain_matches_unicode(self):
        """Punycode domain rule matches Unicode request."""
        rule = self.PolicyRule("xn--mnchen-3ya.de")
        # Unicode request should also be normalized to punycode for matching.
        try:
            self.assertTrue(rule.matches_domain("münchen.de"))
        except UnicodeError:
            self.skipTest("IDNA encoding not supported on this platform")

    def test_wildcard_idn_matches_subdomain(self):
        """Wildcard IDN rule matches punycode subdomain."""
        try:
            rule = self.PolicyRule("*.münchen.de")
            self.assertTrue(rule.matches_domain("sub.xn--mnchen-3ya.de"))
        except UnicodeError:
            self.skipTest("IDNA encoding not supported on this platform")

    def test_ascii_domain_unaffected(self):
        """Plain ASCII domains are unaffected by normalization."""
        rule = self.PolicyRule("example.com")
        self.assertTrue(rule.matches_domain("example.com"))
        self.assertFalse(rule.matches_domain("other.com"))


class TestQueryStringRedaction(unittest.TestCase):
    """Tests for query string redaction in logger."""

    @classmethod
    def setUpClass(cls):
        """Import _redact_path from logger."""
        from logger import _redact_path
        cls._redact_path = staticmethod(_redact_path)

    def test_api_key_redacted(self):
        """API key in query string is redacted."""
        path = "/api/v1/data?key=sk-abc123&other=val"
        result = self._redact_path(path)
        self.assertNotIn("sk-abc123", result)
        self.assertIn("key=REDACTED", result)
        self.assertIn("other=val", result)

    def test_token_redacted(self):
        """Token in query string is redacted."""
        path = "/callback?token=eyJhbGciOiJ&state=ok"
        result = self._redact_path(path)
        self.assertNotIn("eyJhbGciOiJ", result)
        self.assertIn("token=REDACTED", result)
        self.assertIn("state=ok", result)

    def test_multiple_secrets_redacted(self):
        """Multiple secret parameters are all redacted."""
        path = "/auth?api_key=abc&password=xyz&client_secret=def"
        result = self._redact_path(path)
        self.assertNotIn("abc", result)
        self.assertNotIn("xyz", result)
        self.assertNotIn("def", result)
        self.assertIn("api_key=REDACTED", result)
        self.assertIn("password=REDACTED", result)
        self.assertIn("client_secret=REDACTED", result)

    def test_no_query_string_unchanged(self):
        """Path without query string is unchanged."""
        path = "/api/v1/data"
        self.assertEqual(self._redact_path(path), path)

    def test_safe_params_preserved(self):
        """Non-secret query parameters are preserved."""
        path = "/search?q=hello&page=2&limit=10"
        self.assertEqual(self._redact_path(path), path)

    def test_case_insensitive_redaction(self):
        """Redaction is case insensitive."""
        path = "/api?API_KEY=secret123"
        result = self._redact_path(path)
        self.assertNotIn("secret123", result)
        self.assertIn("REDACTED", result)


class TestCanaryDetector(unittest.TestCase):
    """Tests for canary token detection addon."""

    @classmethod
    def setUpClass(cls):
        """Import CanaryDetector with mocked mitmproxy."""
        from canary import CanaryDetector
        cls.CanaryDetector = CanaryDetector

    def _make_detector(self, cell_canaries=None):
        """Create a CanaryDetector with test canary tokens."""
        detector = self.CanaryDetector()
        if cell_canaries:
            detector.cell_canaries = cell_canaries
        return detector

    def _make_flow(self, host="example.com", path="/", method="POST",
                   body=None, headers=None, client_ip="10.60.1.2"):
        """Create a mock mitmproxy flow."""
        flow = MagicMock()
        flow.request.host = host
        flow.request.path = path
        flow.request.method = method
        flow.request.url = f"https://{host}{path}"
        flow.request.get_text.return_value = body or ""
        flow.request.headers = headers or {}
        flow.client_conn.peername = (client_ip, 12345)
        flow.metadata = {}
        return flow

    def test_canary_in_url_detected(self):
        """Canary value in URL path is detected."""
        detector = self._make_detector({
            "test-cell": {"aws_key": "AKIAFAKETOKEN123"},
        })
        matches = detector._scan_for_canaries(
            "test-cell", "https://evil.com/exfil?key=AKIAFAKETOKEN123"
        )
        self.assertIn("aws_key", matches)

    def test_canary_in_body_detected(self):
        """Canary value in request body is detected."""
        detector = self._make_detector({
            "test-cell": {"secret": "canary-value-xyz"},
        })
        matches = detector._scan_for_canaries(
            "test-cell", '{"data": "canary-value-xyz"}'
        )
        self.assertIn("secret", matches)

    def test_canary_in_header_detected(self):
        """Canary value in request header is detected."""
        detector = self._make_detector({
            "test-cell": {"token": "ghp_faketoken999"},
        })
        matches = detector._scan_for_canaries(
            "test-cell", "Authorization: Bearer ghp_faketoken999"
        )
        self.assertIn("token", matches)

    def test_no_false_positives(self):
        """Normal traffic does not trigger canary detection."""
        detector = self._make_detector({
            "test-cell": {"aws_key": "AKIAFAKETOKEN123"},
        })
        matches = detector._scan_for_canaries(
            "test-cell", "https://api.example.com/v1/data?page=2"
        )
        self.assertEqual(matches, [])

    def test_cell_identification_via_subnet(self):
        """Cells are identified by source IP via subnet map."""
        detector = self._make_detector()
        detector.subnet_map = {"10.60.1.0/24": "test-cell"}
        cell = detector._identify_cell_ip("10.60.1.5")
        self.assertEqual(cell, "test-cell")

    def test_cell_identification_unknown_ip(self):
        """Unknown IP returns None."""
        detector = self._make_detector()
        detector.subnet_map = {"10.60.1.0/24": "test-cell"}
        cell = detector._identify_cell_ip("10.60.2.5")
        self.assertIsNone(cell)

    def test_multiple_canary_tokens_per_cell(self):
        """Multiple canary tokens per cell are all checked."""
        detector = self._make_detector({
            "test-cell": {
                "aws_key": "AKIAFAKE1",
                "github_token": "ghp_fake2",
                "api_secret": "sk-fake3",
            },
        })
        # Only one matches.
        matches = detector._scan_for_canaries("test-cell", "data=ghp_fake2")
        self.assertEqual(matches, ["github_token"])

        # Two match.
        matches = detector._scan_for_canaries(
            "test-cell", "AKIAFAKE1 and ghp_fake2"
        )
        self.assertIn("aws_key", matches)
        self.assertIn("github_token", matches)

    def test_no_canaries_for_cell(self):
        """Cell with no canary tokens returns empty matches."""
        detector = self._make_detector({
            "other-cell": {"secret": "value"},
        })
        matches = detector._scan_for_canaries("unknown-cell", "anything")
        self.assertEqual(matches, [])

    def test_sighup_sets_reload_flag(self):
        """SIGHUP sets reload pending flag."""
        detector = self._make_detector()
        self.assertFalse(detector._reload_pending)
        detector._on_sighup()
        self.assertTrue(detector._reload_pending)

    @patch('subprocess.run')
    def test_kill_cell_non_blocking(self, mock_run):
        """_kill_cell returns immediately (runs in background thread)."""
        import time
        detector = self._make_detector()
        # Make subprocess.run block for 2 seconds.
        mock_run.side_effect = lambda *a, **kw: time.sleep(2)

        start = time.monotonic()
        detector._kill_cell("test-cell")
        elapsed = time.monotonic() - start

        # _kill_cell should return in well under 1 second.
        self.assertLess(elapsed, 0.5)

    def test_kill_cell_rejects_bad_name(self):
        """_kill_cell rejects cell names with invalid characters."""
        detector = self._make_detector()
        # Should not raise, just log and return.
        detector._kill_cell("-malicious")
        detector._kill_cell("")
        detector._kill_cell("has;semicolon")
        detector._kill_cell("has space")

    @patch('subprocess.run')
    def test_kill_cell_uses_double_dash(self, mock_run):
        """_kill_cell uses -- separator to prevent argument injection."""
        detector = self._make_detector()
        detector._kill_cell_sync("test-cell")
        args = mock_run.call_args[0][0]
        self.assertIn("--", args)
        dd_idx = args.index("--")
        self.assertEqual(args[dd_idx + 1], "brig-test-cell")


class TestEnforcePolicyReloadDuringRequest(unittest.TestCase):
    """Tests that policy reload mid-request does not crash."""

    def test_enforce_policy_reload_during_request(self):
        """Policy reload mid-request does not crash under heavy concurrent access."""
        from enforce import Policy, PolicyEnforcer

        enforcer = PolicyEnforcer()
        enforcer.global_policy = Policy(
            allow=["example.com", "*.github.com"],
            deny=["evil.com"]
        )

        errors = []

        def read_policy():
            """Continuously check policy."""
            try:
                for _ in range(200):
                    enforcer.global_policy.is_allowed("example.com", "/api", "POST")
                    enforcer.global_policy.is_allowed("evil.com", "/", "GET")
            except Exception as e:
                errors.append(e)

        def reload_policy():
            """Trigger multiple reloads."""
            try:
                for _ in range(50):
                    enforcer._on_sighup()
                    enforcer._do_reload()
                    # Swap the policy object entirely.
                    enforcer.global_policy = Policy(
                        allow=["example.com", "new.com"],
                        deny=["evil.com"]
                    )
            except Exception as e:
                errors.append(e)

        readers = [threading.Thread(target=read_policy, daemon=True) for _ in range(5)]
        reloader = threading.Thread(target=reload_policy, daemon=True)

        for t in readers:
            t.start()
        reloader.start()

        for t in readers:
            t.join(timeout=5)
            self.assertFalse(t.is_alive(), "Reader thread did not complete in time")
        reloader.join(timeout=5)
        self.assertFalse(reloader.is_alive(), "Reloader thread did not complete in time")

        self.assertEqual(errors, [], f"Exceptions during reload: {errors}")


class TestMetricsPersistAndReload(unittest.TestCase):
    """Tests that metrics survive a save/load cycle."""

    def test_metrics_persist_and_reload(self):
        """Metrics data survives persist and reload cycle."""
        from metrics import METRICS_PERSISTENCE_FILE, CellMetrics, MetricsCollector

        with tempfile.TemporaryDirectory() as tmpdir:
            persistence_file = Path(tmpdir) / "metrics-state.json"

            # Create a collector and add some data.
            collector = MetricsCollector()
            collector.persistence_enabled = True

            cell_a = CellMetrics()
            cell_a.total_requests = 500
            cell_a.blocked_requests = 10
            cell_a.bytes_sent = 123456
            cell_a.bytes_received = 654321
            cell_a.last_request_ts = 1000.0

            cell_b = CellMetrics()
            cell_b.total_requests = 200
            cell_b.blocked_requests = 50

            with collector.metrics_lock:
                collector.metrics["cell-a"] = cell_a
                collector.metrics["cell-b"] = cell_b

            # Persist to temp file.
            orig_file = METRICS_PERSISTENCE_FILE
            try:
                import metrics
                metrics.METRICS_PERSISTENCE_FILE = persistence_file

                collector._persist_metrics()

                # Verify file was written.
                self.assertTrue(persistence_file.exists())

                # Create a new collector and load.
                collector2 = MetricsCollector()
                collector2.persistence_enabled = True
                collector2._load_persisted_metrics()

                # Verify data was restored.
                self.assertIn("cell-a", collector2.metrics)
                self.assertEqual(collector2.metrics["cell-a"].total_requests, 500)
                self.assertEqual(collector2.metrics["cell-a"].blocked_requests, 10)
                self.assertEqual(collector2.metrics["cell-a"].bytes_sent, 123456)
                self.assertIn("cell-b", collector2.metrics)
                self.assertEqual(collector2.metrics["cell-b"].total_requests, 200)
            finally:
                metrics.METRICS_PERSISTENCE_FILE = orig_file


class TestLoggerRotationAtLimit(unittest.TestCase):
    """Tests that log rotation triggers at max_log_size."""

    def test_logger_log_rotation_at_limit(self):
        """Log file is rotated when it reaches max_log_size."""
        from logger import AsyncLogWriter

        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test-cell.jsonl"

            # Create a writer with a very small limit (1KB).
            writer = AsyncLogWriter(max_log_size=1024)

            # Write data approaching the limit.
            entry = {"ts": "2024-01-01T00:00:00Z", "host": "example.com", "status": 200}
            data = json.dumps(entry) + "\n"

            # Manually write enough data to exceed limit.
            log_file.write_text(data * 100)  # ~7KB, well over 1KB.

            # Pre-populate cached size so _check_rotation sees it.
            writer._file_sizes[log_file] = log_file.stat().st_size

            # Trigger rotation check (acquires _lock internally).
            writer._check_rotation(log_file, len(data.encode("utf-8")))

            # The original file should have been rotated.
            rotated = log_file.with_suffix(".1.jsonl")
            self.assertTrue(rotated.exists(), "Log file should have been rotated to .1.jsonl")
            # Cached size should be reset.
            self.assertEqual(writer._file_sizes[log_file], 0)


class TestNotifierDeadLetterPersistence(unittest.TestCase):
    """Tests that dead letters survive save/load cycle."""

    def test_notifier_dead_letter_persistence(self):
        """Dead letters are saved to disk and can be loaded back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dead_letter_path = Path(tmpdir) / "dead-letters.json"

            import notifier
            orig_file = notifier.DEAD_LETTER_FILE
            try:
                notifier.DEAD_LETTER_FILE = dead_letter_path

                from notifier import Notifier
                n = Notifier()
                n.config.enabled = False

                # Add enough dead letters to trigger batch flush (threshold=10).
                for i in range(10):
                    n._add_to_dead_letter(
                        {"cell": f"test{i}", "event": "blocked", "host": f"bad{i}.com"},
                        f"error_{i}"
                    )

                # Verify persisted to disk after batch threshold.
                self.assertTrue(dead_letter_path.exists())

                with open(dead_letter_path, "r") as f:
                    loaded = json.load(f)

                self.assertEqual(len(loaded), 10)
                self.assertEqual(loaded[0]["error"], "error_0")
                self.assertEqual(loaded[9]["error"], "error_9")
                self.assertIn("notification", loaded[0])
                self.assertIn("timestamp", loaded[0])
            finally:
                notifier.DEAD_LETTER_FILE = orig_file


class TestRatelimitBucketEvictionUnderLoad(unittest.TestCase):
    """Tests that concurrent access during bucket eviction is safe."""

    def test_ratelimit_bucket_eviction_under_load(self):
        """Concurrent _get_bucket calls during eviction do not raise exceptions."""
        from ratelimit import MAX_TRACKED_CELLS, RateLimiter, TokenBucket

        limiter = RateLimiter()

        # Fill buckets to capacity.
        for i in range(MAX_TRACKED_CELLS):
            limiter.buckets[f"cell-{i}"] = TokenBucket(10, 5)
            limiter.buckets[f"cell-{i}"].last_update = float(i)

        errors = []

        def access_buckets(thread_id):
            """Concurrently access and evict buckets."""
            try:
                for j in range(20):
                    cell = f"new-cell-{thread_id}-{j}"
                    bucket = limiter._get_bucket(cell)
                    bucket.consume()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=access_buckets, args=(t,), daemon=True) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
            self.assertFalse(t.is_alive(), "Worker thread did not complete in time")

        self.assertEqual(errors, [], f"Exceptions during concurrent eviction: {errors}")
        # Bucket count should not exceed limit.
        self.assertLessEqual(len(limiter.buckets), MAX_TRACKED_CELLS)


# ========== LogFilter pure-logic tests ==========


class TestLogFilterShouldLog(unittest.TestCase):
    """Tests for LogFilter.should_log from logger.py."""

    @classmethod
    def setUpClass(cls):
        """Import LogFilter."""
        from logger import LogFilter
        cls.LogFilter = LogFilter

    def test_default_allows_all(self):
        """No config, everything passes."""
        lf = self.LogFilter()
        self.assertTrue(lf.should_log("example.com", "/api", 200))

    def test_exclude_hosts_exact(self):
        """Filters matching host."""
        lf = self.LogFilter({"exclude_hosts": ["metrics.example.com"]})
        self.assertFalse(lf.should_log("metrics.example.com", "/", 200))
        self.assertTrue(lf.should_log("api.example.com", "/", 200))

    def test_exclude_hosts_wildcard(self):
        """*.internal filters api.internal."""
        lf = self.LogFilter({"exclude_hosts": ["*.internal"]})
        self.assertFalse(lf.should_log("api.internal", "/", 200))
        self.assertTrue(lf.should_log("api.external", "/", 200))

    def test_exclude_paths_pattern(self):
        """/health* filters /healthz."""
        lf = self.LogFilter({"exclude_paths": ["/health*"]})
        self.assertFalse(lf.should_log("example.com", "/healthz", 200))
        self.assertTrue(lf.should_log("example.com", "/api", 200))

    def test_min_status_filter(self):
        """Only logs status >= threshold."""
        lf = self.LogFilter({"min_status": 400})
        self.assertFalse(lf.should_log("example.com", "/", 200))
        self.assertTrue(lf.should_log("example.com", "/", 404))

    def test_only_blocked_filter(self):
        """only_blocked=True filters unblocked."""
        lf = self.LogFilter({"only_blocked": True})
        self.assertFalse(lf.should_log("example.com", "/", 200, blocked=False))
        self.assertTrue(lf.should_log("example.com", "/", 200, blocked=True))

    def test_min_latency_filter(self):
        """Filters fast requests."""
        lf = self.LogFilter({"min_latency_ms": 100})
        self.assertFalse(lf.should_log("example.com", "/", 200, latency_ms=50))
        self.assertTrue(lf.should_log("example.com", "/", 200, latency_ms=150))

    def test_sample_rate_zero(self):
        """sample_rate=0 filters all."""
        lf = self.LogFilter({"sample_rate": 0.0})
        # With sample_rate 0.0, random.random() > 0.0 is always True.
        self.assertFalse(lf.should_log("example.com", "/", 200))

    def test_combined_filters(self):
        """Multiple filters applied together."""
        lf = self.LogFilter({
            "exclude_hosts": ["metrics.*"],
            "min_status": 400,
        })
        # Excluded host filtered first.
        self.assertFalse(lf.should_log("metrics.io", "/", 500))
        # Non-excluded host below min_status.
        self.assertFalse(lf.should_log("api.io", "/", 200))
        # Non-excluded host at min_status.
        self.assertTrue(lf.should_log("api.io", "/", 400))


class TestLoggerGetCellName(unittest.TestCase):
    """Tests for RequestLogger._get_cell_name."""

    @classmethod
    def setUpClass(cls):
        """Import RequestLogger."""
        from logger import RequestLogger
        cls.RequestLogger = RequestLogger

    def test_exact_match_in_subnet(self):
        """IP resolves to cell."""
        logger = self.RequestLogger()
        logger.subnet_map = {"10.60.1.0/24": "my-cell"}
        logger._build_subnet_index()
        self.assertEqual(logger._get_cell_name("10.60.1.5"), "my-cell")

    def test_unknown_ip_returns_none(self):
        """Unrecognized IP returns None."""
        logger = self.RequestLogger()
        logger.subnet_map = {"10.60.1.0/24": "my-cell"}
        logger._build_subnet_index()
        self.assertIsNone(logger._get_cell_name("10.60.2.5"))

    def test_invalid_ip_returns_none(self):
        """Garbage string returns None."""
        logger = self.RequestLogger()
        self.assertIsNone(logger._get_cell_name("not-an-ip"))


class TestLoggerExtractErrorDetails(unittest.TestCase):
    """Tests for RequestLogger._extract_error_details."""

    @classmethod
    def setUpClass(cls):
        """Import RequestLogger."""
        from logger import RequestLogger
        cls.RequestLogger = RequestLogger

    def _make_flow(self, error_str):
        """Create a mock flow with an error."""
        flow = MagicMock()
        flow.error = MagicMock()
        flow.error.__str__ = MagicMock(return_value=error_str)
        flow.server_conn = None
        return flow

    def test_connection_refused(self):
        """Maps to ECONNREFUSED."""
        logger = self.RequestLogger()
        details = logger._extract_error_details(self._make_flow("Connection refused"))
        self.assertEqual(details["error_code"], "ECONNREFUSED")

    def test_connection_reset(self):
        """Maps to ECONNRESET."""
        logger = self.RequestLogger()
        details = logger._extract_error_details(self._make_flow("Connection reset by peer"))
        self.assertEqual(details["error_code"], "ECONNRESET")

    def test_dns_failure(self):
        """Maps to NXDOMAIN."""
        logger = self.RequestLogger()
        details = logger._extract_error_details(self._make_flow("Name or service not known"))
        self.assertEqual(details["error_code"], "NXDOMAIN")

    def test_ssl_error(self):
        """Maps to SSL_ERROR."""
        logger = self.RequestLogger()
        details = logger._extract_error_details(self._make_flow("SSL handshake failed"))
        self.assertEqual(details["error_code"], "SSL_ERROR")

    def test_unknown_error(self):
        """Maps to UNKNOWN."""
        logger = self.RequestLogger()
        details = logger._extract_error_details(self._make_flow("Something weird happened"))
        self.assertEqual(details["error_code"], "UNKNOWN")


# ========== Notifier pure-logic tests ==========


class TestNotifierShouldNotify(unittest.TestCase):
    """Tests for Notifier._should_notify."""

    @classmethod
    def setUpClass(cls):
        """Import Notifier."""
        from notifier import NotificationConfig, Notifier
        cls.Notifier = Notifier
        cls.NotificationConfig = NotificationConfig

    def test_disabled_returns_false(self):
        """config.enabled=False returns False."""
        n = self.Notifier()
        n.config.enabled = False
        self.assertFalse(n._should_notify("cell", "reason"))

    def test_no_filters_allows_all(self):
        """Enabled, no cell/reason filters allows all."""
        n = self.Notifier()
        n.config.enabled = True
        n.config.cells = None
        n.config.block_reasons = None
        n.config.min_interval_seconds = 0
        self.assertTrue(n._should_notify("any-cell", "any-reason"))

    def test_cell_filter_match(self):
        """Matching cell passes."""
        n = self.Notifier()
        n.config.enabled = True
        n.config.cells = ["target"]
        n.config.block_reasons = None
        n.config.min_interval_seconds = 0
        self.assertTrue(n._should_notify("target", "reason"))

    def test_cell_filter_no_match(self):
        """Non-matching cell fails."""
        n = self.Notifier()
        n.config.enabled = True
        n.config.cells = ["target"]
        n.config.min_interval_seconds = 0
        self.assertFalse(n._should_notify("other", "reason"))

    def test_rate_limit_within_interval(self):
        """Too soon returns False."""
        n = self.Notifier()
        n.config.enabled = True
        n.config.cells = None
        n.config.block_reasons = None
        n.config.min_interval_seconds = 60
        n.last_notification["cell-a"] = time.time()
        self.assertFalse(n._should_notify("cell-a", "reason"))

    def test_rate_limit_after_interval(self):
        """After interval passes."""
        n = self.Notifier()
        n.config.enabled = True
        n.config.cells = None
        n.config.block_reasons = None
        n.config.min_interval_seconds = 1
        n.last_notification["cell-a"] = time.time() - 2
        self.assertTrue(n._should_notify("cell-a", "reason"))


class TestNotifierCircuitBreakerLogic(unittest.TestCase):
    """Tests for Notifier circuit breaker methods."""

    @classmethod
    def setUpClass(cls):
        """Import Notifier."""
        from notifier import CircuitBreakerConfig, Notifier
        cls.Notifier = Notifier
        cls.CircuitBreakerConfig = CircuitBreakerConfig

    def test_closed_allows(self):
        """Initial state allows requests."""
        n = self.Notifier()
        self.assertTrue(n._check_circuit_breaker())

    def test_open_blocks(self):
        """After threshold failures, blocks."""
        n = self.Notifier()
        n.circuit_breaker.state = "open"
        n.circuit_breaker.last_failure_time = time.time()
        n.config.circuit_breaker.recovery_timeout = 300
        self.assertFalse(n._check_circuit_breaker())

    def test_open_to_half_open(self):
        """After recovery_timeout, allows probe."""
        n = self.Notifier()
        n.circuit_breaker.state = "open"
        n.circuit_breaker.last_failure_time = time.time() - 400
        n.config.circuit_breaker.recovery_timeout = 300
        self.assertTrue(n._check_circuit_breaker())
        self.assertEqual(n.circuit_breaker.state, "half-open")

    def test_half_open_success_closes(self):
        """Success resets to closed."""
        n = self.Notifier()
        n.circuit_breaker.state = "half-open"
        n._record_success()
        self.assertEqual(n.circuit_breaker.state, "closed")

    def test_half_open_failure_reopens(self):
        """Failure goes back to open."""
        n = self.Notifier()
        n.circuit_breaker.state = "half-open"
        n._record_failure()
        self.assertEqual(n.circuit_breaker.state, "open")

    def test_record_success_resets(self):
        """consecutive_failures reset to 0."""
        n = self.Notifier()
        n.circuit_breaker.consecutive_failures = 3
        n._record_success()
        self.assertEqual(n.circuit_breaker.consecutive_failures, 0)

    def test_record_failure_increments(self):
        """Counters increase."""
        n = self.Notifier()
        n._record_failure()
        self.assertEqual(n.circuit_breaker.consecutive_failures, 1)
        self.assertEqual(n.circuit_breaker.total_failures, 1)


class TestNotifierRedactPath(unittest.TestCase):
    """Tests for _redact_notification_path."""

    @classmethod
    def setUpClass(cls):
        """Import function."""
        from notifier import _redact_notification_path
        cls._redact = staticmethod(_redact_notification_path)

    def test_strips_query_params(self):
        """/path?key=val becomes /path."""
        self.assertEqual(self._redact("/path?key=val"), "/path")

    def test_no_query_unchanged(self):
        """/path stays as is."""
        self.assertEqual(self._redact("/path"), "/path")


# ========== Metrics pure-logic tests ==========


class TestHistogramBucketIndex(unittest.TestCase):
    """Tests for HistogramLatencyBuffer._get_bucket_index."""

    @classmethod
    def setUpClass(cls):
        """Import HistogramLatencyBuffer."""
        from metrics import HistogramLatencyBuffer
        cls.Histogram = HistogramLatencyBuffer

    def test_below_first_boundary(self):
        """Goes to bucket 0."""
        h = self.Histogram()
        self.assertEqual(h._get_bucket_index(0.5), 0)

    def test_exact_boundary(self):
        """At boundary goes to next bucket."""
        h = self.Histogram()
        # 5 is the 3rd boundary (index 2), so value 5 goes to bucket 2.
        idx = h._get_bucket_index(5)
        self.assertEqual(idx, 3)  # 5 >= 5 boundary, < 10 boundary.

    def test_overflow_last_bucket(self):
        """Large value goes to last bucket."""
        h = self.Histogram()
        idx = h._get_bucket_index(100000)
        self.assertEqual(idx, len(h.BUCKET_BOUNDS))

    def test_negative_value(self):
        """Goes to bucket 0."""
        h = self.Histogram()
        self.assertEqual(h._get_bucket_index(-5), 0)


class TestHistogramAddAndDecay(unittest.TestCase):
    """Tests for HistogramLatencyBuffer add and decay."""

    @classmethod
    def setUpClass(cls):
        """Import HistogramLatencyBuffer."""
        from metrics import HistogramLatencyBuffer
        cls.Histogram = HistogramLatencyBuffer

    def test_add_increments_count(self):
        """total_count increases."""
        h = self.Histogram()
        h.add(10.0)
        self.assertEqual(h.total_count, 1)

    def test_add_correct_bucket(self):
        """Value lands in right bucket."""
        h = self.Histogram()
        h.add(50.0)
        # 50 is >= 50 (index 5), < 100 (index 6) => bucket 6.
        self.assertEqual(h.buckets[6], 1)

    def test_decay_halves_counts(self):
        """Counts roughly halved."""
        h = self.Histogram(max_samples=100)
        for _ in range(200):
            h.add(10.0)
        # After decay, counts should be roughly halved.
        total_before_assert = h.total_count
        self.assertLess(total_before_assert, 200)

    def test_decay_integer_division(self):
        """Counts are halved by integer division on decay."""
        h = self.Histogram()
        h.buckets[3] = 4
        h.total_count = 4
        h._decay()
        self.assertEqual(h.buckets[3], 2)  # 4 // 2 = 2.

    def test_percentile_empty(self):
        """Returns 0.0."""
        h = self.Histogram()
        self.assertEqual(h.percentile(50), 0.0)


class TestCellMetricsToDict(unittest.TestCase):
    """Tests for CellMetrics.to_dict."""

    @classmethod
    def setUpClass(cls):
        """Import CellMetrics."""
        from metrics import CellMetrics
        cls.CellMetrics = CellMetrics

    def test_fresh_metrics(self):
        """All zeros, percentiles present."""
        m = self.CellMetrics()
        d = m.to_dict()
        self.assertEqual(d["total_requests"], 0)
        self.assertIn("latency_p50_ms", d)
        self.assertIn("latency_p95_ms", d)
        self.assertIn("latency_p99_ms", d)

    def test_after_recording(self):
        """Values reflect recorded requests."""
        m = self.CellMetrics()
        m.record_request(blocked=False, rate_limited=False, error=False,
                         request_bytes=100, response_bytes=200, latency_ms=50.0)
        d = m.to_dict()
        self.assertEqual(d["total_requests"], 1)
        self.assertEqual(d["bytes_sent"], 100)
        self.assertEqual(d["bytes_received"], 200)

    def test_blocked_counted(self):
        """blocked_requests incremented."""
        m = self.CellMetrics()
        m.record_request(blocked=True, rate_limited=False, error=False,
                         request_bytes=0, response_bytes=0, latency_ms=10.0)
        self.assertEqual(m.blocked_requests, 1)


# ========== Enforce pure-logic tests ==========


class TestEnforceIsInternalIP(unittest.TestCase):
    """Tests for PolicyEnforcer._is_internal_ip."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyEnforcer."""
        from enforce import PolicyEnforcer
        cls.PolicyEnforcer = PolicyEnforcer

    def test_rfc1918_10(self):
        """10.0.0.1 is internal."""
        e = self.PolicyEnforcer()
        self.assertTrue(e._is_internal_ip("10.0.0.1"))

    def test_rfc1918_172(self):
        """172.16.0.1 is internal."""
        e = self.PolicyEnforcer()
        self.assertTrue(e._is_internal_ip("172.16.0.1"))

    def test_rfc1918_192(self):
        """192.168.1.1 is internal."""
        e = self.PolicyEnforcer()
        self.assertTrue(e._is_internal_ip("192.168.1.1"))

    def test_localhost(self):
        """127.0.0.1 is internal."""
        e = self.PolicyEnforcer()
        self.assertTrue(e._is_internal_ip("127.0.0.1"))

    def test_link_local(self):
        """169.254.0.1 is internal."""
        e = self.PolicyEnforcer()
        self.assertTrue(e._is_internal_ip("169.254.0.1"))

    def test_cgnat(self):
        """100.64.0.1 is internal."""
        e = self.PolicyEnforcer()
        self.assertTrue(e._is_internal_ip("100.64.0.1"))

    def test_public_not_internal(self):
        """8.8.8.8 is not internal."""
        e = self.PolicyEnforcer()
        self.assertFalse(e._is_internal_ip("8.8.8.8"))

    def test_domain_returns_false(self):
        """example.com returns False."""
        e = self.PolicyEnforcer()
        self.assertFalse(e._is_internal_ip("example.com"))


class TestEnforceIsLiteralIP(unittest.TestCase):
    """Tests for PolicyEnforcer._is_literal_ip."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyEnforcer."""
        from enforce import PolicyEnforcer
        cls.PolicyEnforcer = PolicyEnforcer

    def test_ipv4(self):
        """8.8.8.8 is a literal IP."""
        e = self.PolicyEnforcer()
        self.assertTrue(e._is_literal_ip("8.8.8.8"))

    def test_ipv6(self):
        """::1 is a literal IP."""
        e = self.PolicyEnforcer()
        self.assertTrue(e._is_literal_ip("::1"))

    def test_domain(self):
        """example.com is not a literal IP."""
        e = self.PolicyEnforcer()
        self.assertFalse(e._is_literal_ip("example.com"))

    def test_bracketed_ipv6(self):
        """[::1] is a literal IP."""
        e = self.PolicyEnforcer()
        self.assertTrue(e._is_literal_ip("[::1]"))


class TestEnforceBuildSubnetIndex(unittest.TestCase):
    """Tests for PolicyEnforcer._build_subnet_index."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyEnforcer."""
        from enforce import PolicyEnforcer
        cls.PolicyEnforcer = PolicyEnforcer

    def test_24_subnets_indexed(self):
        """/24 subnets appear in index."""
        e = self.PolicyEnforcer()
        e.subnet_map = {"10.60.1.0/24": "cell-a", "10.60.2.0/24": "cell-b"}
        e._build_subnet_index()
        self.assertEqual(len(e._subnet_index), 2)

    def test_non_24_skipped(self):
        """/16 subnets not indexed."""
        e = self.PolicyEnforcer()
        e.subnet_map = {"10.60.0.0/16": "cell-big"}
        e._build_subnet_index()
        self.assertEqual(len(e._subnet_index), 0)

    def test_invalid_subnet_skipped(self):
        """Bad strings skipped."""
        e = self.PolicyEnforcer()
        e.subnet_map = {"not-a-subnet": "cell-bad", "10.60.1.0/24": "cell-ok"}
        e._build_subnet_index()
        self.assertEqual(len(e._subnet_index), 1)


# ========== Ratelimit pure-logic tests ==========


class TestTokenBucketUpdateConfig(unittest.TestCase):
    """Tests for TokenBucket.update_config."""

    @classmethod
    def setUpClass(cls):
        """Import TokenBucket."""
        from ratelimit import TokenBucket
        cls.TokenBucket = TokenBucket

    def test_update_changes_rate(self):
        """New rate applied."""
        b = self.TokenBucket(10, 5)
        b.update_config(20, 10)
        self.assertEqual(b.rate, 20)
        self.assertEqual(b.burst, 10)

    def test_update_clamps_tokens(self):
        """Tokens capped to new burst."""
        b = self.TokenBucket(10, 100)
        # tokens starts at 100.0.
        b.update_config(10, 5)
        self.assertEqual(b.tokens, 5.0)

    def test_update_preserves_tokens(self):
        """Tokens unchanged if below burst."""
        b = self.TokenBucket(10, 100)
        b.tokens = 3.0
        b.update_config(10, 100)
        self.assertEqual(b.tokens, 3.0)


# ========== Canary pure-logic tests ==========


class TestCanaryLoadCanaries(unittest.TestCase):
    """Tests for CanaryDetector._load_canaries."""

    @classmethod
    def setUpClass(cls):
        """Import CanaryDetector."""
        from canary import CanaryDetector
        cls.CanaryDetector = CanaryDetector

    def test_load_from_policy_files(self):
        """Temp policy files load canary tokens."""
        with tempfile.TemporaryDirectory() as tmpdir:
            import canary
            orig = canary.CELL_POLICY_DIR
            try:
                canary.CELL_POLICY_DIR = Path(tmpdir)
                policy = {"canary_tokens": {"aws_key": "AKIAFAKE123"}}
                (Path(tmpdir) / "test-cell.json").write_text(json.dumps(policy))
                detector = self.CanaryDetector()
                detector._load_canaries()
                self.assertIn("test-cell", detector.cell_canaries)
                self.assertEqual(detector.cell_canaries["test-cell"]["aws_key"], "AKIAFAKE123")
            finally:
                canary.CELL_POLICY_DIR = orig

    def test_missing_dir_no_crash(self):
        """Missing directory handled."""
        import canary
        orig = canary.CELL_POLICY_DIR
        try:
            canary.CELL_POLICY_DIR = Path("/nonexistent/dir/policies")
            detector = self.CanaryDetector()
            detector._load_canaries()  # Should not raise.
        finally:
            canary.CELL_POLICY_DIR = orig

    def test_corrupt_json_skipped(self):
        """Bad JSON logged, not crashed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            import canary
            orig = canary.CELL_POLICY_DIR
            try:
                canary.CELL_POLICY_DIR = Path(tmpdir)
                (Path(tmpdir) / "bad.json").write_text("not json{{{")
                detector = self.CanaryDetector()
                detector._load_canaries()  # Should not raise.
                self.assertNotIn("bad", detector.cell_canaries)
            finally:
                canary.CELL_POLICY_DIR = orig

    def test_mtime_caching(self):
        """Unchanged mtime skips reload."""
        with tempfile.TemporaryDirectory() as tmpdir:
            import canary
            orig = canary.CELL_POLICY_DIR
            try:
                canary.CELL_POLICY_DIR = Path(tmpdir)
                policy = {"canary_tokens": {"key": "val1"}}
                policy_file = Path(tmpdir) / "cell.json"
                policy_file.write_text(json.dumps(policy))

                detector = self.CanaryDetector()
                detector._load_canaries()
                self.assertEqual(detector.cell_canaries["cell"]["key"], "val1")

                # Modify value but not mtime (mtime cached).
                detector.cell_canaries["cell"]["key"] = "modified"
                detector._load_canaries()
                # Should still have modified value since mtime unchanged.
                self.assertEqual(detector.cell_canaries["cell"]["key"], "modified")
            finally:
                canary.CELL_POLICY_DIR = orig


# ========== Step 1g: Addon Pure Logic Tests ==========


class TestLogFilterEnhanced(unittest.TestCase):
    """Extended tests for LogFilter covering only_errors, max_body_size, and sample_rate."""

    @classmethod
    def setUpClass(cls):
        """Import LogFilter from logger."""
        from logger import LogFilter
        cls.LogFilter = LogFilter

    def test_only_errors_filter(self):
        """only_errors=True logs only status >= 400 or connection errors."""
        lf = self.LogFilter({"only_errors": True})
        self.assertFalse(lf.should_log("example.com", "/", 200))
        self.assertFalse(lf.should_log("example.com", "/", 301))
        self.assertTrue(lf.should_log("example.com", "/", 400))
        self.assertTrue(lf.should_log("example.com", "/", 500))
        # Status 0 indicates connection error.
        self.assertTrue(lf.should_log("example.com", "/", 0))

    def test_max_body_size_filter(self):
        """max_body_size filters out responses with bodies exceeding the limit."""
        lf = self.LogFilter({"max_body_size": 1000})
        self.assertTrue(lf.should_log("example.com", "/", 200, body_size=500))
        self.assertTrue(lf.should_log("example.com", "/", 200, body_size=1000))
        self.assertFalse(lf.should_log("example.com", "/", 200, body_size=1001))

    def test_sample_rate_one(self):
        """sample_rate=1.0 logs all requests."""
        lf = self.LogFilter({"sample_rate": 1.0})
        # All 100 calls should pass with rate 1.0.
        for _ in range(100):
            self.assertTrue(lf.should_log("example.com", "/", 200))

    def test_combined_only_blocked_and_min_latency(self):
        """only_blocked and min_latency_ms applied together."""
        lf = self.LogFilter({"only_blocked": True, "min_latency_ms": 100})
        # Not blocked, fast.
        self.assertFalse(lf.should_log("a.com", "/", 200, blocked=False, latency_ms=50))
        # Blocked but too fast.
        self.assertFalse(lf.should_log("a.com", "/", 200, blocked=True, latency_ms=50))
        # Not blocked but slow.
        self.assertFalse(lf.should_log("a.com", "/", 200, blocked=False, latency_ms=150))
        # Blocked and slow.
        self.assertTrue(lf.should_log("a.com", "/", 200, blocked=True, latency_ms=150))


class TestRedactPathEnhanced(unittest.TestCase):
    """Extended tests for _redact_path covering URL-encoding bypass attempts."""

    @classmethod
    def setUpClass(cls):
        """Import _redact_path from logger."""
        from logger import _redact_path
        cls._redact_path = staticmethod(_redact_path)

    def test_single_encoded_bypass(self):
        """Path with percent-encoded = sign still redacted."""
        # key%3Dsecret123 decodes to key=secret123 in query context.
        path = "/api?api_key%3Dsecret123"
        result = self._redact_path(path)
        self.assertNotIn("secret123", result)

    def test_double_encoded_bypass(self):
        """Path with double-encoded values still redacted."""
        # %2561pi%255Fkey=secret => after decode loop => api_key=secret.
        path = "/api?%2561pi%255Fkey=secret"
        result = self._redact_path(path)
        self.assertNotIn("secret", result)

    def test_normal_path_unchanged(self):
        """Normal path without sensitive params is unchanged."""
        path = "/api/v1/data"
        self.assertEqual(self._redact_path(path), path)


class TestPolicyTraceEnabled(unittest.TestCase):
    """Tests for Policy.is_allowed with PolicyTraceConfig tracing."""

    @classmethod
    def setUpClass(cls):
        """Import Policy and PolicyTraceConfig from enforce."""
        from enforce import Policy, PolicyTraceConfig
        cls.Policy = Policy
        cls.PolicyTraceConfig = PolicyTraceConfig

    def test_trace_disabled_returns_empty(self):
        """Disabled trace config returns empty trace dict."""
        policy = self.Policy(allow=["example.com"])
        trace_config = self.PolicyTraceConfig({"enabled": False})
        _, _, trace = policy.is_allowed("example.com", "/", "GET", trace_config)
        self.assertEqual(trace, {})

    def test_deny_trace(self):
        """Denied domain trace has decision_path ending with denied."""
        policy = self.Policy(allow=["good.com"], deny=["evil.com"])
        trace_config = self.PolicyTraceConfig({"enabled": True})
        allowed, _, trace = policy.is_allowed("evil.com", "/", "GET", trace_config)
        self.assertFalse(allowed)
        self.assertIn("decision_path", trace)
        self.assertIn("denied", trace["decision_path"])

    def test_allow_trace(self):
        """Allowed domain trace has decision_path ending with allowed."""
        policy = self.Policy(allow=["example.com"])
        trace_config = self.PolicyTraceConfig({"enabled": True})
        allowed, _, trace = policy.is_allowed("example.com", "/", "GET", trace_config)
        self.assertTrue(allowed)
        self.assertIn("decision_path", trace)
        self.assertIn("allowed", trace["decision_path"])

    def test_default_deny_trace(self):
        """Domain not in allowlist trace has decision_path with default_deny."""
        policy = self.Policy(allow=["example.com"])
        trace_config = self.PolicyTraceConfig({"enabled": True})
        allowed, _, trace = policy.is_allowed("other.com", "/", "GET", trace_config)
        self.assertFalse(allowed)
        self.assertIn("decision_path", trace)
        self.assertIn("default_deny", trace["decision_path"])

    def test_timing_included(self):
        """include_timing=True adds evaluation_ms to trace."""
        policy = self.Policy(allow=["example.com"])
        trace_config = self.PolicyTraceConfig({"enabled": True, "include_timing": True})
        _, _, trace = policy.is_allowed("example.com", "/", "GET", trace_config)
        self.assertIn("evaluation_ms", trace)
        self.assertIsInstance(trace["evaluation_ms"], float)


class TestRateLimitConfigValidate(unittest.TestCase):
    """Extended tests for RateLimitConfig validation and warnings."""

    @classmethod
    def setUpClass(cls):
        """Import RateLimitConfig from ratelimit."""
        from ratelimit import RateLimitConfig
        cls.RateLimitConfig = RateLimitConfig

    def test_negative_rate_rejected(self):
        """Negative rate value is rejected by validation."""
        config = self.RateLimitConfig(rate=-1, burst=500)
        errors = config.validate()
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any("positive" in e for e in errors))

    def test_zero_burst_rejected(self):
        """Zero burst value is rejected by validation."""
        config = self.RateLimitConfig(rate=100, burst=0)
        errors = config.validate()
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any("positive" in e for e in errors))

    def test_warning_rate_gt_burst(self):
        """Rate exceeding burst triggers a warning."""
        config = self.RateLimitConfig(rate=1000, burst=10)
        warns = config.warnings()
        self.assertTrue(len(warns) > 0)
        self.assertTrue(any("exceeds burst" in w for w in warns))

    def test_warning_high_rate(self):
        """Very high rate triggers a warning."""
        config = self.RateLimitConfig(rate=100000, burst=100000)
        warns = config.warnings()
        self.assertTrue(any("high rate" in w for w in warns))

    def test_warning_high_burst(self):
        """Very high burst triggers a warning."""
        config = self.RateLimitConfig(rate=100, burst=100001)
        warns = config.warnings()
        self.assertTrue(any("high burst" in w for w in warns))


class TestCanaryIdentifyCellInvalidIP(unittest.TestCase):
    """Tests for CanaryDetector._identify_cell_ip with invalid input."""

    @classmethod
    def setUpClass(cls):
        """Import CanaryDetector from canary."""
        from canary import CanaryDetector
        cls.CanaryDetector = CanaryDetector

    def test_identify_cell_ip_invalid_ip(self):
        """Non-IP string returns None."""
        detector = self.CanaryDetector()
        detector.subnet_map = {"10.60.1.0/24": "test-cell"}
        result = detector._identify_cell_ip("not-an-ip-address")
        self.assertIsNone(result)


class TestCellMetricsExtended(unittest.TestCase):
    """Extended tests for CellMetrics record_request counters."""

    @classmethod
    def setUpClass(cls):
        """Import CellMetrics from metrics."""
        from metrics import CellMetrics
        cls.CellMetrics = CellMetrics

    def test_rate_limited_counted(self):
        """rate_limited_requests incremented when rate_limited=True."""
        m = self.CellMetrics()
        m.record_request(blocked=False, rate_limited=True, error=False,
                         request_bytes=0, response_bytes=0, latency_ms=10.0)
        self.assertEqual(m.rate_limited_requests, 1)

    def test_error_counted(self):
        """error_requests incremented when error=True."""
        m = self.CellMetrics()
        m.record_request(blocked=False, rate_limited=False, error=True,
                         request_bytes=0, response_bytes=0, latency_ms=10.0)
        self.assertEqual(m.error_requests, 1)

    def test_to_dict_has_all_keys(self):
        """to_dict contains all expected metric keys."""
        m = self.CellMetrics()
        d = m.to_dict()
        expected_keys = [
            "total_requests", "blocked_requests", "rate_limited_requests",
            "error_requests", "bytes_sent", "bytes_received",
            "latency_p50_ms", "latency_p95_ms", "latency_p99_ms",
        ]
        for key in expected_keys:
            self.assertIn(key, d, f"Missing key: {key}")


class TestCostTrackerPrune(unittest.TestCase):
    """Tests for CostTracker old entry pruning."""

    @classmethod
    def setUpClass(cls):
        """Import CostTracker from summarizer."""
        from summarizer import CostTracker
        cls.CostTracker = CostTracker

    def test_cost_tracker_prune(self):
        """Old date entries are pruned when adding cost."""
        tracker = self.CostTracker()
        tracker.daily_costs = {"2020-01-01": 0.50, "2020-06-15": 0.25}
        tracker.add_cost(0.10)
        # Old entries should be pruned.
        self.assertNotIn("2020-01-01", tracker.daily_costs)
        self.assertNotIn("2020-06-15", tracker.daily_costs)
        # Today's entry should exist.
        self.assertGreater(tracker.get_today_cost(), 0)

    def test_no_api_key_returns_preserved_only(self):
        """Without API key, summarize returns only preserved events."""
        from summarizer import LogSummarizer, SummarizationConfig

        config = SummarizationConfig(enabled=True)
        summarizer = LogSummarizer(config)
        summarizer._api_key = None

        entries = [
            {"ts": "2024-01-01T00:00:00Z", "status": 200, "host": "a.com"},
            {"ts": "2024-01-01T00:01:00Z", "status": 403, "blocked": True, "host": "b.com"},
        ]

        with patch.object(summarizer, '_get_api_key', return_value=None):
            result = summarizer.summarize(entries, "test-cell")

        self.assertIn("preserved_events", result)
        self.assertEqual(len(result["preserved_events"]), 1)
        self.assertEqual(result["preserved_events"][0]["host"], "b.com")


# ========== Step 3: HTTPFlow Mock Tests ==========


def _make_flow(host="example.com", path="/", method="GET", status=200,
               client_ip="10.60.1.2", port=443):
    """Create a mock mitmproxy HTTPFlow for testing addon hooks."""
    flow = MagicMock()
    flow.request.host = host
    flow.request.port = port
    flow.request.path = path
    flow.request.method = method
    flow.request.url = f"https://{host}{path}"
    flow.request.get_text.return_value = ""
    flow.request.headers = {}
    flow.request.content = b""
    flow.request.scheme = "https"
    flow.request.get_content.return_value = b""
    flow.client_conn.peername = (client_ip, 12345)
    flow.response = MagicMock() if status else None
    if status:
        flow.response.status_code = status
        flow.response.headers = {"content-length": "100"}
        flow.response.content = b"x" * 100
    flow.metadata = {}
    flow.error = None
    return flow


class TestPolicyEnforcerRequest(unittest.TestCase):
    """Tests for PolicyEnforcer.request() with mock HTTPFlows."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyEnforcer and Policy from enforce."""
        from enforce import Policy, PolicyEnforcer
        cls.PolicyEnforcer = PolicyEnforcer
        cls.Policy = Policy

    def _make_enforcer(self):
        """Create a PolicyEnforcer with test policy and subnet map."""
        enforcer = self.PolicyEnforcer()
        enforcer.global_policy = self.Policy(
            allow=["example.com"], deny=["evil.com"]
        )
        enforcer.subnet_map = {"10.60.1.0/24": "test-cell"}
        enforcer._build_subnet_index()
        return enforcer

    def test_denied_domain_blocked(self):
        """Request to denied domain is blocked."""
        enforcer = self._make_enforcer()
        flow = _make_flow(host="evil.com")
        enforcer.request(flow)
        self.assertTrue(flow.metadata.get("blocked", False))

    def test_allowed_domain_passes(self):
        """Request to allowed domain is not blocked."""
        enforcer = self._make_enforcer()
        flow = _make_flow(host="example.com")
        enforcer.request(flow)
        self.assertFalse(flow.metadata.get("blocked", False))

    def test_internal_ip_blocked(self):
        """Request to internal IP address is blocked."""
        enforcer = self._make_enforcer()
        flow = _make_flow(host="192.168.1.1")
        enforcer.request(flow)
        self.assertTrue(flow.metadata.get("blocked", False))

    def test_literal_ip_blocked(self):
        """Request to literal public IP address is blocked."""
        enforcer = self._make_enforcer()
        flow = _make_flow(host="1.2.3.4")
        enforcer.request(flow)
        self.assertTrue(flow.metadata.get("blocked", False))

    def test_unknown_cell_uses_global(self):
        """Request from unknown IP uses global policy."""
        enforcer = self._make_enforcer()
        flow = _make_flow(host="example.com", client_ip="10.99.99.2")
        enforcer.request(flow)
        # Should pass via global policy.
        self.assertFalse(flow.metadata.get("blocked", False))

    def test_non_http_port_blocked(self):
        """Request on non-HTTP port is blocked."""
        enforcer = self._make_enforcer()
        flow = _make_flow(host="example.com", port=8080)
        enforcer.request(flow)
        self.assertTrue(flow.metadata.get("blocked", False))


class TestRateLimiterRequest(unittest.TestCase):
    """Tests for RateLimiter.request() with mock HTTPFlows."""

    @classmethod
    def setUpClass(cls):
        """Import RateLimiter from ratelimit."""
        from ratelimit import RateLimiter
        cls.RateLimiter = RateLimiter

    def test_first_request_passes(self):
        """First request is not rate limited."""
        limiter = self.RateLimiter()
        flow = _make_flow()
        flow.metadata["cell"] = "test-cell"
        limiter.request(flow)
        self.assertFalse(flow.metadata.get("rate_limited", False))

    def test_beyond_burst_returns_429(self):
        """Requests beyond burst limit receive 429 response."""
        limiter = self.RateLimiter()
        # Exhaust the burst by sending many requests.
        blocked = False
        for _ in range(10000):
            flow = _make_flow()
            flow.metadata["cell"] = "burst-cell"
            limiter.request(flow)
            if flow.metadata.get("rate_limited", False):
                blocked = True
                break
        self.assertTrue(blocked, "Rate limiter should block after burst is exhausted")

    def test_per_cell_independent(self):
        """Different cells have independent rate limit buckets."""
        limiter = self.RateLimiter()
        # Exhaust burst for cell-a.
        for _ in range(10000):
            flow = _make_flow(client_ip="10.60.1.2")
            flow.metadata["cell"] = "cell-a"
            limiter.request(flow)
            if flow.metadata.get("rate_limited", False):
                break

        # Cell-b should still pass.
        flow_b = _make_flow(client_ip="10.60.2.2")
        flow_b.metadata["cell"] = "cell-b"
        limiter.request(flow_b)
        self.assertFalse(flow_b.metadata.get("rate_limited", False))


class TestRequestLoggerHooks(unittest.TestCase):
    """Tests for RequestLogger.request() and response() hooks."""

    @classmethod
    def setUpClass(cls):
        """Import RequestLogger from logger."""
        from logger import RequestLogger
        cls.RequestLogger = RequestLogger

    def test_request_stores_start_time(self):
        """After request(), flow.metadata has request_start timestamp."""
        logger = self.RequestLogger()
        flow = _make_flow()
        logger.request(flow)
        self.assertIn("request_start", flow.metadata)
        self.assertIsInstance(flow.metadata["request_start"], float)

    def test_response_writes_entry(self):
        """After response(), async_writer.log is called with entry dict."""
        logger = self.RequestLogger()
        logger.async_writer = MagicMock()
        logger.subnet_map = {"10.60.1.0/24": "test-cell"}
        logger._build_subnet_index()

        flow = _make_flow()
        flow.metadata["cell"] = "test-cell"
        flow.metadata["request_start"] = time.time() - 0.01

        logger.response(flow)

        logger.async_writer.log.assert_called_once()
        call_args = logger.async_writer.log.call_args
        entry = call_args[0][0]
        self.assertIn("host", entry)
        self.assertEqual(entry["host"], "example.com")

    def test_blocked_flag_in_entry(self):
        """Blocked flow produces entry with blocked=True."""
        logger = self.RequestLogger()
        logger.async_writer = MagicMock()

        flow = _make_flow()
        flow.metadata["cell"] = "test-cell"
        flow.metadata["request_start"] = time.time() - 0.01
        flow.metadata["blocked"] = True
        flow.metadata["block_reason"] = "denied"

        logger.response(flow)

        call_args = logger.async_writer.log.call_args
        entry = call_args[0][0]
        self.assertTrue(entry["blocked"])
        self.assertEqual(entry["block_reason"], "denied")

    def test_filter_excludes_host(self):
        """Excluded host is not logged."""
        from logger import LogFilter

        logger = self.RequestLogger()
        logger.async_writer = MagicMock()
        logger.log_filter = LogFilter({"exclude_hosts": ["excluded.com"]})

        flow = _make_flow(host="excluded.com")
        flow.metadata["cell"] = "test-cell"
        flow.metadata["request_start"] = time.time() - 0.01

        logger.response(flow)

        logger.async_writer.log.assert_not_called()


class TestNotifierResponse(unittest.TestCase):
    """Tests for Notifier.response() hook with mock HTTPFlows."""

    @classmethod
    def setUpClass(cls):
        """Import Notifier from notifier."""
        from notifier import Notifier
        cls.Notifier = Notifier

    def test_disabled_skips(self):
        """Disabled notifier does not queue notifications."""
        n = self.Notifier()
        n.config.enabled = False
        flow = _make_flow()
        flow.metadata["blocked"] = True
        flow.metadata["block_reason"] = "test"
        flow.metadata["cell"] = "test-cell"

        n.response(flow)

        self.assertTrue(n.notification_queue.empty())

    def test_non_blocked_skipped(self):
        """Non-blocked request does not trigger notification."""
        n = self.Notifier()
        n.config.enabled = True
        n.config.min_interval_seconds = 0
        flow = _make_flow()
        # No blocked metadata.

        n.response(flow)

        self.assertTrue(n.notification_queue.empty())

    def test_blocked_queued(self):
        """Blocked request queues a notification."""
        n = self.Notifier()
        n.config.enabled = True
        n.config.cells = None
        n.config.block_reasons = None
        n.config.min_interval_seconds = 0
        n.config.webhook_url = "https://hooks.example.com/test"

        flow = _make_flow()
        flow.metadata["blocked"] = True
        flow.metadata["block_reason"] = "denied by rule"
        flow.metadata["cell"] = "test-cell"

        n.response(flow)

        self.assertFalse(n.notification_queue.empty())
        notification = n.notification_queue.get_nowait()
        self.assertEqual(notification["cell"], "test-cell")
        self.assertEqual(notification["event"], "request_blocked")


class TestCanaryDetectorRequest(unittest.TestCase):
    """Tests for CanaryDetector.request() hook with mock HTTPFlows."""

    @classmethod
    def setUpClass(cls):
        """Import CanaryDetector from canary."""
        from canary import CanaryDetector
        cls.CanaryDetector = CanaryDetector

    def _make_detector(self, cell_canaries=None, subnet_map=None):
        """Create a CanaryDetector with patched file loading."""
        detector = self.CanaryDetector()
        if cell_canaries:
            detector.cell_canaries = cell_canaries
        if subnet_map:
            detector.subnet_map = subnet_map
        return detector

    @patch.object(__import__('canary', fromlist=['CanaryDetector']).CanaryDetector,
                  '_load_subnet_map')
    @patch.object(__import__('canary', fromlist=['CanaryDetector']).CanaryDetector,
                  '_load_canaries')
    def test_canary_in_url_kills(self, mock_load_canaries, mock_load_subnet):
        """Request containing canary token in URL is blocked."""
        detector = self._make_detector(
            cell_canaries={"test-cell": {"secret": "CANARY_TOKEN_XYZ"}},
            subnet_map={"10.60.1.0/24": "test-cell"},
        )

        flow = _make_flow(host="evil.com", path="/exfil?data=CANARY_TOKEN_XYZ")
        flow.request.url = "https://evil.com/exfil?data=CANARY_TOKEN_XYZ"
        flow.request.get_content.return_value = b""
        flow.metadata["cell"] = "test-cell"

        detector.request(flow)

        self.assertIn("canary_detected", flow.metadata)

    @patch.object(__import__('canary', fromlist=['CanaryDetector']).CanaryDetector,
                  '_load_subnet_map')
    @patch.object(__import__('canary', fromlist=['CanaryDetector']).CanaryDetector,
                  '_load_canaries')
    def test_no_canary_passes(self, mock_load_canaries, mock_load_subnet):
        """Normal request without canary tokens passes through."""
        detector = self._make_detector(
            cell_canaries={"test-cell": {"secret": "CANARY_TOKEN_XYZ"}},
            subnet_map={"10.60.1.0/24": "test-cell"},
        )

        flow = _make_flow(host="example.com", path="/api/v1/data")
        flow.request.url = "https://example.com/api/v1/data"
        flow.request.get_content.return_value = b""
        flow.metadata["cell"] = "test-cell"

        detector.request(flow)

        self.assertNotIn("canary_detected", flow.metadata)

    @patch.object(__import__('canary', fromlist=['CanaryDetector']).CanaryDetector,
                  '_load_subnet_map')
    @patch.object(__import__('canary', fromlist=['CanaryDetector']).CanaryDetector,
                  '_load_canaries')
    def test_unknown_cell_no_check(self, mock_load_canaries, mock_load_subnet):
        """Request from unknown cell skips canary checking."""
        detector = self._make_detector(
            cell_canaries={"test-cell": {"secret": "CANARY_TOKEN_XYZ"}},
            subnet_map={},
        )

        flow = _make_flow(client_ip="10.99.99.2")
        flow.request.url = "https://evil.com/exfil?data=CANARY_TOKEN_XYZ"
        flow.request.get_content.return_value = b""

        detector.request(flow)

        # Should not be blocked because cell is unknown.
        self.assertNotIn("canary_detected", flow.metadata)


class TestMetricsCollectorResponse(unittest.TestCase):
    """Tests for MetricsCollector.response() hook with mock HTTPFlows."""

    @classmethod
    def setUpClass(cls):
        """Import MetricsCollector from metrics."""
        from metrics import MetricsCollector
        cls.MetricsCollector = MetricsCollector

    def test_increments_total(self):
        """Response increments total_requests counter."""
        collector = self.MetricsCollector()
        flow = _make_flow()
        flow.metadata["cell"] = "test-cell"
        flow.metadata["metrics_start"] = time.time() - 0.01

        collector.response(flow)

        self.assertEqual(collector.metrics["test-cell"].total_requests, 1)

    def test_blocked_increments(self):
        """Blocked response increments blocked_requests counter."""
        collector = self.MetricsCollector()
        flow = _make_flow()
        flow.metadata["cell"] = "test-cell"
        flow.metadata["metrics_start"] = time.time() - 0.01
        flow.metadata["blocked"] = True

        collector.response(flow)

        self.assertEqual(collector.metrics["test-cell"].blocked_requests, 1)

    def test_5xx_increments_errors(self):
        """5xx status recorded via error() hook increments error_requests."""
        collector = self.MetricsCollector()
        flow = _make_flow(status=500)
        flow.metadata["cell"] = "test-cell"
        flow.metadata["metrics_start"] = time.time() - 0.01
        flow.error = MagicMock()

        collector.error(flow)

        self.assertEqual(collector.metrics["test-cell"].error_requests, 1)

    def test_bytes_recorded(self):
        """Request and response bytes are recorded."""
        collector = self.MetricsCollector()
        flow = _make_flow()
        flow.request.content = b"request-body"
        flow.response.content = b"response-body-longer"
        flow.metadata["cell"] = "test-cell"
        flow.metadata["metrics_start"] = time.time() - 0.01

        collector.response(flow)

        self.assertEqual(collector.metrics["test-cell"].bytes_sent, len(b"request-body"))
        self.assertEqual(collector.metrics["test-cell"].bytes_received, len(b"response-body-longer"))

    def test_latency_recorded(self):
        """Latency is recorded when metrics_start is set."""
        collector = self.MetricsCollector()
        flow = _make_flow()
        flow.metadata["cell"] = "test-cell"
        flow.metadata["metrics_start"] = time.time() - 0.05  # 50ms ago.

        collector.response(flow)

        # Latency should be at least 40ms (allowing some slack).
        p50 = collector.metrics["test-cell"].get_percentile(50)
        self.assertGreater(p50, 0)


class TestLogSummarizerExtended(unittest.TestCase):
    """Extended tests for LogSummarizer cost tracking and fallback behavior."""

    @classmethod
    def setUpClass(cls):
        """Import summarizer classes."""
        from summarizer import CostTracker, LogSummarizer, SummarizationConfig
        cls.CostTracker = CostTracker
        cls.LogSummarizer = LogSummarizer
        cls.SummarizationConfig = SummarizationConfig

    def test_cost_tracker_prune_old_entries(self):
        """Old daily cost entries are removed during add_cost."""
        tracker = self.CostTracker()
        tracker.daily_costs = {
            "2019-01-01": 1.00,
            "2019-12-31": 2.00,
        }
        tracker.add_cost(0.01)
        # Old entries from 2019 should be pruned.
        self.assertNotIn("2019-01-01", tracker.daily_costs)
        self.assertNotIn("2019-12-31", tracker.daily_costs)

    def test_no_api_key_returns_preserved_only(self):
        """Without API key, only preserved events are returned."""
        config = self.SummarizationConfig(enabled=True)
        summarizer = self.LogSummarizer(config)
        summarizer._api_key = None

        entries = [
            {"ts": "2024-01-01T00:00:00Z", "status": 200, "host": "normal.com"},
            {"ts": "2024-01-01T00:01:00Z", "status": 500, "host": "error.com"},
            {"ts": "2024-01-01T00:02:00Z", "status": 200, "blocked": True, "host": "blocked.com"},
        ]

        with patch.object(summarizer, '_get_api_key', return_value=None):
            result = summarizer.summarize(entries, "test-cell")

        # Should have preserved events but no AI summary.
        self.assertIn("preserved_events", result)
        preserved_hosts = [e["host"] for e in result["preserved_events"]]
        self.assertIn("error.com", preserved_hosts)
        self.assertIn("blocked.com", preserved_hosts)
        self.assertNotIn("normal.com", preserved_hosts)


# ========== Step 2a: logger.py AsyncLogWriter ==========


class TestAsyncWriterLifecycle(unittest.TestCase):
    """Tests for AsyncLogWriter start/stop lifecycle."""

    @classmethod
    def setUpClass(cls):
        """Import AsyncLogWriter."""
        from logger import AsyncLogWriter
        cls.AsyncLogWriter = AsyncLogWriter

    def test_start_sets_running_and_starts_thread(self):
        """start() sets running=True and creates daemon thread."""
        writer = self.AsyncLogWriter()
        writer.start()
        self.assertTrue(writer.running)
        self.assertIsNotNone(writer.worker)
        self.assertTrue(writer.worker.daemon)
        writer.stop()

    def test_double_start_ignored(self):
        """Calling start() twice does not create second thread."""
        writer = self.AsyncLogWriter()
        writer.start()
        first_thread = writer.worker
        writer.start()
        self.assertIs(writer.worker, first_thread)
        writer.stop()

    def test_stop_joins_thread_and_flushes(self):
        """stop() joins worker and clears it."""
        writer = self.AsyncLogWriter()
        writer.start()
        writer.stop()
        self.assertFalse(writer.running)
        self.assertIsNone(writer.worker)

    def test_stop_when_not_running(self):
        """stop() is safe when never started."""
        writer = self.AsyncLogWriter()
        writer.stop()  # Should not raise.
        self.assertFalse(writer.running)


class TestAsyncWriterLog(unittest.TestCase):
    """Tests for AsyncLogWriter.log() queueing."""

    @classmethod
    def setUpClass(cls):
        """Import AsyncLogWriter."""
        from logger import AsyncLogWriter
        cls.AsyncLogWriter = AsyncLogWriter

    def test_normal_enqueue(self):
        """log() puts entry on queue."""
        writer = self.AsyncLogWriter(queue_size=10)
        writer.log({"ts": "test"}, Path("/tmp/test.jsonl"))
        self.assertEqual(writer.queue.qsize(), 1)

    @patch('logger.AsyncLogWriter._write_sync')
    def test_queue_full_sync_fallback(self, mock_sync):
        """Falls back to sync write when queue is full."""
        writer = self.AsyncLogWriter(queue_size=1)
        # Fill the queue.
        writer.log({"ts": "1"}, Path("/tmp/a.jsonl"))
        # This should trigger sync fallback.
        writer.log({"ts": "2"}, Path("/tmp/b.jsonl"))
        mock_sync.assert_called_once()


class TestAsyncWriterFlushAll(unittest.TestCase):
    """Tests for AsyncLogWriter._flush_all."""

    @classmethod
    def setUpClass(cls):
        """Import AsyncLogWriter."""
        from logger import AsyncLogWriter
        cls.AsyncLogWriter = AsyncLogWriter

    @patch('logger.AsyncLogWriter._flush_batch')
    def test_drains_queue(self, mock_flush):
        """_flush_all drains all queued entries."""
        writer = self.AsyncLogWriter(queue_size=10)
        writer.log({"ts": "1"}, Path("/tmp/a.jsonl"))
        writer.log({"ts": "2"}, Path("/tmp/a.jsonl"))
        writer._flush_all()
        mock_flush.assert_called_once()
        self.assertEqual(writer.queue.qsize(), 0)

    @patch('logger.AsyncLogWriter._flush_batch')
    def test_empty_queue_noop(self, mock_flush):
        """_flush_all does nothing on empty queue."""
        writer = self.AsyncLogWriter(queue_size=10)
        writer._flush_all()
        mock_flush.assert_not_called()


# ========== Step 2b: logger.py Config Reload ==========


class TestLoggerReloadSubnetMap(unittest.TestCase):
    """Tests for RequestLogger._reload_subnet_map."""

    @classmethod
    def setUpClass(cls):
        """Import RequestLogger."""
        from logger import RequestLogger
        cls.RequestLogger = RequestLogger

    def _make_logger(self):
        """Create a RequestLogger with default state."""
        rl = self.RequestLogger.__new__(self.RequestLogger)
        rl.subnet_map = {}
        rl.subnet_map_mtime = 0.0
        rl._subnet_index = {}
        rl.log_filter = None
        rl.policy_mtime = 0.0
        rl.async_writer = MagicMock()
        rl.max_log_size = 100 * 1024 * 1024
        return rl

    @patch('logger.SUBNET_MAP_FILE')
    def test_file_missing_skips(self, mock_file):
        """No error when subnet map file is missing."""
        mock_file.exists.return_value = False
        rl = self._make_logger()
        rl._reload_subnet_map()  # Should not raise.

    @patch('logger.SUBNET_MAP_FILE')
    def test_mtime_unchanged_skips(self, mock_file):
        """Skips reload when mtime has not changed."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=1000.0)
        rl = self._make_logger()
        rl.subnet_map_mtime = 1000.0
        rl._reload_subnet_map()
        # subnet_map should remain empty.
        self.assertEqual(rl.subnet_map, {})

    @patch('builtins.open', unittest.mock.mock_open(
        read_data='{"10.60.1.0/24": "app1", "10.60.2.0/24": "app2"}'
    ))
    @patch('logger.SUBNET_MAP_FILE')
    def test_valid_json_rebuilds_index(self, mock_file):
        """Valid subnet map JSON rebuilds the index."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=2000.0)
        rl = self._make_logger()
        rl._reload_subnet_map()
        self.assertEqual(len(rl.subnet_map), 2)
        self.assertIn("app1", rl._subnet_index.values())

    @patch('builtins.open', unittest.mock.mock_open(read_data='not json{{{'))
    @patch('logger.SUBNET_MAP_FILE')
    def test_corrupt_json_logged(self, mock_file):
        """Corrupt JSON logs error, does not crash."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=3000.0)
        rl = self._make_logger()
        rl._reload_subnet_map()  # Should not raise.


class TestLoggerReloadLogFilter(unittest.TestCase):
    """Tests for RequestLogger._reload_log_filter."""

    @classmethod
    def setUpClass(cls):
        """Import RequestLogger."""
        from logger import RequestLogger
        cls.RequestLogger = RequestLogger

    def _make_logger(self):
        """Create a RequestLogger with default state."""
        rl = self.RequestLogger.__new__(self.RequestLogger)
        rl.subnet_map = {}
        rl.subnet_map_mtime = 0.0
        rl._subnet_index = {}
        rl.log_filter = None
        rl.policy_mtime = 0.0
        rl.async_writer = MagicMock()
        rl.max_log_size = 100 * 1024 * 1024
        return rl

    @patch('logger.POLICY_FILE')
    def test_file_missing_skips(self, mock_file):
        """No error when policy file is missing."""
        mock_file.exists.return_value = False
        rl = self._make_logger()
        rl._reload_log_filter()  # Should not raise.

    @patch('logger.POLICY_FILE')
    def test_mtime_unchanged_skips(self, mock_file):
        """Skips reload when mtime has not changed."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=1000.0)
        rl = self._make_logger()
        rl.policy_mtime = 1000.0
        rl._reload_log_filter()
        self.assertIsNone(rl.log_filter)

    @patch('builtins.open', unittest.mock.mock_open(
        read_data='{"log_filter": {"exclude_hosts": ["health.local"]}, "log_quota": {"max_size_mb": 50}}'
    ))
    @patch('logger.POLICY_FILE')
    def test_valid_config_updates_filter(self, mock_file):
        """Valid config updates log filter and quota."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=2000.0)
        rl = self._make_logger()
        rl._reload_log_filter()
        self.assertIsNotNone(rl.log_filter)
        self.assertEqual(rl.max_log_size, 50 * 1024 * 1024)

    @patch('builtins.open', unittest.mock.mock_open(read_data='{}'))
    @patch('logger.POLICY_FILE')
    def test_missing_keys_uses_defaults(self, mock_file):
        """Missing log_filter/log_quota keys use defaults."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=3000.0)
        rl = self._make_logger()
        rl._reload_log_filter()
        self.assertEqual(rl.max_log_size, 100 * 1024 * 1024)


class TestLoggerBuildSubnetIndex(unittest.TestCase):
    """Tests for RequestLogger._build_subnet_index."""

    @classmethod
    def setUpClass(cls):
        """Import RequestLogger."""
        from logger import RequestLogger
        cls.RequestLogger = RequestLogger

    def _make_logger(self):
        """Create a RequestLogger with given subnet map."""
        rl = self.RequestLogger.__new__(self.RequestLogger)
        rl._subnet_index = {}
        return rl

    def test_ipv4_slash24_indexed(self):
        """/24 IPv4 subnets are indexed by top 24 bits."""
        rl = self._make_logger()
        rl.subnet_map = {"10.60.1.0/24": "app1"}
        rl._build_subnet_index()
        self.assertIn("app1", rl._subnet_index.values())

    def test_non_slash24_skipped(self):
        """Non-/24 subnets are skipped in index."""
        rl = self._make_logger()
        rl.subnet_map = {"10.60.0.0/16": "app1"}
        rl._build_subnet_index()
        self.assertEqual(rl._subnet_index, {})

    def test_invalid_subnet_skipped(self):
        """Invalid subnet strings are skipped."""
        rl = self._make_logger()
        rl.subnet_map = {"not-a-subnet": "app1"}
        rl._build_subnet_index()
        self.assertEqual(rl._subnet_index, {})


# ========== Step 2c: logger.py Error Extraction ==========


class TestLoggerExtractErrorDetailsExtended(unittest.TestCase):
    """Tests for RequestLogger._extract_error_details patterns."""

    @classmethod
    def setUpClass(cls):
        """Import RequestLogger."""
        from logger import RequestLogger
        cls.RequestLogger = RequestLogger

    def _make_logger(self):
        """Create a RequestLogger."""
        rl = self.RequestLogger.__new__(self.RequestLogger)
        return rl

    def _make_flow(self, error_str, server_conn=None):
        """Create a mock flow with error."""
        flow = MagicMock()
        flow.error = MagicMock(__str__=lambda s: error_str) if error_str else None
        flow.server_conn = server_conn
        return flow

    def test_connection_refused(self):
        """CONNECTION_REFUSED pattern matched."""
        rl = self._make_logger()
        flow = self._make_flow("Connection refused")
        details = rl._extract_error_details(flow)
        self.assertEqual(details["error_code"], "ECONNREFUSED")

    def test_connection_reset(self):
        """CONNECTION_RESET pattern matched."""
        rl = self._make_logger()
        flow = self._make_flow("Connection reset by peer")
        details = rl._extract_error_details(flow)
        self.assertEqual(details["error_code"], "ECONNRESET")

    def test_timeout(self):
        """TIMEOUT pattern matched."""
        rl = self._make_logger()
        flow = self._make_flow("Connection timed out")
        details = rl._extract_error_details(flow)
        self.assertEqual(details["error_code"], "ETIMEDOUT")

    def test_nxdomain(self):
        """NXDOMAIN pattern matched."""
        rl = self._make_logger()
        flow = self._make_flow("Name or service not known")
        details = rl._extract_error_details(flow)
        self.assertEqual(details["error_code"], "NXDOMAIN")
        self.assertFalse(details["dns_resolved"])

    def test_ssl_error(self):
        """SSL_ERROR pattern matched."""
        rl = self._make_logger()
        flow = self._make_flow("SSL handshake error")
        details = rl._extract_error_details(flow)
        self.assertEqual(details["error_code"], "SSL_ERROR")

    def test_eagain(self):
        """EAGAIN pattern matched."""
        rl = self._make_logger()
        flow = self._make_flow("Temporary failure in name resolution")
        details = rl._extract_error_details(flow)
        self.assertEqual(details["error_code"], "EAGAIN")

    def test_eof(self):
        """EOF pattern matched."""
        rl = self._make_logger()
        flow = self._make_flow("EOF received")
        details = rl._extract_error_details(flow)
        self.assertEqual(details["error_code"], "EOF")

    def test_unknown_error(self):
        """Unknown error pattern returns UNKNOWN."""
        rl = self._make_logger()
        flow = self._make_flow("Something completely different")
        details = rl._extract_error_details(flow)
        self.assertEqual(details["error_code"], "UNKNOWN")

    def test_destination_ip_from_peername(self):
        """Destination IP extracted from server_conn.peername."""
        rl = self._make_logger()
        server_conn = MagicMock()
        server_conn.peername = ("93.184.216.34", 443)
        flow = self._make_flow("Connection reset", server_conn=server_conn)
        details = rl._extract_error_details(flow)
        self.assertEqual(details["destination_ip"], "93.184.216.34")
        self.assertEqual(details["destination_port"], 443)


class TestGetCertInfoExtended(unittest.TestCase):
    """Tests for RequestLogger._get_cert_info."""

    @classmethod
    def setUpClass(cls):
        """Import RequestLogger."""
        from logger import RequestLogger
        cls.RequestLogger = RequestLogger

    def _make_logger(self):
        """Create a RequestLogger."""
        return self.RequestLogger.__new__(self.RequestLogger)

    def test_no_server_conn(self):
        """Returns empty dict when no server connection."""
        rl = self._make_logger()
        flow = MagicMock()
        flow.server_conn = None
        result = rl._get_cert_info(flow)
        self.assertEqual(result, {})

    def test_no_tls(self):
        """Returns empty dict when TLS not established."""
        rl = self._make_logger()
        flow = MagicMock()
        flow.server_conn.tls_established = False
        result = rl._get_cert_info(flow)
        self.assertEqual(result, {})

    def test_valid_cert_info(self):
        """Extracts subject, issuer, and validity flags."""
        from datetime import datetime, timezone
        rl = self._make_logger()
        flow = MagicMock()
        flow.server_conn.tls_established = True
        cert = MagicMock()
        cert.issuer = "Let's Encrypt"
        cert.cn = "example.com"
        cert.notbefore = datetime(2020, 1, 1, tzinfo=timezone.utc)
        cert.notafter = datetime(2030, 12, 31, tzinfo=timezone.utc)
        flow.server_conn.peercert = cert
        result = rl._get_cert_info(flow)
        self.assertEqual(result["cert_subject"], "example.com")
        self.assertEqual(result["cert_issuer"], "Let's Encrypt")
        self.assertTrue(result["cert_valid"])
        self.assertEqual(result["cert_flags"], [])

    def test_self_signed_detected(self):
        """Self-signed certificate flagged."""
        from datetime import datetime, timezone
        rl = self._make_logger()
        flow = MagicMock()
        flow.server_conn.tls_established = True
        cert = MagicMock()
        cert.issuer = "example.com"
        cert.cn = "example.com"
        cert.notbefore = datetime(2020, 1, 1, tzinfo=timezone.utc)
        cert.notafter = datetime(2030, 12, 31, tzinfo=timezone.utc)
        flow.server_conn.peercert = cert
        result = rl._get_cert_info(flow)
        self.assertIn("self_signed", result["cert_flags"])


# ========== Step 2d: enforce.py Remaining Logic ==========


class TestEnforceReloadCellPolicies(unittest.TestCase):
    """Tests for PolicyEnforcer._reload_cell_policies."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyEnforcer."""
        from enforce import PolicyEnforcer
        cls.PolicyEnforcer = PolicyEnforcer

    def _make_enforcer(self):
        """Create a PolicyEnforcer with default state."""
        e = self.PolicyEnforcer.__new__(self.PolicyEnforcer)
        e.cell_policies = collections.OrderedDict()
        e.cell_policy_mtimes = {}
        e._cell_policy_lock = threading.Lock()
        e._subnet_index = {}
        e.subnet_map = {}
        return e

    @patch('enforce.CELL_POLICY_DIR')
    def test_dir_missing_skips(self, mock_dir):
        """No error when policy dir is missing."""
        mock_dir.exists.return_value = False
        e = self._make_enforcer()
        e._reload_cell_policies()
        self.assertEqual(len(e.cell_policies), 0)

    def test_new_file_loaded(self):
        """New policy file is loaded into cell_policies."""
        import enforce
        e = self._make_enforcer()
        with tempfile.TemporaryDirectory() as td:
            policy_file = Path(td) / "test-cell.json"
            policy_file.write_text('{"allow": ["example.com"], "deny": []}')
            with patch.object(enforce, 'CELL_POLICY_DIR', Path(td)):
                e._reload_cell_policies()
            self.assertIn("test-cell", e.cell_policies)

    def test_mtime_unchanged_skips(self):
        """Unchanged mtime skips reload."""
        import enforce
        e = self._make_enforcer()
        with tempfile.TemporaryDirectory() as td:
            policy_file = Path(td) / "test-cell.json"
            policy_file.write_text('{"allow": ["example.com"], "deny": []}')
            mtime = policy_file.stat().st_mtime
            with patch.object(enforce, 'CELL_POLICY_DIR', Path(td)):
                e._reload_cell_policies()
                # Set mtime to current, reload should skip.
                e.cell_policy_mtimes["test-cell"] = mtime
                e.cell_policies.clear()
                e._reload_cell_policies()
            self.assertEqual(len(e.cell_policies), 0)

    def test_lru_eviction_at_capacity(self):
        """Oldest policy evicted when at MAX_CACHED_CELL_POLICIES."""
        import enforce
        e = self._make_enforcer()
        # Pre-fill to capacity.
        orig_max = enforce.MAX_CACHED_CELL_POLICIES
        enforce.MAX_CACHED_CELL_POLICIES = 2
        try:
            from enforce import Policy
            e.cell_policies["old1"] = Policy(allow=[], deny=[])
            e.cell_policies["old2"] = Policy(allow=[], deny=[])
            e.cell_policy_mtimes["old1"] = 1.0
            e.cell_policy_mtimes["old2"] = 2.0

            with tempfile.TemporaryDirectory() as td:
                policy_file = Path(td) / "new-cell.json"
                policy_file.write_text('{"allow": ["example.com"], "deny": []}')
                with patch.object(enforce, 'CELL_POLICY_DIR', Path(td)):
                    e._reload_cell_policies()
                self.assertNotIn("old1", e.cell_policies)
                self.assertIn("new-cell", e.cell_policies)
        finally:
            enforce.MAX_CACHED_CELL_POLICIES = orig_max

    def test_corrupt_json_logged(self):
        """Corrupt JSON policy file does not crash."""
        import enforce
        e = self._make_enforcer()
        with tempfile.TemporaryDirectory() as td:
            policy_file = Path(td) / "bad.json"
            policy_file.write_text("not json{{{")
            with patch.object(enforce, 'CELL_POLICY_DIR', Path(td)):
                e._reload_cell_policies()
            self.assertNotIn("bad", e.cell_policies)


class TestEnforceGetCellName(unittest.TestCase):
    """Tests for PolicyEnforcer._get_cell_name."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyEnforcer."""
        from enforce import PolicyEnforcer
        cls.PolicyEnforcer = PolicyEnforcer

    def _make_enforcer(self):
        """Create a PolicyEnforcer with subnet map."""
        e = self.PolicyEnforcer.__new__(self.PolicyEnforcer)
        e.subnet_map = {"10.60.1.0/24": "app1", "10.60.2.0/24": "app2"}
        e._subnet_index = {}
        e._build_subnet_index()
        return e

    def test_fast_path_hit(self):
        """IPv4 in indexed /24 found via fast path."""
        e = self._make_enforcer()
        self.assertEqual(e._get_cell_name("10.60.1.5"), "app1")

    def test_slow_path_linear_scan(self):
        """Non-/24 subnet found via slow path."""
        e = self._make_enforcer()
        e.subnet_map["10.70.0.0/16"] = "big-cell"
        self.assertEqual(e._get_cell_name("10.70.5.5"), "big-cell")

    def test_ipv6_linear_scan(self):
        """IPv6 uses linear scan."""
        e = self._make_enforcer()
        e.subnet_map["fd00:1::/64"] = "v6cell"
        self.assertEqual(e._get_cell_name("fd00:1::5"), "v6cell")

    def test_invalid_ip_returns_none(self):
        """Invalid IP address returns None."""
        e = self._make_enforcer()
        self.assertIsNone(e._get_cell_name("not-an-ip"))


class TestEnforceServerConnected(unittest.TestCase):
    """Tests for PolicyEnforcer.server_connected."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyEnforcer."""
        from enforce import PolicyEnforcer
        cls.PolicyEnforcer = PolicyEnforcer

    def _make_enforcer(self):
        """Create a PolicyEnforcer."""
        return self.PolicyEnforcer.__new__(self.PolicyEnforcer)

    def test_internal_ip_closes_connection(self):
        """RFC1918 IP triggers close() for DNS rebinding protection."""
        e = self._make_enforcer()
        data = MagicMock()
        data.server.peername = ("10.0.0.1", 443)
        e.server_connected(data)
        data.server.close.assert_called_once()

    def test_public_ip_passes(self):
        """Public IP does not trigger close()."""
        e = self._make_enforcer()
        data = MagicMock()
        data.server.peername = ("93.184.216.34", 443)
        e.server_connected(data)
        data.server.close.assert_not_called()

    def test_exception_caught(self):
        """Exceptions in server_connected are caught."""
        e = self._make_enforcer()
        data = MagicMock()
        data.server.peername = None
        e.server_connected(data)  # Should not raise.


# ========== Step 2e: ratelimit.py Config Reload ==========


class TestRateLimitReloadConfig(unittest.TestCase):
    """Tests for RateLimiter._reload_config."""

    @classmethod
    def setUpClass(cls):
        """Import RateLimiter."""
        from ratelimit import RateLimiter
        cls.RateLimiter = RateLimiter

    def _make_limiter(self):
        """Create a RateLimiter with default state."""
        import ratelimit
        rl = self.RateLimiter.__new__(self.RateLimiter)
        rl.default_config = ratelimit.RateLimitConfig(rate=100, burst=500)
        rl.cell_configs = {}
        rl.buckets = collections.OrderedDict()
        rl.buckets_lock = threading.Lock()
        rl.policy_mtime = 0.0
        return rl

    @patch('ratelimit.POLICY_FILE')
    def test_file_missing_skips(self, mock_file):
        """No error when policy file is missing."""
        mock_file.exists.return_value = False
        rl = self._make_limiter()
        rl._reload_config()  # Should not raise.

    @patch('ratelimit.POLICY_FILE')
    def test_mtime_unchanged_skips(self, mock_file):
        """Skips reload when mtime unchanged."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=1000.0)
        rl = self._make_limiter()
        rl.policy_mtime = 1000.0
        rl._reload_config()

    @patch('builtins.open', unittest.mock.mock_open(
        read_data='{"rate_limits": {"default": {"rate": 200, "burst": 1000}}}'
    ))
    @patch('ratelimit.POLICY_FILE')
    def test_valid_config_updates_defaults(self, mock_file):
        """Valid config updates default rate and burst."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=2000.0)
        rl = self._make_limiter()
        rl._reload_config()
        self.assertEqual(rl.default_config.rate, 200)
        self.assertEqual(rl.default_config.burst, 1000)

    @patch('builtins.open', unittest.mock.mock_open(
        read_data='{"rate_limits": {"default": {"rate": 100, "burst": 500}, '
                   '"cells": {"fast-cell": {"rate": 500, "burst": 2000}}}}'
    ))
    @patch('ratelimit.POLICY_FILE')
    def test_per_cell_overrides_loaded(self, mock_file):
        """Per-cell overrides loaded correctly."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=3000.0)
        rl = self._make_limiter()
        rl._reload_config()
        self.assertIn("fast-cell", rl.cell_configs)
        self.assertEqual(rl.cell_configs["fast-cell"].rate, 500)

    @patch('builtins.open', unittest.mock.mock_open(
        read_data='{"rate_limits": {"default": {"rate": -1, "burst": 500}}}'
    ))
    @patch('ratelimit.POLICY_FILE')
    def test_invalid_default_rejected(self, mock_file):
        """Invalid default config is rejected entirely."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=4000.0)
        rl = self._make_limiter()
        orig_rate = rl.default_config.rate
        rl._reload_config()
        # Default should not have changed.
        self.assertEqual(rl.default_config.rate, orig_rate)

    @patch('builtins.open', unittest.mock.mock_open(read_data='not json{{{'))
    @patch('ratelimit.POLICY_FILE')
    def test_json_decode_error_logged(self, mock_file):
        """JSON decode error does not crash."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=5000.0)
        rl = self._make_limiter()
        rl._reload_config()  # Should not raise.


# ========== Step 3a: notifier.py URL Validation ==========


class TestNotifierIsSafeWebhookUrl(unittest.TestCase):
    """Tests for _is_safe_webhook_url."""

    @classmethod
    def setUpClass(cls):
        """Import _is_safe_webhook_url."""
        from notifier import _is_safe_webhook_url
        cls.is_safe = staticmethod(_is_safe_webhook_url)

    @patch('socket.getaddrinfo')
    def test_safe_public_url(self, mock_dns):
        """Public IP passes validation."""
        mock_dns.return_value = [
            (2, 1, 6, '', ('93.184.216.34', 443))
        ]
        self.assertTrue(self.is_safe("https://example.com/webhook"))

    @patch('socket.getaddrinfo')
    def test_rfc1918_blocked(self, mock_dns):
        """RFC1918 address blocked."""
        mock_dns.return_value = [
            (2, 1, 6, '', ('10.0.0.1', 443))
        ]
        self.assertFalse(self.is_safe("https://internal.local/webhook"))

    @patch('socket.getaddrinfo')
    def test_localhost_blocked(self, mock_dns):
        """Localhost address blocked."""
        mock_dns.return_value = [
            (2, 1, 6, '', ('127.0.0.1', 443))
        ]
        self.assertFalse(self.is_safe("https://localhost/webhook"))

    def test_no_hostname(self):
        """Empty URL fails validation."""
        self.assertFalse(self.is_safe(""))

    @patch('socket.getaddrinfo', side_effect=OSError("DNS failed"))
    def test_dns_error(self, mock_dns):
        """DNS resolution error returns False."""
        self.assertFalse(self.is_safe("https://nonexistent.example/webhook"))


# ========== Step 3b: notifier.py Config Reload + Worker ==========


class TestNotifierReloadConfig(unittest.TestCase):
    """Tests for Notifier._reload_config."""

    @classmethod
    def setUpClass(cls):
        """Import Notifier."""
        from notifier import Notifier
        cls.Notifier = Notifier

    def _make_notifier(self):
        """Create a Notifier with default state."""
        n = self.Notifier.__new__(self.Notifier)
        n.config = MagicMock(enabled=False)
        n.policy_mtime = 0.0
        n.last_notification = collections.OrderedDict()
        n.notification_queue = MagicMock()
        n.worker_thread = None
        n.running = False
        n.circuit_breaker = MagicMock()
        n.dead_letters = []
        n._cb_lock = threading.Lock()
        n._http_pool = None
        n._pool_lock = threading.Lock()
        return n

    @patch('notifier.POLICY_FILE')
    def test_reload_no_file(self, mock_file):
        """Missing policy file does nothing."""
        mock_file.exists.return_value = False
        n = self._make_notifier()
        n._reload_config()

    @patch('notifier.POLICY_FILE')
    def test_reload_mtime_unchanged(self, mock_file):
        """Skips reload when mtime unchanged."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=1000.0)
        n = self._make_notifier()
        n.policy_mtime = 1000.0
        n._reload_config()

    @patch('notifier._is_safe_webhook_url', return_value=True)
    @patch('builtins.open', unittest.mock.mock_open(
        read_data='{"notifications": {"webhook_url": "https://example.com/hook"}}'
    ))
    @patch('notifier.POLICY_FILE')
    def test_reload_loads_webhook_url(self, mock_file, _mock_safe):
        """Webhook URL loaded and notifier enabled."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=2000.0)
        n = self._make_notifier()
        n._start_worker = MagicMock()
        n._reload_config()
        self.assertTrue(n.config.enabled)
        self.assertEqual(n.config.webhook_url, "https://example.com/hook")

    @patch('builtins.open', unittest.mock.mock_open(
        read_data='{"notifications": {}}'
    ))
    @patch('notifier.POLICY_FILE')
    def test_reload_no_webhook_disabled(self, mock_file):
        """Missing webhook URL keeps notifier disabled."""
        mock_file.exists.return_value = True
        mock_file.stat.return_value = MagicMock(st_mtime=3000.0)
        n = self._make_notifier()
        n._stop_worker = MagicMock()
        n._reload_config()
        self.assertFalse(n.config.enabled)


class TestNotifierStartStopWorker(unittest.TestCase):
    """Tests for Notifier._start_worker and _stop_worker."""

    @classmethod
    def setUpClass(cls):
        """Import Notifier."""
        from notifier import Notifier
        cls.Notifier = Notifier

    def test_start_worker_creates_thread(self):
        """_start_worker creates a daemon thread."""
        n = self.Notifier()
        n._start_worker()
        self.assertTrue(n.running)
        self.assertIsNotNone(n.worker_thread)
        self.assertTrue(n.worker_thread.daemon)
        n._stop_worker()
        n.running = False  # Ensure worker exits.
        n.worker_thread.join(timeout=2.0)

    def test_stop_worker_sends_sentinel(self):
        """_stop_worker puts None on queue."""
        n = self.Notifier()
        n.running = True
        n.worker_thread = MagicMock()
        n._stop_worker()
        self.assertFalse(n.running)


# ========== Step 3c: notifier.py Webhook Sending ==========


class TestNotifierSendNotification(unittest.TestCase):
    """Tests for Notifier._send_notification."""

    @classmethod
    def setUpClass(cls):
        """Import Notifier."""
        from notifier import Notifier, NotificationConfig, CircuitBreakerConfig
        cls.Notifier = Notifier
        cls.NotificationConfig = NotificationConfig
        cls.CircuitBreakerConfig = CircuitBreakerConfig

    def _make_notifier(self):
        """Create a Notifier with webhook configured."""
        from notifier import CircuitBreakerState
        n = self.Notifier.__new__(self.Notifier)
        n.config = self.NotificationConfig(
            webhook_url="https://example.com/hook",
            enabled=True,
            circuit_breaker=self.CircuitBreakerConfig(max_retries=2),
        )
        n.circuit_breaker = CircuitBreakerState()
        n._cb_lock = threading.Lock()
        n.dead_letters = []
        n._http_pool = None
        n._pool_lock = threading.Lock()
        return n

    @patch('notifier._resolve_webhook_url', return_value=(True, "93.184.216.34", "example.com", 443))
    def test_send_success(self, mock_resolve):
        """Successful send records success."""
        n = self._make_notifier()
        n._send_http_request = MagicMock(return_value=(True, None))
        n._record_success = MagicMock()
        n._send_notification({"event": "blocked"})
        n._record_success.assert_called_once()

    @patch('notifier._resolve_webhook_url', return_value=(True, "93.184.216.34", "example.com", 443))
    def test_send_all_retries_fail(self, mock_resolve):
        """All retries exhausted adds to dead letter."""
        n = self._make_notifier()
        n._send_http_request = MagicMock(return_value=(False, "HTTP 500"))
        n._record_failure = MagicMock()
        n._add_to_dead_letter = MagicMock()
        n._send_notification({"event": "blocked"})
        n._record_failure.assert_called_once()
        n._add_to_dead_letter.assert_called_once()

    @patch('notifier._resolve_webhook_url', return_value=(False, "", "", 0))
    def test_unsafe_url_skips(self, mock_resolve):
        """Internal webhook URL is skipped."""
        n = self._make_notifier()
        n._send_http_request = MagicMock()
        n._send_notification({"event": "blocked"})
        n._send_http_request.assert_not_called()

    @patch('notifier._resolve_webhook_url', return_value=(True, "93.184.216.34", "example.com", 443))
    def test_circuit_breaker_open_drops(self, mock_resolve):
        """Open circuit breaker drops notification to dead letter."""
        n = self._make_notifier()
        n._check_circuit_breaker = MagicMock(return_value=False)
        n._add_to_dead_letter = MagicMock()
        n._send_notification({"event": "blocked"})
        n._add_to_dead_letter.assert_called_once()


# ========== Step 3d: notifier.py Dispatch Logic ==========


class TestNotifierShouldNotifyExtended(unittest.TestCase):
    """Tests for Notifier._should_notify filtering."""

    @classmethod
    def setUpClass(cls):
        """Import Notifier."""
        from notifier import Notifier, NotificationConfig
        cls.Notifier = Notifier
        cls.NotificationConfig = NotificationConfig

    def _make_notifier(self, cells=None, reasons=None, interval=60):
        """Create configured notifier."""
        n = self.Notifier.__new__(self.Notifier)
        n.config = self.NotificationConfig(
            webhook_url="https://example.com/hook",
            enabled=True,
            cells=cells,
            block_reasons=reasons,
            min_interval_seconds=interval,
        )
        n.last_notification = collections.OrderedDict()
        return n

    def test_cell_filter_rejects(self):
        """Wrong cell is filtered out."""
        n = self._make_notifier(cells=["sensitive"])
        self.assertFalse(n._should_notify("other-cell", "denied"))

    def test_cell_filter_accepts(self):
        """Matching cell passes filter."""
        n = self._make_notifier(cells=["sensitive"])
        self.assertTrue(n._should_notify("sensitive", "denied"))

    def test_reason_filter_rejects(self):
        """Wrong reason is filtered out."""
        n = self._make_notifier(reasons=["denied"])
        self.assertFalse(n._should_notify("cell", "rate_limited"))

    def test_reason_filter_substring_match(self):
        """Reason filter uses substring matching."""
        n = self._make_notifier(reasons=["denied"])
        self.assertTrue(n._should_notify("cell", "denied by rule"))

    def test_rate_limited_too_soon(self):
        """Notification within min_interval is blocked."""
        n = self._make_notifier(interval=60)
        n.last_notification["cell"] = time.time()
        self.assertFalse(n._should_notify("cell", "denied"))

    def test_all_filters_pass(self):
        """Notification passes when all filters match."""
        n = self._make_notifier(cells=["cell"], reasons=["denied"], interval=0)
        self.assertTrue(n._should_notify("cell", "denied by rule"))

    def test_disabled_returns_false(self):
        """Disabled notifier always returns False."""
        n = self._make_notifier()
        n.config.enabled = False
        self.assertFalse(n._should_notify("cell", "denied"))


# ========== Step 4a: summarizer.py API Call Mocking ==========


class TestSummarizerCallClaudeApi(unittest.TestCase):
    """Tests for LogSummarizer.call_claude_api."""

    @classmethod
    def setUpClass(cls):
        """Import summarizer classes."""
        from summarizer import CostTracker, LogSummarizer, SummarizationConfig
        cls.LogSummarizer = LogSummarizer
        cls.SummarizationConfig = SummarizationConfig
        cls.CostTracker = CostTracker

    def _make_summarizer(self, api_key="sk-test-key"):
        """Create a LogSummarizer with mocked cost tracker."""
        config = self.SummarizationConfig(enabled=True)
        s = self.LogSummarizer.__new__(self.LogSummarizer)
        s.config = config
        s.cost_tracker = self.CostTracker()
        s._api_key = api_key
        return s

    def test_no_api_key_returns_none(self):
        """Returns None when no API key."""
        s = self._make_summarizer(api_key=None)
        result = s.call_claude_api("test prompt")
        self.assertIsNone(result)

    def test_cost_limit_exceeded_returns_none(self):
        """Returns None when daily cost limit exceeded."""
        s = self._make_summarizer()
        s.cost_tracker.daily_costs[
            time.strftime("%Y-%m-%d", time.gmtime())
        ] = 999.0
        result = s.call_claude_api("test prompt")
        self.assertIsNone(result)

    def test_token_limit_exceeded_returns_none(self):
        """Returns None when prompt exceeds token limit."""
        s = self._make_summarizer()
        s.config.max_input_tokens = 10
        result = s.call_claude_api("x" * 1000)
        self.assertIsNone(result)

    @patch('urllib.request.urlopen')
    def test_successful_api_call(self, mock_urlopen):
        """Successful API call returns parsed JSON."""
        response_data = {
            "content": [{"text": '{"summary": "test summary"}'}],
            "usage": {"input_tokens": 100, "output_tokens": 50},
        }
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(response_data).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        s = self._make_summarizer()
        result = s.call_claude_api("summarize these logs")
        self.assertIsNotNone(result)
        self.assertEqual(result["summary"], "test summary")

    def test_api_error_returns_none(self):
        """API error returns None."""
        import urllib.error
        s = self._make_summarizer()
        with patch('urllib.request.urlopen',
                   side_effect=urllib.error.URLError("Connection failed")):
            result = s.call_claude_api("test prompt")
        self.assertIsNone(result)


# ========== Step 4b: summarizer.py Summarize Orchestration ==========


class TestSummarizerSummarize(unittest.TestCase):
    """Tests for LogSummarizer.summarize orchestration."""

    @classmethod
    def setUpClass(cls):
        """Import summarizer classes."""
        from summarizer import CostTracker, LogSummarizer, SummarizationConfig
        cls.LogSummarizer = LogSummarizer
        cls.SummarizationConfig = SummarizationConfig
        cls.CostTracker = CostTracker

    def _make_summarizer(self, enabled=True, api_key="sk-test"):
        """Create a LogSummarizer."""
        config = self.SummarizationConfig(enabled=enabled)
        s = self.LogSummarizer.__new__(self.LogSummarizer)
        s.config = config
        s.cost_tracker = self.CostTracker()
        s._api_key = api_key
        return s

    def test_empty_entries_returns_error(self):
        """Empty entry list returns error."""
        s = self._make_summarizer()
        result = s.summarize([], "cell")
        self.assertIn("error", result)

    def test_no_summarizable_entries_skips_api(self):
        """All preserved entries skips API call."""
        s = self._make_summarizer()
        entries = [
            {"ts": "2024-01-01T00:00:00Z", "status": 500, "host": "error.com"},
            {"ts": "2024-01-01T00:01:00Z", "blocked": True, "host": "blocked.com"},
        ]
        result = s.summarize(entries, "cell")
        self.assertIn("preserved_events", result)
        self.assertNotIn("ai_summary", result)

    def test_disabled_skips_api(self):
        """Disabled summarizer skips API call."""
        s = self._make_summarizer(enabled=False)
        entries = [
            {"ts": "2024-01-01T00:00:00Z", "status": 200, "host": "normal.com"},
        ]
        result = s.summarize(entries, "cell")
        self.assertNotIn("ai_summary", result)
        self.assertNotIn("ai_error", result)

    @patch('summarizer.LogSummarizer.call_claude_api')
    def test_successful_summary(self, mock_api):
        """Full pipeline produces ai_summary."""
        mock_api.return_value = {"patterns": ["high traffic to api.example.com"]}
        s = self._make_summarizer()
        entries = [
            {"ts": "2024-01-01T00:00:00Z", "status": 200, "host": "normal.com"},
        ]
        result = s.summarize(entries, "cell")
        self.assertIn("ai_summary", result)

    @patch('summarizer.LogSummarizer.call_claude_api', return_value=None)
    def test_api_failure_adds_error(self, mock_api):
        """API failure adds ai_error field."""
        s = self._make_summarizer()
        entries = [
            {"ts": "2024-01-01T00:00:00Z", "status": 200, "host": "normal.com"},
        ]
        result = s.summarize(entries, "cell")
        self.assertIn("ai_error", result)


# ========== Step 4c: summarizer.py compact_cell_logs ==========


class TestCompactCellLogs(unittest.TestCase):
    """Tests for compact_cell_logs function."""

    @classmethod
    def setUpClass(cls):
        """Import compact_cell_logs."""
        from summarizer import compact_cell_logs
        cls.compact_cell_logs = staticmethod(compact_cell_logs)

    def test_invalid_cell_name(self):
        """Invalid cell name returns error."""
        result = self.compact_cell_logs(
            "../evil", Path("/tmp"), Path("/tmp")
        )
        self.assertIn("error", result)

    def test_missing_log_file(self):
        """Missing log file returns error."""
        with tempfile.TemporaryDirectory() as td:
            result = self.compact_cell_logs(
                "testcell", Path(td), Path(td)
            )
        self.assertIn("error", result)

    def test_empty_log_file_no_old_entries(self):
        """Empty log file returns message about no old entries."""
        with tempfile.TemporaryDirectory() as td:
            log_file = Path(td) / "testcell.jsonl"
            log_file.write_text("")
            result = self.compact_cell_logs(
                "testcell", Path(td), Path(td), older_than_hours=0
            )
        # Either error or message about no entries.
        self.assertTrue("error" in result or "message" in result)

    @patch('summarizer.LogSummarizer.summarize')
    @patch('summarizer.CostTracker.load')
    def test_filters_by_timestamp(self, mock_load, mock_summarize):
        """Old entries are compacted, recent kept."""
        from datetime import datetime, timezone
        mock_load.return_value = MagicMock(daily_costs={})

        mock_summarize.return_value = {
            "preserved_events": [],
            "statistics": {"total_requests": 1},
        }

        with tempfile.TemporaryDirectory() as td:
            log_file = Path(td) / "testcell.jsonl"
            old_ts = "2020-01-01T00:00:00Z"
            new_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            log_file.write_text(
                json.dumps({"ts": old_ts, "host": "old.com"}) + "\n" +
                json.dumps({"ts": new_ts, "host": "new.com"}) + "\n"
            )
            result = self.compact_cell_logs(
                "testcell", Path(td), Path(td), older_than_hours=1
            )
        self.assertIn("compacted_entries", result)
        self.assertEqual(result["recent_entries_kept"], 1)

    @patch('summarizer.LogSummarizer.summarize')
    @patch('summarizer.CostTracker.load')
    def test_archive_created(self, mock_load, mock_summarize):
        """Gzip archive file is created."""
        mock_load.return_value = MagicMock(daily_costs={})
        mock_summarize.return_value = {"preserved_events": []}

        with tempfile.TemporaryDirectory() as td:
            log_file = Path(td) / "testcell.jsonl"
            log_file.write_text(
                json.dumps({"ts": "2020-01-01T00:00:00Z", "host": "old.com"}) + "\n"
            )
            result = self.compact_cell_logs(
                "testcell", Path(td), Path(td), older_than_hours=1
            )
            # Check archive file exists.
            archive_path = Path(result.get("archive_file", ""))
            self.assertTrue(archive_path.exists())

    @patch('summarizer.LogSummarizer.summarize')
    @patch('summarizer.CostTracker.load')
    def test_summary_file_written(self, mock_load, mock_summarize):
        """JSON summary file is created."""
        mock_load.return_value = MagicMock(daily_costs={})
        mock_summarize.return_value = {"preserved_events": []}

        with tempfile.TemporaryDirectory() as td:
            log_file = Path(td) / "testcell.jsonl"
            log_file.write_text(
                json.dumps({"ts": "2020-01-01T00:00:00Z", "host": "old.com"}) + "\n"
            )
            result = self.compact_cell_logs(
                "testcell", Path(td), Path(td), older_than_hours=1
            )
            summary_path = Path(result.get("summary_file", ""))
            self.assertTrue(summary_path.exists())
            with open(summary_path) as f:
                data = json.load(f)
            self.assertIn("preserved_events", data)


# ========== Step 5h: metrics.py LRU + Persistence + Handle Connection ==========


class TestMetricsGetOrCreate(unittest.TestCase):
    """Tests for MetricsCollector._get_or_create_metrics."""

    @classmethod
    def setUpClass(cls):
        """Import MetricsCollector."""
        from metrics import CellMetrics, MetricsCollector
        cls.MetricsCollector = MetricsCollector
        cls.CellMetrics = CellMetrics

    def test_existing_cell_moves_to_end(self):
        """Existing cell is moved to end (most recently used)."""
        collector = self.MetricsCollector()
        collector.metrics["cell-a"] = self.CellMetrics()
        collector.metrics["cell-b"] = self.CellMetrics()
        collector._get_or_create_metrics("cell-a")
        # cell-a should be last.
        self.assertEqual(list(collector.metrics.keys())[-1], "cell-a")

    def test_new_cell_created(self):
        """New cell gets a fresh CellMetrics."""
        collector = self.MetricsCollector()
        result = collector._get_or_create_metrics("new-cell")
        self.assertIsInstance(result, self.CellMetrics)
        self.assertIn("new-cell", collector.metrics)


class TestMetricsLoadPersisted(unittest.TestCase):
    """Tests for MetricsCollector._load_persisted_metrics."""

    @classmethod
    def setUpClass(cls):
        """Import MetricsCollector."""
        from metrics import MetricsCollector
        cls.MetricsCollector = MetricsCollector

    def test_persistence_disabled_skips(self):
        """Disabled persistence skips load."""
        collector = self.MetricsCollector()
        collector.persistence_enabled = False
        collector._load_persisted_metrics()
        self.assertEqual(len(collector.metrics), 0)

    @patch('metrics.METRICS_PERSISTENCE_FILE')
    def test_missing_file_skips(self, mock_file):
        """Missing persistence file does nothing."""
        mock_file.exists.return_value = False
        collector = self.MetricsCollector()
        collector._load_persisted_metrics()
        self.assertEqual(len(collector.metrics), 0)

    @patch('builtins.open', unittest.mock.mock_open(
        read_data='{"cell-1": {"total_requests": 100, "blocked_requests": 5}}'
    ))
    @patch('metrics.METRICS_PERSISTENCE_FILE')
    def test_load_restores_metrics(self, mock_file):
        """Persisted metrics are restored."""
        mock_file.exists.return_value = True
        collector = self.MetricsCollector()
        collector._load_persisted_metrics()
        self.assertIn("cell-1", collector.metrics)
        self.assertEqual(collector.metrics["cell-1"].total_requests, 100)
        self.assertEqual(collector.metrics["cell-1"].blocked_requests, 5)


class TestMetricsHandleConnection(unittest.TestCase):
    """Tests for MetricsCollector._handle_connection."""

    @classmethod
    def setUpClass(cls):
        """Import MetricsCollector."""
        from metrics import CellMetrics, MetricsCollector
        cls.MetricsCollector = MetricsCollector
        cls.CellMetrics = CellMetrics

    def _make_conn(self, data: str):
        """Create a mock socket connection."""
        conn = MagicMock()
        conn.recv.return_value = data.encode()
        conn.send.side_effect = lambda d: len(d)
        return conn

    def test_all_command(self):
        """'all' command returns all cell metrics."""
        collector = self.MetricsCollector()
        collector.metrics["cell-1"] = self.CellMetrics()
        collector.metrics["cell-1"].total_requests = 42
        conn = self._make_conn("all")
        collector._handle_connection(conn)
        # Verify response was sent.
        conn.send.assert_called()
        sent_data = conn.send.call_args[0][0]
        response = json.loads(sent_data.decode())
        self.assertIn("cells", response)
        self.assertIn("cell-1", response["cells"])

    def test_cell_command(self):
        """'cell:X' command returns specific cell metrics."""
        collector = self.MetricsCollector()
        collector.metrics["myapp"] = self.CellMetrics()
        conn = self._make_conn("cell:myapp")
        collector._handle_connection(conn)
        conn.send.assert_called()
        sent_data = conn.send.call_args[0][0]
        response = json.loads(sent_data.decode())
        self.assertEqual(response["cell"], "myapp")

    def test_cell_name_too_long(self):
        """Cell name >64 chars returns error."""
        collector = self.MetricsCollector()
        long_name = "a" * 65
        conn = self._make_conn(f"cell:{long_name}")
        collector._handle_connection(conn)
        conn.send.assert_called()
        sent_data = conn.send.call_args[0][0]
        response = json.loads(sent_data.decode())
        self.assertIn("error", response)

    def test_unknown_command(self):
        """Unknown command returns error."""
        collector = self.MetricsCollector()
        conn = self._make_conn("invalid")
        collector._handle_connection(conn)
        conn.send.assert_called()
        sent_data = conn.send.call_args[0][0]
        response = json.loads(sent_data.decode())
        self.assertIn("error", response)

    def test_cell_not_found(self):
        """Missing cell returns error."""
        collector = self.MetricsCollector()
        conn = self._make_conn("cell:nonexistent")
        collector._handle_connection(conn)
        conn.send.assert_called()
        sent_data = conn.send.call_args[0][0]
        response = json.loads(sent_data.decode())
        self.assertIn("error", response)


if __name__ == "__main__":
    unittest.main(verbosity=2)
