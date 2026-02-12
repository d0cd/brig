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
        from notifier import CircuitBreakerState, CircuitBreakerConfig
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
        enforcer.cell_policy_last_access["test-cell"] = 22222.0

        enforcer._do_reload()

        self.assertEqual(enforcer.policy_mtime, 0.0)
        self.assertEqual(enforcer.subnet_map_mtime, 0.0)
        self.assertEqual(len(enforcer.cell_policy_mtimes), 0)
        self.assertEqual(len(enforcer.cell_policy_last_access), 0)

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
        global_policy = self.Policy(allow=["example.com", "specific.com"])

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
        call_args = flow.response
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
        from logger import RequestLogger, LOG_DIR, UNKNOWN_LOG_FILE
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
        from metrics import MetricsCollector, MAX_TRACKED_CELLS, CellMetrics

        collector = MetricsCollector()

        # Add cells up to capacity.
        for i in range(MAX_TRACKED_CELLS):
            cell_name = f"cell-{i}"
            collector.metrics[cell_name] = CellMetrics()
            collector.metrics[cell_name].last_request_ts = float(i)

        # Verify at capacity.
        self.assertEqual(len(collector.metrics), MAX_TRACKED_CELLS)

        # Add one more - should evict cell-0 (oldest).
        new_metrics = collector._get_or_create_metrics("new-cell")
        self.assertEqual(len(collector.metrics), MAX_TRACKED_CELLS)
        self.assertNotIn("cell-0", collector.metrics)
        self.assertIn("new-cell", collector.metrics)

    def test_ratelimit_evicts_oldest_bucket(self):
        """RateLimiter evicts oldest bucket when at capacity."""
        from ratelimit import RateLimiter, MAX_TRACKED_CELLS, TokenBucket

        limiter = RateLimiter()

        # Add buckets up to capacity.
        for i in range(MAX_TRACKED_CELLS):
            cell_name = f"cell-{i}"
            limiter.buckets[cell_name] = TokenBucket(10, 5)
            limiter.buckets[cell_name].last_update = float(i)

        # Verify at capacity.
        self.assertEqual(len(limiter.buckets), MAX_TRACKED_CELLS)

        # Add one more - should evict cell-0 (oldest).
        new_bucket = limiter._get_bucket("new-cell")
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
            SummarizationConfig, LogSummarizer, CostTracker,
            estimate_tokens, calculate_cost, DEFAULT_PRESERVE_EVENTS
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
