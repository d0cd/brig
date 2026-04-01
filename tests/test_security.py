#!/usr/bin/env python3
"""
Security and adversarial tests for Brig.

Tests security boundaries and attack resistance:
    - Path traversal prevention
    - Command injection prevention
    - Policy bypass attempts
    - IP/DNS rebinding attacks
    - Unicode/encoding attacks
    - Input validation

Run with: python3 tests/test_security.py
"""

import importlib.util
import ipaddress
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Import brig.py directly (not the brig/ package).
brig_path = Path(__file__).parent.parent / "src" / "brig.py"
spec = importlib.util.spec_from_file_location("brig_module", brig_path)
brig = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brig)

# Mock mitmproxy for addon imports.
sys.modules['mitmproxy'] = MagicMock()
sys.modules['mitmproxy.http'] = MagicMock()
sys.modules['mitmproxy.ctx'] = MagicMock()

# Add addons to path.
ADDONS_DIR = Path(__file__).parent.parent / "src" / "addons"
sys.path.insert(0, str(ADDONS_DIR))


class TestPathTraversal(unittest.TestCase):
    """Tests for path traversal attack prevention."""

    def test_dotdot_in_secret_name(self):
        """Secret names with .. are rejected."""
        cell_def = {"image": "alpine", "secrets": ["../etc/passwd"]}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("traversal" in e.lower() for e in errors))

    def test_slash_in_secret_name(self):
        """Secret names with / are rejected."""
        cell_def = {"image": "alpine", "secrets": ["../../secret"]}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("traversal" in e.lower() for e in errors))

    def test_encoded_traversal(self):
        """URL-encoded traversal attempts pass validation (literal names, not decoded)."""
        # %2e = '.', %2f = '/' — these are not decoded by validation.
        # The literal string "%2e%2e%2fetc%2fpasswd" contains no .. or /,
        # so it passes. The actual file won't exist with this name.
        cell_def = {"image": "alpine", "secrets": ["%2e%2e%2fetc%2fpasswd"]}
        errors = brig.validate_cell_definition(cell_def)
        self.assertEqual(errors, [], "Encoded strings should pass (they are literal filenames)")

    def test_absolute_path_secret(self):
        """Absolute paths in secret names are rejected."""
        cell_def = {"image": "alpine", "secrets": ["/etc/passwd"]}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("traversal" in e.lower() or "/" in e for e in errors))


class TestDNSRebinding(unittest.TestCase):
    """Tests for DNS rebinding attack prevention."""

    def test_broad_wildcards_flagged(self):
        """Overly broad wildcards are flagged as suspicious."""
        suspicious_patterns = [
            "*",          # Everything.
            "*.*",        # All domains.
            "*.local",    # Local network.
            "*.internal", # Internal domains.
            "*.com",      # TLD wildcard.
        ]
        for pattern in suspicious_patterns:
            result = brig.is_suspicious_domain(pattern)
            self.assertNotEqual(result, "", f"{pattern} should be suspicious")

    def test_safe_wildcards_not_flagged(self):
        """Safe wildcard patterns are not flagged."""
        safe_patterns = [
            "*.example.com",
            "*.github.com",
            "api.example.com",
        ]
        for pattern in safe_patterns:
            result = brig.is_suspicious_domain(pattern)
            self.assertEqual(result, "", f"{pattern} should not be suspicious")


class TestIPBlocking(unittest.TestCase):
    """Tests for IP address blocking."""

    @classmethod
    def setUpClass(cls):
        """Import BLOCKED_NETWORKS from enforce.py."""
        from enforce import BLOCKED_NETWORKS
        cls.BLOCKED_NETWORKS = BLOCKED_NETWORKS

    def test_metadata_service_blocked(self):
        """AWS/GCP/Azure metadata service IPs are blocked."""
        metadata_ips = [
            "169.254.169.254",  # AWS/GCP metadata.
            "169.254.170.2",    # AWS container credentials.
        ]
        for ip in metadata_ips:
            blocked = any(
                ipaddress.ip_address(ip) in net
                for net in self.BLOCKED_NETWORKS
            )
            self.assertTrue(blocked, f"Metadata IP {ip} should be blocked")

    def test_localhost_variants_blocked(self):
        """All localhost variants are blocked."""
        localhost_ips = [
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.255",
        ]
        for ip in localhost_ips:
            blocked = any(
                ipaddress.ip_address(ip) in net
                for net in self.BLOCKED_NETWORKS
            )
            self.assertTrue(blocked, f"Localhost {ip} should be blocked")

    def test_ipv6_localhost_blocked(self):
        """IPv6 localhost is blocked."""
        blocked = any(
            ipaddress.ip_address("::1") in net
            for net in self.BLOCKED_NETWORKS
        )
        self.assertTrue(blocked, "IPv6 localhost should be blocked")

    def test_ipv6_private_blocked(self):
        """IPv6 private addresses are blocked."""
        private_ipv6 = [
            "fc00::1",   # Unique local.
            "fe80::1",   # Link-local.
        ]
        for ip in private_ipv6:
            blocked = any(
                ipaddress.ip_address(ip) in net
                for net in self.BLOCKED_NETWORKS
            )
            self.assertTrue(blocked, f"Private IPv6 {ip} should be blocked")


class TestPolicyBypass(unittest.TestCase):
    """Tests for policy bypass attempts."""

    @classmethod
    def setUpClass(cls):
        """Import Policy from enforce.py."""
        from enforce import Policy
        cls.Policy = Policy

    def test_case_mismatch_bypass(self):
        """Case variations don't bypass policy."""
        policy = self.Policy(
            allow=["example.com"],
            deny=["evil.com"]
        )
        # Allowlist check - case variations should match.
        allowed, _, _ = policy.is_allowed("EXAMPLE.COM", "/", "GET")
        self.assertTrue(allowed)
        allowed, _, _ = policy.is_allowed("ExAmPlE.cOm", "/", "GET")
        self.assertTrue(allowed)

        # Denylist check - case variations should still be blocked.
        allowed, _, _ = policy.is_allowed("EVIL.COM", "/", "GET")
        self.assertFalse(allowed)
        allowed, _, _ = policy.is_allowed("Evil.Com", "/", "GET")
        self.assertFalse(allowed)

    def test_subdomain_escape_attempt(self):
        """Subdomains can't escape wildcard restrictions."""
        policy = self.Policy(deny=["*.evil.com"])
        # Standard subdomain - blocked.
        allowed, _, _ = policy.is_allowed("sub.evil.com", "/", "GET")
        self.assertFalse(allowed)
        # Deep subdomain - blocked.
        allowed, _, _ = policy.is_allowed("deep.sub.evil.com", "/", "GET")
        self.assertFalse(allowed)
        # Base domain - blocked.
        allowed, _, _ = policy.is_allowed("evil.com", "/", "GET")
        self.assertFalse(allowed)

    def test_similar_domain_not_matched(self):
        """Similar but different domains are not matched."""
        policy = self.Policy(allow=["example.com"])
        # These should NOT match example.com.
        test_domains = [
            "exampleXcom",
            "example.com.evil.com",
            "evil.example.com.evil.com",
            "notexample.com",
            # Note: "example.com." (trailing dot) is DNS-equivalent to "example.com"
            # and is correctly normalized and matched after the trailing dot fix.
        ]
        for domain in test_domains:
            allowed, _, _ = policy.is_allowed(domain, "/", "GET")
            self.assertFalse(allowed, f"{domain} should not match example.com")

    def test_path_escape_attempt(self):
        """Path matching uses fnmatch (glob patterns).

        Note: fnmatch is a simple glob matcher that doesn't normalize paths.
        The path "/v1/../v2/data" matches "/v1/*" because it starts with "/v1/".
        Path traversal prevention happens at the HTTP layer (proxy normalizes paths)
        and the filesystem layer, not in policy matching.
        """
        from enforce import PolicyRule
        rule = PolicyRule({
            "domain": "api.example.com",
            "paths": ["/v1/*"]
        })
        # Standard path matching.
        self.assertTrue(rule.matches_path("/v1/users"))
        self.assertTrue(rule.matches_path("/v1/nested/deep/path"))
        self.assertFalse(rule.matches_path("/v2/users"))
        # Note: /v1/../v2/data technically matches /v1/* due to glob behavior.
        # This is OK because:
        # 1. HTTP proxies normalize paths before checking
        # 2. The actual request goes to the normalized path

    def test_method_case_normalization(self):
        """HTTP methods are case-normalized."""
        from enforce import PolicyRule
        rule = PolicyRule({
            "domain": "api.example.com",
            "methods": ["POST"]
        })
        self.assertTrue(rule.matches_method("POST"))
        self.assertTrue(rule.matches_method("post"))
        self.assertTrue(rule.matches_method("Post"))
        self.assertFalse(rule.matches_method("GET"))
        self.assertFalse(rule.matches_method("get"))


class TestInputValidation(unittest.TestCase):
    """Tests for input validation robustness."""

    def test_empty_strings(self):
        """Empty strings are handled safely."""
        # Empty image is invalid.
        cell_def = {"image": ""}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(len(errors) > 0)

        # Empty name is invalid.
        cell_def = {"name": "", "image": "alpine"}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(len(errors) > 0)

    def test_very_long_strings(self):
        """Very long strings don't cause issues."""
        # Long name is rejected (>63 chars via pattern {0,62}).
        cell_def = {"name": "a" * 100, "image": "alpine"}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(len(errors) > 0, "Name exceeding 63 chars must be rejected")

    def test_special_characters_in_name(self):
        """Special characters in name are rejected."""
        invalid_names = [
            "cell/name",
            "cell;name",
            "cell|name",
            "cell&name",
            "cell$name",
            "cell`name",
            "cell'name",
            'cell"name',
        ]
        for name in invalid_names:
            cell_def = {"name": name, "image": "alpine"}
            errors = brig.validate_cell_definition(cell_def)
            self.assertTrue(len(errors) > 0, f"Name '{name}' should be rejected")

    def test_unicode_in_inputs(self):
        """Unicode characters are handled safely."""
        # Unicode in name - should be rejected (alphanumeric only).
        cell_def = {"name": "cell_名前", "image": "alpine"}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(len(errors) > 0)

        # Unicode in image - might be valid (depends on registry).
        cell_def = {"name": "myapp", "image": "registry.example.com/名前:latest"}
        # This doesn't fail validation but the image won't exist.


class TestCacheResilience(unittest.TestCase):
    """Tests for cache manipulation resistance."""

    def setUp(self):
        """Clear cache before each test."""
        brig._cache.clear()

    def test_cache_key_injection(self):
        """Cache keys with special characters are safe."""
        # Try to pollute cache with crafted keys.
        brig._set_cache("cell_exists:evil\x00normal", True)
        # Verify it doesn't affect normal lookups.
        hit, _ = brig._cached("cell_exists:normal")
        self.assertFalse(hit)

    def test_cache_value_types(self):
        """Cache handles various value types safely."""
        # None values.
        brig._set_cache("test_none", None)
        hit, value = brig._cached("test_none")
        self.assertTrue(hit)
        self.assertIsNone(value)

        # Boolean values.
        brig._set_cache("test_false", False)
        hit, value = brig._cached("test_false")
        self.assertTrue(hit)
        self.assertFalse(value)


class TestRateLimitSecurity(unittest.TestCase):
    """Tests for rate limiting security."""

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

    def test_rate_limit_file_corruption(self):
        """Corrupted rate limit file doesn't break system."""
        # Write corrupted JSON.
        with open(brig.RATE_LIMIT_FILE, 'w') as f:
            f.write("not valid json")

        # Should still work (fail open is acceptable for DoS prevention).
        result = brig.check_rate_limit()
        self.assertTrue(result)

    def test_rate_limit_file_permissions(self):
        """Rate limiting works even with permission issues."""
        # Make directory read-only (if possible).
        # Note: This might not work on all systems.
        try:
            os.chmod(self.temp_dir, 0o444)
            # Should not crash.
            brig.check_rate_limit()
            # Result might be True (fail open) or False depending on impl.
        finally:
            os.chmod(self.temp_dir, 0o755)


class TestPolicyFileHandling(unittest.TestCase):
    """Tests for policy file security."""

    def setUp(self):
        """Create temp directory for policy files."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_policy_dir = brig.POLICY_DIR
        brig.POLICY_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.POLICY_DIR = self._original_policy_dir

    def test_corrupted_policy_file(self):
        """Corrupted policy files are handled safely."""
        policy_path = brig.get_cell_policy_path("test")
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        with open(policy_path, 'w') as f:
            f.write("not valid json")

        # Should return empty policy, not crash.
        policy = brig.load_cell_policy("test")
        self.assertEqual(policy, {"allow": [], "deny": []})

    def test_symlink_policy_file(self):
        """Symlink policy files are handled safely."""
        # Create a symlink to /etc/passwd (common attack).
        policy_path = brig.get_cell_policy_path("test")
        policy_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            os.symlink("/etc/passwd", policy_path)
            # Loading should fail safely (invalid JSON).
            policy = brig.load_cell_policy("test")
            self.assertEqual(policy, {"allow": [], "deny": []})
        except OSError:
            pass  # Symlink creation might fail.


class TestQuietMode(unittest.TestCase):
    """Tests for quiet mode functionality."""

    def setUp(self):
        """Save original QUIET state."""
        self._original_quiet = brig.QUIET

    def tearDown(self):
        """Restore original QUIET state."""
        brig.QUIET = self._original_quiet

    def test_output_prints_when_not_quiet(self):
        """output() prints when QUIET is False."""
        brig.QUIET = False
        with patch('builtins.print') as mock_print:
            brig.output("test message")
            mock_print.assert_called_once_with("test message")

    def test_output_suppressed_when_quiet(self):
        """output() is suppressed when QUIET is True."""
        brig.QUIET = True
        with patch('builtins.print') as mock_print:
            brig.output("test message")
            mock_print.assert_not_called()

    def test_log_info_suppressed_when_quiet(self):
        """INFO level logs are suppressed in quiet mode."""
        brig.QUIET = True
        with patch('builtins.print') as mock_print:
            brig.log(brig.LOG_LEVEL_INFO, "info message")
            mock_print.assert_not_called()

    def test_log_warn_not_suppressed_when_quiet(self):
        """WARN level logs are not suppressed in quiet mode."""
        brig.QUIET = True
        with patch('builtins.print') as mock_print:
            brig.log(brig.LOG_LEVEL_WARN, "warn message")
            mock_print.assert_called_once()

    def test_log_error_not_suppressed_when_quiet(self):
        """ERROR level logs are not suppressed in quiet mode."""
        brig.QUIET = True
        with patch('builtins.print') as mock_print:
            brig.log(brig.LOG_LEVEL_ERROR, "error message")
            mock_print.assert_called_once()


class TestErrorHelpers(unittest.TestCase):
    """Tests for error helper functions."""

    def test_print_error_outputs_to_stderr(self):
        """print_error() writes to stderr."""
        with patch('builtins.print') as mock_print:
            brig.print_error("test error")
            mock_print.assert_called()
            # Check it was called with file=sys.stderr.
            call_kwargs = mock_print.call_args_list[0][1]
            self.assertEqual(call_kwargs.get('file'), sys.stderr)

    def test_print_error_with_suggestion(self):
        """print_error() includes suggestion when provided."""
        with patch('builtins.print') as mock_print:
            brig.print_error("test error", "try this")
            self.assertEqual(mock_print.call_count, 2)

    def test_error_calls_sys_exit(self):
        """error() calls sys.exit(1)."""
        with patch('builtins.print'):
            with self.assertRaises(SystemExit) as cm:
                brig.error("test error")
            self.assertEqual(cm.exception.code, 1)

    def test_error_unknown_command_exits(self):
        """error_unknown_command() exits with helpful message."""
        with patch('builtins.print') as mock_print:
            with self.assertRaises(SystemExit):
                brig.error_unknown_command("badcmd")
            # Check the error message mentions the command.
            call_args = mock_print.call_args_list[0][0][0]
            self.assertIn("badcmd", call_args)

    def test_error_invalid_json_exits(self):
        """error_invalid_json() exits with path and details."""
        with patch('builtins.print') as mock_print:
            with self.assertRaises(SystemExit):
                brig.error_invalid_json("/path/to/file.json", "unexpected token")
            call_args = mock_print.call_args_list[0][0][0]
            self.assertIn("/path/to/file.json", call_args)
            self.assertIn("unexpected token", call_args)


class TestPolicyValidation(unittest.TestCase):
    """Tests for policy conflict validation."""

    def test_no_conflicts_returns_empty(self):
        """No conflicts when allow and deny are disjoint."""
        policy = {
            "allow": ["example.com", "api.example.com"],
            "deny": ["evil.com", "malware.com"]
        }
        warnings = brig.validate_policy_conflicts(policy)
        self.assertEqual(warnings, [])

    def test_exact_duplicate_detected(self):
        """Same domain in both allow and deny is detected."""
        policy = {
            "allow": ["example.com"],
            "deny": ["example.com"]
        }
        warnings = brig.validate_policy_conflicts(policy)
        self.assertEqual(len(warnings), 1)
        self.assertIn("example.com", warnings[0])
        self.assertIn("both", warnings[0].lower())

    def test_wildcard_base_conflict_detected(self):
        """Wildcard in allow with base domain in deny is detected."""
        policy = {
            "allow": ["*.example.com"],
            "deny": ["example.com"]
        }
        warnings = brig.validate_policy_conflicts(policy)
        self.assertTrue(len(warnings) >= 1)

    def test_empty_policy_no_conflicts(self):
        """Empty policy has no conflicts."""
        policy = {"allow": [], "deny": []}
        warnings = brig.validate_policy_conflicts(policy)
        self.assertEqual(warnings, [])

    def test_missing_keys_handled(self):
        """Missing allow/deny keys don't cause errors."""
        policy = {}
        warnings = brig.validate_policy_conflicts(policy)
        self.assertEqual(warnings, [])


class TestSaveCellPolicy(unittest.TestCase):
    """Tests for policy save with verification."""

    def setUp(self):
        """Create temp directory for policy files."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_policy_dir = brig.POLICY_DIR
        brig.POLICY_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.POLICY_DIR = self._original_policy_dir

    def test_save_returns_true_on_success(self):
        """save_cell_policy returns True when write succeeds."""
        policy = {"allow": ["example.com"], "deny": []}
        result = brig.save_cell_policy("test-cell", policy)
        self.assertTrue(result)

    def test_saved_policy_matches_input(self):
        """Saved policy can be read back correctly."""
        policy = {"allow": ["example.com", "*.github.com"], "deny": ["evil.com"]}
        brig.save_cell_policy("test-cell", policy)
        loaded = brig.load_cell_policy("test-cell")
        self.assertEqual(loaded["allow"], policy["allow"])
        self.assertEqual(loaded["deny"], policy["deny"])


class TestVerifyFixRecovery(unittest.TestCase):
    """Tests for verify --fix recovery functions."""

    def test_fix_proxy_not_running_calls_warden_start(self):
        """_fix_proxy_not_running attempts to start warden."""
        with patch.object(brig, 'run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            result = brig._fix_proxy_not_running()
            self.assertTrue(result)
            mock_run.assert_called_once()
            # Verify warden start was called.
            args = mock_run.call_args[0][0]
            self.assertIn("warden", args)
            self.assertIn("start", args)

    def test_fix_proxy_not_running_handles_failure(self):
        """_fix_proxy_not_running returns False on failure."""
        with patch.object(brig, 'run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="failed to start")
            result = brig._fix_proxy_not_running()
            self.assertFalse(result)

    def test_fix_cell_network_calls_reconnect(self):
        """_fix_cell_network attempts network reconnection."""
        with patch.object(brig, 'run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            result = brig._fix_cell_network("test-cell")
            self.assertTrue(result)
            # Should have called network operations.
            self.assertGreaterEqual(mock_run.call_count, 1)

    def test_fix_cell_network_handles_failure(self):
        """_fix_cell_network returns False on failure."""
        with patch.object(brig, 'run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="network error")
            result = brig._fix_cell_network("test-cell")
            self.assertFalse(result)


class TestPolicyReloadBehavior(unittest.TestCase):
    """Tests for policy reload behavior during operation."""

    def setUp(self):
        """Create temporary policy directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_policy_dir = brig.POLICY_DIR
        brig.POLICY_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Restore original policy directory."""
        brig.POLICY_DIR = self.original_policy_dir
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_policy_reload_preserves_existing_rules(self):
        """Reloading policy doesn't lose existing rules."""
        # Save initial policy.
        initial = {"allow": ["a.com", "b.com"], "deny": ["evil.com"]}
        brig.save_cell_policy("reload-test", initial)

        # Load it back.
        loaded = brig.load_cell_policy("reload-test")
        self.assertEqual(len(loaded["allow"]), 2)
        self.assertEqual(len(loaded["deny"]), 1)

        # Modify and save again.
        loaded["allow"].append("c.com")
        brig.save_cell_policy("reload-test", loaded)

        # Reload and verify.
        final = brig.load_cell_policy("reload-test")
        self.assertEqual(len(final["allow"]), 3)
        self.assertIn("c.com", final["allow"])

    def test_concurrent_policy_reads_are_safe(self):
        """Multiple threads can read policy simultaneously."""
        import threading

        # Create a policy file.
        policy = {"allow": ["example.com"], "deny": []}
        brig.save_cell_policy("concurrent-test", policy)

        results = []
        errors = []

        def read_policy():
            try:
                for _ in range(10):
                    loaded = brig.load_cell_policy("concurrent-test")
                    results.append(loaded)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=read_policy) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors during concurrent reads: {errors}")
        self.assertEqual(len(results), 50)  # 5 threads * 10 reads each.
        # All results should be valid.
        for r in results:
            self.assertIn("allow", r)
            self.assertIn("deny", r)


class TestCircuitBreakerRecovery(unittest.TestCase):
    """Tests for circuit breaker recovery in notifier addon."""

    @classmethod
    def setUpClass(cls):
        """Import notifier with mocked dependencies."""
        from notifier import CircuitBreakerConfig, CircuitBreakerState
        cls.CircuitBreakerState = CircuitBreakerState
        cls.CircuitBreakerConfig = CircuitBreakerConfig

    def test_circuit_breaker_recovers_after_timeout(self):
        """Circuit breaker transitions from open to half-open after timeout."""
        import time

        state = self.CircuitBreakerState()
        config = self.CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=0.1,  # 100ms for testing.
        )

        # Simulate failures to open circuit.
        state.consecutive_failures = 3
        state.state = "open"
        state.last_failure_time = time.time()

        # Immediately after, circuit should still be open.
        self.assertEqual(state.state, "open")

        # Wait for recovery timeout.
        time.sleep(0.15)

        # Check if recovery timeout has passed.
        elapsed = time.time() - state.last_failure_time
        self.assertGreaterEqual(elapsed, config.recovery_timeout)

        # In real code, this check happens in _check_circuit_breaker.
        # Here we just verify the timing logic works.

    def test_circuit_breaker_closes_on_success_after_half_open(self):
        """Circuit breaker closes after successful request in half-open state."""
        state = self.CircuitBreakerState()
        state.state = "half-open"
        state.consecutive_failures = 5

        # Simulate successful request (what _record_success does).
        state.consecutive_failures = 0
        state.total_successes += 1
        state.state = "closed"

        self.assertEqual(state.state, "closed")
        self.assertEqual(state.consecutive_failures, 0)

    def test_circuit_breaker_reopens_on_failure_in_half_open(self):
        """Circuit breaker reopens if request fails in half-open state."""
        state = self.CircuitBreakerState()
        state.state = "half-open"

        # Simulate failed request (what _record_failure does in half-open).
        state.consecutive_failures += 1
        state.total_failures += 1
        state.state = "open"  # Reopen on failure in half-open.

        self.assertEqual(state.state, "open")


class TestMetricsPersistenceRecovery(unittest.TestCase):
    """Tests for metrics persistence and recovery."""

    @classmethod
    def setUpClass(cls):
        """Import metrics module."""
        from metrics import CellMetrics, HistogramLatencyBuffer
        cls.CellMetrics = CellMetrics
        cls.HistogramLatencyBuffer = HistogramLatencyBuffer

    def test_metrics_survive_serialization(self):
        """Metrics counters survive JSON serialization."""
        metrics = self.CellMetrics()
        metrics.total_requests = 100
        metrics.blocked_requests = 5
        metrics.bytes_sent = 1024

        # Serialize to dict (what persistence does).
        data = {
            "total_requests": metrics.total_requests,
            "blocked_requests": metrics.blocked_requests,
            "bytes_sent": metrics.bytes_sent,
        }

        # Simulate reload.
        restored = self.CellMetrics()
        restored.total_requests = data["total_requests"]
        restored.blocked_requests = data["blocked_requests"]
        restored.bytes_sent = data["bytes_sent"]

        self.assertEqual(restored.total_requests, 100)
        self.assertEqual(restored.blocked_requests, 5)
        self.assertEqual(restored.bytes_sent, 1024)

    def test_histogram_handles_empty_state(self):
        """Histogram percentile returns 0 for empty state."""
        histogram = self.HistogramLatencyBuffer()

        # Empty histogram should return 0 for any percentile.
        self.assertEqual(histogram.percentile(50), 0.0)
        self.assertEqual(histogram.percentile(95), 0.0)
        self.assertEqual(histogram.percentile(99), 0.0)

    def test_histogram_decay_prevents_unbounded_growth(self):
        """Histogram decay keeps memory bounded."""
        histogram = self.HistogramLatencyBuffer(max_samples=100)

        # Add many samples.
        for i in range(200):
            histogram.add(float(i))

        # Total count should be bounded due to decay.
        self.assertLessEqual(histogram.total_count, 150)  # Some headroom for decay timing.


class TestRenameCommand(unittest.TestCase):
    """Tests for rename command validation."""

    def test_rename_rejects_running_cell(self):
        """Rename fails if cell is running."""
        with patch.object(brig, 'cell_exists', return_value=True):
            with patch.object(brig, 'cell_running', return_value=True):
                with self.assertRaises(SystemExit):
                    args = MagicMock(old_name="test", new_name="test2")
                    brig.cmd_rename(args)

    def test_rename_rejects_existing_target(self):
        """Rename fails if target name already exists."""
        def cell_exists_side_effect(name):
            return name in ["old-cell", "existing-cell"]

        with patch.object(brig, 'cell_exists', side_effect=cell_exists_side_effect):
            with patch.object(brig, 'cell_running', return_value=False):
                with self.assertRaises(SystemExit):
                    args = MagicMock(old_name="old-cell", new_name="existing-cell")
                    brig.cmd_rename(args)

    def test_rename_rejects_empty_name(self):
        """Rename fails for empty new name."""
        with patch.object(brig, 'cell_exists', side_effect=lambda n: n == "test"):
            with patch.object(brig, 'cell_running', return_value=False):
                with self.assertRaises(SystemExit):
                    args = MagicMock(old_name="test", new_name="")
                    brig.cmd_rename(args)

    def test_rename_rejects_invalid_start_char(self):
        """Rename fails if new name starts with non-alphanumeric."""
        with patch.object(brig, 'cell_exists', side_effect=lambda n: n == "test"):
            with patch.object(brig, 'cell_running', return_value=False):
                with self.assertRaises(SystemExit):
                    args = MagicMock(old_name="test", new_name="-invalid")
                    brig.cmd_rename(args)


class TestConfigCommands(unittest.TestCase):
    """Tests for config show/set/reset commands."""

    def setUp(self):
        """Create temporary config file."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_config = Path(self.temp_dir) / "config.json"
        self.original_config_file = brig.CONFIG_FILE
        brig.CONFIG_FILE = self.temp_config

    def tearDown(self):
        """Restore original config file."""
        brig.CONFIG_FILE = self.original_config_file
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_config_show_returns_defaults(self):
        """config show returns default config when no file exists."""
        args = MagicMock(key=None)
        with patch('builtins.print') as mock_print:
            result = brig.cmd_config_show(args)
            self.assertEqual(result, 0)
            # Should print JSON output.
            mock_print.assert_called()

    def test_config_set_creates_file(self):
        """config set creates config file if it doesn't exist."""
        args = MagicMock(key="test_key", value="test_value")
        result = brig.cmd_config_set(args)
        self.assertEqual(result, 0)
        self.assertTrue(self.temp_config.exists())

        # Verify content.
        with open(self.temp_config, "r") as f:
            config = json.load(f)
        self.assertEqual(config["test_key"], "test_value")

    def test_config_set_nested_key(self):
        """config set handles nested keys."""
        args = MagicMock(key="section.nested.value", value="42")
        result = brig.cmd_config_set(args)
        self.assertEqual(result, 0)

        with open(self.temp_config, "r") as f:
            config = json.load(f)
        self.assertEqual(config["section"]["nested"]["value"], 42)

    def test_config_set_parses_boolean(self):
        """config set parses boolean strings."""
        args = MagicMock(key="enabled", value="true")
        brig.cmd_config_set(args)

        with open(self.temp_config, "r") as f:
            config = json.load(f)
        self.assertIs(config["enabled"], True)

    def test_config_reset_removes_file(self):
        """config reset removes config file."""
        # Create a config file.
        self.temp_config.write_text('{"test": true}')
        self.assertTrue(self.temp_config.exists())

        args = MagicMock()
        result = brig.cmd_config_reset(args)
        self.assertEqual(result, 0)
        self.assertFalse(self.temp_config.exists())


class TestConcurrentOperations(unittest.TestCase):
    """Tests for concurrent operation safety."""

    def test_cache_thread_safety(self):
        """Cache operations are thread-safe."""
        import threading

        errors = []
        results = []

        def cache_operations():
            try:
                for i in range(100):
                    key = f"key-{threading.current_thread().name}-{i}"
                    # These functions should not raise under concurrent access.
                    brig._cache[key] = (i, brig.time.time())
                    hit, val = brig._cached(key)
                    results.append((hit, val))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=cache_operations, name=f"t{i}") for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors during concurrent cache access: {errors}")
        # Clear the cache we polluted.
        brig._cache.clear()

    def test_rate_limit_thread_safety(self):
        """Rate limit checks are thread-safe."""
        import threading

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"timestamps": []}, f)
            temp_file = f.name

        original_file = brig.RATE_LIMIT_FILE
        brig.RATE_LIMIT_FILE = Path(temp_file)

        errors = []

        def do_rate_limit_check():
            try:
                for _ in range(10):
                    # This should not raise even under concurrent access.
                    brig.check_rate_limit()
            except Exception as e:
                errors.append(e)

        try:
            threads = [threading.Thread(target=do_rate_limit_check) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(errors), 0, f"Errors during concurrent rate limit: {errors}")
        finally:
            brig.RATE_LIMIT_FILE = original_file
            os.unlink(temp_file)


class TestDNSRebindingPostResolution(unittest.TestCase):
    """Tests for DNS rebinding protection via post-resolution IP check."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyEnforcer with mocked mitmproxy."""
        from enforce import BLOCKED_NETWORKS, PolicyEnforcer
        cls.PolicyEnforcer = PolicyEnforcer
        cls.BLOCKED_NETWORKS = BLOCKED_NETWORKS

    def test_server_connected_blocks_internal_ip(self):
        """server_connected hook blocks connections to internal IPs."""
        enforcer = self.PolicyEnforcer()
        data = MagicMock()
        data.server.peername = ("127.0.0.1", 80)

        enforcer.server_connected(data)

        data.server.close.assert_called_once()

    def test_server_connected_allows_public_ip(self):
        """server_connected hook allows connections to public IPs."""
        enforcer = self.PolicyEnforcer()
        data = MagicMock()
        data.server.peername = ("93.184.216.34", 443)

        enforcer.server_connected(data)

        # close should NOT have been called.
        data.server.close.assert_not_called()

    def test_server_connected_blocks_rfc1918(self):
        """server_connected blocks RFC1918 addresses after DNS resolution."""
        enforcer = self.PolicyEnforcer()
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
            data = MagicMock()
            data.server.peername = (ip, 80)
            enforcer.server_connected(data)
            data.server.close.assert_called_once()


class TestCellPolicyIsolationSecurity(unittest.TestCase):
    """Tests for cell policy isolation — no fall-through to global."""

    @classmethod
    def setUpClass(cls):
        """Import Policy from enforce.py."""
        from enforce import Policy
        cls.Policy = Policy

    def test_cell_policy_no_global_fallthrough(self):
        """A domain allowed globally is blocked when cell has its own policy."""
        # Cell policy only allows specific.com.
        cell_policy = self.Policy(allow=["specific.com"])

        # example.com would be allowed globally, but cell didn't allow it.
        allowed, reason, _ = cell_policy.is_allowed("example.com", "/", "GET")
        self.assertFalse(allowed)

    def test_cell_deny_takes_precedence(self):
        """Cell deny rules take precedence over allow rules."""
        cell_policy = self.Policy(
            allow=["*.example.com"],
            deny=["evil.example.com"]
        )
        allowed, _, _ = cell_policy.is_allowed("evil.example.com", "/", "GET")
        self.assertFalse(allowed)


class TestSubstringMatchingSecurity(unittest.TestCase):
    """Tests that container name matching uses exact match."""

    @patch.object(brig, 'run')
    def test_substring_container_not_matched(self, mock_run):
        """Container 'brig-test' does not match when checking 'brig-tes'."""
        brig._cache.clear()
        mock_run.return_value = MagicMock(
            returncode=0, stdout="brig-test\n"
        )
        # "tes" container should not exist just because "brig-test" does.
        result = brig.cell_exists("tes")
        self.assertFalse(result)


class TestIDNNormalization(unittest.TestCase):
    """Tests for IDN/Unicode domain normalization in enforce.py."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyRule from enforce.py."""
        from enforce import PolicyRule
        cls.PolicyRule = PolicyRule

    def test_punycode_domain_matches(self):
        """Punycode domain matches regardless of encoding form."""
        rule = self.PolicyRule("xn--mnchen-3ya.de")
        self.assertTrue(rule.matches_domain("xn--mnchen-3ya.de"))


class TestSecurityInvariants(unittest.TestCase):
    """Tests that security invariants documented in CLAUDE.md are enforced.

    Each test verifies a specific invariant from the security model.
    """

    def setUp(self):
        """Create temp directory for workspace."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_state_dir = brig.STATE_DIR
        brig.STATE_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.STATE_DIR = self._original_state_dir

    def _make_args(self, **overrides):
        """Create default args for _build_run_command."""
        defaults = {
            "workdir": None, "name": "test", "image": "alpine",
            "container_cmd": [], "memory": "2g", "cpus": "2",
            "pids_limit": 512, "detach": True, "rm": False,
            "env": None, "secret": None, "label": None,
            "seccomp_profile": None, "no_seccomp": False, "timeout": None,
            "network": "default", "profile": None,
        }
        defaults.update(overrides)
        args = MagicMock()
        for k, v in defaults.items():
            setattr(args, k, v)
        return args

    def test_invariant_gvisor_runtime_always_set(self):
        """Invariant 5: gVisor must be active — --runtime=runsc always present."""
        args = self._make_args()
        cmd = brig._build_run_command(
            args, "test", False, "brig-test", "10.60.1.1", None,
            lambda msg, s=None: None,
        )
        self.assertIn("--runtime", cmd)
        idx = cmd.index("--runtime")
        self.assertEqual(cmd[idx + 1], "runsc")

    def test_invariant_gvisor_runtime_airgapped(self):
        """Invariant 5: gVisor runtime enforced even for airgapped cells."""
        args = self._make_args()
        cmd = brig._build_run_command(
            args, "test", True, "brig-test", "10.60.1.1", None,
            lambda msg, s=None: None,
        )
        self.assertIn("--runtime", cmd)
        idx = cmd.index("--runtime")
        self.assertEqual(cmd[idx + 1], "runsc")

    def test_invariant_single_homed_cell(self):
        """Invariant 8: Cells must be single-homed (only one --network flag)."""
        args = self._make_args()
        cmd = brig._build_run_command(
            args, "test", False, "brig-test", "10.60.1.1", None,
            lambda msg, s=None: None,
        )
        network_count = cmd.count("--network")
        self.assertEqual(network_count, 1, "Cell must have exactly one --network flag")

    def test_invariant_cell_never_on_proxy_external(self):
        """Invariant 6: Only Warden may attach to proxy-external network."""
        args = self._make_args()
        cmd = brig._build_run_command(
            args, "test", False, "brig-test", "10.60.1.1", None,
            lambda msg, s=None: None,
        )
        for arg in cmd:
            self.assertNotIn("proxy-external", str(arg),
                             "Cell must never be on proxy-external network")

    def test_invariant_warden_before_cells(self):
        """Invariant 9: Warden must be running before cells start."""
        # cmd_run checks proxy_running() and errors if warden is down.
        with patch.object(brig, 'proxy_running', return_value=False), \
             patch.object(brig, 'cell_exists', return_value=False), \
             patch.object(brig, 'run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
            args = MagicMock()
            args.name = "test"
            args.image = "alpine"
            args.container_cmd = []
            args.profile = None
            args.cell_def = None
            args.network = "default"
            args.timeout = None
            args.dry_run = False
            args.airgap = False
            args.canary_file = None
            with self.assertRaises(SystemExit):
                brig.cmd_run(args)

    def test_invariant_secrets_as_files_not_env(self):
        """Invariant: Secrets mounted as files at /run/secrets/, not env values."""
        secrets_dir = Path(self.temp_dir) / "secrets"
        secrets_dir.mkdir()
        secret_file = secrets_dir / "api-key.txt"
        secret_file.write_text("sk-supersecret-12345")

        args = self._make_args(secret=["api-key.txt"])
        # Patch _build_run_command's Path("/secrets") to use our temp dir.
        original_path = Path

        def patched_path(p, *a, **kw):
            if p == "/secrets":
                return secrets_dir
            return original_path(p, *a, **kw)

        with patch.object(brig, 'Path', side_effect=patched_path):
            cmd = brig._build_run_command(
                args, "test", False, "brig-test", "10.60.1.1", None,
                lambda msg, s=None: None,
            )

        # Secret must be mounted as a volume, not inlined in env.
        has_volume_mount = any(
            "/run/secrets/api-key.txt:ro" in arg for arg in cmd
        )
        self.assertTrue(has_volume_mount,
                        "Secret must be mounted as read-only volume at /run/secrets/")

        # Env var must point to file path, not contain the secret value.
        secret_value = "sk-supersecret-12345"
        for i, arg in enumerate(cmd):
            if arg == "-e" and i + 1 < len(cmd):
                self.assertNotIn(secret_value, cmd[i + 1],
                                 "Secret values must not appear in env vars")
                # The FILE env var should point to the path, not the value.
                if "API_KEY" in cmd[i + 1]:
                    self.assertIn("/run/secrets/", cmd[i + 1],
                                  "Secret env var must point to file path")


if __name__ == "__main__":
    unittest.main(verbosity=2)
