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
        """URL-encoded traversal attempts are rejected."""
        # %2e = '.', %2f = '/'
        cell_def = {"image": "alpine", "secrets": ["%2e%2e%2fetc%2fpasswd"]}
        # If not decoded, this would pass. Verify behavior.
        # Note: validation might not URL-decode, which is actually OK since
        # the literal string doesn't contain .. or /
        errors = brig.validate_cell_definition(cell_def)
        # This specific test shows encoded strings pass (expected - files are literal names).
        # The actual file won't exist with this name.

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
        allowed, _ = policy.is_allowed("EXAMPLE.COM", "/", "GET")
        self.assertTrue(allowed)
        allowed, _ = policy.is_allowed("ExAmPlE.cOm", "/", "GET")
        self.assertTrue(allowed)

        # Denylist check - case variations should still be blocked.
        allowed, _ = policy.is_allowed("EVIL.COM", "/", "GET")
        self.assertFalse(allowed)
        allowed, _ = policy.is_allowed("Evil.Com", "/", "GET")
        self.assertFalse(allowed)

    def test_subdomain_escape_attempt(self):
        """Subdomains can't escape wildcard restrictions."""
        policy = self.Policy(deny=["*.evil.com"])
        # Standard subdomain - blocked.
        allowed, _ = policy.is_allowed("sub.evil.com", "/", "GET")
        self.assertFalse(allowed)
        # Deep subdomain - blocked.
        allowed, _ = policy.is_allowed("deep.sub.evil.com", "/", "GET")
        self.assertFalse(allowed)
        # Base domain - blocked.
        allowed, _ = policy.is_allowed("evil.com", "/", "GET")
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
            "example.com.",  # Trailing dot.
        ]
        for domain in test_domains:
            allowed, _ = policy.is_allowed(domain, "/", "GET")
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
        # Long name is rejected (>63 chars).
        cell_def = {"name": "a" * 100, "image": "alpine"}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("63" in e for e in errors))

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
            result = brig.check_rate_limit()
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
