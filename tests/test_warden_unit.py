#!/usr/bin/env python3
"""
Unit tests for Warden components.

Tests the Python logic without requiring mitmproxy or the VM.
Run with: python3 -m pytest tests/test_warden_unit.py -v

Or without pytest:
    python3 tests/test_warden_unit.py
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Add src to path for imports.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestPolicyMatching(unittest.TestCase):
    """Tests for policy domain/path/method matching logic."""

    def test_exact_domain_match(self):
        """Exact domain matches."""
        from warden import _matches_domain
        self.assertTrue(_matches_domain("example.com", "example.com"))
        self.assertFalse(_matches_domain("example.com", "other.com"))
        self.assertFalse(_matches_domain("example.com", "sub.example.com"))

    def test_wildcard_domain_match(self):
        """Wildcard domain patterns match subdomains."""
        from warden import _matches_domain
        self.assertTrue(_matches_domain("*.example.com", "sub.example.com"))
        self.assertTrue(_matches_domain("*.example.com", "deep.sub.example.com"))
        self.assertTrue(_matches_domain("*.example.com", "example.com"))
        self.assertFalse(_matches_domain("*.example.com", "other.com"))
        self.assertFalse(_matches_domain("*.example.com", "exampleXcom"))

    def test_case_insensitive_match(self):
        """Domain matching is case insensitive."""
        from warden import _matches_domain
        self.assertTrue(_matches_domain("Example.COM", "example.com"))
        self.assertTrue(_matches_domain("*.GITHUB.com", "api.github.COM"))

    def test_string_rule_matching(self):
        """String rules match by domain only."""
        from warden import _matches_rule
        self.assertTrue(_matches_rule("example.com", "example.com", "/any/path", "GET"))
        self.assertTrue(_matches_rule("example.com", "example.com", "/", "POST"))
        self.assertFalse(_matches_rule("example.com", "other.com", "/", "GET"))

    def test_dict_rule_with_paths(self):
        """Dict rules can restrict by path."""
        from warden import _matches_rule
        rule = {"domain": "api.example.com", "paths": ["/v1/*", "/v2/*"]}
        self.assertTrue(_matches_rule(rule, "api.example.com", "/v1/users", "GET"))
        self.assertTrue(_matches_rule(rule, "api.example.com", "/v2/data", "POST"))
        self.assertFalse(_matches_rule(rule, "api.example.com", "/v3/other", "GET"))
        self.assertFalse(_matches_rule(rule, "other.com", "/v1/users", "GET"))

    def test_dict_rule_with_methods(self):
        """Dict rules can restrict by method."""
        from warden import _matches_rule
        rule = {"domain": "api.example.com", "methods": ["GET", "POST"]}
        self.assertTrue(_matches_rule(rule, "api.example.com", "/", "GET"))
        self.assertTrue(_matches_rule(rule, "api.example.com", "/", "POST"))
        self.assertFalse(_matches_rule(rule, "api.example.com", "/", "DELETE"))

    def test_dict_rule_with_paths_and_methods(self):
        """Dict rules can combine path and method restrictions."""
        from warden import _matches_rule
        rule = {"domain": "api.example.com", "paths": ["/v1/*"], "methods": ["POST"]}
        self.assertTrue(_matches_rule(rule, "api.example.com", "/v1/create", "POST"))
        self.assertFalse(_matches_rule(rule, "api.example.com", "/v1/create", "GET"))
        self.assertFalse(_matches_rule(rule, "api.example.com", "/v2/create", "POST"))


class TestPolicyValidation(unittest.TestCase):
    """Tests for policy validation logic."""

    def test_validate_string_rule(self):
        """String rules are validated."""
        from warden import _validate_rule
        self.assertEqual(_validate_rule("example.com", "allow[0]"), [])
        self.assertEqual(_validate_rule("*.github.com", "allow[1]"), [])
        errors = _validate_rule("", "allow[2]")
        self.assertTrue(len(errors) > 0)

    def test_validate_dict_rule_valid(self):
        """Valid dict rules pass validation."""
        from warden import _validate_rule
        rule = {"domain": "api.example.com", "paths": ["/v1/*"], "methods": ["GET"]}
        self.assertEqual(_validate_rule(rule, "allow[0]"), [])

    def test_validate_dict_rule_missing_domain(self):
        """Dict rules require domain field."""
        from warden import _validate_rule
        rule = {"paths": ["/v1/*"]}
        errors = _validate_rule(rule, "allow[0]")
        self.assertTrue(any("domain" in e for e in errors))

    def test_validate_dict_rule_invalid_method(self):
        """Dict rules validate HTTP methods."""
        from warden import _validate_rule
        rule = {"domain": "example.com", "methods": ["INVALID"]}
        errors = _validate_rule(rule, "allow[0]")
        self.assertTrue(any("INVALID" in e for e in errors))

    def test_validate_invalid_rule_type(self):
        """Invalid rule types are rejected."""
        from warden import _validate_rule
        errors = _validate_rule(123, "allow[0]")
        self.assertTrue(len(errors) > 0)


class TestPolicyFile(unittest.TestCase):
    """Tests for policy file loading and validation."""

    def test_cmd_policy_validate_valid(self):
        """Valid policy file passes validation."""
        from warden import cmd_policy_validate

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": ["example.com", "*.github.com"],
                "deny": ["evil.com"]
            }, f)
            f.flush()

            try:
                # Should return 0 for valid policy.
                result = cmd_policy_validate(f.name)
                self.assertEqual(result, 0)
            finally:
                os.unlink(f.name)

    def test_cmd_policy_validate_invalid_json(self):
        """Invalid JSON fails validation."""
        from warden import cmd_policy_validate

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json")
            f.flush()

            try:
                result = cmd_policy_validate(f.name)
                self.assertEqual(result, 1)
            finally:
                os.unlink(f.name)

    def test_cmd_policy_validate_missing_file(self):
        """Missing file fails validation."""
        from warden import cmd_policy_validate
        result = cmd_policy_validate("/nonexistent/file.json")
        self.assertEqual(result, 1)


class TestPolicyTest(unittest.TestCase):
    """Tests for policy test command."""

    def setUp(self):
        """Create a test policy file."""
        self.policy_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        json.dump({
            "allow": [
                "example.com",
                "*.github.com",
                {"domain": "api.openai.com", "paths": ["/v1/*"], "methods": ["POST"]}
            ],
            "deny": ["evil.com"]
        }, self.policy_file)
        self.policy_file.flush()
        self.policy_file.close()

        # Patch POLICY_FILE to use our test file.
        import warden
        self._original_policy_file = warden.POLICY_FILE
        warden.POLICY_FILE = Path(self.policy_file.name)

    def tearDown(self):
        """Clean up test policy file."""
        import warden
        warden.POLICY_FILE = self._original_policy_file
        os.unlink(self.policy_file.name)

    def test_allowed_domain(self):
        """Allowed domains return 0."""
        from warden import cmd_policy_test
        result = cmd_policy_test("example.com")
        self.assertEqual(result, 0)

    def test_wildcard_subdomain(self):
        """Wildcard subdomains are allowed."""
        from warden import cmd_policy_test
        result = cmd_policy_test("api.github.com")
        self.assertEqual(result, 0)

    def test_denied_domain(self):
        """Denied domains return 1."""
        from warden import cmd_policy_test
        result = cmd_policy_test("evil.com")
        self.assertEqual(result, 1)

    def test_unlisted_domain(self):
        """Unlisted domains are blocked (default deny)."""
        from warden import cmd_policy_test
        result = cmd_policy_test("random-domain.com")
        self.assertEqual(result, 1)

    def test_path_restriction(self):
        """Path restrictions are enforced."""
        from warden import cmd_policy_test
        # Allowed path.
        result = cmd_policy_test("api.openai.com", "/v1/completions", "POST")
        self.assertEqual(result, 0)
        # Disallowed path.
        result = cmd_policy_test("api.openai.com", "/v2/other", "POST")
        self.assertEqual(result, 1)

    def test_method_restriction(self):
        """Method restrictions are enforced."""
        from warden import cmd_policy_test
        # Allowed method.
        result = cmd_policy_test("api.openai.com", "/v1/completions", "POST")
        self.assertEqual(result, 0)
        # Disallowed method.
        result = cmd_policy_test("api.openai.com", "/v1/completions", "GET")
        self.assertEqual(result, 1)


class TestRateLimiter(unittest.TestCase):
    """Tests for rate limiting token bucket."""

    def test_token_bucket_initial_burst(self):
        """Token bucket allows initial burst."""
        # Import the addon module directly.
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "addons"))

        # Create a simple TokenBucket class for testing.
        # (Can't import directly due to mitmproxy dependency)
        import threading

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

        bucket = TokenBucket(rate=10, burst=5)

        # Should allow burst of 5.
        for i in range(5):
            self.assertTrue(bucket.consume(), f"Burst request {i+1} should succeed")

        # 6th request should fail (no time has passed).
        self.assertFalse(bucket.consume(), "Request beyond burst should fail")

    def test_token_bucket_refill(self):
        """Token bucket refills over time."""
        import threading

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

        bucket = TokenBucket(rate=100, burst=1)

        # Consume the one token.
        self.assertTrue(bucket.consume())
        self.assertFalse(bucket.consume())

        # Wait for refill (at 100/s, 10ms = 1 token).
        time.sleep(0.015)

        # Should have refilled.
        self.assertTrue(bucket.consume())


if __name__ == "__main__":
    # Run tests.
    unittest.main(verbosity=2)
