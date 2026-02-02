#!/usr/bin/env python3
"""
Unit tests for brig.py CLI tool.

Tests the Python logic without requiring the VM or containers.
Run with: python3 -m pytest tests/test_brig_unit.py -v

Or without pytest:
    python3 tests/test_brig_unit.py
"""

import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import brig.py directly (not the brig/ package).
brig_path = Path(__file__).parent.parent / "src" / "brig.py"
spec = importlib.util.spec_from_file_location("brig_module", brig_path)
brig = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brig)


class TestColorize(unittest.TestCase):
    """Tests for colorize and status_color functions."""

    def test_colorize_with_valid_color(self):
        """Colorize applies ANSI codes when enabled."""
        brig.COLOR_ENABLED = True
        result = brig.colorize("test", "green")
        self.assertIn("\033[32m", result)
        self.assertIn("test", result)
        self.assertIn("\033[0m", result)

    def test_colorize_with_invalid_color(self):
        """Colorize returns plain text for invalid colors."""
        brig.COLOR_ENABLED = True
        result = brig.colorize("test", "invalid")
        self.assertEqual(result, "test")

    def test_colorize_disabled(self):
        """Colorize returns plain text when disabled."""
        brig.COLOR_ENABLED = False
        result = brig.colorize("test", "green")
        self.assertEqual(result, "test")
        brig.COLOR_ENABLED = True  # Reset.

    def test_status_color_running(self):
        """Running status is green."""
        brig.COLOR_ENABLED = True
        result = brig.status_color("running")
        self.assertIn("\033[32m", result)

    def test_status_color_paused(self):
        """Paused status is yellow."""
        brig.COLOR_ENABLED = True
        result = brig.status_color("paused")
        self.assertIn("\033[33m", result)

    def test_status_color_exited(self):
        """Exited status is red."""
        brig.COLOR_ENABLED = True
        result = brig.status_color("exited")
        self.assertIn("\033[31m", result)

    def test_status_color_case_insensitive(self):
        """Status color matching is case insensitive."""
        brig.COLOR_ENABLED = True
        result = brig.status_color("RUNNING")
        self.assertIn("\033[32m", result)


class TestNamingFunctions(unittest.TestCase):
    """Tests for container_name and network_name functions."""

    def test_container_name(self):
        """Container name adds brig- prefix."""
        self.assertEqual(brig.container_name("myapp"), "brig-myapp")

    def test_container_name_empty(self):
        """Container name handles empty input."""
        self.assertEqual(brig.container_name(""), "brig-")

    def test_network_name(self):
        """Network name adds brig- prefix."""
        self.assertEqual(brig.network_name("myapp"), "brig-myapp")

    def test_network_name_with_special_chars(self):
        """Network name preserves special characters."""
        self.assertEqual(brig.network_name("my-app_1"), "brig-my-app_1")


class TestCacheFunctions(unittest.TestCase):
    """Tests for _cached and _set_cache functions."""

    def setUp(self):
        """Clear cache before each test."""
        brig._cache.clear()

    def test_set_and_get_cache(self):
        """Cache stores and retrieves values."""
        brig._set_cache("test_key", "test_value")
        hit, value = brig._cached("test_key")
        self.assertTrue(hit)
        self.assertEqual(value, "test_value")

    def test_cache_miss(self):
        """Cache returns miss for unknown keys."""
        hit, value = brig._cached("nonexistent")
        self.assertFalse(hit)
        self.assertIsNone(value)

    def test_cache_expiry(self):
        """Cache expires after TTL."""
        brig._set_cache("test_key", "test_value")
        # Manually expire by setting old timestamp.
        brig._cache["test_key"] = (time.time() - 10, "test_value")
        hit, value = brig._cached("test_key", ttl=1.0)
        self.assertFalse(hit)

    def test_cache_not_expired(self):
        """Cache hit when within TTL."""
        brig._set_cache("test_key", "test_value")
        hit, value = brig._cached("test_key", ttl=10.0)
        self.assertTrue(hit)
        self.assertEqual(value, "test_value")


class TestSuspiciousDomain(unittest.TestCase):
    """Tests for is_suspicious_domain function.

    Note: is_suspicious_domain checks for patterns that could allow DNS rebinding.
    It returns empty string for safe domains, non-empty reason for suspicious ones.
    It does NOT check for literal localhost or IPs (that's done in warden/enforce).
    """

    def test_normal_domain_returns_empty(self):
        """Normal domains return empty string (not suspicious)."""
        result = brig.is_suspicious_domain("example.com")
        self.assertEqual(result, "")

    def test_wildcard_all_suspicious(self):
        """Pure wildcard '*' is suspicious."""
        result = brig.is_suspicious_domain("*")
        self.assertNotEqual(result, "")
        self.assertIn("too broad", result.lower())

    def test_wildcard_local_suspicious(self):
        """*.local is suspicious (allows DNS rebinding)."""
        result = brig.is_suspicious_domain("*.local")
        self.assertNotEqual(result, "")

    def test_wildcard_internal_suspicious(self):
        """*.internal is suspicious."""
        result = brig.is_suspicious_domain("*.internal")
        self.assertNotEqual(result, "")

    def test_wildcard_lan_suspicious(self):
        """*.lan is suspicious."""
        result = brig.is_suspicious_domain("*.lan")
        self.assertNotEqual(result, "")

    def test_wildcard_tld_suspicious(self):
        """Wildcard on TLD like *.com is suspicious."""
        result = brig.is_suspicious_domain("*.com")
        self.assertNotEqual(result, "")
        self.assertIn("tld", result.lower())

    def test_specific_subdomain_not_suspicious(self):
        """Specific subdomains like myhost.local are not flagged.
        (IP checks are done elsewhere, domain-only check here.)"""
        # Note: myhost.local is a specific domain, not a wildcard pattern.
        result = brig.is_suspicious_domain("myhost.local")
        self.assertEqual(result, "")


class TestCellDefinitionValidation(unittest.TestCase):
    """Tests for validate_cell_definition function.

    Note: This function validates cell definitions but doesn't require all fields.
    - 'image' is validated if present but not required (can be set later)
    - 'command' can be string or list
    - 'env' can be dict or list of KEY=value strings
    """

    def test_valid_minimal_definition(self):
        """Minimal valid definition passes (even empty)."""
        cell_def = {"image": "alpine:latest"}
        errors = brig.validate_cell_definition(cell_def)
        self.assertEqual(errors, [])

    def test_empty_definition_valid(self):
        """Empty definition is valid (image set separately)."""
        cell_def = {}
        errors = brig.validate_cell_definition(cell_def)
        self.assertEqual(errors, [])

    def test_invalid_image_type(self):
        """Image must be a string if present."""
        cell_def = {"image": 123}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("image" in e.lower() for e in errors))

    def test_empty_image_invalid(self):
        """Empty image string is invalid."""
        cell_def = {"image": ""}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("image" in e.lower() for e in errors))

    def test_valid_with_command_list(self):
        """Definition with command list is valid."""
        cell_def = {"image": "alpine", "command": ["echo", "hello"]}
        errors = brig.validate_cell_definition(cell_def)
        self.assertEqual(errors, [])

    def test_valid_with_command_string(self):
        """Definition with command string is valid (shell form)."""
        cell_def = {"image": "alpine", "command": "echo hello"}
        errors = brig.validate_cell_definition(cell_def)
        self.assertEqual(errors, [])

    def test_invalid_command_type(self):
        """Command must be a string or list."""
        cell_def = {"image": "alpine", "command": 123}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("command" in e.lower() for e in errors))

    def test_valid_env_dict(self):
        """Valid environment variables as dict passes."""
        cell_def = {"image": "alpine", "env": {"FOO": "bar", "BAZ": "qux"}}
        errors = brig.validate_cell_definition(cell_def)
        self.assertEqual(errors, [])

    def test_valid_env_list(self):
        """Valid environment variables as list passes."""
        cell_def = {"image": "alpine", "env": ["FOO=bar", "BAZ=qux"]}
        errors = brig.validate_cell_definition(cell_def)
        self.assertEqual(errors, [])

    def test_invalid_env_type(self):
        """Env must be a dict or list."""
        cell_def = {"image": "alpine", "env": "FOO=bar"}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("env" in e.lower() for e in errors))

    def test_invalid_env_list_format(self):
        """Env list items must be KEY=value format."""
        cell_def = {"image": "alpine", "env": ["NOEQUALS"]}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("env" in e.lower() for e in errors))

    def test_valid_secrets(self):
        """Valid secrets list passes."""
        cell_def = {"image": "alpine", "secrets": ["api-key", "db-pass"]}
        errors = brig.validate_cell_definition(cell_def)
        self.assertEqual(errors, [])

    def test_invalid_secrets_type(self):
        """Secrets must be a list."""
        cell_def = {"image": "alpine", "secrets": "api-key"}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("secrets" in e.lower() for e in errors))

    def test_secret_path_traversal_blocked(self):
        """Secret names with path traversal are rejected."""
        cell_def = {"image": "alpine", "secrets": ["../etc/passwd"]}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("traversal" in e.lower() for e in errors))

    def test_valid_memory_formats(self):
        """Valid memory formats pass."""
        for mem in ["512m", "2g", "1024k"]:
            cell_def = {"image": "alpine", "memory": mem}
            errors = brig.validate_cell_definition(cell_def)
            self.assertEqual(errors, [], f"Memory format {mem} should be valid")

    def test_valid_policy(self):
        """Valid policy passes."""
        cell_def = {
            "image": "alpine",
            "policy": {
                "allow": ["example.com", "*.github.com"],
                "deny": ["evil.com"]
            }
        }
        errors = brig.validate_cell_definition(cell_def)
        self.assertEqual(errors, [])

    def test_invalid_name_format(self):
        """Name must be alphanumeric starting."""
        cell_def = {"name": "-invalid", "image": "alpine"}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("name" in e.lower() for e in errors))


class TestCellPolicy(unittest.TestCase):
    """Tests for policy file operations."""

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

    def test_get_cell_policy_path(self):
        """Policy path uses cell name."""
        path = brig.get_cell_policy_path("myapp")
        self.assertEqual(path.name, "myapp.json")

    def test_load_nonexistent_policy(self):
        """Loading nonexistent policy returns empty."""
        policy = brig.load_cell_policy("nonexistent")
        self.assertEqual(policy, {"allow": [], "deny": []})

    def test_save_and_load_policy(self):
        """Save and load policy round-trips correctly."""
        policy = {"allow": ["example.com"], "deny": ["evil.com"]}
        brig.save_cell_policy("myapp", policy)
        loaded = brig.load_cell_policy("myapp")
        self.assertEqual(loaded, policy)

    def test_delete_policy(self):
        """Delete removes policy file."""
        brig.save_cell_policy("myapp", {"allow": []})
        self.assertTrue(brig.get_cell_policy_path("myapp").exists())
        brig.delete_cell_policy("myapp")
        self.assertFalse(brig.get_cell_policy_path("myapp").exists())

    def test_delete_nonexistent_policy(self):
        """Delete nonexistent policy doesn't error."""
        brig.delete_cell_policy("nonexistent")  # Should not raise.


class TestCellDefinitionLoading(unittest.TestCase):
    """Tests for load_cell_definition function."""

    def test_load_json_definition(self):
        """Load JSON cell definition."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"image": "alpine", "command": ["echo", "test"]}, f)
            f.flush()
            try:
                cell_def = brig.load_cell_definition(f.name)
                self.assertEqual(cell_def["image"], "alpine")
                self.assertEqual(cell_def["command"], ["echo", "test"])
            finally:
                os.unlink(f.name)

    def test_load_yaml_definition(self):
        """Load YAML cell definition (if PyYAML available)."""
        if not brig.YAML_AVAILABLE:
            self.skipTest("PyYAML not available")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("image: alpine\ncommand:\n  - echo\n  - test\n")
            f.flush()
            try:
                cell_def = brig.load_cell_definition(f.name)
                self.assertEqual(cell_def["image"], "alpine")
            finally:
                os.unlink(f.name)

    def test_load_invalid_json(self):
        """Invalid JSON raises error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json")
            f.flush()
            try:
                with self.assertRaises(SystemExit):
                    brig.load_cell_definition(f.name)
            finally:
                os.unlink(f.name)


class TestRateLimiting(unittest.TestCase):
    """Tests for check_rate_limit function."""

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

    def test_first_request_allowed(self):
        """First request is always allowed."""
        self.assertTrue(brig.check_rate_limit())

    def test_under_limit_allowed(self):
        """Requests under limit are allowed."""
        for _ in range(brig.RATE_LIMIT_MAX - 1):
            self.assertTrue(brig.check_rate_limit())

    def test_over_limit_blocked(self):
        """Requests over limit are blocked."""
        for _ in range(brig.RATE_LIMIT_MAX):
            brig.check_rate_limit()
        self.assertFalse(brig.check_rate_limit())

    def test_limit_resets_after_window(self):
        """Rate limit resets after time window."""
        # Fill up the limit.
        for _ in range(brig.RATE_LIMIT_MAX):
            brig.check_rate_limit()

        # Manually expire timestamps.
        with open(brig.RATE_LIMIT_FILE, 'r') as f:
            data = json.load(f)
        data["timestamps"] = [time.time() - brig.RATE_LIMIT_WINDOW - 1]
        with open(brig.RATE_LIMIT_FILE, 'w') as f:
            json.dump(data, f)

        # Should be allowed again.
        self.assertTrue(brig.check_rate_limit())


class TestSpinner(unittest.TestCase):
    """Tests for Spinner class."""

    def test_spinner_context_manager(self):
        """Spinner works as context manager."""
        with brig.Spinner("Testing") as spinner:
            self.assertIsNotNone(spinner)
            self.assertEqual(spinner.message, "Testing")

    def test_spinner_success(self):
        """Spinner success method works."""
        spinner = brig.Spinner("Testing")
        spinner.success("Done")  # Should not raise.

    def test_spinner_fail(self):
        """Spinner fail method works."""
        spinner = brig.Spinner("Testing")
        spinner.fail("Error")  # Should not raise.


class TestLogFunctions(unittest.TestCase):
    """Tests for logging functions."""

    def test_log_respects_level(self):
        """Log respects log level setting."""
        original_level = brig.LOG_LEVEL
        brig.LOG_LEVEL = brig.LOG_LEVEL_ERROR

        # Debug should not output (captured by checking no exception).
        brig.debug("test debug")
        brig.info("test info")
        brig.warn("test warn")

        brig.LOG_LEVEL = original_level


class TestInvalidateCellCache(unittest.TestCase):
    """Tests for invalidate_cell_cache function."""

    def setUp(self):
        """Clear cache before each test."""
        brig._cache.clear()

    def test_invalidate_removes_entries(self):
        """Invalidate removes cell-specific cache entries."""
        brig._set_cache("cell_exists:myapp", True)
        brig._set_cache("cell_running:myapp", True)
        brig._set_cache("other_key", "value")

        brig.invalidate_cell_cache("myapp")

        self.assertNotIn("cell_exists:myapp", brig._cache)
        self.assertNotIn("cell_running:myapp", brig._cache)
        self.assertIn("other_key", brig._cache)

    def test_invalidate_nonexistent_safe(self):
        """Invalidating nonexistent keys doesn't error."""
        brig.invalidate_cell_cache("nonexistent")  # Should not raise.


if __name__ == "__main__":
    unittest.main(verbosity=2)
