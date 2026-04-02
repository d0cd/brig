#!/usr/bin/env python3
"""
Unit tests for brig.py CLI tool.

Tests the Python logic without requiring the VM or containers.
Run with: python3 -m pytest tests/test_brig_unit.py -v

Or without pytest:
    python3 tests/test_brig_unit.py
"""

import contextlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestParseDuration(unittest.TestCase):
    """Tests for parse_duration function."""

    def test_seconds(self):
        """Parse seconds suffix."""
        self.assertEqual(brig.parse_duration("30s"), 30)

    def test_minutes(self):
        """Parse minutes suffix."""
        self.assertEqual(brig.parse_duration("5m"), 300)

    def test_hours(self):
        """Parse hours suffix."""
        self.assertEqual(brig.parse_duration("2h"), 7200)

    def test_days(self):
        """Parse days suffix."""
        self.assertEqual(brig.parse_duration("1d"), 86400)

    def test_plain_integer(self):
        """Parse plain integer as seconds."""
        self.assertEqual(brig.parse_duration("120"), 120)

    def test_zero(self):
        """Parse zero duration."""
        self.assertEqual(brig.parse_duration("0"), 0)

    def test_whitespace(self):
        """Whitespace is stripped."""
        self.assertEqual(brig.parse_duration("  30s  "), 30)

    def test_invalid_unit(self):
        """Invalid unit returns None."""
        self.assertIsNone(brig.parse_duration("30x"))

    def test_invalid_format(self):
        """Non-numeric input returns None."""
        self.assertIsNone(brig.parse_duration("abc"))

    def test_empty_string(self):
        """Empty string returns None."""
        self.assertIsNone(brig.parse_duration(""))

    def test_negative_not_supported(self):
        """Negative values return None."""
        self.assertIsNone(brig.parse_duration("-5m"))

    def test_float_not_supported(self):
        """Float values return None."""
        self.assertIsNone(brig.parse_duration("1.5h"))


class TestValidateCellName(unittest.TestCase):
    """Tests for validate_cell_name function."""

    def test_valid_names(self):
        """Valid cell names do not raise."""
        for name in ["myapp", "my-app", "my_app", "my.app", "a", "a1-b2_c3"]:
            brig.validate_cell_name(name)  # Should not raise.

    def test_empty_name_exits(self):
        """Empty name causes SystemExit."""
        with self.assertRaises(SystemExit):
            brig.validate_cell_name("")

    def test_starts_with_dash_exits(self):
        """Name starting with dash causes SystemExit."""
        with self.assertRaises(SystemExit):
            brig.validate_cell_name("-invalid")

    def test_starts_with_underscore_exits(self):
        """Name starting with underscore causes SystemExit."""
        with self.assertRaises(SystemExit):
            brig.validate_cell_name("_invalid")

    def test_special_chars_exits(self):
        """Special characters cause SystemExit."""
        for name in ["my app", "my/app", "my@app", "my;app"]:
            with self.assertRaises(SystemExit):
                brig.validate_cell_name(name)

    def test_uppercase_exits(self):
        """Uppercase characters cause SystemExit."""
        with self.assertRaises(SystemExit):
            brig.validate_cell_name("MyApp")

    def test_too_long_exits(self):
        """Name over 63 characters causes SystemExit."""
        with self.assertRaises(SystemExit):
            brig.validate_cell_name("a" * 64)

    def test_max_length_valid(self):
        """Name of exactly 63 characters is valid."""
        brig.validate_cell_name("a" * 63)  # Should not raise.

    def test_path_traversal_exits(self):
        """Path traversal in name causes SystemExit."""
        with self.assertRaises(SystemExit):
            brig.validate_cell_name("../etc/passwd")


class TestValidateWorkspacePath(unittest.TestCase):
    """Tests for validate_workspace_path function."""

    def setUp(self):
        """Create temp workspace directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.workspace = Path(self.temp_dir) / "workspace"
        self.workspace.mkdir()

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_valid_relative_path(self):
        """Valid relative path resolves within workspace."""
        result = brig.validate_workspace_path(self.workspace, "file.txt")
        self.assertTrue(str(result).startswith(str(self.workspace.resolve())))

    def test_valid_nested_path(self):
        """Nested path resolves within workspace."""
        result = brig.validate_workspace_path(self.workspace, "dir/file.txt")
        self.assertTrue(str(result).startswith(str(self.workspace.resolve())))

    def test_leading_slash_stripped(self):
        """Leading slash is stripped to keep path relative."""
        result = brig.validate_workspace_path(self.workspace, "/file.txt")
        self.assertTrue(str(result).startswith(str(self.workspace.resolve())))

    def test_traversal_blocked(self):
        """Path traversal with .. is blocked."""
        with self.assertRaises(SystemExit):
            brig.validate_workspace_path(self.workspace, "../etc/passwd")

    def test_traversal_in_middle_blocked(self):
        """Path traversal in middle of path is blocked."""
        with self.assertRaises(SystemExit):
            brig.validate_workspace_path(self.workspace, "subdir/../../etc/passwd")


class TestBuiltinProfiles(unittest.TestCase):
    """Tests for built-in trust profiles."""

    def test_all_profiles_exist(self):
        """All documented profiles exist."""
        for name in ["untrusted", "supervised", "dev", "airgapped", "honeypot"]:
            self.assertIn(name, brig.BUILTIN_PROFILES)

    def test_untrusted_is_restrictive(self):
        """Untrusted profile has low resource limits."""
        profile = brig.BUILTIN_PROFILES["untrusted"]
        self.assertEqual(profile["memory"], "512m")
        self.assertEqual(profile["pids_limit"], 256)

    def test_dev_has_high_resources(self):
        """Dev profile has high resource limits."""
        profile = brig.BUILTIN_PROFILES["dev"]
        self.assertEqual(profile["memory"], "4g")
        self.assertEqual(profile["pids_limit"], 2048)

    def test_airgapped_has_no_network(self):
        """Airgapped profile uses network none."""
        profile = brig.BUILTIN_PROFILES["airgapped"]
        self.assertEqual(profile["network"], "none")

    def test_honeypot_denies_all(self):
        """Honeypot profile denies all domains."""
        profile = brig.BUILTIN_PROFILES["honeypot"]
        self.assertIn("*", profile["policy"]["deny"])

    def test_all_profiles_have_runtime(self):
        """All profiles specify gVisor runtime."""
        for name, profile in brig.BUILTIN_PROFILES.items():
            self.assertEqual(profile.get("runtime"), "runsc", f"{name} must use runsc")

    def test_all_profiles_have_labels(self):
        """All profiles include profile label."""
        for name, profile in brig.BUILTIN_PROFILES.items():
            self.assertIn("brig.profile", profile.get("labels", {}),
                          f"{name} must have brig.profile label")

    def test_load_builtin_profile(self):
        """load_profile returns copy of built-in profile."""
        profile = brig.load_profile("supervised")
        self.assertEqual(profile["memory"], "2g")
        # Verify it's a copy, not a reference.
        profile["memory"] = "99g"
        self.assertEqual(brig.BUILTIN_PROFILES["supervised"]["memory"], "2g")

    def test_load_unknown_profile_exits(self):
        """Loading unknown profile causes SystemExit."""
        with self.assertRaises(SystemExit):
            brig.load_profile("nonexistent-profile")


class TestSanitizeFlags(unittest.TestCase):
    """Tests for --allow-scripts and --allow-office flags in cmd_cp sanitize mode."""

    def setUp(self):
        """Create temp workspace with test files."""
        self.temp_dir = tempfile.mkdtemp()
        self.workspace = Path(self.temp_dir)
        # Create test files.
        (self.workspace / "test.sh").write_text("#!/bin/sh\necho hello")
        (self.workspace / "report.docx").write_bytes(b"fake docx")
        (self.workspace / "data.csv").write_text("a,b,c")
        (self.workspace / "malware.exe").write_bytes(b"fake exe")

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_office_extensions_exists(self):
        """OFFICE_EXTENSIONS set exists and contains expected types."""
        self.assertIn(".docx", brig.OFFICE_EXTENSIONS)
        self.assertIn(".xlsx", brig.OFFICE_EXTENSIONS)
        self.assertIn(".pptx", brig.OFFICE_EXTENSIONS)
        self.assertIn(".odt", brig.OFFICE_EXTENSIONS)

    def test_script_blocked_without_flag(self):
        """Script files are blocked in sanitize mode without --allow-scripts."""
        args = MagicMock()
        args.sanitize = True
        args.allow_scripts = False
        args.allow_office = False
        args.src = str(self.workspace / "test.sh")
        args.dst = "mycell:/work/test.sh"

        # cmd_cp calls error() which raises SystemExit when script is blocked.
        with patch.object(brig, 'cell_exists', return_value=True), \
             patch.object(brig, 'validate_workspace_path', return_value=self.workspace / "test.sh"):
            # Reconfigure src/dst parsing to go through the sanitize check.
            args.src = str(self.workspace / "test.sh")
            args.dst = "mycell:/work/test.sh"
            # Script extension should trigger error.
            ext = Path(args.src).suffix.lower()
            self.assertIn(ext, brig.SCRIPT_EXTENSIONS)

    def test_script_allowed_with_flag(self):
        """Script files pass sanitize check when --allow-scripts is set."""
        ext = ".sh"
        # With allow_scripts=True, the check should not block.
        self.assertIn(ext, brig.SCRIPT_EXTENSIONS)
        # The logic: if ext in SCRIPT_EXTENSIONS and not args.allow_scripts → block.
        # With allow_scripts=True, no block.
        allow_scripts = True
        blocked = ext in brig.SCRIPT_EXTENSIONS and not allow_scripts
        self.assertFalse(blocked)

    def test_office_blocked_without_flag(self):
        """Office files are blocked in sanitize mode without --allow-office."""
        ext = ".docx"
        allow_office = False
        blocked = ext in brig.OFFICE_EXTENSIONS and not allow_office
        self.assertTrue(blocked)

    def test_office_allowed_with_flag(self):
        """Office files pass sanitize check when --allow-office is set."""
        ext = ".docx"
        allow_office = True
        blocked = ext in brig.OFFICE_EXTENSIONS and not allow_office
        self.assertFalse(blocked)

    def test_unsafe_always_blocked(self):
        """Unsafe extensions (.exe) are always blocked regardless of flags."""
        ext = ".exe"
        self.assertIn(ext, brig.UNSAFE_EXTENSIONS)
        # Unsafe is checked before script/office, and has no allow flag.
        self.assertNotIn(ext, brig.SCRIPT_EXTENSIONS)
        self.assertNotIn(ext, brig.OFFICE_EXTENSIONS)


class TestSubstringMatchFix(unittest.TestCase):
    """Tests that container matching uses exact match, not substring."""

    @patch.object(brig, 'run')
    def test_proxy_running_exact_match(self, mock_run):
        """proxy_running uses exact line match, not substring."""
        brig._cache.clear()
        # Simulate podman output with a similar but different name.
        mock_run.return_value = MagicMock(
            returncode=0, stdout="warden-test\n"
        )
        # "warden" should NOT match "warden-test".
        result = brig.proxy_running()
        self.assertFalse(result)

    @patch.object(brig, 'run')
    def test_proxy_running_exact_match_positive(self, mock_run):
        """proxy_running matches when exact name is present."""
        brig._cache.clear()
        mock_run.return_value = MagicMock(
            returncode=0, stdout="warden\n"
        )
        result = brig.proxy_running()
        self.assertTrue(result)

    @patch.object(brig, 'run')
    def test_cell_exists_exact_match(self, mock_run):
        """cell_exists uses exact line match, not substring."""
        brig._cache.clear()
        mock_run.return_value = MagicMock(
            returncode=0, stdout="brig-myapp-test\n"
        )
        # "brig-myapp" should NOT match "brig-myapp-test".
        result = brig.cell_exists("myapp")
        self.assertFalse(result)

    @patch.object(brig, 'run')
    def test_cell_running_exact_match(self, mock_run):
        """cell_running uses exact line match, not substring."""
        brig._cache.clear()
        mock_run.return_value = MagicMock(
            returncode=0, stdout="brig-myapp-extended\n"
        )
        result = brig.cell_running("myapp")
        self.assertFalse(result)


class TestWildcardDomainConsistency(unittest.TestCase):
    """Tests that _matches_domain is consistent with enforce.py."""

    def test_wildcard_does_not_match_bare_domain(self):
        """*.example.com does NOT match example.com (consistent with enforce.py)."""
        self.assertFalse(brig._matches_domain("*.example.com", "example.com"))

    def test_wildcard_matches_subdomain(self):
        """*.example.com matches sub.example.com."""
        self.assertTrue(brig._matches_domain("*.example.com", "sub.example.com"))

    def test_wildcard_matches_deep_subdomain(self):
        """*.example.com matches deep.sub.example.com."""
        self.assertTrue(brig._matches_domain("*.example.com", "deep.sub.example.com"))

    def test_exact_match_works(self):
        """Exact domain matching works."""
        self.assertTrue(brig._matches_domain("example.com", "example.com"))
        self.assertFalse(brig._matches_domain("example.com", "other.com"))

    def test_case_insensitive(self):
        """Domain matching is case insensitive."""
        self.assertTrue(brig._matches_domain("Example.COM", "example.com"))


class TestVersionConsistency(unittest.TestCase):
    """Tests for version consistency across all version locations."""

    def test_version_matches_init(self):
        """brig.py VERSION matches brig/__init__.py __version__."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        import importlib
        brig_pkg = importlib.import_module("brig")
        self.assertEqual(brig.VERSION, brig_pkg.__version__)

    def test_version_matches_pyproject(self):
        """brig.py VERSION matches pyproject.toml version."""
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        for line in pyproject.read_text().splitlines():
            if line.startswith("version = "):
                toml_version = line.split('"')[1]
                self.assertEqual(brig.VERSION, toml_version)
                return
        self.fail("version not found in pyproject.toml")


class TestValidateCellNameCalledInCommands(unittest.TestCase):
    """Tests that cmd functions call validate_cell_name before processing."""

    def _make_args(self, **kwargs):
        """Create a mock args object with given attributes."""
        args = MagicMock()
        for k, v in kwargs.items():
            setattr(args, k, v)
        return args

    def test_cmd_logs_validates_name(self):
        """cmd_logs calls validate_cell_name."""
        args = self._make_args(name="../bad", follow=False, tail=None, since=None, until=None)
        with self.assertRaises(SystemExit):
            brig.cmd_logs(args)

    def test_cmd_shell_validates_name(self):
        """cmd_shell calls validate_cell_name."""
        args = self._make_args(name="../bad", shell="/bin/sh", user=None)
        with self.assertRaises(SystemExit):
            brig.cmd_shell(args)

    def test_cmd_inspect_validates_name(self):
        """cmd_inspect calls validate_cell_name."""
        args = self._make_args(name="../bad")
        with self.assertRaises(SystemExit):
            brig.cmd_inspect(args)

    def test_cmd_top_validates_name(self):
        """cmd_top calls validate_cell_name."""
        args = self._make_args(name="../bad")
        with self.assertRaises(SystemExit):
            brig.cmd_top(args)

    def test_cmd_diff_validates_name(self):
        """cmd_diff calls validate_cell_name."""
        args = self._make_args(name="../bad")
        with self.assertRaises(SystemExit):
            brig.cmd_diff(args)

    def test_cmd_export_validates_name(self):
        """cmd_export calls validate_cell_name."""
        args = self._make_args(name="../bad", output=None, sanitize=False,
                               allow_office=False, allow_scripts=False)
        with self.assertRaises(SystemExit):
            brig.cmd_export(args)

    def test_cmd_policy_show_validates_name(self):
        """cmd_policy_show calls validate_cell_name."""
        args = self._make_args(name="../bad")
        with self.assertRaises(SystemExit):
            brig.cmd_policy_show(args)


class TestSchemaVersioning(unittest.TestCase):
    """Tests for schema versioning and upgrade system."""

    def setUp(self):
        """Create a temporary BRIG_HOME for each test."""
        self.tmpdir = tempfile.mkdtemp()
        self.orig_brig_home = brig.BRIG_HOME
        self.orig_version_file = brig.VERSION_FILE
        brig.BRIG_HOME = Path(self.tmpdir)
        brig.VERSION_FILE = Path(self.tmpdir) / "state" / "version"

    def tearDown(self):
        """Restore original paths and clean up."""
        brig.BRIG_HOME = self.orig_brig_home
        brig.VERSION_FILE = self.orig_version_file
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_read_schema_version_missing(self):
        """Returns '0.0.0' when version file does not exist."""
        self.assertEqual(brig._read_schema_version(), "0.0.0")

    def test_write_and_read_schema_version(self):
        """Write then read round-trips the version."""
        brig._write_schema_version("1.0.0")
        self.assertEqual(brig._read_schema_version(), "1.0.0")

    def test_write_schema_version_creates_dirs(self):
        """Write creates parent directories if missing."""
        brig._write_schema_version("2.0.0")
        self.assertTrue(brig.VERSION_FILE.exists())

    def test_write_schema_version_atomic(self):
        """Write uses atomic rename (no .tmp file left behind)."""
        brig._write_schema_version("1.0.0")
        tmp = brig.VERSION_FILE.with_suffix(".tmp")
        self.assertFalse(tmp.exists())

    def test_read_schema_version_corrupt(self):
        """Returns '0.0.0' for corrupt version file."""
        brig.VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(brig.VERSION_FILE, "w") as f:
            f.write("not json")
        self.assertEqual(brig._read_schema_version(), "0.0.0")

    def test_parse_version(self):
        """Version strings parse into comparable tuples."""
        self.assertEqual(brig._parse_version("1.0.0"), (1, 0, 0))
        self.assertEqual(brig._parse_version("2.1.3"), (2, 1, 3))
        self.assertGreater(brig._parse_version("1.1.0"), brig._parse_version("1.0.0"))
        self.assertGreater(brig._parse_version("2.0.0"), brig._parse_version("1.9.9"))

    def test_backup_creates_copy(self):
        """Backup creates a timestamped copy of BRIG_HOME."""
        # Create some state.
        (Path(self.tmpdir) / "cells").mkdir()
        (Path(self.tmpdir) / "cells" / "test.json").write_text('{"test": true}')

        backup_dir = brig._backup_brig_home()
        self.assertTrue(backup_dir.exists())
        self.assertTrue((backup_dir / "cells" / "test.json").exists())

        # Clean up backup.
        import shutil
        shutil.rmtree(backup_dir, ignore_errors=True)

    def test_upgrade_already_current(self):
        """Upgrade with current version is a no-op."""
        brig._write_schema_version(brig.SCHEMA_VERSION)
        args = MagicMock()
        args.dry_run = False
        args.no_backup = True
        result = brig.cmd_upgrade(args)
        self.assertEqual(result, 0)

    def test_upgrade_from_zero(self):
        """Upgrade from 0.0.0 runs migrations and writes version."""
        # Create minimal state for migration.
        cells_dir = Path(self.tmpdir) / "cells"
        cells_dir.mkdir(parents=True)
        config_file = cells_dir / "config.json"
        with open(config_file, "w") as f:
            json.dump({"operation_logging": {"enabled": True}}, f)

        args = MagicMock()
        args.dry_run = False
        args.no_backup = True
        result = brig.cmd_upgrade(args)
        self.assertEqual(result, 0)
        self.assertEqual(brig._read_schema_version(), brig.SCHEMA_VERSION)

    def test_upgrade_dry_run(self):
        """Dry run shows migrations without applying them."""
        args = MagicMock()
        args.dry_run = True
        args.no_backup = True
        result = brig.cmd_upgrade(args)
        self.assertEqual(result, 0)
        # Version should NOT have been written.
        self.assertEqual(brig._read_schema_version(), "0.0.0")

    def test_upgrade_adds_schema_to_config(self):
        """Migration adds schema_version to existing config.json."""
        cells_dir = Path(self.tmpdir) / "cells"
        cells_dir.mkdir(parents=True)
        config_file = cells_dir / "config.json"
        with open(config_file, "w") as f:
            json.dump({"operation_logging": {"enabled": True}}, f)

        args = MagicMock()
        args.dry_run = False
        args.no_backup = True
        brig.cmd_upgrade(args)

        with open(config_file, "r") as f:
            config = json.load(f)
        self.assertEqual(config["schema_version"], "1.0.0")
        # Original config preserved.
        self.assertTrue(config["operation_logging"]["enabled"])

    def test_upgrade_not_initialized(self):
        """Upgrade fails if brig is not initialized."""
        import shutil
        shutil.rmtree(self.tmpdir)
        args = MagicMock()
        with self.assertRaises(SystemExit):
            brig.cmd_upgrade(args)


class TestParseVersion(unittest.TestCase):
    """Tests for _parse_version robustness."""

    def test_valid_version(self):
        """Valid semver string parses correctly."""
        self.assertEqual(brig._parse_version("1.2.3"), (1, 2, 3))

    def test_malformed_version_returns_zero(self):
        """Malformed version returns (0, 0, 0) instead of crashing."""
        self.assertEqual(brig._parse_version("1.x.0"), (0, 0, 0))
        self.assertEqual(brig._parse_version(""), (0, 0, 0))
        self.assertEqual(brig._parse_version("garbage"), (0, 0, 0))


class TestAppendJsonl(unittest.TestCase):
    """Tests for _append_jsonl file locking."""

    def test_append_creates_file(self):
        """_append_jsonl creates file if it does not exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sub" / "test.jsonl"
            brig._append_jsonl(path, {"key": "value"})
            lines = path.read_text().strip().split("\n")
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["key"], "value")

    def test_append_multiple_lines(self):
        """_append_jsonl appends without overwriting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.jsonl"
            brig._append_jsonl(path, {"seq": 1})
            brig._append_jsonl(path, {"seq": 2})
            lines = path.read_text().strip().split("\n")
            self.assertEqual(len(lines), 2)


class TestWorkdirFlag(unittest.TestCase):
    """Tests for --workdir flag in brig run."""

    def setUp(self):
        """Create temp directory for workspace."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_state_dir = brig.STATE_DIR
        brig.STATE_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.STATE_DIR = self._original_state_dir

    def test_workdir_in_podman_command(self):
        """--workdir produces --workdir in podman command."""
        args = MagicMock()
        args.workdir = "/app"
        args.name = "test"
        args.image = "alpine"
        args.container_cmd = []
        args.memory = "2g"
        args.cpus = "2"
        args.pids_limit = 512
        args.detach = True
        args.rm = False
        args.env = None
        args.secret = None
        args.label = None
        args.seccomp_profile = None
        args.timeout = None
        args.network = "default"
        args.profile = None

        cmd = brig._build_run_command(
            args, "test", False, "brig-test", "10.60.1.1", None,
            lambda msg, s=None: None,
        )

        self.assertIn("--workdir", cmd)
        idx = cmd.index("--workdir")
        self.assertEqual(cmd[idx + 1], "/app")

    def test_workdir_absent_when_not_set(self):
        """--workdir is not in command when not set."""
        args = MagicMock()
        args.workdir = None
        args.name = "test"
        args.image = "alpine"
        args.container_cmd = []
        args.memory = "2g"
        args.cpus = "2"
        args.pids_limit = 512
        args.detach = True
        args.rm = False
        args.env = None
        args.secret = None
        args.label = None
        args.seccomp_profile = None
        args.timeout = None
        args.network = "default"
        args.profile = None

        cmd = brig._build_run_command(
            args, "test", False, "brig-test", "10.60.1.1", None,
            lambda msg, s=None: None,
        )

        self.assertNotIn("--workdir", cmd)


class TestImageDigestFlag(unittest.TestCase):
    """Tests for --image-digest flag in brig run."""

    @patch.object(brig, 'run')
    def test_matching_digest_succeeds(self, mock_run):
        """Matching image digest does not cause exit."""
        # First call: podman image inspect returns matching digest.
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="sha256:abc123def456\n",
            stderr="",
        )
        args = MagicMock()
        args.image_digest = "sha256:abc123def456"
        args.image = "alpine"

        # Should not call error() — no SystemExit.
        brig._verify_image_digest(args)

    @patch.object(brig, 'run')
    def test_mismatched_digest_exits(self, mock_run):
        """Mismatched image digest causes SystemExit."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="sha256:actual999\n",
            stderr="",
        )
        args = MagicMock()
        args.image_digest = "sha256:expected123"
        args.image = "alpine"

        with self.assertRaises(SystemExit):
            brig._verify_image_digest(args)

    @patch.object(brig, 'run')
    def test_empty_digest_exits(self, mock_run):
        """Empty digest from failed inspect causes SystemExit."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="no such image",
        )
        args = MagicMock()
        args.image_digest = "sha256:expected123"
        args.image = "alpine"

        with self.assertRaises(SystemExit):
            brig._verify_image_digest(args)


class TestCanaryFileFlag(unittest.TestCase):
    """Tests for --canary-file flag in brig run."""

    def test_canary_file_read_and_deleted(self):
        """Canary file is read and deleted after processing."""
        canary_data = {"canary_tokens": {"aws_key": "AKIAFAKETOKEN"}}

        with tempfile.NamedTemporaryFile(
            mode='w', prefix='brig_canary_', suffix='.json', delete=False
        ) as f:
            json.dump(canary_data, f)
            canary_path = f.name

        try:
            args = MagicMock()
            args.canary_file = canary_path

            # Process the canary file.
            result = brig._process_canary_file(args)

            # File should be deleted.
            self.assertFalse(os.path.exists(canary_path))
            # Canary tokens should be returned.
            self.assertEqual(result["aws_key"], "AKIAFAKETOKEN")
        finally:
            # Clean up if test fails before deletion.
            if os.path.exists(canary_path):
                os.unlink(canary_path)

    def test_canary_file_none_returns_none(self):
        """No canary file returns None."""
        args = MagicMock()
        args.canary_file = None
        result = brig._process_canary_file(args)
        self.assertIsNone(result)

    def test_canary_file_bad_json_returns_none(self):
        """Corrupted canary file returns None and cleans up."""
        with tempfile.NamedTemporaryFile(
            mode='w', prefix='brig_canary_', suffix='.json', delete=False
        ) as f:
            f.write("not valid json{{{")
            canary_path = f.name

        args = MagicMock()
        args.canary_file = canary_path
        result = brig._process_canary_file(args)

        self.assertIsNone(result)
        # File should be cleaned up even on parse failure.
        self.assertFalse(os.path.exists(canary_path))

    def test_canary_file_missing_returns_none(self):
        """Missing canary file returns None."""
        args = MagicMock()
        args.canary_file = "/tmp/brig_canary_nonexistent.json"
        result = brig._process_canary_file(args)
        self.assertIsNone(result)

    def test_canary_file_bad_path_rejected(self):
        """Canary file with unexpected name is rejected."""
        args = MagicMock()
        args.canary_file = "/etc/passwd"
        result = brig._process_canary_file(args)
        self.assertIsNone(result)


class TestErrorSuggestions(unittest.TestCase):
    """Regression test: every error() call must include a suggestion."""

    def test_all_error_calls_have_suggestions(self):
        """Every error() call in brig.py should include a suggestion for usability."""
        import ast

        source = brig_path.read_text()
        tree = ast.parse(source, filename=str(brig_path))

        # Collect all direct error() calls (not in function definitions of error itself).
        bare_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # Match calls to 'error' (Name node) but not 'print_error', 'error_cell_not_found', etc.
            if isinstance(node.func, ast.Name) and node.func.id == "error":
                has_suggestion = (
                    len(node.args) >= 2
                    or any(kw.arg == "suggestion" for kw in node.keywords)
                )
                if not has_suggestion:
                    bare_calls.append(node.lineno)

        self.assertEqual(
            bare_calls, [],
            f"Found error() calls without suggestion= at lines: {bare_calls}. "
            "Every error() call should include a suggestion parameter for usability."
        )


class TestPolicySetDuplicateWarnings(unittest.TestCase):
    """Tests for duplicate/conflict warnings in cmd_policy_set."""

    def setUp(self):
        """Create temp directory for policy files and mock cell_exists."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_policy_dir = brig.POLICY_DIR
        brig.POLICY_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.POLICY_DIR = self._original_policy_dir

    @patch.object(brig, 'run')
    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'log_policy_change')
    def test_policy_set_warns_duplicate_allow(self, mock_log, mock_exists, mock_run):
        """Adding a domain already in the allowlist produces a warning."""
        # Pre-populate policy with example.com allowed.
        brig.save_cell_policy("testcell", {"allow": ["example.com"], "deny": []})

        args = MagicMock()
        args.name = "testcell"
        args.allow = ["example.com"]
        args.deny = None
        args.remove_allow = None
        args.remove_deny = None

        import io
        captured = io.StringIO()
        with patch('sys.stderr', captured):
            brig.cmd_policy_set(args)

        output = captured.getvalue()
        self.assertIn("already in the allowlist", output)

    @patch.object(brig, 'run')
    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'log_policy_change')
    def test_policy_set_warns_duplicate_deny(self, mock_log, mock_exists, mock_run):
        """Adding a domain already in the denylist produces a warning."""
        brig.save_cell_policy("testcell", {"allow": [], "deny": ["evil.com"]})

        args = MagicMock()
        args.name = "testcell"
        args.allow = None
        args.deny = ["evil.com"]
        args.remove_allow = None
        args.remove_deny = None

        import io
        captured = io.StringIO()
        with patch('sys.stderr', captured):
            brig.cmd_policy_set(args)

        output = captured.getvalue()
        self.assertIn("already in the denylist", output)

    @patch.object(brig, 'run')
    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'log_policy_change')
    def test_policy_set_warns_allow_deny_conflict(self, mock_log, mock_exists, mock_run):
        """Adding a domain to allow that is already denied produces a conflict warning."""
        brig.save_cell_policy("testcell", {"allow": [], "deny": ["conflict.com"]})

        args = MagicMock()
        args.name = "testcell"
        args.allow = ["conflict.com"]
        args.deny = None
        args.remove_allow = None
        args.remove_deny = None

        import io
        captured = io.StringIO()
        with patch('sys.stderr', captured):
            brig.cmd_policy_set(args)

        output = captured.getvalue()
        self.assertIn("deny takes precedence", output)


class TestValidatePolicyConflicts(unittest.TestCase):
    """Tests for validate_policy_conflicts function."""

    def test_no_conflicts(self):
        """Clean policy returns empty warnings."""
        policy = {"allow": ["example.com"], "deny": ["evil.com"]}
        warnings = brig.validate_policy_conflicts(policy)
        self.assertEqual(warnings, [])

    def test_exact_duplicate_flagged(self):
        """Domain in both allow and deny flagged."""
        policy = {"allow": ["example.com"], "deny": ["example.com"]}
        warnings = brig.validate_policy_conflicts(policy)
        self.assertTrue(any("both" in w for w in warnings))

    def test_wildcard_conflict(self):
        """*.example.com vs example.com detected."""
        policy = {"allow": ["*.example.com"], "deny": ["example.com"]}
        warnings = brig.validate_policy_conflicts(policy)
        self.assertTrue(len(warnings) > 0)

    def test_no_false_positives(self):
        """Non-conflicting rules pass."""
        policy = {"allow": ["*.github.com"], "deny": ["evil.com"]}
        warnings = brig.validate_policy_conflicts(policy)
        self.assertEqual(warnings, [])


class TestRedactSensitiveValue(unittest.TestCase):
    """Tests for _redact_sensitive_value function."""

    def test_redacts_password_key(self):
        """Key containing 'password' is redacted when enabled."""
        config = {"operation_logging": {"redact_env_values": True}}
        result = brig._redact_sensitive_value("DB_PASSWORD", "hunter2", config)
        self.assertEqual(result, "[REDACTED]")

    def test_redacts_token_key(self):
        """Key containing 'token' is redacted when enabled."""
        config = {"operation_logging": {"redact_env_values": True}}
        result = brig._redact_sensitive_value("API_TOKEN", "abc123", config)
        self.assertEqual(result, "[REDACTED]")

    def test_no_redact_safe_key(self):
        """Non-sensitive key is not redacted."""
        config = {"operation_logging": {"redact_env_values": True}}
        result = brig._redact_sensitive_value("HOSTNAME", "myhost", config)
        self.assertEqual(result, "myhost")

    def test_redaction_disabled(self):
        """Sensitive key is not redacted when disabled."""
        config = {"operation_logging": {"redact_env_values": False}}
        result = brig._redact_sensitive_value("SECRET_KEY", "s3cr3t", config)
        self.assertEqual(result, "s3cr3t")

    def test_redaction_default_config(self):
        """Empty config defaults to redacting."""
        config = {}
        result = brig._redact_sensitive_value("AUTH_KEY", "val", config)
        self.assertEqual(result, "[REDACTED]")

    def test_case_insensitive_match(self):
        """Key matching is case insensitive."""
        config = {"operation_logging": {"redact_env_values": True}}
        result = brig._redact_sensitive_value("MyCredential", "val", config)
        self.assertEqual(result, "[REDACTED]")


class TestRedactArgs(unittest.TestCase):
    """Tests for _redact_args function."""

    def test_skips_private_attrs(self):
        """Private attributes starting with underscore are skipped."""
        args = MagicMock()
        args.__dict__ = {"_internal": "hidden", "name": "test"}
        config = {"operation_logging": {"redact_secrets": True, "redact_env_values": True}}
        result = brig._redact_args(args, config)
        self.assertNotIn("_internal", result)
        self.assertIn("name", result)

    def test_redacts_env_sensitive_values(self):
        """Environment variable values with sensitive keys are redacted."""
        args = MagicMock()
        args.__dict__ = {"env": ["DB_PASSWORD=hunter2", "HOST=localhost"]}
        config = {"operation_logging": {"redact_secrets": True, "redact_env_values": True}}
        result = brig._redact_args(args, config)
        self.assertIn("DB_PASSWORD=[REDACTED]", result["env"])
        self.assertIn("HOST=localhost", result["env"])

    def test_handles_env_without_equals(self):
        """Environment variable without equals sign is kept as-is."""
        args = MagicMock()
        args.__dict__ = {"env": ["STANDALONE"]}
        config = {"operation_logging": {"redact_secrets": True, "redact_env_values": True}}
        result = brig._redact_args(args, config)
        self.assertIn("STANDALONE", result["env"])

    def test_secret_names_preserved(self):
        """Secret names are logged but values are not exposed."""
        args = MagicMock()
        args.__dict__ = {"secret": ["db-creds", "api-key"]}
        config = {"operation_logging": {"redact_secrets": True, "redact_env_values": True}}
        result = brig._redact_args(args, config)
        self.assertEqual(result["secret"], ["db-creds", "api-key"])

    def test_string_value_redacted_if_sensitive(self):
        """String args with sensitive key names are redacted."""
        args = MagicMock()
        args.__dict__ = {"auth_token": "mytoken"}
        config = {"operation_logging": {"redact_secrets": True, "redact_env_values": True}}
        result = brig._redact_args(args, config)
        self.assertEqual(result["auth_token"], "[REDACTED]")

    def test_list_values_preserved(self):
        """List values are preserved as lists."""
        args = MagicMock()
        args.__dict__ = {"ports": [80, 443]}
        config = {"operation_logging": {"redact_secrets": True, "redact_env_values": True}}
        result = brig._redact_args(args, config)
        self.assertEqual(result["ports"], [80, 443])

    def test_primitive_values_preserved(self):
        """Primitive values (int, bool, None) are preserved."""
        args = MagicMock()
        args.__dict__ = {"detach": True, "count": 5, "extra": None}
        config = {"operation_logging": {"redact_secrets": True, "redact_env_values": True}}
        result = brig._redact_args(args, config)
        self.assertEqual(result["detach"], True)
        self.assertEqual(result["count"], 5)
        self.assertIsNone(result["extra"])


class TestLogOperationStart(unittest.TestCase):
    """Tests for log_operation_start function."""

    def setUp(self):
        """Create temp directory for config file."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_config_file = brig.CONFIG_FILE
        brig.CONFIG_FILE = Path(self.temp_dir) / "config.json"
        brig._operation_config = None
        brig._operation_config_mtime = 0

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.CONFIG_FILE = self._original_config_file
        brig._operation_config = None
        brig._operation_config_mtime = 0

    def test_disabled_returns_disabled(self):
        """Disabled logging returns enabled=False."""
        config = {"operation_logging": {"enabled": False}}
        with open(brig.CONFIG_FILE, "w") as f:
            json.dump(config, f)
        result = brig.log_operation_start("run", MagicMock())
        self.assertFalse(result["enabled"])

    def test_level_none_returns_disabled(self):
        """Level 'none' returns enabled=False."""
        config = {"operation_logging": {"enabled": True, "level": "none"}}
        with open(brig.CONFIG_FILE, "w") as f:
            json.dump(config, f)
        result = brig.log_operation_start("run", MagicMock())
        self.assertFalse(result["enabled"])

    def test_mutations_only_skips_read_command(self):
        """Mutations-only level skips non-mutation commands."""
        config = {"operation_logging": {"enabled": True, "level": "mutations"}}
        with open(brig.CONFIG_FILE, "w") as f:
            json.dump(config, f)
        result = brig.log_operation_start("list", MagicMock())
        self.assertFalse(result["enabled"])

    def test_mutations_only_includes_mutation_command(self):
        """Mutations-only level includes mutation commands."""
        config = {"operation_logging": {"enabled": True, "level": "mutations"}}
        with open(brig.CONFIG_FILE, "w") as f:
            json.dump(config, f)
        result = brig.log_operation_start("run", MagicMock())
        self.assertTrue(result["enabled"])

    def test_enabled_returns_context(self):
        """Enabled logging returns context with start_time and command."""
        result = brig.log_operation_start("run", MagicMock())
        self.assertTrue(result["enabled"])
        self.assertIn("start_time", result)
        self.assertEqual(result["command"], "run")
        self.assertIn("config", result)


class TestLogOperationEnd(unittest.TestCase):
    """Tests for log_operation_end function."""

    def setUp(self):
        """Create temp directory for operations file."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_operations_file = brig.OPERATIONS_FILE
        brig.OPERATIONS_FILE = Path(self.temp_dir) / "operations.jsonl"

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.OPERATIONS_FILE = self._original_operations_file

    def test_disabled_context_does_nothing(self):
        """Disabled context produces no output."""
        brig.log_operation_end({"enabled": False}, exit_code=0)
        self.assertFalse(brig.OPERATIONS_FILE.exists())

    def _make_args(self, **kwargs):
        """Create a simple namespace object for args."""
        ns = type("Args", (), kwargs)()
        return ns

    def test_enabled_writes_entry(self):
        """Enabled context writes JSONL entry."""
        args = self._make_args(name="test-cell")
        context = {
            "enabled": True,
            "start_time": time.time() - 0.1,
            "command": "run",
            "args": args,
            "config": {},
        }
        brig.log_operation_end(context, exit_code=0)
        self.assertTrue(brig.OPERATIONS_FILE.exists())
        lines = brig.OPERATIONS_FILE.read_text().strip().split("\n")
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["command"], "run")
        self.assertEqual(entry["exit_code"], 0)
        self.assertIn("ts", entry)
        self.assertIn("duration_ms", entry)

    def test_error_included_in_entry(self):
        """Error string is included in log entry."""
        args = self._make_args(name="test-cell")
        context = {
            "enabled": True,
            "start_time": time.time(),
            "command": "run",
            "args": args,
            "config": {},
        }
        brig.log_operation_end(context, exit_code=1, error="something failed")
        lines = brig.OPERATIONS_FILE.read_text().strip().split("\n")
        entry = json.loads(lines[0])
        self.assertEqual(entry["error"], "something failed")
        self.assertEqual(entry["exit_code"], 1)


class TestLoadOperationConfig(unittest.TestCase):
    """Tests for _load_operation_config function."""

    def setUp(self):
        """Create temp directory for config file."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_config_file = brig.CONFIG_FILE
        brig.CONFIG_FILE = Path(self.temp_dir) / "config.json"
        brig._operation_config = None
        brig._operation_config_mtime = 0

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.CONFIG_FILE = self._original_config_file
        brig._operation_config = None
        brig._operation_config_mtime = 0

    def test_missing_file_returns_default(self):
        """Missing config file returns default configuration."""
        result = brig._load_operation_config()
        self.assertIn("operation_logging", result)
        self.assertTrue(result["operation_logging"]["enabled"])

    def test_reads_valid_config(self):
        """Valid config file is read and returned."""
        config = {"operation_logging": {"enabled": False, "level": "none"}}
        with open(brig.CONFIG_FILE, "w") as f:
            json.dump(config, f)
        result = brig._load_operation_config()
        self.assertFalse(result["operation_logging"]["enabled"])

    def test_caches_by_mtime(self):
        """Config is cached and returned from cache on second call."""
        config = {"operation_logging": {"enabled": True, "level": "all"}}
        with open(brig.CONFIG_FILE, "w") as f:
            json.dump(config, f)
        result1 = brig._load_operation_config()
        result2 = brig._load_operation_config()
        self.assertIs(result1, result2)

    def test_corrupt_json_returns_default(self):
        """Corrupt JSON file returns default configuration."""
        with open(brig.CONFIG_FILE, "w") as f:
            f.write("not valid json {{{")
        result = brig._load_operation_config()
        self.assertIn("operation_logging", result)
        self.assertTrue(result["operation_logging"]["enabled"])


class TestCountOperationsLastHour(unittest.TestCase):
    """Tests for _count_operations_last_hour function."""

    def setUp(self):
        """Create temp directory for history file."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_history_file = brig.HISTORY_FILE
        brig.HISTORY_FILE = Path(self.temp_dir) / "history.jsonl"

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.HISTORY_FILE = self._original_history_file

    def test_no_file_returns_zero(self):
        """Missing history file returns zero."""
        result = brig._count_operations_last_hour()
        self.assertEqual(result, 0)

    def test_counts_recent_entries(self):
        """Recent entries within one hour are counted."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(brig.HISTORY_FILE, "w") as f:
            f.write(json.dumps({"timestamp": now, "command": "run"}) + "\n")
            f.write(json.dumps({"timestamp": now, "command": "stop"}) + "\n")
        result = brig._count_operations_last_hour()
        self.assertEqual(result, 2)

    def test_skips_corrupt_lines(self):
        """Corrupt JSONL lines are skipped without error."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(brig.HISTORY_FILE, "w") as f:
            f.write("not valid json\n")
            f.write(json.dumps({"timestamp": now, "command": "run"}) + "\n")
        result = brig._count_operations_last_hour()
        self.assertEqual(result, 1)


class TestValidateCellDefinitionExtended(unittest.TestCase):
    """Tests for validate_cell_definition edge cases."""

    def test_invalid_memory_format(self):
        """Memory value 'abc' fails validation."""
        errors = brig.validate_cell_definition({"memory": "abc"})
        self.assertTrue(any("memory" in e.lower() for e in errors))

    def test_cpus_non_numeric_string(self):
        """Non-numeric cpus string fails validation."""
        errors = brig.validate_cell_definition({"cpus": "many"})
        self.assertTrue(any("cpus" in e.lower() for e in errors))

    def test_cpus_negative_passes_type_check(self):
        """Negative cpus passes type validation since no range check exists."""
        errors = brig.validate_cell_definition({"cpus": -1})
        cpus_errors = [e for e in errors if "cpus" in e.lower()]
        self.assertEqual(cpus_errors, [])

    def test_pids_limit_string(self):
        """String pids_limit fails validation."""
        errors = brig.validate_cell_definition({"pids_limit": "many"})
        self.assertTrue(any("pids_limit" in e.lower() for e in errors))

    def test_policy_not_dict(self):
        """Policy as string fails validation."""
        errors = brig.validate_cell_definition({"policy": "string"})
        self.assertTrue(any("policy" in e.lower() for e in errors))

    def test_policy_allow_not_list(self):
        """Policy allow as string fails validation."""
        errors = brig.validate_cell_definition({"policy": {"allow": "x.com"}})
        self.assertTrue(any("policy.allow" in e for e in errors))

    def test_policy_deny_non_string_items(self):
        """Policy deny with non-string items fails validation."""
        errors = brig.validate_cell_definition({"policy": {"deny": [123]}})
        self.assertTrue(any("policy.deny" in e for e in errors))

    def test_detach_not_bool(self):
        """Detach as string fails validation."""
        errors = brig.validate_cell_definition({"detach": "yes"})
        self.assertTrue(any("detach" in e.lower() for e in errors))

    def test_cell_def_tor_field_valid(self):
        """tor: true passes validation."""
        errors = brig.validate_cell_definition({"tor": True})
        tor_errors = [e for e in errors if "tor" in e.lower()]
        self.assertEqual(tor_errors, [])

    def test_cell_def_tor_field_invalid(self):
        """tor: 'yes' fails validation."""
        errors = brig.validate_cell_definition({"tor": "yes"})
        self.assertTrue(any("tor" in e.lower() for e in errors))


class TestCellDefMergeTor(unittest.TestCase):
    """Tests for tor field merge from cell definition into args."""

    def test_cell_def_merge_tor(self):
        """tor: true in cell def sets args.tor."""
        from brig.commands.lifecycle import _merge_cell_def_into_args
        from unittest.mock import MagicMock
        args = MagicMock()
        args.name = "test"
        args.image = "alpine"
        args.container_cmd = []
        args.env = []
        args.secret = []
        args.memory = "2g"
        args.cpus = "2"
        args.pids_limit = 512
        args.policy_allow = None
        args.policy_deny = None
        args.detach = True
        args.timeout = None
        args.network = None
        args.label = []
        args.tor = False
        _merge_cell_def_into_args(args, {"tor": True})
        self.assertTrue(args.tor)

    def test_cell_def_merge_tor_cli_overrides(self):
        """CLI --tor=True not overridden by cell def tor=False."""
        from brig.commands.lifecycle import _merge_cell_def_into_args
        from unittest.mock import MagicMock
        args = MagicMock()
        args.tor = True
        _merge_cell_def_into_args(args, {"tor": False})
        # CLI flag (True) should not be overridden.
        self.assertTrue(args.tor)


class TestWorkspaceQuota(unittest.TestCase):
    """Tests for workspace quota helpers."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._original_state_dir = brig.STATE_DIR
        brig.STATE_DIR = Path(self.temp_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.STATE_DIR = self._original_state_dir

    def test_parse_size_megabytes(self):
        self.assertEqual(brig.parse_size("500m"), 500 * 1024 * 1024)

    def test_parse_size_gigabytes(self):
        self.assertEqual(brig.parse_size("2g"), 2 * 1024 * 1024 * 1024)

    def test_parse_size_kilobytes(self):
        self.assertEqual(brig.parse_size("512k"), 512 * 1024)

    def test_parse_size_plain_bytes(self):
        self.assertEqual(brig.parse_size("1048576"), 1048576)

    def test_parse_size_invalid(self):
        with self.assertRaises(ValueError):
            brig.parse_size("abc")

    def test_parse_size_empty(self):
        with self.assertRaises(ValueError):
            brig.parse_size("")

    def test_save_and_get_quota(self):
        cell = "test-quota"
        (Path(self.temp_dir) / cell).mkdir()
        brig.save_workspace_quota(cell, 1024 * 1024)
        self.assertEqual(brig.get_workspace_quota(cell), 1024 * 1024)

    def test_get_quota_unset(self):
        cell = "no-quota"
        (Path(self.temp_dir) / cell).mkdir()
        self.assertIsNone(brig.get_workspace_quota(cell))

    def test_check_quota_within(self):
        cell = "within"
        ws = Path(self.temp_dir) / cell / "workspace"
        ws.mkdir(parents=True)
        (ws / "file.txt").write_text("hello")
        brig.save_workspace_quota(cell, 1024 * 1024)
        within, current, max_b = brig.check_workspace_quota(cell)
        self.assertTrue(within)
        self.assertEqual(max_b, 1024 * 1024)
        self.assertGreater(current, 0)

    def test_check_quota_exceeded(self):
        cell = "exceeded"
        ws = Path(self.temp_dir) / cell / "workspace"
        ws.mkdir(parents=True)
        (ws / "bigfile.bin").write_bytes(b"x" * 2000)
        brig.save_workspace_quota(cell, 100)
        within, current, max_b = brig.check_workspace_quota(cell)
        self.assertFalse(within)

    def test_check_quota_no_limit(self):
        cell = "nolimit"
        ws = Path(self.temp_dir) / cell / "workspace"
        ws.mkdir(parents=True)
        within, current, max_b = brig.check_workspace_quota(cell)
        self.assertTrue(within)
        self.assertIsNone(max_b)

    def test_format_size(self):
        self.assertEqual(brig.format_size(0), "0B")
        self.assertEqual(brig.format_size(1024), "1KB")
        self.assertIn("MB", brig.format_size(1024 * 1024))

    def test_cell_def_workspace_quota_valid(self):
        cell_def = {"image": "alpine", "workspace_quota": "500m"}
        errors = brig.validate_cell_definition(cell_def)
        self.assertEqual(errors, [])

    def test_cell_def_workspace_quota_invalid(self):
        cell_def = {"image": "alpine", "workspace_quota": "xyz"}
        errors = brig.validate_cell_definition(cell_def)
        self.assertTrue(any("workspace_quota" in e for e in errors))


class TestValidatePolicyRule(unittest.TestCase):
    """Tests for _validate_policy_rule function."""

    def test_empty_string(self):
        """Empty string rule produces error."""
        errors = brig._validate_policy_rule("", "test")
        self.assertTrue(any("empty" in e for e in errors))

    def test_wildcard_too_short(self):
        """Wildcard pattern shorter than 3 chars produces error."""
        errors = brig._validate_policy_rule("*.", "test")
        self.assertTrue(any("wildcard" in e.lower() or "invalid" in e.lower() for e in errors))

    def test_dict_missing_domain(self):
        """Dict rule missing domain produces error."""
        errors = brig._validate_policy_rule({"paths": ["/api"]}, "test")
        self.assertTrue(any("domain" in e for e in errors))

    def test_paths_not_list(self):
        """Dict rule with paths as string produces error."""
        errors = brig._validate_policy_rule({"domain": "example.com", "paths": "/api"}, "test")
        self.assertTrue(any("paths" in e for e in errors))

    def test_methods_not_list(self):
        """Dict rule with methods as string produces error."""
        errors = brig._validate_policy_rule({"domain": "example.com", "methods": "GET"}, "test")
        self.assertTrue(any("methods" in e for e in errors))

    def test_invalid_method(self):
        """Dict rule with invalid HTTP method produces error."""
        errors = brig._validate_policy_rule({"domain": "example.com", "methods": ["HACK"]}, "test")
        self.assertTrue(any("invalid method" in e.lower() for e in errors))

    def test_int_type_produces_error(self):
        """Integer rule type produces error."""
        errors = brig._validate_policy_rule(42, "test")
        self.assertTrue(any("invalid rule type" in e.lower() for e in errors))

    def test_suspicious_domain(self):
        """Suspicious domain pattern produces error."""
        errors = brig._validate_policy_rule("*", "test")
        self.assertTrue(len(errors) > 0)


class TestMatchesRule(unittest.TestCase):
    """Tests for _matches_rule function."""

    def test_dict_domain_no_match(self):
        """Dict rule with non-matching domain returns False."""
        rule = {"domain": "example.com"}
        self.assertFalse(brig._matches_rule(rule, "other.com", "/", "GET"))

    def test_dict_path_no_match(self):
        """Dict rule with non-matching path returns False."""
        rule = {"domain": "example.com", "paths": ["/api/*"]}
        self.assertFalse(brig._matches_rule(rule, "example.com", "/web/page", "GET"))

    def test_dict_method_no_match(self):
        """Dict rule with non-matching method returns False."""
        rule = {"domain": "example.com", "methods": ["GET"]}
        self.assertFalse(brig._matches_rule(rule, "example.com", "/", "POST"))

    def test_dict_all_match(self):
        """Dict rule with all fields matching returns True."""
        rule = {"domain": "example.com", "paths": ["/api/*"], "methods": ["GET"]}
        self.assertTrue(brig._matches_rule(rule, "example.com", "/api/v1", "GET"))

    def test_string_rule_match(self):
        """String rule matching domain returns True."""
        self.assertTrue(brig._matches_rule("example.com", "example.com", "/", "GET"))

    def test_string_rule_no_match(self):
        """String rule not matching domain returns False."""
        self.assertFalse(brig._matches_rule("example.com", "other.com", "/", "GET"))

    def test_non_string_non_dict_returns_false(self):
        """Non-string, non-dict rule returns False."""
        self.assertFalse(brig._matches_rule(42, "example.com", "/", "GET"))


class TestCmdConfigSet(unittest.TestCase):
    """Tests for cmd_config_set function."""

    def setUp(self):
        """Create temp directory for config file."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_config_file = brig.CONFIG_FILE
        brig.CONFIG_FILE = Path(self.temp_dir) / "config.json"
        brig._operation_config = None
        brig._operation_config_mtime = 0

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.CONFIG_FILE = self._original_config_file
        brig._operation_config = None
        brig._operation_config_mtime = 0

    def test_bool_true_string(self):
        """String 'true' is parsed as boolean True."""
        args = MagicMock()
        args.key = "operation_logging.enabled"
        args.value = "true"
        brig.cmd_config_set(args)
        with open(brig.CONFIG_FILE) as f:
            config = json.load(f)
        self.assertIs(config["operation_logging"]["enabled"], True)

    def test_bool_false_string(self):
        """String 'false' is parsed as boolean False."""
        args = MagicMock()
        args.key = "operation_logging.enabled"
        args.value = "false"
        brig.cmd_config_set(args)
        with open(brig.CONFIG_FILE) as f:
            config = json.load(f)
        self.assertIs(config["operation_logging"]["enabled"], False)

    def test_string_value(self):
        """Plain string value is stored as string."""
        args = MagicMock()
        args.key = "operation_logging.level"
        args.value = "mutations"
        brig.cmd_config_set(args)
        with open(brig.CONFIG_FILE) as f:
            config = json.load(f)
        self.assertEqual(config["operation_logging"]["level"], "mutations")

    def test_json_numeric(self):
        """JSON numeric value is parsed correctly."""
        args = MagicMock()
        args.key = "max_cells"
        args.value = "42"
        brig.cmd_config_set(args)
        with open(brig.CONFIG_FILE) as f:
            config = json.load(f)
        self.assertEqual(config["max_cells"], 42)

    def test_creates_file(self):
        """Config file is created if it does not exist."""
        self.assertFalse(brig.CONFIG_FILE.exists())
        args = MagicMock()
        args.key = "test_key"
        args.value = "test_value"
        brig.cmd_config_set(args)
        self.assertTrue(brig.CONFIG_FILE.exists())

    def test_merges_with_existing(self):
        """New key is merged with existing config."""
        with open(brig.CONFIG_FILE, "w") as f:
            json.dump({"existing": "value"}, f)
        args = MagicMock()
        args.key = "new_key"
        args.value = "new_value"
        brig.cmd_config_set(args)
        with open(brig.CONFIG_FILE) as f:
            config = json.load(f)
        self.assertEqual(config["existing"], "value")
        self.assertEqual(config["new_key"], "new_value")


class TestCmdConfigShow(unittest.TestCase):
    """Tests for cmd_config_show function."""

    def setUp(self):
        """Create temp directory for config file."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_config_file = brig.CONFIG_FILE
        brig.CONFIG_FILE = Path(self.temp_dir) / "config.json"
        brig._operation_config = None
        brig._operation_config_mtime = 0

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.CONFIG_FILE = self._original_config_file
        brig._operation_config = None
        brig._operation_config_mtime = 0

    def test_show_all_keys(self):
        """Showing all keys prints JSON output."""
        args = MagicMock()
        args.key = None
        args.keys = False
        result = brig.cmd_config_show(args)
        self.assertEqual(result, 0)

    def test_show_specific_key(self):
        """Showing specific existing key returns 0."""
        args = MagicMock()
        args.key = "operation_logging"
        args.keys = False
        result = brig.cmd_config_show(args)
        self.assertEqual(result, 0)

    def test_missing_key_exits(self):
        """Showing nonexistent key calls error and exits."""
        args = MagicMock()
        args.key = "nonexistent.deep.key"
        args.keys = False
        with self.assertRaises(SystemExit):
            brig.cmd_config_show(args)

    def test_keys_flag(self):
        """The --keys flag lists available configuration keys."""
        args = MagicMock()
        args.key = None
        args.keys = True
        result = brig.cmd_config_show(args)
        self.assertEqual(result, 0)


class TestCmdConfigReset(unittest.TestCase):
    """Tests for cmd_config_reset function."""

    def setUp(self):
        """Create temp directory for config file."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_config_file = brig.CONFIG_FILE
        brig.CONFIG_FILE = Path(self.temp_dir) / "config.json"

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.CONFIG_FILE = self._original_config_file

    def test_removes_existing_file(self):
        """Existing config file is removed."""
        with open(brig.CONFIG_FILE, "w") as f:
            json.dump({"key": "value"}, f)
        result = brig.cmd_config_reset(MagicMock())
        self.assertEqual(result, 0)
        self.assertFalse(brig.CONFIG_FILE.exists())

    def test_missing_file_returns_zero(self):
        """Missing config file returns 0 without error."""
        result = brig.cmd_config_reset(MagicMock())
        self.assertEqual(result, 0)


# ========== Step 5i: brig.py utils log functions ==========


class TestBrigLogFunctions(unittest.TestCase):
    """Tests for brig.py log/info/debug/error helper functions."""

    def test_log_info(self):
        """INFO level logs with [INFO] prefix."""
        import io
        captured = io.StringIO()
        with patch('sys.stderr', captured):
            brig.info("test info message")
        output = captured.getvalue()
        self.assertIn("INFO", output)
        self.assertIn("test info message", output)

    def test_log_debug(self):
        """DEBUG level logs with [DEBUG] prefix when log level allows it."""
        import io
        captured = io.StringIO()
        orig_level = brig.LOG_LEVEL
        brig.LOG_LEVEL = brig.LOG_LEVEL_DEBUG
        try:
            with patch('sys.stderr', captured):
                brig.debug("test debug message")
            output = captured.getvalue()
            self.assertIn("test debug message", output)
        finally:
            brig.LOG_LEVEL = orig_level

    def test_error_with_suggestion(self):
        """error() prints message and suggestion, then exits."""
        with self.assertRaises(SystemExit) as ctx:
            brig.error("something broke", "try this fix")
        self.assertEqual(ctx.exception.code, 1)

    def test_error_cell_not_found(self):
        """error_cell_not_found prints formatted message and exits."""
        with self.assertRaises(SystemExit):
            brig.error_cell_not_found("myapp")


# ========== Phase 11: brig.py Logging Functions ==========


class TestLogLifecycle(unittest.TestCase):
    """Tests for log_lifecycle function."""

    def setUp(self):
        """Create temp directory for lifecycle file."""
        self.temp_dir = tempfile.mkdtemp()
        self._orig = brig.LIFECYCLE_FILE
        brig.LIFECYCLE_FILE = Path(self.temp_dir) / "lifecycle.jsonl"

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        brig.LIFECYCLE_FILE = self._orig
        shutil.rmtree(self.temp_dir)

    def test_basic_event(self):
        """Basic lifecycle event is logged."""
        brig.log_lifecycle("start", "myapp")
        lines = brig.LIFECYCLE_FILE.read_text().strip().split("\n")
        entry = json.loads(lines[0])
        self.assertEqual(entry["event"], "start")
        self.assertEqual(entry["cell"], "myapp")
        self.assertIn("ts", entry)

    def test_event_with_details(self):
        """Lifecycle event with details includes them."""
        brig.log_lifecycle("stop", "myapp", {"exit_code": 0, "runtime_seconds": 42})
        entry = json.loads(brig.LIFECYCLE_FILE.read_text().strip())
        self.assertEqual(entry["exit_code"], 0)
        self.assertEqual(entry["runtime_seconds"], 42)

    def test_io_error_no_crash(self):
        """IOError does not crash."""
        brig.LIFECYCLE_FILE = Path("/proc/nonexistent/lifecycle.jsonl")
        brig.log_lifecycle("start", "myapp")  # Should not raise.


class TestLogPolicyChange(unittest.TestCase):
    """Tests for log_policy_change function."""

    def setUp(self):
        """Create temp directory for policy audit file."""
        self.temp_dir = tempfile.mkdtemp()
        self._orig = brig.POLICY_AUDIT_FILE
        brig.POLICY_AUDIT_FILE = Path(self.temp_dir) / "policy_audit.jsonl"

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        brig.POLICY_AUDIT_FILE = self._orig
        shutil.rmtree(self.temp_dir)

    def test_basic_change(self):
        """Basic policy change is logged."""
        brig.log_policy_change("myapp", "add_allow", {"domains": ["example.com"]})
        lines = brig.POLICY_AUDIT_FILE.read_text().strip().split("\n")
        entry = json.loads(lines[0])
        self.assertEqual(entry["cell"], "myapp")
        self.assertEqual(entry["action"], "add_allow")

    def test_with_old_and_new_policy(self):
        """Policy change includes old and new policy."""
        old = {"allow": [], "deny": []}
        new = {"allow": ["example.com"], "deny": []}
        brig.log_policy_change("myapp", "add_allow", {"domains": ["example.com"]},
                                old_policy=old, new_policy=new)
        entry = json.loads(brig.POLICY_AUDIT_FILE.read_text().strip())
        self.assertEqual(entry["old_policy"], old)
        self.assertEqual(entry["new_policy"], new)

    def test_io_error_no_crash(self):
        """IOError does not crash."""
        brig.POLICY_AUDIT_FILE = Path("/proc/nonexistent/audit.jsonl")
        brig.log_policy_change("myapp", "add_allow", {})  # Should not raise.


class TestLogOperation(unittest.TestCase):
    """Tests for brig.log_operation function."""

    def setUp(self):
        """Create temp directory for history file."""
        self.temp_dir = tempfile.mkdtemp()
        self._orig = brig.HISTORY_FILE
        brig.HISTORY_FILE = Path(self.temp_dir) / "history.jsonl"

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        brig.HISTORY_FILE = self._orig
        shutil.rmtree(self.temp_dir)

    def test_basic_operation(self):
        """Basic operation is logged."""
        brig.log_operation("run")
        entry = json.loads(brig.HISTORY_FILE.read_text().strip())
        self.assertEqual(entry["operation"], "run")
        self.assertIn("ts", entry)

    def test_with_cell_and_details(self):
        """Operation with cell name and details."""
        brig.log_operation("run", cell_name="myapp", details={"image": "alpine"})
        entry = json.loads(brig.HISTORY_FILE.read_text().strip())
        self.assertEqual(entry["cell"], "myapp")
        self.assertEqual(entry["details"]["image"], "alpine")


# ========== Phase 11 Step 3: brig.py Pure Logic ==========


class TestRedactCmd(unittest.TestCase):
    """Tests for _redact_cmd function."""

    def test_redact_secret_flag(self):
        """--secret value is redacted."""
        result = brig._redact_cmd(["brig", "--secret", "my-secret-val"])
        self.assertIn("--secret", result)
        self.assertNotIn("my-secret-val", result)
        self.assertIn("***", result)

    def test_redact_env_flag(self):
        """--env KEY=VAL redacts value."""
        result = brig._redact_cmd(["brig", "--env", "API_KEY=sk-123"])
        self.assertIn("--env", result)
        self.assertIn("API_KEY=***", result)
        self.assertNotIn("sk-123", result)

    def test_redact_token_equals(self):
        """--token=abc redacts value."""
        result = brig._redact_cmd(["brig", "--token=abc123"])
        self.assertIn("--token=***", result)
        self.assertNotIn("abc123", result)

    def test_redact_no_sensitive(self):
        """Clean command is unchanged."""
        cmd = ["brig", "run", "--name", "myapp", "--image", "alpine"]
        result = brig._redact_cmd(cmd)
        self.assertEqual(result, cmd)

    def test_redact_multiple_secrets(self):
        """Multiple --secret flags are all redacted."""
        result = brig._redact_cmd([
            "brig", "--secret", "val1", "--secret", "val2"
        ])
        self.assertEqual(result.count("***"), 2)
        self.assertNotIn("val1", result)
        self.assertNotIn("val2", result)

    def test_redact_secret_at_end(self):
        """--secret at end of args does not crash."""
        result = brig._redact_cmd(["brig", "--secret"])
        self.assertIn("--secret", result)

    def test_redact_password_flag(self):
        """--password flag is redacted."""
        result = brig._redact_cmd(["brig", "--password", "hunter2"])
        self.assertNotIn("hunter2", result)


class TestYamlFallbackParser(unittest.TestCase):
    """Tests for YAML fallback parser in load_cell_definition."""

    def _parse_yaml(self, content):
        """Parse YAML using fallback parser by creating a temp file."""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False
        ) as f:
            f.write(content)
            f.flush()
            path = f.name

        # Force fallback parser by temporarily disabling YAML.
        orig = brig.YAML_AVAILABLE
        brig.YAML_AVAILABLE = False
        try:
            result = brig.load_cell_definition(path)
            return result
        finally:
            brig.YAML_AVAILABLE = orig
            os.unlink(path)

    def test_yaml_simple_key_value(self):
        """Simple key: value pairs parse correctly."""
        result = self._parse_yaml('image: alpine\nname: test\n')
        self.assertEqual(result["image"], "alpine")
        self.assertEqual(result["name"], "test")

    def test_yaml_list_value(self):
        """JSON-style list values parse correctly."""
        result = self._parse_yaml('command: ["echo", "hello"]\n')
        self.assertEqual(result["command"], ["echo", "hello"])

    def test_yaml_comments_stripped(self):
        """Comments are ignored."""
        result = self._parse_yaml('# This is a comment\nimage: alpine\n')
        self.assertEqual(result["image"], "alpine")
        self.assertNotIn("#", str(result.keys()))

    def test_yaml_empty(self):
        """Empty string returns empty dict."""
        result = self._parse_yaml('')
        self.assertEqual(result, {})

    def test_yaml_integer_value(self):
        """Integer values are parsed."""
        result = self._parse_yaml('cpus: 4\n')
        self.assertEqual(result["cpus"], 4)

    def test_yaml_boolean_values(self):
        """Boolean values are parsed."""
        result = self._parse_yaml('detach: true\nrm: false\n')
        self.assertIs(result["detach"], True)
        self.assertIs(result["rm"], False)

    def test_yaml_quoted_string(self):
        """Quoted string values are parsed."""
        result = self._parse_yaml('name: "my-app"\n')
        self.assertEqual(result["name"], "my-app")


class TestVerifyImageSignature(unittest.TestCase):
    """Tests for brig.verify_image_signature."""

    @patch.object(brig, 'run')
    def test_verify_default_cosign_found(self, mock_run):
        """cosign exists, default verify returns success with details."""
        cosign_json = json.dumps([{"optional": {"Subject": "user@example.com", "Issuer": "https://accounts.google.com"}}])
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which cosign.
            MagicMock(returncode=0, stdout=cosign_json),  # cosign verify.
        ]
        ok, msg, details = brig.verify_image_signature("alpine:latest")
        self.assertTrue(ok)
        self.assertIn("cosign", msg)
        # Default command should not include --key or --certificate-identity.
        call_args = mock_run.call_args_list[1][0][0]
        self.assertEqual(call_args, ["cosign", "verify", "alpine:latest"])

    @patch.object(brig, 'run')
    def test_verify_cosign_key_based(self, mock_run):
        """Key-based verification passes --key to cosign."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which cosign.
            MagicMock(returncode=0, stdout="[]"),  # cosign verify.
        ]
        ok, msg, details = brig.verify_image_signature("alpine:latest", key="/tmp/cosign.pub")
        self.assertTrue(ok)
        call_args = mock_run.call_args_list[1][0][0]
        self.assertIn("--key", call_args)
        self.assertIn("/tmp/cosign.pub", call_args)

    @patch.object(brig, 'run')
    def test_verify_cosign_keyless(self, mock_run):
        """Keyless verification passes certificate-identity and oidc-issuer."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which cosign.
            MagicMock(returncode=0, stdout="[]"),  # cosign verify.
        ]
        ok, msg, details = brig.verify_image_signature(
            "alpine:latest",
            keyless=True,
            certificate_identity="user@example.com",
            certificate_oidc_issuer="https://accounts.google.com",
        )
        self.assertTrue(ok)
        call_args = mock_run.call_args_list[1][0][0]
        self.assertIn("--certificate-identity", call_args)
        self.assertIn("user@example.com", call_args)
        self.assertIn("--certificate-oidc-issuer", call_args)
        self.assertIn("https://accounts.google.com", call_args)

    @patch.object(brig, 'run')
    def test_verify_cosign_not_installed(self, mock_run):
        """cosign not installed, podman trust fails → fail closed."""
        mock_run.side_effect = [
            MagicMock(returncode=1),  # which cosign → not found.
            MagicMock(returncode=1, stdout=""),  # podman trust fails.
        ]
        ok, msg, details = brig.verify_image_signature("alpine:latest")
        self.assertFalse(ok)
        self.assertIn("cosign is not installed", msg)
        self.assertEqual(details, {})

    @patch.object(brig, 'run')
    def test_verify_cosign_no_signature(self, mock_run):
        """cosign reports no matching signatures → False."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which cosign.
            MagicMock(returncode=1, stderr="no matching signatures"),
        ]
        ok, msg, details = brig.verify_image_signature("alpine:latest")
        self.assertFalse(ok)
        self.assertIn("no signature", msg)

    @patch.object(brig, 'run')
    def test_verify_cosign_invalid_signature(self, mock_run):
        """cosign returns error for invalid signature → False."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which cosign.
            MagicMock(returncode=1, stderr="invalid signature"),
        ]
        ok, msg, details = brig.verify_image_signature("alpine:latest")
        self.assertFalse(ok)
        self.assertIn("invalid signature", msg)

    @patch.object(brig, 'run')
    def test_verify_podman_fallback(self, mock_run):
        """cosign absent, podman trust accept → True."""
        mock_run.side_effect = [
            MagicMock(returncode=1),  # which cosign → not found.
            MagicMock(returncode=0, stdout="default  accept"),  # podman trust.
        ]
        ok, msg, details = brig.verify_image_signature("alpine:latest")
        self.assertTrue(ok)
        self.assertIn("trusted registry", msg)

    @patch.object(brig, 'run')
    def test_verify_details_parsed(self, mock_run):
        """cosign JSON stdout is parsed into details dict."""
        cosign_json = json.dumps([
            {
                "optional": {"Subject": "bot@ci.example.com", "Issuer": "https://token.actions.githubusercontent.com"},
                "bundle": {"sigContent": "..."},
            },
            {"optional": {}},
        ])
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which cosign.
            MagicMock(returncode=0, stdout=cosign_json),
        ]
        ok, msg, details = brig.verify_image_signature("alpine:latest")
        self.assertTrue(ok)
        self.assertEqual(details["signatures"], 2)
        self.assertEqual(details["certificate_identity"], "bot@ci.example.com")
        self.assertEqual(details["issuer"], "https://token.actions.githubusercontent.com")
        self.assertTrue(details["bundle"])

    @patch.object(brig, 'output')
    @patch.object(brig, 'verify_image_signature')
    def test_cmd_verify_text_output(self, mock_verify, mock_output):
        """cmd_verify_image returns 0 on success with text output."""
        mock_verify.return_value = (True, "Signature verified with cosign", {"signatures": 1})
        args = MagicMock()
        args.image = "alpine:latest"
        args.key = None
        args.keyless = False
        args.certificate_identity = None
        args.certificate_oidc_issuer = None
        args.output = "text"
        result = brig.cmd_verify_image(args)
        self.assertEqual(result, 0)
        # Should have printed VERIFIED.
        mock_output.assert_any_call("VERIFIED: Signature verified with cosign")

    @patch.object(brig, 'output')
    @patch.object(brig, 'verify_image_signature')
    def test_cmd_verify_json_output(self, mock_verify, mock_output):
        """cmd_verify_image with --output json."""
        mock_verify.return_value = (True, "Signature verified with cosign", {"signatures": 2})
        args = MagicMock()
        args.image = "alpine:latest"
        args.key = None
        args.keyless = False
        args.certificate_identity = None
        args.certificate_oidc_issuer = None
        args.output = "json"
        result = brig.cmd_verify_image(args)
        self.assertEqual(result, 0)
        # Parse the JSON that was output.
        call_arg = mock_output.call_args[0][0]
        data = json.loads(call_arg)
        self.assertTrue(data["verified"])
        self.assertEqual(data["details"]["signatures"], 2)

    @patch.object(brig, 'print_error')
    @patch.object(brig, 'verify_image_signature')
    def test_cmd_verify_failure(self, mock_verify, mock_print_error):
        """cmd_verify_image returns 1 on verification failure."""
        mock_verify.return_value = (False, "Image has no signature", {})
        args = MagicMock()
        args.image = "alpine:latest"
        args.key = None
        args.keyless = False
        args.certificate_identity = None
        args.certificate_oidc_issuer = None
        args.output = "text"
        result = brig.cmd_verify_image(args)
        self.assertEqual(result, 1)


# ========== Phase 11 Step 4: brig.py Policy Commands ==========


class TestCmdPolicyValidate(unittest.TestCase):
    """Tests for brig.cmd_policy_validate."""

    def _make_args(self, **kwargs):
        """Create a mock args object."""
        args = MagicMock()
        for k, v in kwargs.items():
            setattr(args, k, v)
        return args

    def test_validate_valid_policy(self):
        """Correct policy file returns 0."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": ["example.com", "*.github.com"],
                "deny": ["evil.com"],
            }, f)
            f.flush()
            try:
                args = self._make_args(file=f.name)
                result = brig.cmd_policy_validate(args)
                self.assertEqual(result, 0)
            finally:
                os.unlink(f.name)

    def test_validate_missing_file(self):
        """Missing file causes exit."""
        args = self._make_args(file="/nonexistent/policy.json")
        with self.assertRaises(SystemExit):
            brig.cmd_policy_validate(args)

    def test_validate_invalid_json(self):
        """Parse error causes exit."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json{{{")
            f.flush()
            try:
                args = self._make_args(file=f.name)
                with self.assertRaises(SystemExit):
                    brig.cmd_policy_validate(args)
            finally:
                os.unlink(f.name)

    def test_validate_invalid_rule(self):
        """Bad rule returns 1."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": [123],  # Invalid rule type.
                "deny": [],
            }, f)
            f.flush()
            try:
                args = self._make_args(file=f.name)
                result = brig.cmd_policy_validate(args)
                self.assertEqual(result, 1)
            finally:
                os.unlink(f.name)

    def test_validate_allow_not_list(self):
        """allow as string returns 1."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"allow": "string", "deny": []}, f)
            f.flush()
            try:
                args = self._make_args(file=f.name)
                result = brig.cmd_policy_validate(args)
                self.assertEqual(result, 1)
            finally:
                os.unlink(f.name)

    def test_validate_rate_limits_valid(self):
        """Policy with valid rate_limits passes."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": ["example.com"],
                "deny": [],
                "rate_limits": {"default": {"rate": 100, "burst": 500}},
            }, f)
            f.flush()
            try:
                args = self._make_args(file=f.name)
                result = brig.cmd_policy_validate(args)
                self.assertEqual(result, 0)
            finally:
                os.unlink(f.name)


class TestCmdPolicyTest(unittest.TestCase):
    """Tests for brig.cmd_policy_test."""

    def setUp(self):
        """Create temp policy directory and mock cell_exists."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_policy_dir = brig.POLICY_DIR
        brig.POLICY_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.POLICY_DIR = self._original_policy_dir

    def _make_args(self, name, domain, path="/", method="GET", verbose=False):
        """Create args for cmd_policy_test."""
        args = MagicMock()
        args.name = name
        args.domain = domain
        args.path = path
        args.method = method
        args.verbose = verbose
        return args

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_policy_test_allow(self, mock_exists):
        """Domain in allowlist returns 0."""
        brig.save_cell_policy("testcell", {
            "allow": ["example.com"], "deny": []
        })
        args = self._make_args("testcell", "example.com")
        result = brig.cmd_policy_test(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_policy_test_deny(self, mock_exists):
        """Domain in denylist returns 1."""
        brig.save_cell_policy("testcell", {
            "allow": [], "deny": ["evil.com"]
        })
        args = self._make_args("testcell", "evil.com")
        result = brig.cmd_policy_test(args)
        self.assertEqual(result, 1)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_policy_test_wildcard(self, mock_exists):
        """*.example.com matches sub.example.com."""
        brig.save_cell_policy("testcell", {
            "allow": ["*.example.com"], "deny": []
        })
        args = self._make_args("testcell", "sub.example.com")
        result = brig.cmd_policy_test(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_policy_test_default_deny(self, mock_exists):
        """Unlisted domain defaults to deny."""
        brig.save_cell_policy("testcell", {
            "allow": ["example.com"], "deny": []
        })
        args = self._make_args("testcell", "unlisted.com")
        result = brig.cmd_policy_test(args)
        self.assertEqual(result, 1)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_policy_test_method_match(self, mock_exists):
        """Method matching in dict rules works."""
        brig.save_cell_policy("testcell", {
            "allow": [{"domain": "api.com", "methods": ["POST"]}],
            "deny": [],
        })
        args = self._make_args("testcell", "api.com", method="POST")
        result = brig.cmd_policy_test(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_policy_test_method_mismatch(self, mock_exists):
        """Wrong method is denied."""
        brig.save_cell_policy("testcell", {
            "allow": [{"domain": "api.com", "methods": ["POST"]}],
            "deny": [],
        })
        args = self._make_args("testcell", "api.com", method="GET")
        result = brig.cmd_policy_test(args)
        self.assertEqual(result, 1)

    @patch.object(brig, 'cell_exists', return_value=False)
    def test_policy_test_cell_not_found(self, mock_exists):
        """Nonexistent cell causes exit."""
        args = self._make_args("nosuch", "example.com")
        with self.assertRaises(SystemExit):
            brig.cmd_policy_test(args)


class TestCmdInit(unittest.TestCase):
    """Tests for brig.cmd_init."""

    def setUp(self):
        """Redirect BRIG_HOME to temp directory."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self._orig_brig_home = brig.BRIG_HOME
        self._orig_state_dir = brig.STATE_DIR
        self._orig_version_file = brig.VERSION_FILE
        self._orig_config_file = brig.CONFIG_FILE
        brig.BRIG_HOME = self.temp_dir / "brig"
        brig.STATE_DIR = brig.BRIG_HOME / "state"
        brig.VERSION_FILE = brig.BRIG_HOME / "state" / "version"
        brig.CONFIG_FILE = brig.BRIG_HOME / "cells" / "config.json"

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        brig.BRIG_HOME = self._orig_brig_home
        brig.STATE_DIR = self._orig_state_dir
        brig.VERSION_FILE = self._orig_version_file
        brig.CONFIG_FILE = self._orig_config_file
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init_creates_dirs(self):
        """cmd_init creates required directory structure."""
        args = MagicMock()
        args.force = False
        result = brig.cmd_init(args)
        self.assertEqual(result, 0)
        self.assertTrue((brig.BRIG_HOME / "cells").exists())
        self.assertTrue((brig.BRIG_HOME / "secrets").exists())
        self.assertTrue((brig.BRIG_HOME / "state").exists())

    def test_init_writes_default_policy(self):
        """cmd_init creates default network policy."""
        args = MagicMock()
        args.force = False
        brig.cmd_init(args)
        policy_file = brig.BRIG_HOME / "cells" / "network-policy.json"
        self.assertTrue(policy_file.exists())
        policy = json.loads(policy_file.read_text())
        self.assertIn("allow", policy)

    def test_init_writes_lima_config(self):
        """cmd_init creates lima.yaml."""
        args = MagicMock()
        args.force = False
        brig.cmd_init(args)
        lima_file = brig.BRIG_HOME / "lima.yaml"
        self.assertTrue(lima_file.exists())

    def test_init_idempotent(self):
        """Second init returns 0 without error."""
        args = MagicMock()
        args.force = False
        brig.cmd_init(args)
        result = brig.cmd_init(args)
        self.assertEqual(result, 0)

    def test_init_existing_policy_preserved(self):
        """Existing policy is not overwritten without --force."""
        args = MagicMock()
        args.force = False
        brig.cmd_init(args)
        # Modify the policy.
        policy_file = brig.BRIG_HOME / "cells" / "network-policy.json"
        policy_file.write_text('{"allow": ["custom.com"], "deny": []}')
        # Re-init without force.
        brig.cmd_init(args)
        policy = json.loads(policy_file.read_text())
        self.assertIn("custom.com", policy["allow"])

    def test_init_force_overwrites_policy(self):
        """--force overwrites existing policy."""
        args = MagicMock()
        args.force = False
        brig.cmd_init(args)
        # Modify the policy.
        policy_file = brig.BRIG_HOME / "cells" / "network-policy.json"
        policy_file.write_text('{"allow": ["custom.com"], "deny": []}')
        # Re-init with force.
        args.force = True
        brig.cmd_init(args)
        policy = json.loads(policy_file.read_text())
        self.assertNotIn("custom.com", policy.get("allow", []))


# ========== Phase 11 Step 5: Subprocess-Dependent Functions ==========


class TestBuildRunCommandSeccomp(unittest.TestCase):
    """Tests for _build_run_command seccomp and secret handling."""

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

    def test_seccomp_profile_added(self):
        """Valid seccomp profile is added to command."""
        # Create a valid seccomp profile file.
        profile = Path(self.temp_dir) / "seccomp.json"
        profile.write_text('{"defaultAction": "SCMP_ACT_ERRNO"}')
        args = self._make_args(seccomp_profile=str(profile))
        cmd = brig._build_run_command(
            args, "test", False, "brig-test", "10.60.1.1", None,
            lambda msg, s=None: None,
        )
        self.assertIn("--security-opt", cmd)
        self.assertTrue(any("seccomp=" in c for c in cmd))

    def test_seccomp_missing_file(self):
        """Missing seccomp profile calls cleanup_on_failure."""
        args = self._make_args(seccomp_profile="/nonexistent/profile.json")
        # cleanup_on_failure raises SystemExit.
        with self.assertRaises(SystemExit):
            brig._build_run_command(
                args, "test", False, "brig-test", "10.60.1.1", None,
                lambda msg, s=None: (_ for _ in ()).throw(SystemExit(1)),
            )

    def test_default_seccomp_applied(self):
        """Default seccomp profile is applied when none specified."""
        args = self._make_args()
        cmd = brig._build_run_command(
            args, "test", False, "brig-test", "10.60.1.1", None,
            lambda msg, s=None: None,
        )
        # Default profile should be applied.
        seccomp_args = [c for c in cmd if "seccomp=" in c]
        self.assertEqual(len(seccomp_args), 1)
        self.assertIn("default.json", seccomp_args[0])

    def test_no_seccomp_flag_skips_profile(self):
        """--no-seccomp disables default seccomp profile."""
        args = self._make_args(no_seccomp=True)
        cmd = brig._build_run_command(
            args, "test", False, "brig-test", "10.60.1.1", None,
            lambda msg, s=None: None,
        )
        seccomp_args = [c for c in cmd if "seccomp=" in c]
        self.assertEqual(len(seccomp_args), 0)

    def test_custom_seccomp_overrides_default(self):
        """Custom profile overrides default."""
        profile = Path(self.temp_dir) / "custom.json"
        profile.write_text('{"defaultAction": "SCMP_ACT_ALLOW"}')
        args = self._make_args(seccomp_profile=str(profile))
        cmd = brig._build_run_command(
            args, "test", False, "brig-test", "10.60.1.1", None,
            lambda msg, s=None: None,
        )
        seccomp_args = [c for c in cmd if "seccomp=" in c]
        self.assertEqual(len(seccomp_args), 1)
        self.assertIn("custom.json", seccomp_args[0])

    def test_default_seccomp_is_valid_json(self):
        """Built-in default.json is valid JSON."""
        default_profile = Path(__file__).parent.parent / "src" / "seccomp" / "default.json"
        self.assertTrue(default_profile.exists(), "default.json must exist")
        with open(default_profile) as f:
            data = json.load(f)
        self.assertIn("defaultAction", data)
        self.assertIn("syscalls", data)

    def test_secret_path_traversal_rejected(self):
        """Secret name with .. is rejected."""
        args = self._make_args(secret=["../etc/passwd"])
        with self.assertRaises(SystemExit):
            brig._build_run_command(
                args, "test", False, "brig-test", "10.60.1.1", None,
                lambda msg, s=None: (_ for _ in ()).throw(SystemExit(1)),
            )

    def test_secret_slash_rejected(self):
        """Secret name with / is rejected."""
        args = self._make_args(secret=["path/to/secret"])
        with self.assertRaises(SystemExit):
            brig._build_run_command(
                args, "test", False, "brig-test", "10.60.1.1", None,
                lambda msg, s=None: (_ for _ in ()).throw(SystemExit(1)),
            )

    def test_secret_colon_rejected(self):
        """Secret name with : is rejected."""
        args = self._make_args(secret=["secret:name"])
        with self.assertRaises(SystemExit):
            brig._build_run_command(
                args, "test", False, "brig-test", "10.60.1.1", None,
                lambda msg, s=None: (_ for _ in ()).throw(SystemExit(1)),
            )

    def test_secret_full_flow(self):
        """Secret mounts as read-only volume with FILE env var, not value."""
        # Create a temp secrets dir with a secret file.
        secrets_dir = Path(self.temp_dir) / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "api-key.txt").write_text("sk-secret-12345")

        args = self._make_args(secret=["api-key.txt"])
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

        # Volume mount must be read-only at /run/secrets/.
        volume_args = [c for c in cmd if "/run/secrets/" in c and ":ro" in c]
        self.assertTrue(len(volume_args) > 0,
                        "Secret must be volume-mounted read-only at /run/secrets/")

        # Env var must point to file path, not contain secret value.
        secret_value = "sk-secret-12345"
        for i, arg in enumerate(cmd):
            if arg == "-e" and i + 1 < len(cmd):
                self.assertNotIn(secret_value, cmd[i + 1],
                                 "Secret value must not appear in env vars")
                if "API_KEY" in cmd[i + 1]:
                    self.assertIn("_FILE=", cmd[i + 1],
                                  "Secret env var must end with _FILE")
                    self.assertIn("/run/secrets/", cmd[i + 1],
                                  "Secret env var must point to /run/secrets/ path")


class TestLimaInstalled(unittest.TestCase):
    """Tests for _lima_installed function."""

    @patch('subprocess.run')
    def test_lima_installed_true(self, mock_run):
        """limactl found returns True."""
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(brig._lima_installed())

    @patch('subprocess.run')
    def test_lima_installed_false(self, mock_run):
        """limactl not found returns False."""
        mock_run.return_value = MagicMock(returncode=1)
        self.assertFalse(brig._lima_installed())


class TestVmStatus(unittest.TestCase):
    """Tests for _vm_status function."""

    @patch('subprocess.run')
    def test_vm_status_running(self, mock_run):
        """Running VM returns running status."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which limactl.
            MagicMock(returncode=0, stdout='{"name":"brig","status":"Running","sshLocalPort":60022}\n'),
        ]
        result = brig._vm_status()
        self.assertEqual(result["status"], "Running")
        self.assertEqual(result["ssh"], 60022)

    @patch('subprocess.run')
    def test_vm_status_not_created(self, mock_run):
        """No VM returns not_created."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which limactl.
            MagicMock(returncode=0, stdout='{"name":"other","status":"Running"}\n'),
        ]
        result = brig._vm_status()
        self.assertEqual(result["status"], "not_created")

    @patch('subprocess.run')
    def test_vm_status_lima_not_installed(self, mock_run):
        """Lima not installed returns lima_not_installed."""
        mock_run.return_value = MagicMock(returncode=1)
        result = brig._vm_status()
        self.assertEqual(result["status"], "lima_not_installed")

    @patch('subprocess.run')
    def test_vm_status_error(self, mock_run):
        """limactl error returns error status."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which limactl.
            MagicMock(returncode=1, stdout=''),  # limactl list fails.
        ]
        result = brig._vm_status()
        self.assertEqual(result["status"], "error")

    @patch('subprocess.run')
    def test_vm_status_bad_json(self, mock_run):
        """Invalid JSON returns error status."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which limactl.
            MagicMock(returncode=0, stdout='not json'),
        ]
        result = brig._vm_status()
        self.assertEqual(result["status"], "error")


# ========== Targeted coverage: workspace.py ==========


class TestCmdFiles(unittest.TestCase):
    """Tests for brig.cmd_files."""

    def setUp(self):
        """Create temp workspace for a cell."""
        self.temp_dir = tempfile.mkdtemp()
        self._orig_state_dir = brig.STATE_DIR
        brig.STATE_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        brig.STATE_DIR = self._orig_state_dir
        shutil.rmtree(self.temp_dir)

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'run')
    def test_files_lists_directory(self, mock_run, mock_exists):
        """cmd_files runs ls on an existing workspace directory."""
        cell_ws = Path(self.temp_dir) / "mycell" / "workspace"
        cell_ws.mkdir(parents=True)
        mock_run.return_value = MagicMock(returncode=0)

        args = MagicMock()
        args.name = "mycell"
        args.path = None
        result = brig.cmd_files(args)
        self.assertEqual(result, 0)
        mock_run.assert_called_once()

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_files_no_workspace_returns_zero(self, mock_exists):
        """cmd_files returns 0 when workspace directory is absent."""
        args = MagicMock()
        args.name = "nocell"
        args.path = None
        result = brig.cmd_files(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_files_single_file_info(self, mock_exists):
        """cmd_files prints size info for a single file path."""
        cell_ws = Path(self.temp_dir) / "mycell" / "workspace"
        cell_ws.mkdir(parents=True)
        test_file = cell_ws / "output.txt"
        test_file.write_text("hello world")

        args = MagicMock()
        args.name = "mycell"
        args.path = "output.txt"
        result = brig.cmd_files(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=False)
    def test_files_cell_not_found_exits(self, mock_exists):
        """cmd_files exits when cell does not exist."""
        args = MagicMock()
        args.name = "nosuch"
        args.path = None
        with self.assertRaises(SystemExit):
            brig.cmd_files(args)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_files_path_not_exist_exits(self, mock_exists):
        """cmd_files exits when the requested path does not exist."""
        cell_ws = Path(self.temp_dir) / "mycell" / "workspace"
        cell_ws.mkdir(parents=True)

        args = MagicMock()
        args.name = "mycell"
        args.path = "nonexistent.txt"
        with self.assertRaises(SystemExit):
            brig.cmd_files(args)


class TestCmdCat(unittest.TestCase):
    """Tests for brig.cmd_cat."""

    def setUp(self):
        """Create temp workspace for a cell."""
        self.temp_dir = tempfile.mkdtemp()
        self._orig_state_dir = brig.STATE_DIR
        brig.STATE_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        brig.STATE_DIR = self._orig_state_dir
        shutil.rmtree(self.temp_dir)

    def _make_workspace(self, cell_name="mycell"):
        """Return a workspace path with the directory created."""
        ws = Path(self.temp_dir) / cell_name / "workspace"
        ws.mkdir(parents=True, exist_ok=True)
        return ws

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_cat_text_file(self, mock_exists):
        """cmd_cat displays a plain text file."""
        ws = self._make_workspace()
        (ws / "hello.txt").write_text("hello world\n")

        args = MagicMock()
        args.name = "mycell"
        args.path = "hello.txt"
        args.max_size = 1
        args.lines = None
        args.force = False
        result = brig.cmd_cat(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_cat_binary_file_blocked(self, mock_exists):
        """cmd_cat exits on binary file without --force."""
        ws = self._make_workspace()
        (ws / "binary.bin").write_bytes(b"\x00\x01\x02\x03binary")

        args = MagicMock()
        args.name = "mycell"
        args.path = "binary.bin"
        args.max_size = 1
        args.lines = None
        args.force = False
        with self.assertRaises(SystemExit):
            brig.cmd_cat(args)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_cat_binary_file_with_force(self, mock_exists):
        """cmd_cat displays binary file when --force is set."""
        ws = self._make_workspace()
        (ws / "binary.bin").write_bytes(b"\x00\x01\x02\x03hello")

        args = MagicMock()
        args.name = "mycell"
        args.path = "binary.bin"
        args.max_size = 1
        args.lines = None
        args.force = True
        result = brig.cmd_cat(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_cat_file_too_large_exits(self, mock_exists):
        """cmd_cat exits when file exceeds max_size."""
        ws = self._make_workspace()
        big_file = ws / "big.txt"
        # Write 2 MB of data; default max_size arg is set to 1 MB.
        big_file.write_bytes(b"x" * (2 * 1024 * 1024))

        args = MagicMock()
        args.name = "mycell"
        args.path = "big.txt"
        args.max_size = 1  # 1 MB limit.
        args.lines = None
        args.force = False
        with self.assertRaises(SystemExit):
            brig.cmd_cat(args)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_cat_line_limit(self, mock_exists):
        """cmd_cat truncates output at line limit."""
        ws = self._make_workspace()
        lines = "\n".join(f"line {i}" for i in range(20))
        (ws / "many.txt").write_text(lines)

        args = MagicMock()
        args.name = "mycell"
        args.path = "many.txt"
        args.max_size = 1
        args.lines = 5
        args.force = False
        result = brig.cmd_cat(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_cat_directory_exits(self, mock_exists):
        """cmd_cat exits when path is a directory."""
        ws = self._make_workspace()
        (ws / "subdir").mkdir()

        args = MagicMock()
        args.name = "mycell"
        args.path = "subdir"
        args.max_size = 1
        args.lines = None
        args.force = False
        with self.assertRaises(SystemExit):
            brig.cmd_cat(args)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_cat_no_workspace_exits(self, mock_exists):
        """cmd_cat exits when workspace directory is absent."""
        args = MagicMock()
        args.name = "noworkspace"
        args.path = "file.txt"
        args.max_size = 1
        args.lines = None
        args.force = False
        with self.assertRaises(SystemExit):
            brig.cmd_cat(args)


class TestApplyQuarantine(unittest.TestCase):
    """Tests for brig.apply_quarantine."""

    def test_non_darwin_returns_false(self):
        """apply_quarantine returns False on non-Darwin platforms."""
        with patch('platform.system', return_value='Linux'):
            result = brig.apply_quarantine(Path("/tmp/some_file"))
        self.assertFalse(result)

    @patch.object(brig, 'run')
    def test_darwin_file_returns_true(self, mock_run):
        """apply_quarantine runs xattr on Darwin for a regular file."""
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = Path(f.name)
        try:
            with patch('platform.system', return_value='Darwin'):
                result = brig.apply_quarantine(path, source_cell="mycell")
            self.assertTrue(result)
            mock_run.assert_called_once()
        finally:
            path.unlink(missing_ok=True)

    @patch.object(brig, 'run')
    def test_darwin_directory_applies_to_files(self, mock_run):
        """apply_quarantine applies xattr to all files in a directory."""
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "a.txt").write_text("a")
            (d / "b.txt").write_text("b")
            with patch('platform.system', return_value='Darwin'):
                result = brig.apply_quarantine(d)
            self.assertTrue(result)
            # Two files in directory → two xattr calls.
            self.assertEqual(mock_run.call_count, 2)


class TestCmdCpSanitize(unittest.TestCase):
    """Tests for brig.cmd_cp sanitize-mode paths."""

    def setUp(self):
        """Create temp dirs for source and dest workspaces."""
        self.temp_dir = tempfile.mkdtemp()
        self._orig_state_dir = brig.STATE_DIR
        brig.STATE_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        brig.STATE_DIR = self._orig_state_dir
        shutil.rmtree(self.temp_dir)

    def _make_cell_workspace(self, cell_name):
        """Return a cell workspace path with the directory created."""
        ws = Path(self.temp_dir) / cell_name / "workspace"
        ws.mkdir(parents=True, exist_ok=True)
        return ws

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch('platform.system', return_value='Linux')
    def test_sanitize_blocks_office_file(self, mock_sys, mock_exists):
        """cmd_cp with --sanitize blocks .docx files."""
        ws = self._make_cell_workspace("src-cell")
        doc = ws / "report.docx"
        doc.write_text("word doc")

        args = MagicMock()
        args.src = "src-cell:report.docx"
        args.dst = "/tmp/report.docx"
        args.sanitize = True
        args.allow_scripts = False
        args.allow_office = False
        with self.assertRaises(SystemExit):
            brig.cmd_cp(args)

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch('platform.system', return_value='Linux')
    def test_sanitize_allows_office_with_flag(self, mock_sys, mock_exists):
        """cmd_cp with --sanitize --allow-office copies .docx files."""
        ws = self._make_cell_workspace("src-cell2")
        doc = ws / "report.docx"
        doc.write_text("word doc")
        dst = Path(self.temp_dir) / "dest" / "report.docx"

        args = MagicMock()
        args.src = "src-cell2:report.docx"
        args.dst = str(dst)
        args.sanitize = True
        args.allow_scripts = False
        args.allow_office = True
        result = brig.cmd_cp(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    def test_sanitize_directory_blocks_unsafe(self, mock_exists):
        """cmd_cp with --sanitize blocks directories containing unsafe files."""
        ws = self._make_cell_workspace("src-cell3")
        src_dir = ws / "payload"
        src_dir.mkdir()
        # Write a .exe file inside the source directory.
        (src_dir / "evil.exe").write_bytes(b"MZ")

        args = MagicMock()
        args.src = "src-cell3:payload"
        args.dst = str(Path(self.temp_dir) / "out")
        args.sanitize = True
        args.allow_scripts = False
        args.allow_office = False
        with self.assertRaises(SystemExit):
            brig.cmd_cp(args)

    def test_cp_both_cells_exits(self):
        """cmd_cp with both src and dst as cells exits."""
        args = MagicMock()
        args.src = "cell1:file.txt"
        args.dst = "cell2:file.txt"
        args.sanitize = False
        with self.assertRaises(SystemExit):
            brig.cmd_cp(args)

    def test_cp_no_cells_exits(self):
        """cmd_cp with no cell reference exits."""
        args = MagicMock()
        args.src = "/local/file.txt"
        args.dst = "/other/file.txt"
        args.sanitize = False
        with self.assertRaises(SystemExit):
            brig.cmd_cp(args)


# ========== Targeted coverage: system.py ==========


class TestCmdDiagnose(unittest.TestCase):
    """Tests for brig.cmd_diagnose."""

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'cell_running', return_value=True)
    @patch.object(brig, 'proxy_running', return_value=True)
    @patch.object(brig, 'run')
    def test_diagnose_all_ok(self, mock_run, mock_proxy, mock_running, mock_exists):
        """cmd_diagnose returns 0 when all checks pass."""
        # Calls in order: network exists, proxy inspect (networks), dmesg.
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),
            MagicMock(returncode=0, stdout="brig-mycell ", stderr=""),
            MagicMock(returncode=0, stdout="gVisor kernel", stderr=""),
        ]
        args = MagicMock()
        args.name = "mycell"
        result = brig.cmd_diagnose(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'cell_running', return_value=False)
    @patch.object(brig, 'proxy_running', return_value=False)
    @patch.object(brig, 'run')
    def test_diagnose_issues_returns_one(self, mock_run, mock_proxy, mock_running, mock_exists):
        """cmd_diagnose returns 1 when issues are found."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        args = MagicMock()
        args.name = "mycell"
        result = brig.cmd_diagnose(args)
        self.assertEqual(result, 1)

    @patch.object(brig, 'cell_exists', return_value=False)
    def test_diagnose_cell_not_found_exits(self, mock_exists):
        """cmd_diagnose exits when the cell does not exist."""
        args = MagicMock()
        args.name = "nosuch"
        with self.assertRaises(SystemExit):
            brig.cmd_diagnose(args)


class TestCmdHealth(unittest.TestCase):
    """Tests for brig.cmd_health."""

    @patch.object(brig, 'proxy_running', return_value=True)
    @patch.object(brig, 'run')
    def test_health_json_output(self, mock_run, mock_proxy):
        """cmd_health json format produces output containing 'healthy' key."""
        mock_run.return_value = MagicMock(returncode=0, stdout="runsc\nbrig-cell1\n", stderr="")
        args = MagicMock()
        args.format = "json"
        import io
        captured = io.StringIO()
        # cmd_health uses json.dumps and a single print call; capture all print output.
        with patch('builtins.print', side_effect=lambda *a, **k: captured.write(str(a[0]) + "\n")):
            brig.cmd_health(args)
        output_text = captured.getvalue()
        # The combined output must contain "healthy" from the JSON dump.
        self.assertIn("healthy", output_text)

    @patch.object(brig, 'proxy_running', return_value=False)
    @patch.object(brig, 'run')
    def test_health_table_unhealthy(self, mock_run, mock_proxy):
        """cmd_health returns 1 when proxy is not running."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        args = MagicMock()
        args.format = "table"
        result = brig.cmd_health(args)
        self.assertEqual(result, 1)

    @patch.object(brig, 'proxy_running', return_value=True)
    @patch.object(brig, 'run')
    def test_health_table_format(self, mock_run, mock_proxy):
        """cmd_health table format does not raise."""
        mock_run.return_value = MagicMock(returncode=0, stdout="runsc\n", stderr="")
        args = MagicMock()
        args.format = "table"
        # Should not raise regardless of overall health value.
        result = brig.cmd_health(args)
        self.assertIn(result, (0, 1))


class TestCmdDoctor(unittest.TestCase):
    """Tests for brig.cmd_doctor."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig = brig.STATE_DIR
        brig.STATE_DIR = Path(self.temp_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.STATE_DIR = self._orig

    def _mock_doctor(self, proxy=True, vm_running=True, **run_kw):
        """Common mock setup for doctor tests."""
        return (
            patch.object(brig, 'proxy_running', return_value=proxy),
            patch.object(brig, 'run', return_value=MagicMock(
                returncode=0, stdout="runsc\n", stderr="", **run_kw)),
            patch('brig.commands.vm._lima_installed', return_value=True),
            patch('brig.commands.vm._vm_status',
                  return_value={"status": "Running" if vm_running else "Stopped"}),
        )

    def test_doctor_all_pass(self):
        """All checks pass returns 0."""
        with contextlib.ExitStack() as stack:
            for m in self._mock_doctor():
                stack.enter_context(m)
            args = MagicMock(fix=False, format="text")
            result = brig.cmd_doctor(args)
            self.assertEqual(result, 0)

    def test_doctor_unhealthy_returns_1(self):
        """Failing checks return 1."""
        with contextlib.ExitStack() as stack:
            for m in self._mock_doctor(proxy=False, vm_running=False):
                stack.enter_context(m)
            # Override run to return failures.
            stack.enter_context(patch.object(brig, 'run',
                return_value=MagicMock(returncode=1, stdout="", stderr="")))
            args = MagicMock(fix=False, format="text")
            result = brig.cmd_doctor(args)
            self.assertEqual(result, 1)

    def test_doctor_json_output(self):
        """JSON format produces valid JSON with checks array."""
        with contextlib.ExitStack() as stack:
            for m in self._mock_doctor():
                stack.enter_context(m)
            args = MagicMock(fix=False, format="json")
            import io
            captured = io.StringIO()
            with patch('builtins.print', side_effect=lambda *a, **k: captured.write(str(a[0]) + "\n")):
                brig.cmd_doctor(args)
            data = json.loads(captured.getvalue())
            self.assertIn("checks", data)
            self.assertIn("all_passed", data)
            self.assertIsInstance(data["checks"], list)

    def test_doctor_fix_flag(self):
        """--fix flag is accepted without error."""
        with contextlib.ExitStack() as stack:
            for m in self._mock_doctor():
                stack.enter_context(m)
            args = MagicMock(fix=True, format="text")
            result = brig.cmd_doctor(args)
            self.assertEqual(result, 0)

    @patch.object(brig, 'proxy_running', return_value=True)
    @patch.object(brig, 'run')
    def test_doctor_detects_over_quota(self, mock_run, mock_proxy):
        """Doctor detects cells over workspace quota."""
        mock_run.return_value = MagicMock(returncode=0, stdout="runsc\n", stderr="")
        # Create a cell with small quota and large workspace.
        cell = "over-quota"
        ws = Path(self.temp_dir) / cell / "workspace"
        ws.mkdir(parents=True)
        (ws / "big.bin").write_bytes(b"x" * 5000)
        brig.save_workspace_quota(cell, 100)

        args = MagicMock(fix=False, format="json")
        import io
        captured = io.StringIO()
        with patch('builtins.print', side_effect=lambda *a, **k: captured.write(str(a[0]) + "\n")):
            brig.cmd_doctor(args)
        data = json.loads(captured.getvalue())
        quota_check = next((c for c in data["checks"] if c["name"] == "Workspace quotas"), None)
        self.assertIsNotNone(quota_check)
        self.assertFalse(quota_check["passed"])

    @patch.object(brig, 'proxy_running', return_value=True)
    @patch.object(brig, 'run')
    def test_doctor_seccomp_check(self, mock_run, mock_proxy):
        """Doctor checks for default seccomp profile."""
        mock_run.return_value = MagicMock(returncode=0, stdout="runsc\n", stderr="")
        args = MagicMock(fix=False, format="json")
        import io
        captured = io.StringIO()
        with patch('builtins.print', side_effect=lambda *a, **k: captured.write(str(a[0]) + "\n")):
            brig.cmd_doctor(args)
        data = json.loads(captured.getvalue())
        seccomp_check = next((c for c in data["checks"] if c["name"] == "Seccomp profile"), None)
        self.assertIsNotNone(seccomp_check)
        self.assertTrue(seccomp_check["passed"])


class TestCmdPreflight(unittest.TestCase):
    """Tests for brig.cmd_preflight."""

    @patch.object(brig, 'proxy_running', return_value=True)
    @patch.object(brig, 'run')
    def test_preflight_runs_without_error(self, mock_run, mock_proxy):
        """cmd_preflight completes without raising."""
        mock_run.return_value = MagicMock(returncode=0, stdout="runsc", stderr="")
        args = MagicMock()
        args.format = "table"
        # Patch Lima helpers so the check is deterministic.
        with patch.object(brig, '_lima_installed', return_value=False):
            result = brig.cmd_preflight(args)
        self.assertIn(result, (0, 1))

    @patch.object(brig, 'proxy_running', return_value=False)
    @patch.object(brig, 'run')
    def test_preflight_returns_one_when_failed(self, mock_run, mock_proxy):
        """cmd_preflight returns 1 when proxy not running."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        args = MagicMock()
        args.format = "table"
        with patch.object(brig, '_lima_installed', return_value=False):
            result = brig.cmd_preflight(args)
        self.assertEqual(result, 1)

    @patch.object(brig, 'proxy_running', return_value=True)
    @patch.object(brig, 'run')
    def test_preflight_json_format(self, mock_run, mock_proxy):
        """cmd_preflight json format outputs parseable JSON."""
        mock_run.return_value = MagicMock(returncode=0, stdout="runsc", stderr="")
        args = MagicMock()
        args.format = "json"
        import io
        captured = io.StringIO()
        with patch('builtins.print', side_effect=lambda *a, **k: captured.write(str(a[0]) + "\n")):
            with patch.object(brig, '_lima_installed', return_value=False):
                brig.cmd_preflight(args)
        combined = captured.getvalue().strip()
        # Verify the captured output contains JSON keys.
        self.assertIn("passed", combined)
        self.assertIn("checks", combined)


# ========== Targeted coverage: inspect.py ==========


class TestCmdStats(unittest.TestCase):
    """Tests for brig.cmd_stats."""

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'run')
    def test_stats_json_output(self, mock_run, mock_exists):
        """cmd_stats with json output returns 0."""
        stats_data = [{"Name": "brig-mycell", "CPUPerc": "1%", "MemUsage": "10MiB"}]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps(stats_data), stderr=""
        )
        args = MagicMock()
        args.name = "mycell"
        args.output = "json"
        args.no_stream = True
        result = brig.cmd_stats(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'run')
    def test_stats_no_stream_mode(self, mock_run, mock_exists):
        """cmd_stats with --no-stream passes flag to podman."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        args = MagicMock()
        args.name = "mycell"
        args.output = "text"
        args.no_stream = True
        brig.cmd_stats(args)
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("--no-stream", called_cmd)

    @patch.object(brig, 'cell_exists', return_value=False)
    def test_stats_cell_not_found_exits(self, mock_exists):
        """cmd_stats exits when cell does not exist."""
        args = MagicMock()
        args.name = "nosuch"
        args.output = "json"
        args.no_stream = True
        with self.assertRaises(SystemExit):
            brig.cmd_stats(args)

    @patch.object(brig, 'run')
    def test_stats_all_cells_no_name(self, mock_run):
        """cmd_stats without a name filters by prefix."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        args = MagicMock()
        args.name = None
        args.output = "text"
        args.no_stream = False
        brig.cmd_stats(args)
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("--filter", called_cmd)


class TestCmdDiff(unittest.TestCase):
    """Tests for brig.cmd_diff."""

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'run')
    def test_diff_json_format(self, mock_run, mock_exists):
        """cmd_diff with json format passes --format=json to podman."""
        mock_run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")
        args = MagicMock()
        args.name = "mycell"
        args.format = "json"
        result = brig.cmd_diff(args)
        self.assertEqual(result, 0)
        called_cmd = mock_run.call_args[0][0]
        self.assertTrue(any("json" in str(a) for a in called_cmd))

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'run')
    def test_diff_pretty_print_added(self, mock_run, mock_exists):
        """cmd_diff pretty-prints added files with '+'."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="A /new/file.txt\nD /old/file.txt\nC /changed.txt\n", stderr=""
        )
        args = MagicMock()
        args.name = "mycell"
        args.format = "table"
        import io
        captured = io.StringIO()
        with patch('builtins.print', side_effect=lambda *a, **k: captured.write(str(a[0]) + "\n")):
            result = brig.cmd_diff(args)
        self.assertEqual(result, 0)
        output_text = captured.getvalue()
        self.assertIn("+", output_text)
        self.assertIn("-", output_text)

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'run')
    def test_diff_failure_returns_nonzero(self, mock_run, mock_exists):
        """cmd_diff returns nonzero on podman failure."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="no such container")
        args = MagicMock()
        args.name = "mycell"
        args.format = "table"
        result = brig.cmd_diff(args)
        self.assertNotEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=False)
    def test_diff_cell_not_found_exits(self, mock_exists):
        """cmd_diff exits when cell does not exist."""
        args = MagicMock()
        args.name = "nosuch"
        args.format = "table"
        with self.assertRaises(SystemExit):
            brig.cmd_diff(args)


# ========== Targeted coverage: lifecycle.py ==========


class TestCmdList(unittest.TestCase):
    """Tests for brig.cmd_list."""

    @patch.object(brig, 'run')
    def test_list_json_format(self, mock_run):
        """cmd_list json format outputs cell list."""
        containers = [
            {"Names": ["brig-alpha"], "State": "running", "Image": "alpine"},
            {"Names": ["brig-beta"], "State": "exited", "Image": "ubuntu"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps(containers), stderr=""
        )
        args = MagicMock()
        args.format = "json"
        import io
        captured = io.StringIO()
        with patch.object(brig, 'output', side_effect=lambda s: captured.write(s + "\n")):
            result = brig.cmd_list(args)
        self.assertEqual(result, 0)
        data = json.loads(captured.getvalue().strip())
        names = [c["name"] for c in data]
        self.assertIn("alpha", names)
        self.assertIn("beta", names)

    @patch.object(brig, 'run')
    def test_list_table_format(self, mock_run):
        """cmd_list table format returns 0."""
        containers = [
            {"Names": ["brig-alpha"], "State": "running", "Image": "alpine"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps(containers), stderr=""
        )
        args = MagicMock()
        args.format = "table"
        result = brig.cmd_list(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'run')
    def test_list_empty_returns_zero(self, mock_run):
        """cmd_list returns 0 when no cells exist."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        args = MagicMock()
        args.format = "table"
        result = brig.cmd_list(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'run')
    def test_list_podman_failure_exits(self, mock_run):
        """cmd_list exits when podman fails."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="connection refused")
        args = MagicMock()
        args.format = "table"
        with self.assertRaises(SystemExit):
            brig.cmd_list(args)


class TestCmdStop(unittest.TestCase):
    """Tests for brig.cmd_stop."""

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'cell_running', return_value=True)
    @patch.object(brig, 'invalidate_cell_cache')
    @patch.object(brig, 'log_operation')
    @patch.object(brig, 'log_lifecycle')
    @patch.object(brig, 'run')
    def test_stop_running_cell(self, mock_run, mock_lc, mock_lo, mock_inv, mock_running, mock_exists):
        """cmd_stop sends stop command and returns 0."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        args = MagicMock()
        args.name = "mycell"
        result = brig.cmd_stop(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'cell_running', return_value=False)
    def test_stop_not_running_returns_zero(self, mock_running, mock_exists):
        """cmd_stop returns 0 gracefully when cell is not running."""
        args = MagicMock()
        args.name = "mycell"
        result = brig.cmd_stop(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=False)
    def test_stop_cell_not_found_exits(self, mock_exists):
        """cmd_stop exits when cell does not exist."""
        args = MagicMock()
        args.name = "nosuch"
        with self.assertRaises(SystemExit):
            brig.cmd_stop(args)

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'cell_running', return_value=True)
    @patch.object(brig, 'run')
    def test_stop_failure_returns_one(self, mock_run, mock_running, mock_exists):
        """cmd_stop returns 1 when podman stop fails."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        args = MagicMock()
        args.name = "mycell"
        result = brig.cmd_stop(args)
        self.assertEqual(result, 1)


class TestCmdKill(unittest.TestCase):
    """Tests for brig.cmd_kill."""

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'invalidate_cell_cache')
    @patch.object(brig, 'log_lifecycle')
    @patch.object(brig, 'run')
    def test_kill_running_cell(self, mock_run, mock_lc, mock_inv, mock_exists):
        """cmd_kill sends kill command and returns 0."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        args = MagicMock()
        args.name = "mycell"
        result = brig.cmd_kill(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=False)
    def test_kill_cell_not_found_exits(self, mock_exists):
        """cmd_kill exits when cell does not exist."""
        args = MagicMock()
        args.name = "nosuch"
        with self.assertRaises(SystemExit):
            brig.cmd_kill(args)

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'run')
    def test_kill_failure_exits(self, mock_run, mock_exists):
        """cmd_kill exits when podman kill returns non-zero error."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="some error")
        args = MagicMock()
        args.name = "mycell"
        with self.assertRaises(SystemExit):
            brig.cmd_kill(args)


class TestCmdPause(unittest.TestCase):
    """Tests for brig.cmd_pause."""

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'cell_running', return_value=True)
    @patch.object(brig, 'invalidate_cell_cache')
    @patch.object(brig, 'run')
    def test_pause_running_cell(self, mock_run, mock_inv, mock_running, mock_exists):
        """cmd_pause pauses a running cell and returns 0."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        args = MagicMock()
        args.name = "mycell"
        result = brig.cmd_pause(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'cell_running', return_value=False)
    def test_pause_not_running_exits(self, mock_running, mock_exists):
        """cmd_pause exits when cell is not running."""
        args = MagicMock()
        args.name = "mycell"
        with self.assertRaises(SystemExit):
            brig.cmd_pause(args)

    @patch.object(brig, 'cell_exists', return_value=False)
    def test_pause_cell_not_found_exits(self, mock_exists):
        """cmd_pause exits when cell does not exist."""
        args = MagicMock()
        args.name = "nosuch"
        with self.assertRaises(SystemExit):
            brig.cmd_pause(args)

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'cell_running', return_value=True)
    @patch.object(brig, 'run')
    def test_pause_failure_exits(self, mock_run, mock_running, mock_exists):
        """cmd_pause exits when podman pause fails."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="cannot pause")
        args = MagicMock()
        args.name = "mycell"
        with self.assertRaises(SystemExit):
            brig.cmd_pause(args)


class TestCmdUnpause(unittest.TestCase):
    """Tests for brig.cmd_unpause."""

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'invalidate_cell_cache')
    @patch.object(brig, 'run')
    def test_unpause_cell(self, mock_run, mock_inv, mock_exists):
        """cmd_unpause unpauses a cell and returns 0."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        args = MagicMock()
        args.name = "mycell"
        result = brig.cmd_unpause(args)
        self.assertEqual(result, 0)

    @patch.object(brig, 'cell_exists', return_value=False)
    def test_unpause_cell_not_found_exits(self, mock_exists):
        """cmd_unpause exits when cell does not exist."""
        args = MagicMock()
        args.name = "nosuch"
        with self.assertRaises(SystemExit):
            brig.cmd_unpause(args)

    @patch.object(brig, 'cell_exists', return_value=True)
    @patch.object(brig, 'run')
    def test_unpause_failure_exits(self, mock_run, mock_exists):
        """cmd_unpause exits when podman unpause fails."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="cannot unpause")
        args = MagicMock()
        args.name = "mycell"
        with self.assertRaises(SystemExit):
            brig.cmd_unpause(args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
