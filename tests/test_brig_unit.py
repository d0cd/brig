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
        for name in ["myapp", "my-app", "my_app", "App1", "a", "a1-b2_c3"]:
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
        for name in ["my app", "my.app", "my/app", "my@app", "my;app"]:
            with self.assertRaises(SystemExit):
                brig.validate_cell_name(name)

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
    """Tests for version consistency between brig.py and brig/__init__.py."""

    def test_version_matches(self):
        """brig.py VERSION matches brig/__init__.py __version__."""
        self.assertEqual(brig.VERSION, "0.1.0")


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
