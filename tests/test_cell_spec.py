"""Tests for brig.cell.spec — CellSpec, validation, loading.

Covers invariants 1, 6, 8 (network validation).
"""

import json
import tempfile
import unittest
from pathlib import Path

from brig.cell.spec import (
    CellSpec,
    load_cell_definition,
    parse_duration,
    parse_size,
    validate_cell_definition,
)


class TestValidateCellDefinition(unittest.TestCase):
    """Test validate_cell_definition() catches errors and enforces invariants."""

    def test_valid_minimal(self):
        errors = validate_cell_definition({"name": "test", "image": "alpine"})
        self.assertEqual(errors, [])

    def test_invalid_name(self):
        errors = validate_cell_definition({"name": "INVALID!"})
        self.assertTrue(any("must match pattern" in e for e in errors))

    def test_name_not_string(self):
        errors = validate_cell_definition({"name": 123})
        self.assertTrue(any("must be a string" in e for e in errors))

    def test_image_empty(self):
        errors = validate_cell_definition({"image": ""})
        self.assertTrue(any("non-empty string" in e for e in errors))

    def test_command_string(self):
        errors = validate_cell_definition({"command": "echo hi"})
        self.assertEqual(errors, [])

    def test_command_list(self):
        errors = validate_cell_definition({"command": ["echo", "hi"]})
        self.assertEqual(errors, [])

    def test_command_list_non_string(self):
        errors = validate_cell_definition({"command": [1, 2]})
        self.assertTrue(any("strings" in e for e in errors))

    def test_env_dict(self):
        errors = validate_cell_definition({"env": {"FOO": "bar"}})
        self.assertEqual(errors, [])

    def test_env_list(self):
        errors = validate_cell_definition({"env": ["FOO=bar"]})
        self.assertEqual(errors, [])

    def test_env_list_no_equals(self):
        errors = validate_cell_definition({"env": ["NOEQUALS"]})
        self.assertTrue(any("KEY=value" in e for e in errors))

    def test_secrets_traversal(self):
        errors = validate_cell_definition({"secrets": ["../etc/passwd"]})
        self.assertTrue(any("path traversal" in e for e in errors))

    def test_invalid_memory(self):
        errors = validate_cell_definition({"memory": "abc"})
        self.assertTrue(any("memory" in e.lower() for e in errors))

    def test_invalid_cpus(self):
        errors = validate_cell_definition({"cpus": "abc"})
        self.assertTrue(any("valid number" in e for e in errors))

    def test_pids_limit_negative(self):
        errors = validate_cell_definition({"pids_limit": -1})
        self.assertTrue(any("positive integer" in e for e in errors))

    # --- Security Invariant 1/6: network=proxy-external rejected ---
    def test_network_proxy_external_rejected(self):
        errors = validate_cell_definition({"network": "proxy-external"})
        self.assertTrue(any("single-homing" in e for e in errors))

    # --- Security Invariant 6: arbitrary network rejected ---
    def test_network_arbitrary_rejected(self):
        errors = validate_cell_definition({"network": "my-custom-net"})
        self.assertTrue(any("single-homing" in e for e in errors))

    # --- Security Invariant 8: list network rejected ---
    def test_network_list_rejected(self):
        errors = validate_cell_definition({"network": ["net1", "net2"]})
        self.assertTrue(any("must be a string" in e for e in errors))

    def test_network_default_allowed(self):
        errors = validate_cell_definition({"network": "default"})
        self.assertEqual(errors, [])

    def test_network_none_allowed(self):
        errors = validate_cell_definition({"network": "none"})
        self.assertEqual(errors, [])

    def test_policy_suspicious_domain(self):
        errors = validate_cell_definition({"policy": {"allow": ["*.localhost"]}})
        self.assertTrue(any("Security:" in e for e in errors))

    def test_workspace_quota_valid(self):
        errors = validate_cell_definition({"workspace_quota": "500m"})
        self.assertEqual(errors, [])

    def test_workspace_quota_invalid(self):
        errors = validate_cell_definition({"workspace_quota": "not-a-size"})
        self.assertTrue(any("workspace_quota" in e for e in errors))

    def test_file_path_in_context(self):
        errors = validate_cell_definition({"name": "INVALID!"}, file_path="test.yaml")
        self.assertTrue(any("in test.yaml" in e for e in errors))


class TestLoadCellDefinition(unittest.TestCase):
    """Test load_cell_definition() from JSON and YAML."""

    def test_load_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"name": "test", "image": "alpine"}, f)
            f.flush()
            result = load_cell_definition(f.name)
            self.assertEqual(result["name"], "test")

    def test_load_nonexistent(self):
        from brig.errors import BrigError
        with self.assertRaises(BrigError):
            load_cell_definition("/nonexistent/file.json")

    def test_load_invalid_json(self):
        from brig.errors import BrigError
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write("not json")
            f.flush()
            with self.assertRaises(BrigError):
                load_cell_definition(f.name)


class TestParseSize(unittest.TestCase):
    def test_megabytes(self):
        self.assertEqual(parse_size("500m"), 500 * 1024**2)

    def test_gigabytes(self):
        self.assertEqual(parse_size("2g"), 2 * 1024**3)

    def test_kilobytes(self):
        self.assertEqual(parse_size("100k"), 100 * 1024)

    def test_plain_bytes(self):
        self.assertEqual(parse_size("1048576"), 1048576)

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            parse_size("")

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            parse_size("not-a-size")


class TestParseDuration(unittest.TestCase):
    def test_seconds(self):
        self.assertEqual(parse_duration("30s"), 30)

    def test_minutes(self):
        self.assertEqual(parse_duration("5m"), 300)

    def test_hours(self):
        self.assertEqual(parse_duration("2h"), 7200)

    def test_days(self):
        self.assertEqual(parse_duration("1d"), 86400)

    def test_plain_integer(self):
        self.assertEqual(parse_duration("60"), 60)

    def test_invalid(self):
        self.assertIsNone(parse_duration("abc"))
