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
    validate_cell_definition as _validate_raw,
)


def validate_cell_definition(cell_def, file_path=""):
    """Test wrapper that supplies a default `name` if the caller is
    only exercising another field — the per-field tests below predate
    the "name is required" rule and shouldn't have to repeat it."""
    if isinstance(cell_def, dict) and "name" not in cell_def:
        cell_def = {"name": "test", **cell_def}
    return _validate_raw(cell_def, file_path)


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

    def test_policy_tls_passthrough_accepted_when_in_allow(self):
        errors = validate_cell_definition({"policy": {
            "allow": ["chatgpt.com", "api.openai.com"],
            "tls_passthrough": ["chatgpt.com"],
        }})
        self.assertEqual(errors, [])

    def test_policy_tls_passthrough_rejected_when_not_in_allow(self):
        """Invariant 11: passthrough hosts MUST also appear in allow,
        otherwise an operator could opt a host out of MITM without ever
        granting it — silently bypassing policy."""
        errors = validate_cell_definition({"policy": {
            "allow": ["api.anthropic.com"],
            "tls_passthrough": ["chatgpt.com"],
        }})
        self.assertTrue(
            any("must also appear in 'policy.allow'" in e for e in errors),
            errors,
        )

    def test_policy_tls_passthrough_must_be_list(self):
        errors = validate_cell_definition({"policy": {
            "allow": ["chatgpt.com"],
            "tls_passthrough": "chatgpt.com",
        }})
        self.assertTrue(any("tls_passthrough" in e and "list" in e for e in errors))

    def test_policy_tls_passthrough_rejects_bad_domain(self):
        errors = validate_cell_definition({"policy": {
            "allow": ["chatgpt.com"],
            "tls_passthrough": ["not a domain!"],
        }})
        self.assertTrue(any("Invalid domain" in e for e in errors))

    def test_workspace_quota_valid(self):
        errors = validate_cell_definition({"workspace_quota": "500m"})
        self.assertEqual(errors, [])

    def test_workspace_quota_invalid(self):
        errors = validate_cell_definition({"workspace_quota": "not-a-size"})
        self.assertTrue(any("workspace_quota" in e for e in errors))

    def test_workspace_mount_default_is_fine(self):
        # /work (the default) and /workspace pass through cleanly.
        for path in ("/work", "/workspace", "/data", "/srv/app"):
            errors = validate_cell_definition({"workspace_mount": path})
            self.assertEqual(errors, [], f"{path} should validate")

    def test_workspace_mount_relative_rejected(self):
        errors = validate_cell_definition({"workspace_mount": "work"})
        self.assertTrue(any("absolute" in e for e in errors), errors)

    def test_workspace_mount_dotdot_rejected(self):
        errors = validate_cell_definition({"workspace_mount": "/foo/../bar"})
        self.assertTrue(any(".." in e for e in errors), errors)

    def test_workspace_mount_shadowing_run_secrets_rejected(self):
        # The crown jewel: a cell that sets workspace_mount: /run/secrets
        # would hide its own secrets dir behind the workspace mount. Reject.
        for shadow in ("/run/secrets", "/run/secrets/foo",
                       "/proc", "/sys", "/dev", "/etc/passwd"):
            errors = validate_cell_definition({"workspace_mount": shadow})
            self.assertTrue(
                any("must not shadow" in e for e in errors),
                f"expected shadow rejection for {shadow}, got: {errors}",
            )

    def test_workspace_mount_non_string_rejected(self):
        errors = validate_cell_definition({"workspace_mount": 42})
        self.assertTrue(any("must be a string" in e for e in errors), errors)

    def test_writable_rootfs_accepts_bool(self):
        for value in (True, False):
            errors = validate_cell_definition({"writable_rootfs": value})
            self.assertEqual(errors, [], f"bool {value} should validate")

    def test_writable_rootfs_rejects_non_bool(self):
        for value in ("true", 1, "yes", None):
            errors = validate_cell_definition({"writable_rootfs": value})
            self.assertTrue(any("boolean" in e for e in errors),
                f"{value!r} should be rejected with 'boolean' in the error")

    def test_workspace_mount_root_rejected(self):
        errors = validate_cell_definition({"workspace_mount": "/"})
        self.assertTrue(any("shadows rootfs" in e for e in errors), errors)

    def test_yaml_int_cpus_coerced_to_string(self):
        """`cpus: 4` in yaml (parses as int) used
        to slip through validation and reach subprocess as an int, raising
        `argument of type 'int' is not iterable` at the redact-args check.
        CellSpec.__post_init__ now coerces."""
        spec = CellSpec(name="c", image="alpine", cpus=4)
        self.assertEqual(spec.cpus, "4")
        self.assertIsInstance(spec.cpus, str)

    def test_yaml_float_cpus_coerced_to_string(self):
        spec = CellSpec(name="c", image="alpine", cpus=0.5)
        self.assertEqual(spec.cpus, "0.5")

    def test_yaml_int_memory_coerced_to_string(self):
        """Same class of bug — `memory: 4` without quotes would slip
        through and crash subprocess. (Unlikely in practice since memory
        usually has a unit suffix, but the validator accepts bare ints.)"""
        spec = CellSpec(name="c", image="alpine", memory=4)
        self.assertEqual(spec.memory, "4")

    def test_workspace_mount_ancestor_of_forbidden_rejected(self):
        """Audit M3: workspace_mount: /run would shadow /run/secrets via
        mount-over-mount, even though /run itself isn't in the forbidden
        set. The cell starts fine; secrets silently disappear."""
        errors = validate_cell_definition({"workspace_mount": "/run"})
        self.assertTrue(any("ancestor of /run/secrets" in e for e in errors),
                        errors)

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
