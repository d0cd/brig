"""Tests for brig.ops.history — operation and lifecycle logging."""

import json
import tempfile
import types
import unittest
from pathlib import Path

from brig.ops.history import (
    MAX_LOG_SIZE,
    _append_jsonl,
    _extract_cell_name,
    _maybe_rotate,
    _redact_args,
    _redact_sensitive_value,
    log_lifecycle,
    log_operation,
    log_operation_end,
    log_operation_start,
    log_policy_change,
)


class TestAppendJsonl(unittest.TestCase):
    """Test _append_jsonl() writes valid JSONL with parent directory creation."""

    def test_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sub" / "dir" / "log.jsonl"
            _append_jsonl(path, {"key": "value"})
            self.assertTrue(path.exists())

    def test_appends_valid_json_lines(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "log.jsonl"
            _append_jsonl(path, {"a": 1})
            _append_jsonl(path, {"b": 2})
            lines = path.read_text().strip().split("\n")
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0]), {"a": 1})
            self.assertEqual(json.loads(lines[1]), {"b": 2})


class TestLogOperation(unittest.TestCase):
    """Test log_operation() writes history entries."""

    def test_log_basic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "history.jsonl"
            log_operation("run", cell_name="test-cell", history_file=path)
            entry = json.loads(path.read_text().strip())
            self.assertEqual(entry["operation"], "run")
            self.assertEqual(entry["cell"], "test-cell")
            self.assertIn("ts", entry)

    def test_log_with_details(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "history.jsonl"
            log_operation("run", details={"image": "alpine"}, history_file=path)
            entry = json.loads(path.read_text().strip())
            self.assertEqual(entry["details"]["image"], "alpine")

    def test_log_no_cell(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "history.jsonl"
            log_operation("list", history_file=path)
            entry = json.loads(path.read_text().strip())
            self.assertNotIn("cell", entry)


class TestLogLifecycle(unittest.TestCase):
    """Test log_lifecycle() writes lifecycle entries."""

    def test_lifecycle_event(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "lifecycle.jsonl"
            log_lifecycle("start", "my-cell", details={"image": "alpine"}, lifecycle_file=path)
            entry = json.loads(path.read_text().strip())
            self.assertEqual(entry["event"], "start")
            self.assertEqual(entry["cell"], "my-cell")
            self.assertEqual(entry["image"], "alpine")


class TestLogPolicyChange(unittest.TestCase):
    """Test log_policy_change() writes audit entries."""

    def test_policy_change(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            log_policy_change(
                "my-cell", "add_allow",
                changes={"domains": ["example.com"]},
                old_policy={"allow": []},
                new_policy={"allow": ["example.com"]},
                audit_file=path,
            )
            entry = json.loads(path.read_text().strip())
            self.assertEqual(entry["cell"], "my-cell")
            self.assertEqual(entry["action"], "add_allow")
            self.assertEqual(entry["changes"]["domains"], ["example.com"])
            self.assertEqual(entry["old_policy"], {"allow": []})
            self.assertEqual(entry["new_policy"], {"allow": ["example.com"]})


class TestRedaction(unittest.TestCase):
    """Test argument redaction helpers."""

    def test_redact_sensitive_value(self):
        config = {"operation_logging": {"redact_env_values": True}}
        self.assertEqual(_redact_sensitive_value("PASSWORD", "hunter2", config), "[REDACTED]")
        self.assertEqual(_redact_sensitive_value("api_token", "abc", config), "[REDACTED]")
        self.assertEqual(_redact_sensitive_value("name", "foo", config), "foo")

    def test_redact_disabled(self):
        config = {"operation_logging": {"redact_env_values": False}}
        self.assertEqual(_redact_sensitive_value("PASSWORD", "hunter2", config), "hunter2")

    def test_redact_args_env(self):
        config = {"operation_logging": {"redact_secrets": True, "redact_env_values": True}}
        args = types.SimpleNamespace(
            name="cell1",
            env=["NORMAL=hello", "API_KEY=secret123"],
        )
        result = _redact_args(args, config)
        self.assertEqual(result["name"], "cell1")
        self.assertIn("NORMAL=hello", result["env"])
        self.assertIn("API_KEY=[REDACTED]", result["env"])

    def test_redact_args_secrets(self):
        config = {"operation_logging": {"redact_secrets": True, "redact_env_values": True}}
        args = types.SimpleNamespace(secret=["api-key", "db-pass"])
        result = _redact_args(args, config)
        # Secret names are kept (they're safe), not values.
        self.assertEqual(result["secret"], ["api-key", "db-pass"])

    def test_extract_cell_name(self):
        args = types.SimpleNamespace(name="my-cell")
        self.assertEqual(_extract_cell_name(args), "my-cell")

    def test_extract_cell_name_none(self):
        args = types.SimpleNamespace(image="alpine")
        self.assertIsNone(_extract_cell_name(args))


class TestErrorRedaction(unittest.TestCase):
    """Error strings logged to operations.jsonl must redact host paths
    AND secret-shaped tokens. A naive regex that stops at the first ':'
    leaves traceback fragments intact.
    """

    def test_user_home_path_redacted(self):
        from brig.ops.history import _redact_error
        err = 'File "/Users/d0c/projects/brig/foo.py", line 12'
        result = _redact_error(err)
        self.assertNotIn("/Users/d0c", result)
        self.assertIn("<path>", result)

    def test_tmp_path_redacted(self):
        from brig.ops.history import _redact_error
        err = 'tempfile at /tmp/brig-abc/secret.json failed'
        result = _redact_error(err)
        self.assertNotIn("/tmp/brig-abc/secret.json", result)
        self.assertIn("<path>", result)

    def test_long_hex_token_redacted(self):
        from brig.ops.history import _redact_error
        err = "auth header carried " + ("a" * 40) + " value"
        result = _redact_error(err)
        self.assertNotIn("a" * 40, result)
        self.assertIn("<redacted>", result)

    def test_base64ish_long_token_redacted(self):
        from brig.ops.history import _redact_error
        token = "x" * 32 + "Y" * 8
        err = f"failure due to token {token}"
        result = _redact_error(err)
        self.assertNotIn(token, result)


class TestOperationStartEnd(unittest.TestCase):
    """Test log_operation_start/end with config."""

    def test_disabled_returns_disabled_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.json"
            config_file.write_text(json.dumps({
                "operation_logging": {"enabled": False}
            }))
            ctx = log_operation_start("run", types.SimpleNamespace(name="x"), config_file=config_file)
            self.assertFalse(ctx["enabled"])

    def test_mutations_only_skips_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.json"
            config_file.write_text(json.dumps({
                "operation_logging": {"enabled": True, "level": "mutations"}
            }))
            ctx = log_operation_start("list", types.SimpleNamespace(), config_file=config_file)
            self.assertFalse(ctx["enabled"])

    def test_mutations_allows_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.json"
            config_file.write_text(json.dumps({
                "operation_logging": {"enabled": True, "level": "mutations"}
            }))
            ctx = log_operation_start("run", types.SimpleNamespace(name="x"), config_file=config_file)
            self.assertTrue(ctx["enabled"])

    def test_end_writes_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ops_file = Path(tmpdir) / "ops.jsonl"
            ctx = {
                "enabled": True,
                "start_time": 1000.0,
                "command": "run",
                "args": types.SimpleNamespace(name="test-cell"),
                "config": {"operation_logging": {"redact_secrets": True, "redact_env_values": True}},
            }
            log_operation_end(ctx, exit_code=0, operations_file=ops_file)
            entry = json.loads(ops_file.read_text().strip())
            self.assertEqual(entry["command"], "run")
            self.assertEqual(entry["exit_code"], 0)
            self.assertEqual(entry["cell"], "test-cell")

    def test_end_redacts_paths_in_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ops_file = Path(tmpdir) / "ops.jsonl"
            ctx = {
                "enabled": True,
                "start_time": 1000.0,
                "command": "run",
                "args": None,
                "config": {},
            }
            log_operation_end(ctx, exit_code=1, error="Failed at /home/user/secret/file", operations_file=ops_file)
            entry = json.loads(ops_file.read_text().strip())
            self.assertNotIn("/home/user/secret/file", entry.get("error", ""))
            self.assertIn("<path>", entry.get("error", ""))

    def test_end_noop_when_disabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ops_file = Path(tmpdir) / "ops.jsonl"
            log_operation_end({"enabled": False}, operations_file=ops_file)
            self.assertFalse(ops_file.exists())


class TestLogRotation(unittest.TestCase):
    """Test _maybe_rotate() rotates logs at MAX_LOG_SIZE."""

    def test_no_rotation_under_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.jsonl"
            path.write_text("small\n")
            _maybe_rotate(path)
            self.assertTrue(path.exists())
            self.assertFalse(path.with_suffix(".jsonl.1").exists())

    def test_rotates_at_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.jsonl"
            # Write more than MAX_LOG_SIZE.
            path.write_text("x" * (MAX_LOG_SIZE + 1))
            _maybe_rotate(path)
            # Current file should be gone (renamed to .1).
            self.assertFalse(path.exists())
            self.assertTrue(path.with_suffix(".jsonl.1").exists())

    def test_cascading_rotation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.jsonl"
            path.with_suffix(".jsonl.1").write_text("old-1")
            path.write_text("x" * (MAX_LOG_SIZE + 1))
            _maybe_rotate(path)
            # .1 should have moved to .2, current to .1.
            self.assertTrue(path.with_suffix(".jsonl.2").exists())
            self.assertEqual(path.with_suffix(".jsonl.2").read_text(), "old-1")

    def test_max_3_rotations(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.jsonl"
            path.with_suffix(".jsonl.1").write_text("old-1")
            path.with_suffix(".jsonl.2").write_text("old-2-should-be-deleted")
            path.write_text("x" * (MAX_LOG_SIZE + 1))
            _maybe_rotate(path)
            # .2 was the oldest, should be deleted. .1 → .2, current → .1.
            self.assertFalse(path.with_suffix(".jsonl.3").exists())
            self.assertEqual(path.with_suffix(".jsonl.2").read_text(), "old-1")
