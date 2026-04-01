#!/usr/bin/env python3
"""
Unit tests for Brig Python SDK and signer addon.

Tests SDK logic without requiring brig CLI or containers.
Tests signer addon thread safety and batch signing.

Run with: python3 -m pytest tests/test_sdk_unit.py -v

Or without pytest:
    python3 tests/test_sdk_unit.py
"""

import asyncio
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Add src to path for imports.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from brig.sdk import (
    Brig,
    BrigError,
    Cell,
    CellEvent,
    CellInfo,
    CellNotFoundError,
    CellResult,
    CellRunResult,
    CellStats,
    ImageVerificationError,
    ProfileError,
    SecretNotFoundError,
    WardenHandle,
    WardenStatus,
    _run_sync,
)


def _async_run(coro):
    """Run an async coroutine for testing."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


class TestCellResult(unittest.TestCase):
    """Tests for CellResult dataclass."""

    def test_create(self):
        """CellResult stores cell name and exit code."""
        r = CellResult(cell="test", exit_code=0)
        self.assertEqual(r.cell, "test")
        self.assertEqual(r.exit_code, 0)

    def test_nonzero_exit_code(self):
        """CellResult stores nonzero exit codes."""
        r = CellResult(cell="test", exit_code=137)
        self.assertEqual(r.exit_code, 137)


class TestCellRunResult(unittest.TestCase):
    """Tests for CellRunResult dataclass."""

    def test_create_minimal(self):
        """CellRunResult with minimal fields."""
        r = CellRunResult(
            cell="test", cell_id="abc123", image="alpine",
            status="running", network="brig-test", runtime="runsc",
        )
        self.assertEqual(r.cell, "test")
        self.assertIsNone(r.timeout_seconds)
        self.assertEqual(r.labels, {})

    def test_create_with_optionals(self):
        """CellRunResult with optional fields."""
        r = CellRunResult(
            cell="test", cell_id="abc123", image="alpine",
            status="running", network="brig-test", runtime="runsc",
            timeout_seconds=3600, labels={"env": "prod"},
        )
        self.assertEqual(r.timeout_seconds, 3600)
        self.assertEqual(r.labels["env"], "prod")


class TestCellRepr(unittest.TestCase):
    """Tests for Cell repr."""

    def test_repr(self):
        """Cell repr includes name."""
        b = Brig()
        c = Cell("myapp", b)
        self.assertIn("myapp", repr(c))


class TestBrigRepr(unittest.TestCase):
    """Tests for Brig repr."""

    def test_repr(self):
        """Brig repr includes binary path."""
        b = Brig(brig_bin="/usr/local/bin/brig")
        self.assertIn("/usr/local/bin/brig", repr(b))


class TestBrigInit(unittest.TestCase):
    """Tests for Brig initialization."""

    def test_default_bins(self):
        """Brig uses default binary names."""
        b = Brig()
        self.assertEqual(b._bin, "brig")
        self.assertEqual(b._warden_bin, "warden")

    def test_custom_bins(self):
        """Brig accepts custom binary paths."""
        b = Brig(brig_bin="/custom/brig", warden_bin="/custom/warden")
        self.assertEqual(b._bin, "/custom/brig")
        self.assertEqual(b._warden_bin, "/custom/warden")

    def test_warden_handle_created(self):
        """Brig creates warden handle."""
        b = Brig()
        self.assertIsInstance(b.warden, WardenHandle)


class TestBrigRunCmdBuildsCli(unittest.TestCase):
    """Tests that Brig.run() builds correct CLI commands."""

    def test_run_builds_basic_command(self):
        """run() builds correct basic CLI command."""
        b = Brig()
        # We can't actually run the command, but we can verify the
        # SDK constructs the right command by mocking _run_cmd.
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout='{"cell":"test","cell_id":"x","image":"alpine","status":"running","network":"n","runtime":"runsc"}',
                returncode=0,
            )
            _async_run(b.run(name="test", image="alpine"))

            # Verify the command was built correctly.
            args = mock_cmd.call_args[0][0]
            self.assertIn("run", args)
            self.assertIn("--name", args)
            self.assertIn("test", args)
            self.assertIn("alpine", args)
            self.assertIn("-d", args)  # Default detach.
            self.assertIn("--output", args)
            self.assertIn("json", args)

    def test_run_includes_profile(self):
        """run() includes --profile flag when set."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(name="test", image="alpine", profile="supervised"))
            args = mock_cmd.call_args[0][0]
            self.assertIn("--profile", args)
            self.assertIn("supervised", args)

    def test_run_includes_timeout(self):
        """run() includes --timeout flag when set."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(name="test", image="alpine", timeout="2h"))
            args = mock_cmd.call_args[0][0]
            self.assertIn("--timeout", args)
            self.assertIn("2h", args)

    def test_run_includes_policy_domains(self):
        """run() includes --policy-allow and --policy-deny flags."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(
                name="test", image="alpine",
                policy_allow=["a.com", "b.com"],
                policy_deny=["c.com"],
            ))
            args = mock_cmd.call_args[0][0]
            # Check allow domains.
            allow_indices = [i for i, a in enumerate(args) if a == "--policy-allow"]
            self.assertEqual(len(allow_indices), 2)
            # Check deny domains.
            deny_indices = [i for i, a in enumerate(args) if a == "--policy-deny"]
            self.assertEqual(len(deny_indices), 1)

    def test_run_includes_secrets(self):
        """run() includes --secret flags."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(
                name="test", image="alpine",
                secrets=["openai-key", "db-pass"],
            ))
            args = mock_cmd.call_args[0][0]
            secret_indices = [i for i, a in enumerate(args) if a == "--secret"]
            self.assertEqual(len(secret_indices), 2)

    def test_run_includes_labels(self):
        """run() includes --label flags."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(
                name="test", image="alpine",
                labels={"env": "prod", "team": "infra"},
            ))
            args = mock_cmd.call_args[0][0]
            label_indices = [i for i, a in enumerate(args) if a == "--label"]
            self.assertEqual(len(label_indices), 2)

    def test_run_no_detach(self):
        """run() omits -d when detach=False."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(name="test", image="alpine", detach=False))
            args = mock_cmd.call_args[0][0]
            self.assertNotIn("-d", args)

    def test_run_with_rm(self):
        """run() includes --rm when set."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(name="test", image="alpine", rm=True))
            args = mock_cmd.call_args[0][0]
            self.assertIn("--rm", args)

    def test_run_with_command(self):
        """run() appends command after image."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(
                name="test", image="python:3.12",
                command=["python", "main.py"],
            ))
            args = mock_cmd.call_args[0][0]
            # Image should come before command.
            img_idx = args.index("python:3.12")
            py_idx = args.index("python")
            self.assertGreater(py_idx, img_idx)


class TestBrigRunCmdError(unittest.TestCase):
    """Tests for Brig._run_cmd error handling."""

    def test_raises_on_nonzero_exit(self):
        """_run_cmd raises BrigError on non-zero exit when check=True."""
        b = Brig()
        with self.assertRaises(BrigError) as ctx:
            _async_run(b._run_cmd(["false"]))
        self.assertGreater(ctx.exception.returncode, 0)

    def test_no_raise_when_check_false(self):
        """_run_cmd does not raise when check=False."""
        b = Brig()
        result = _async_run(b._run_cmd(["false"], check=False))
        self.assertNotEqual(result.returncode, 0)


class TestCellWait(unittest.TestCase):
    """Tests for Cell.wait()."""

    def test_wait_returns_result(self):
        """wait() returns int exit code."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout='{"cell":"test","exit_code":0}',
                returncode=0,
            )
            result = _async_run(c.wait())
            self.assertIsInstance(result, int)
            self.assertEqual(result, 0)

    def test_wait_with_timeout(self):
        """wait() passes timeout to CLI."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout='{"cell":"test","exit_code":0}',
                returncode=0,
            )
            _async_run(c.wait(timeout="30s"))
            args = mock_cmd.call_args[0][0]
            self.assertIn("--timeout", args)
            self.assertIn("30s", args)


class TestCellCp(unittest.TestCase):
    """Tests for Cell.cp_in() and cp_out()."""

    def test_cp_in_format(self):
        """cp_in() builds correct command."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(returncode=0)
            _async_run(c.cp_in("local.txt", "/work/file.txt"))
            args = mock_cmd.call_args[0][0]
            self.assertIn("cp", args)
            self.assertIn("local.txt", args)
            self.assertIn("test:/work/file.txt", args)

    def test_cp_out_format(self):
        """cp_out() builds correct command."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(returncode=0)
            _async_run(c.cp_out("/work/output.json", "result.json"))
            args = mock_cmd.call_args[0][0]
            self.assertIn("cp", args)
            self.assertIn("test:/work/output.json", args)
            self.assertIn("result.json", args)


class TestBrigPipe(unittest.TestCase):
    """Tests for Brig.pipe() temp file safety."""

    def test_pipe_uses_mkstemp(self):
        """pipe() uses mkstemp, not mktemp (verified by source inspection)."""
        import inspect
        source_code = inspect.getsource(Brig.pipe)
        self.assertIn("mkstemp", source_code)
        self.assertNotIn("mktemp", source_code)

    def test_pipe_calls_cp_operations(self):
        """pipe() calls cp_out then cp_in."""
        b = Brig()
        source = Cell("src", b)
        dest = Cell("dst", b)

        with patch.object(source, 'cp_out', new_callable=AsyncMock) as mock_out, \
             patch.object(dest, 'cp_in', new_callable=AsyncMock) as mock_in:
            _async_run(b.pipe(source, "/out.json", dest, "/in.json"))
            mock_out.assert_called_once()
            mock_in.assert_called_once()


class TestBrigList(unittest.TestCase):
    """Tests for Brig.list()."""

    def test_list_parses_cells(self):
        """list() parses JSON cell list."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout=json.dumps([
                    {"name": "a", "status": "running", "image": "alpine"},
                    {"name": "b", "status": "exited", "image": "python:3.12"},
                ]),
                returncode=0,
            )
            cells = _async_run(b.list())
            self.assertEqual(len(cells), 2)
            self.assertIsInstance(cells[0], CellInfo)
            self.assertEqual(cells[0].name, "a")
            self.assertEqual(cells[1].status, "exited")

    def test_list_handles_empty(self):
        """list() handles empty response."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='[]', returncode=0)
            cells = _async_run(b.list())
            self.assertEqual(cells, [])

    def test_list_handles_invalid_json(self):
        """list() handles invalid JSON gracefully."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='not json', returncode=0)
            cells = _async_run(b.list())
            self.assertEqual(cells, [])


class TestCellRm(unittest.TestCase):
    """Tests for Cell.rm()."""

    def test_rm_basic(self):
        """rm() builds correct command."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(returncode=0)
            _async_run(c.rm())
            args = mock_cmd.call_args[0][0]
            self.assertIn("rm", args)
            self.assertIn("test", args)
            self.assertNotIn("-f", args)

    def test_rm_force(self):
        """rm(force=True) includes -f flag."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(returncode=0)
            _async_run(c.rm(force=True))
            args = mock_cmd.call_args[0][0]
            self.assertIn("-f", args)

    def test_rm_purge(self):
        """rm(purge=True) includes --purge flag."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(returncode=0)
            _async_run(c.rm(purge=True))
            args = mock_cmd.call_args[0][0]
            self.assertIn("--purge", args)


class TestRunSync(unittest.TestCase):
    """Tests for _run_sync helper."""

    def test_run_sync_returns_result(self):
        """_run_sync runs coroutine and returns result."""
        async def coro():
            return 42

        result = _run_sync(coro())
        self.assertEqual(result, 42)

    def test_run_sync_propagates_error(self):
        """_run_sync propagates exceptions."""
        async def coro():
            raise ValueError("test error")

        with self.assertRaises(ValueError):
            _run_sync(coro())


class TestSDKInputValidation(unittest.TestCase):
    """Tests for SDK input validation in Brig.run()."""

    def test_invalid_cell_name_rejected(self):
        """Invalid cell names are rejected."""
        b = Brig()
        for bad_name in ["-bad", "_bad", "has space", "a" * 64, "../etc"]:
            with self.assertRaises(BrigError, msg=f"Name {bad_name!r} should be rejected"):
                _run_sync(b.run(name=bad_name, image="alpine"))

    def test_valid_cell_name_accepted(self):
        """Valid cell names pass validation."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            for good_name in ["myapp", "my-app", "app1", "a1b2c3"]:
                _run_sync(b.run(name=good_name, image="alpine"))

    def test_image_starting_with_dash_rejected(self):
        """Image names starting with - are rejected."""
        b = Brig()
        with self.assertRaises(BrigError):
            _run_sync(b.run(name="test", image="--unsafe"))

    def test_profile_starting_with_dash_rejected(self):
        """Profile starting with - is rejected."""
        b = Brig()
        with self.assertRaises(BrigError):
            _run_sync(b.run(name="test", image="alpine", profile="--runtime=runc"))

    def test_invalid_env_key_rejected(self):
        """Invalid env keys are rejected."""
        b = Brig()
        for bad_key in ["1bad", "has-dash", "has space", "has;semi"]:
            with self.assertRaises(BrigError, msg=f"Env key {bad_key!r} should be rejected"):
                _run_sync(b.run(name="test", image="alpine", env={bad_key: "val"}))

    def test_valid_env_keys_accepted(self):
        """Valid env keys pass validation."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _run_sync(b.run(name="test", image="alpine", env={"FOO": "bar", "_BAR": "baz"}))

    def test_env_secret_values_rejected(self):
        """Env values that look like secrets are rejected."""
        b = Brig()
        secret_values = [
            ("API_KEY", "sk-proj-abc123"),
            ("TOKEN", "ghp_xxxxxxxxxxxxxxxxxxxx"),
            ("AWS_KEY", "AKIAIOSFODNN7EXAMPLE"),
            ("SLACK", "xoxb-fake-token"),
            ("GITLAB", "glpat-xxxxxxxxxxxx"),
        ]
        for key, val in secret_values:
            with self.assertRaises(BrigError, msg=f"Env {key}={val!r} should be rejected"):
                _run_sync(b.run(name="test", image="alpine", env={key: val}))

    def test_env_nonsecret_values_accepted(self):
        """Env values that are not secrets pass validation."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _run_sync(b.run(name="test", image="alpine", env={
                "TASK_ID": "550e8400",
                "LOG_LEVEL": "debug",
                "WORKERS": "4",
            }))

    def test_double_dash_separator_in_command(self):
        """run() inserts -- before image to prevent flag injection."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _run_sync(b.run(name="test", image="alpine", command=["echo", "hi"]))
            args = mock_cmd.call_args[0][0]
            # Find -- separator before image.
            dd_idx = args.index("--")
            img_idx = args.index("alpine")
            self.assertLess(dd_idx, img_idx)

    def test_policy_allow_dash_rejected(self):
        """Policy allow domains starting with - are rejected."""
        b = Brig()
        with self.assertRaises(BrigError):
            _run_sync(b.run(name="test", image="alpine", policy_allow=["--flag"]))


class TestSDKTimeout(unittest.TestCase):
    """Tests for SDK command timeout."""

    def test_timeout_raises_brig_error(self):
        """_run_cmd raises BrigError on timeout."""
        b = Brig()
        with self.assertRaises(BrigError) as ctx:
            _run_sync(b._run_cmd(["sleep", "10"], timeout=0.1))
        self.assertIn("timed out", str(ctx.exception))

    def test_error_message_hides_full_command(self):
        """BrigError only shows binary + subcommand, not full args."""
        b = Brig()
        with self.assertRaises(BrigError) as ctx:
            _run_sync(b._run_cmd(["false", "subcommand", "--secret", "mysecret"]))
        msg = str(ctx.exception)
        self.assertNotIn("mysecret", msg)
        self.assertIn("false subcommand", msg)


class TestExceptionSubclasses(unittest.TestCase):
    """Tests for SDK exception subclasses."""

    def test_cell_not_found_inherits(self):
        """CellNotFoundError inherits from BrigError."""
        self.assertTrue(issubclass(CellNotFoundError, BrigError))

    def test_image_verification_inherits(self):
        """ImageVerificationError inherits from BrigError."""
        self.assertTrue(issubclass(ImageVerificationError, BrigError))

    def test_profile_error_inherits(self):
        """ProfileError inherits from BrigError."""
        self.assertTrue(issubclass(ProfileError, BrigError))

    def test_secret_not_found_inherits(self):
        """SecretNotFoundError inherits from BrigError."""
        self.assertTrue(issubclass(SecretNotFoundError, BrigError))

    def test_exceptions_are_catchable_as_brig_error(self):
        """All subclasses are catchable as BrigError."""
        for exc_cls in (CellNotFoundError, ImageVerificationError,
                        ProfileError, SecretNotFoundError):
            with self.assertRaises(BrigError):
                raise exc_cls("test")

    def test_exceptions_carry_fields(self):
        """Subclasses carry returncode and stderr from BrigError."""
        e = CellNotFoundError("gone", returncode=1, stderr="not found")
        self.assertEqual(e.returncode, 1)
        self.assertEqual(e.stderr, "not found")


class TestErrorPatternMatching(unittest.TestCase):
    """Tests for _run_cmd raising correct exception subclass."""

    def test_not_found_raises_cell_not_found(self):
        """stderr containing 'not found' raises CellNotFoundError."""
        b = Brig()
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            proc = AsyncMock()
            proc.communicate.return_value = (b"", b"cell does not exist")
            proc.returncode = 1
            proc.kill = AsyncMock()
            proc.wait = AsyncMock()
            mock_exec.return_value = proc
            with self.assertRaises(CellNotFoundError):
                _async_run(b._run_cmd(["brig", "inspect", "missing"]))

    def test_unknown_profile_raises_profile_error(self):
        """stderr containing 'Unknown profile' raises ProfileError."""
        b = Brig()
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            proc = AsyncMock()
            proc.communicate.return_value = (b"", b"Unknown profile: badprofile")
            proc.returncode = 1
            proc.kill = AsyncMock()
            proc.wait = AsyncMock()
            mock_exec.return_value = proc
            with self.assertRaises(ProfileError):
                _async_run(b._run_cmd(["brig", "run", "--profile", "badprofile"]))

    def test_secret_not_found_raises(self):
        """stderr containing 'not found in secrets' raises SecretNotFoundError."""
        b = Brig()
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            proc = AsyncMock()
            proc.communicate.return_value = (b"", b"Secret 'mykey' not found in secrets")
            proc.returncode = 1
            proc.kill = AsyncMock()
            proc.wait = AsyncMock()
            mock_exec.return_value = proc
            with self.assertRaises(SecretNotFoundError):
                _async_run(b._run_cmd(["brig", "run", "--secret", "mykey"]))

    def test_digest_mismatch_raises_image_verification(self):
        """stderr containing 'digest mismatch' raises ImageVerificationError."""
        b = Brig()
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            proc = AsyncMock()
            proc.communicate.return_value = (b"", b"Image digest mismatch: expected sha256:abc")
            proc.returncode = 1
            proc.kill = AsyncMock()
            proc.wait = AsyncMock()
            mock_exec.return_value = proc
            with self.assertRaises(ImageVerificationError):
                _async_run(b._run_cmd(["brig", "run", "alpine"]))

    def test_generic_error_still_raises_brig_error(self):
        """Unrecognized stderr raises generic BrigError."""
        b = Brig()
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            proc = AsyncMock()
            proc.communicate.return_value = (b"", b"some unknown error")
            proc.returncode = 1
            proc.kill = AsyncMock()
            proc.wait = AsyncMock()
            mock_exec.return_value = proc
            with self.assertRaises(BrigError) as ctx:
                _async_run(b._run_cmd(["brig", "run"]))
            # Should not be a subclass.
            self.assertEqual(type(ctx.exception), BrigError)


class TestErrorPatternSync(unittest.TestCase):
    """Verify SDK error patterns match actual CLI error messages.

    Guards against the CLI changing error messages without updating the
    SDK pattern list, which would cause the wrong exception subclass.
    """

    @classmethod
    def setUpClass(cls):
        """Load brig CLI source (including command modules) for pattern matching."""
        src_dir = Path(__file__).parent.parent / "src"
        # Read brig.py and all command modules.
        sources = [src_dir / "brig.py"]
        commands_dir = src_dir / "brig" / "commands"
        if commands_dir.exists():
            sources.extend(sorted(commands_dir.glob("*.py")))
        cls.cli_source = "\n".join(p.read_text() for p in sources if p.exists())

    def test_cli_has_does_not_exist_message(self):
        """CLI contains 'does not exist' for CellNotFoundError."""
        self.assertIn("does not exist", self.cli_source)

    def test_cli_has_unknown_profile_message(self):
        """CLI contains 'Unknown profile' for ProfileError."""
        self.assertIn("Unknown profile", self.cli_source)

    def test_cli_has_secret_not_found_message(self):
        """CLI contains 'Secret not found' for SecretNotFoundError."""
        self.assertIn("Secret not found", self.cli_source)

    def test_cli_has_digest_mismatch_message(self):
        """CLI contains 'digest mismatch' for ImageVerificationError."""
        self.assertIn("digest mismatch", self.cli_source)


class TestBrigGet(unittest.TestCase):
    """Tests for Brig.get() method."""

    def test_get_existing_cell(self):
        """get() returns Cell for existing cell."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout='[{"Name":"brig-myapp","State":{"Running":true}}]',
                returncode=0,
            )
            cell = _async_run(b.get("myapp"))
            self.assertIsInstance(cell, Cell)
            self.assertEqual(cell.name, "myapp")

    def test_get_nonexistent_cell(self):
        """get() returns None for nonexistent cell."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='', returncode=1)
            cell = _async_run(b.get("nosuch"))
            self.assertIsNone(cell)

    def test_get_passes_check_false(self):
        """get() calls _run_cmd with check=False."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='', returncode=1)
            _async_run(b.get("test"))
            _, kwargs = mock_cmd.call_args
            self.assertFalse(kwargs.get("check", True))


class TestCellIsAlive(unittest.TestCase):
    """Tests for Cell.is_alive() method."""

    def test_is_alive_running(self):
        """is_alive() returns True for running cell."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout='[{"State":{"Running":true}}]',
                returncode=0,
            )
            self.assertTrue(_async_run(c.is_alive()))

    def test_is_alive_stopped(self):
        """is_alive() returns False for stopped cell."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout='[{"State":{"Running":false}}]',
                returncode=0,
            )
            self.assertFalse(_async_run(c.is_alive()))

    def test_is_alive_removed(self):
        """is_alive() returns False for removed cell."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='', returncode=1)
            self.assertFalse(_async_run(c.is_alive()))

    def test_is_alive_bad_json(self):
        """is_alive() returns False for malformed JSON."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='not json', returncode=0)
            self.assertFalse(_async_run(c.is_alive()))


class TestCellRmIdempotent(unittest.TestCase):
    """Tests for Cell.rm() idempotency."""

    def test_rm_idempotent_second_call(self):
        """rm() does not raise when cell is already gone."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.side_effect = CellNotFoundError("not found")
            # Should not raise.
            _async_run(c.rm())

    def test_rm_propagates_non_notfound_error(self):
        """rm() propagates non-CellNotFoundError errors."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.side_effect = BrigError("connection timed out")
            with self.assertRaises(BrigError):
                _async_run(c.rm())


class TestCellWaitReturnsInt(unittest.TestCase):
    """Tests for Cell.wait() returning int."""

    def test_wait_returns_int(self):
        """wait() returns int exit code."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout='{"cell":"test","exit_code":42}',
                returncode=0,
            )
            result = _async_run(c.wait())
            self.assertIsInstance(result, int)
            self.assertEqual(result, 42)

    def test_wait_returns_zero(self):
        """wait() returns 0 for successful cell."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout='{"cell":"test","exit_code":0}',
                returncode=0,
            )
            result = _async_run(c.wait())
            self.assertEqual(result, 0)

    def test_wait_fallback_returncode(self):
        """wait() raises BrigError when JSON parsing fails with non-zero exit."""
        from brig.utils import BrigError
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout='not json',
                stderr='',
                returncode=137,
            )
            with self.assertRaises(BrigError):
                _async_run(c.wait())


class TestBrigRunNewParams(unittest.TestCase):
    """Tests for Brig.run() new parameters."""

    def test_egress_allow_maps_to_policy_allow(self):
        """egress_allow maps to --policy-allow flags."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(
                name="test", image="alpine",
                command=["echo", "hi"],
                egress_allow=["api.openai.com", "github.com"],
            ))
            args = mock_cmd.call_args[0][0]
            allow_indices = [i for i, a in enumerate(args) if a == "--policy-allow"]
            self.assertEqual(len(allow_indices), 2)

    def test_workdir_flag(self):
        """workdir adds --workdir flag."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(
                name="test", image="alpine",
                command=["echo", "hi"],
                workdir="/app",
            ))
            args = mock_cmd.call_args[0][0]
            self.assertIn("--workdir", args)
            self.assertIn("/app", args)

    def test_image_digest_flag(self):
        """image_digest adds --image-digest flag."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(
                name="test", image="alpine",
                command=["echo", "hi"],
                image_digest="sha256:abc123",
            ))
            args = mock_cmd.call_args[0][0]
            self.assertIn("--image-digest", args)
            self.assertIn("sha256:abc123", args)

    def test_canary_tokens_written_to_tempfile(self):
        """canary_tokens are written to a tempfile, not in CLI args."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(
                name="test", image="alpine",
                command=["echo", "hi"],
                canary_tokens={"aws_key": "AKIAFAKETOKEN123"},
            ))
            args = mock_cmd.call_args[0][0]
            # Canary value must NOT appear in CLI args.
            args_str = " ".join(args)
            self.assertNotIn("AKIAFAKETOKEN123", args_str)
            # --canary-file flag must be present.
            self.assertIn("--canary-file", args)

    def test_unknown_profile_raises_profile_error(self):
        """Unknown profile raises ProfileError before calling CLI."""
        b = Brig()
        with self.assertRaises(ProfileError):
            _async_run(b.run(
                name="test", image="alpine",
                command=["echo", "hi"],
                profile="nonexistent",
            ))

    def test_known_profile_accepted(self):
        """Known profiles pass validation."""
        b = Brig()
        for profile in ("untrusted", "supervised", "dev", "airgapped", "honeypot"):
            with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
                mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
                _async_run(b.run(
                    name="test", image="alpine",
                    command=["echo", "hi"],
                    profile=profile,
                ))

    def test_command_required(self):
        """command parameter is accepted (backward compat: still optional)."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(name="test", image="alpine", command=["ls"]))

    def test_egress_allow_and_policy_allow_combined(self):
        """egress_allow and policy_allow are combined."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _async_run(b.run(
                name="test", image="alpine",
                command=["echo", "hi"],
                policy_allow=["a.com"],
                egress_allow=["b.com"],
            ))
            args = mock_cmd.call_args[0][0]
            allow_indices = [i for i, a in enumerate(args) if a == "--policy-allow"]
            self.assertEqual(len(allow_indices), 2)

    def test_image_digest_flag_injection_rejected(self):
        """image_digest starting with - is rejected."""
        b = Brig()
        with self.assertRaises(BrigError):
            _async_run(b.run(
                name="test", image="alpine",
                image_digest="--some-flag",
            ))

    def test_image_digest_bad_format_rejected(self):
        """image_digest not starting with sha256: is rejected."""
        b = Brig()
        with self.assertRaises(BrigError):
            _async_run(b.run(
                name="test", image="alpine",
                image_digest="md5:abc123",
            ))

    def test_secret_flag_injection_rejected(self):
        """Secret names starting with - are rejected."""
        b = Brig()
        with self.assertRaises(BrigError):
            _async_run(b.run(
                name="test", image="alpine",
                secrets=["--exec=malicious"],
            ))


class TestLogsStreaming(unittest.TestCase):
    """Tests for Cell.logs() streaming behavior."""

    def test_logs_follow_false_returns_string(self):
        """logs(follow=False) returns str."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout='line1\nline2\n', returncode=0,
            )
            result = _async_run(c.logs(follow=False))
            self.assertIsInstance(result, str)
            self.assertIn("line1", result)

    def test_logs_follow_true_returns_async_iterator(self):
        """logs(follow=True) returns an async iterator."""
        b = Brig()
        c = Cell("test", b)

        class MockStdout:
            """Mock async iterable for subprocess stdout."""
            def __init__(self, data):
                self._data = data
                self._index = 0

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._index >= len(self._data):
                    raise StopAsyncIteration
                val = self._data[self._index]
                self._index += 1
                return val

        async def collect_logs():
            lines = []
            mock_proc = MagicMock()
            mock_proc.stdout = MockStdout([b"line1\n", b"line2\n"])
            mock_proc.stderr = MockStdout([])
            mock_proc.kill = MagicMock()
            mock_proc.wait = AsyncMock()
            with patch('asyncio.create_subprocess_exec',
                       new_callable=AsyncMock, return_value=mock_proc):
                # logs(follow=True) is an async method returning an async generator.
                stream = await c.logs(follow=True)
                async for line in stream:
                    lines.append(line)
                # Generator is fully consumed; finally block runs cleanly.
            return lines

        lines = _async_run(collect_logs())
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], "line1")
        self.assertEqual(lines[1], "line2")

    def test_logs_sync_follow_raises(self):
        """logs_sync(follow=True) raises BrigError."""
        b = Brig()
        c = Cell("test", b)
        with self.assertRaises(BrigError):
            c.logs_sync(follow=True)


# ========== Signer addon tests ==========

class TestSDKEdgeCases(unittest.TestCase):
    """Tests for SDK edge cases: empty strings, None values."""

    def test_empty_name_rejected(self):
        """Empty string name is rejected."""
        b = Brig()
        with self.assertRaises(BrigError):
            _run_sync(b.run(name="", image="alpine"))

    def test_empty_image_rejected(self):
        """Empty string image is rejected."""
        b = Brig()
        with self.assertRaises(BrigError):
            _run_sync(b.run(name="test", image=""))

    def test_empty_profile_rejected(self):
        """Empty string profile is rejected."""
        b = Brig()
        with self.assertRaises(BrigError):
            _run_sync(b.run(name="test", image="alpine", profile=""))

    def test_double_dash_without_command(self):
        """run() inserts -- before image even without a command list."""
        b = Brig()
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(stdout='{}', returncode=0)
            _run_sync(b.run(name="test", image="alpine"))
            args = mock_cmd.call_args[0][0]
            # -- should still appear before image.
            dd_idx = args.index("--")
            img_idx = args.index("alpine")
            self.assertLess(dd_idx, img_idx)


class TestHMACKeyNaming(unittest.TestCase):
    """Tests for HMAC key naming (H9): secret only in private key path."""

    def setUp(self):
        """Set up signer with temp directories."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from addons import signer
        self.signer = signer

        self.tmpdir = tempfile.mkdtemp()
        audit_dir = Path(self.tmpdir) / "audit"

        self._orig_audit = signer.AUDIT_DIR
        self._orig_signed = signer.SIGNED_DIR
        self._orig_pubkey = signer.PUBKEY_PATH
        self._orig_privkey = signer.PRIVKEY_PATH

        signer.AUDIT_DIR = audit_dir
        signer.SIGNED_DIR = audit_dir / "signed"
        signer.PUBKEY_PATH = audit_dir / "session_pubkey.pem"
        signer.PRIVKEY_PATH = audit_dir / ".session_privkey.pem"

        # Force HMAC mode by clearing any cached signing key.
        signer._signing_key = None
        signer._algorithm = None

    def tearDown(self):
        """Restore signer state."""
        import shutil
        self.signer.AUDIT_DIR = self._orig_audit
        self.signer.SIGNED_DIR = self._orig_signed
        self.signer.PUBKEY_PATH = self._orig_pubkey
        self.signer.PRIVKEY_PATH = self._orig_privkey
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_hmac_key_not_in_pubkey_file(self):
        """HMAC secret is not stored in the public key file."""
        self.signer.init()
        if self.signer._algorithm != "hmac-sha256":
            self.skipTest("Ed25519 available; HMAC path not exercised")

        pubkey_content = self.signer.PUBKEY_PATH.read_text()
        # Public key file should be a plaintext note, not JSON with the key.
        self.assertIn("HMAC mode", pubkey_content)
        self.assertNotIn('"key"', pubkey_content)

    def test_hmac_key_in_privkey_file(self):
        """HMAC secret is stored in the private key file."""
        self.signer.init()
        if self.signer._algorithm != "hmac-sha256":
            self.skipTest("Ed25519 available; HMAC path not exercised")

        privkey_data = json.loads(self.signer.PRIVKEY_PATH.read_bytes())
        self.assertEqual(privkey_data["algorithm"], "hmac-sha256")
        self.assertIn("key", privkey_data)

    def test_verify_works_with_privkey_path(self):
        """verify_batch works when given the private key path directly."""
        self.signer.init()
        if self.signer._algorithm != "hmac-sha256":
            self.skipTest("Ed25519 available; HMAC path not exercised")

        self.signer._batch_entries = []
        self.signer._batch_start_time = None
        self.signer._batch_counter = 0

        self.signer.add_entry({"action": "test"})
        self.signer.flush()

        batch_path = str(self.signer.SIGNED_DIR / "batch_000001.jsonl")
        # Pass private key path (where HMAC key actually lives).
        self.assertTrue(self.signer.verify_batch(batch_path, str(self.signer.PRIVKEY_PATH)))


try:
    import cryptography  # noqa: F401
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


@unittest.skipUnless(_HAS_CRYPTOGRAPHY, "requires cryptography package")
class TestSignerInit(unittest.TestCase):
    """Tests for signer addon initialization."""

    def test_init_creates_dirs(self):
        """init() creates audit directories."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from addons import signer

        with tempfile.TemporaryDirectory() as tmpdir:
            audit_dir = Path(tmpdir) / "audit"
            signed_dir = audit_dir / "signed"

            # Patch paths.
            orig_audit = signer.AUDIT_DIR
            orig_signed = signer.SIGNED_DIR
            orig_pubkey = signer.PUBKEY_PATH
            orig_privkey = signer.PRIVKEY_PATH
            try:
                signer.AUDIT_DIR = audit_dir
                signer.SIGNED_DIR = signed_dir
                signer.PUBKEY_PATH = audit_dir / "session_pubkey.pem"
                signer.PRIVKEY_PATH = audit_dir / ".session_privkey.pem"

                signer.init()

                self.assertTrue(audit_dir.exists())
                self.assertTrue(signed_dir.exists())
                # Verify key files were created.
                self.assertTrue(signer.PUBKEY_PATH.exists())
                self.assertTrue(signer.PRIVKEY_PATH.exists())
            finally:
                signer.AUDIT_DIR = orig_audit
                signer.SIGNED_DIR = orig_signed
                signer.PUBKEY_PATH = orig_pubkey
                signer.PRIVKEY_PATH = orig_privkey


@unittest.skipUnless(_HAS_CRYPTOGRAPHY, "requires cryptography package")
class TestSignerBatchOperations(unittest.TestCase):
    """Tests for signer batch add/flush operations."""

    def setUp(self):
        """Set up signer with temp directories."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from addons import signer
        self.signer = signer

        self.tmpdir = tempfile.mkdtemp()
        audit_dir = Path(self.tmpdir) / "audit"

        self._orig_audit = signer.AUDIT_DIR
        self._orig_signed = signer.SIGNED_DIR
        self._orig_pubkey = signer.PUBKEY_PATH
        self._orig_privkey = signer.PRIVKEY_PATH
        self._orig_entries = signer._batch_entries
        self._orig_start = signer._batch_start_time
        self._orig_counter = signer._batch_counter

        signer.AUDIT_DIR = audit_dir
        signer.SIGNED_DIR = audit_dir / "signed"
        signer.PUBKEY_PATH = audit_dir / "session_pubkey.pem"
        signer.PRIVKEY_PATH = audit_dir / ".session_privkey.pem"
        signer._batch_entries = []
        signer._batch_start_time = None
        signer._batch_counter = 0

        signer.init()

    def tearDown(self):
        """Restore signer state."""
        import shutil
        self.signer.AUDIT_DIR = self._orig_audit
        self.signer.SIGNED_DIR = self._orig_signed
        self.signer.PUBKEY_PATH = self._orig_pubkey
        self.signer.PRIVKEY_PATH = self._orig_privkey
        self.signer._batch_entries = self._orig_entries
        self.signer._batch_start_time = self._orig_start
        self.signer._batch_counter = self._orig_counter
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_add_entry_accumulates(self):
        """add_entry() accumulates entries in batch."""
        self.signer.add_entry({"action": "test1"})
        self.signer.add_entry({"action": "test2"})
        self.assertEqual(len(self.signer._batch_entries), 2)

    def test_flush_writes_batch(self):
        """flush() writes batch and signature files."""
        self.signer.add_entry({"action": "test"})
        self.signer.flush()

        batch_file = self.signer.SIGNED_DIR / "batch_000001.jsonl"
        sig_file = self.signer.SIGNED_DIR / "batch_000001.jsonl.sig"
        self.assertTrue(batch_file.exists())
        self.assertTrue(sig_file.exists())

    def test_flush_clears_entries(self):
        """flush() clears the batch after writing."""
        self.signer.add_entry({"action": "test"})
        self.signer.flush()
        self.assertEqual(len(self.signer._batch_entries), 0)

    def test_flush_empty_batch_noop(self):
        """flush() with empty batch does nothing."""
        self.signer.flush()
        # No files should be created.
        signed_files = list(self.signer.SIGNED_DIR.iterdir())
        self.assertEqual(len(signed_files), 0)

    def test_batch_content_is_valid_json(self):
        """Batch file contains valid JSON."""
        self.signer.add_entry({"action": "test", "cell": "myapp"})
        self.signer.flush()

        batch_file = self.signer.SIGNED_DIR / "batch_000001.jsonl"
        data = json.loads(batch_file.read_bytes())
        self.assertEqual(data["entry_count"], 1)
        self.assertEqual(data["entries"][0]["action"], "test")

    def test_signature_is_valid(self):
        """Signature file contains valid verification data."""
        self.signer.add_entry({"action": "test"})
        self.signer.flush()

        sig_file = self.signer.SIGNED_DIR / "batch_000001.jsonl.sig"
        sig_data = json.loads(sig_file.read_bytes())
        self.assertIn("content_hash", sig_data)
        self.assertIn("signature", sig_data)
        self.assertIn("algorithm", sig_data)
        self.assertIn(sig_data["algorithm"], ("ed25519", "hmac-sha256"))

    def test_content_hash_matches(self):
        """Content hash in signature matches batch content."""
        self.signer.add_entry({"action": "test"})
        self.signer.flush()

        batch_file = self.signer.SIGNED_DIR / "batch_000001.jsonl"
        sig_file = self.signer.SIGNED_DIR / "batch_000001.jsonl.sig"

        batch_bytes = batch_file.read_bytes()
        sig_data = json.loads(sig_file.read_bytes())
        expected_hash = hashlib.sha256(batch_bytes).hexdigest()
        self.assertEqual(sig_data["content_hash"], expected_hash)

    def test_verify_batch_succeeds(self):
        """verify_batch() returns True for valid batch."""
        self.signer.add_entry({"action": "test"})
        self.signer.flush()

        batch_path = str(self.signer.SIGNED_DIR / "batch_000001.jsonl")
        pubkey_path = str(self.signer.PUBKEY_PATH)
        self.assertTrue(self.signer.verify_batch(batch_path, pubkey_path))

    def test_verify_batch_detects_tampering(self):
        """verify_batch() returns False for tampered batch."""
        self.signer.add_entry({"action": "test"})
        self.signer.flush()

        batch_path = self.signer.SIGNED_DIR / "batch_000001.jsonl"
        # Tamper with batch content.
        batch_path.write_bytes(b'{"tampered": true}')

        result = self.signer.verify_batch(
            str(batch_path), str(self.signer.PUBKEY_PATH)
        )
        self.assertFalse(result)

    def test_auto_flush_on_batch_size(self):
        """Batch auto-flushes when reaching BATCH_SIZE."""
        orig_size = self.signer.BATCH_SIZE
        self.signer.BATCH_SIZE = 5
        try:
            for i in range(5):
                self.signer.add_entry({"action": f"test{i}"})
            # Batch should have been flushed.
            self.assertEqual(len(self.signer._batch_entries), 0)
            batch_file = self.signer.SIGNED_DIR / "batch_000001.jsonl"
            self.assertTrue(batch_file.exists())
        finally:
            self.signer.BATCH_SIZE = orig_size


@unittest.skipUnless(_HAS_CRYPTOGRAPHY, "requires cryptography package")
class TestSignerThreadSafety(unittest.TestCase):
    """Tests for signer thread safety."""

    def setUp(self):
        """Set up signer with temp directories."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from addons import signer
        self.signer = signer

        self.tmpdir = tempfile.mkdtemp()
        audit_dir = Path(self.tmpdir) / "audit"

        self._orig_audit = signer.AUDIT_DIR
        self._orig_signed = signer.SIGNED_DIR
        self._orig_pubkey = signer.PUBKEY_PATH
        self._orig_privkey = signer.PRIVKEY_PATH
        self._orig_entries = signer._batch_entries
        self._orig_start = signer._batch_start_time
        self._orig_counter = signer._batch_counter
        self._orig_batch_size = signer.BATCH_SIZE

        signer.AUDIT_DIR = audit_dir
        signer.SIGNED_DIR = audit_dir / "signed"
        signer.PUBKEY_PATH = audit_dir / "session_pubkey.pem"
        signer.PRIVKEY_PATH = audit_dir / ".session_privkey.pem"
        signer._batch_entries = []
        signer._batch_start_time = None
        signer._batch_counter = 0
        signer.BATCH_SIZE = 1000  # High to prevent auto-flush during test.

        signer.init()

    def tearDown(self):
        """Restore signer state."""
        import shutil
        self.signer.AUDIT_DIR = self._orig_audit
        self.signer.SIGNED_DIR = self._orig_signed
        self.signer.PUBKEY_PATH = self._orig_pubkey
        self.signer.PRIVKEY_PATH = self._orig_privkey
        self.signer._batch_entries = self._orig_entries
        self.signer._batch_start_time = self._orig_start
        self.signer._batch_counter = self._orig_counter
        self.signer.BATCH_SIZE = self._orig_batch_size
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_concurrent_add_entry(self):
        """Concurrent add_entry() calls don't lose entries."""
        entries_per_thread = 50
        num_threads = 4

        def worker(thread_id):
            for i in range(entries_per_thread):
                self.signer.add_entry({"thread": thread_id, "seq": i})

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All entries should be present.
        total = len(self.signer._batch_entries)
        self.assertEqual(total, entries_per_thread * num_threads)

    def test_concurrent_flush(self):
        """Concurrent flush() calls don't corrupt data."""
        # Add entries, then flush from multiple threads.
        for i in range(20):
            self.signer.add_entry({"seq": i})

        def flusher():
            self.signer.flush()

        threads = [threading.Thread(target=flusher) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Entries should be flushed, no duplicates.
        self.assertEqual(len(self.signer._batch_entries), 0)


@unittest.skipUnless(_HAS_CRYPTOGRAPHY, "requires cryptography package")
class TestSignerAlgorithmTracking(unittest.TestCase):
    """Tests for signer algorithm tracking."""

    def test_algorithm_field_set(self):
        """_algorithm is set after init."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from addons import signer

        with tempfile.TemporaryDirectory() as tmpdir:
            audit_dir = Path(tmpdir) / "audit"
            orig = (signer.AUDIT_DIR, signer.SIGNED_DIR,
                    signer.PUBKEY_PATH, signer.PRIVKEY_PATH)
            try:
                signer.AUDIT_DIR = audit_dir
                signer.SIGNED_DIR = audit_dir / "signed"
                signer.PUBKEY_PATH = audit_dir / "session_pubkey.pem"
                signer.PRIVKEY_PATH = audit_dir / ".session_privkey.pem"
                signer.init()
                self.assertIn(signer._algorithm, ("ed25519", "hmac-sha256"))
            finally:
                signer.AUDIT_DIR, signer.SIGNED_DIR, \
                    signer.PUBKEY_PATH, signer.PRIVKEY_PATH = orig


# ========== brig/utils.py tests ==========

from brig import utils as brig_utils


class TestUtilsCheckRateLimit(unittest.TestCase):
    """Tests for brig/utils.py check_rate_limit function."""

    def setUp(self):
        """Create temp directory and redirect rate limit file."""
        self.temp_dir = tempfile.mkdtemp()
        self._orig_file = brig_utils.RATE_LIMIT_FILE
        self._orig_max = brig_utils.RATE_LIMIT_MAX
        self._orig_window = brig_utils.RATE_LIMIT_WINDOW
        brig_utils.RATE_LIMIT_FILE = Path(self.temp_dir) / "rate_limit.json"

    def tearDown(self):
        """Restore originals and clean up."""
        import shutil
        brig_utils.RATE_LIMIT_FILE = self._orig_file
        brig_utils.RATE_LIMIT_MAX = self._orig_max
        brig_utils.RATE_LIMIT_WINDOW = self._orig_window
        shutil.rmtree(self.temp_dir)

    def test_first_request_allowed(self):
        """Fresh file returns True."""
        self.assertTrue(brig_utils.check_rate_limit())

    def test_within_limit_allowed(self):
        """N-1 requests within window pass."""
        for _ in range(brig_utils.RATE_LIMIT_MAX - 1):
            self.assertTrue(brig_utils.check_rate_limit())

    def test_at_limit_blocked(self):
        """RATE_LIMIT_MAX requests, next returns False."""
        for _ in range(brig_utils.RATE_LIMIT_MAX):
            brig_utils.check_rate_limit()
        self.assertFalse(brig_utils.check_rate_limit())

    def test_window_expiry_resets(self):
        """Old timestamps expire, new requests allowed."""
        for _ in range(brig_utils.RATE_LIMIT_MAX):
            brig_utils.check_rate_limit()
        # Manually expire timestamps.
        with open(brig_utils.RATE_LIMIT_FILE, "r") as f:
            data = json.load(f)
        data["timestamps"] = [time.time() - brig_utils.RATE_LIMIT_WINDOW - 1]
        with open(brig_utils.RATE_LIMIT_FILE, "w") as f:
            json.dump(data, f)
        self.assertTrue(brig_utils.check_rate_limit())

    def test_corrupted_file_allows(self):
        """JSONDecodeError falls back to allow (fail-open)."""
        brig_utils.RATE_LIMIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(brig_utils.RATE_LIMIT_FILE, "w") as f:
            f.write("not json{{{")
        self.assertTrue(brig_utils.check_rate_limit())

    def test_missing_directory_created(self):
        """Parent dir created on first call."""
        brig_utils.RATE_LIMIT_FILE = Path(self.temp_dir) / "subdir" / "rate.json"
        self.assertTrue(brig_utils.check_rate_limit())
        self.assertTrue(brig_utils.RATE_LIMIT_FILE.parent.exists())

    def test_io_error_allows(self):
        """IOError returns True (fail-open)."""
        # Point to unwritable location.
        brig_utils.RATE_LIMIT_FILE = Path("/proc/nonexistent/rate.json")
        self.assertTrue(brig_utils.check_rate_limit())


class TestUtilsRedactCmd(unittest.TestCase):
    """Tests for brig/utils.py _redact_cmd function."""

    def test_flag_value_pair(self):
        """--secret mysecret is redacted."""
        result = brig_utils._redact_cmd(["cmd", "--secret", "mysecret"])
        self.assertIn("***", result)
        self.assertNotIn("mysecret", result)

    def test_equals_form(self):
        """--token=abc is redacted."""
        result = brig_utils._redact_cmd(["cmd", "--token=abc"])
        self.assertIn("--token=***", result)
        self.assertNotIn("abc", result)

    def test_normal_args_unchanged(self):
        """--name myapp is unchanged."""
        result = brig_utils._redact_cmd(["cmd", "--name", "myapp"])
        self.assertIn("myapp", result)

    def test_flag_at_end(self):
        """--secret at end does not crash."""
        result = brig_utils._redact_cmd(["cmd", "--secret"])
        self.assertIn("--secret", result)


class TestUtilsLogOperation(unittest.TestCase):
    """Tests for brig/utils.py log_operation function."""

    def setUp(self):
        """Redirect history file to temp."""
        self.temp_dir = tempfile.mkdtemp()
        self._orig = brig_utils.HISTORY_FILE
        brig_utils.HISTORY_FILE = Path(self.temp_dir) / "history.jsonl"

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        brig_utils.HISTORY_FILE = self._orig
        shutil.rmtree(self.temp_dir)

    def test_writes_jsonl(self):
        """Valid JSONL written with timestamp and operation."""
        brig_utils.log_operation("test_op")
        lines = brig_utils.HISTORY_FILE.read_text().strip().split("\n")
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["operation"], "test_op")
        self.assertIn("timestamp", entry)

    def test_with_cell_and_details(self):
        """Includes optional fields."""
        brig_utils.log_operation("run", cell_name="myapp", details={"image": "alpine"})
        entry = json.loads(brig_utils.HISTORY_FILE.read_text().strip())
        self.assertEqual(entry["cell"], "myapp")
        self.assertEqual(entry["details"]["image"], "alpine")

    def test_io_error_no_crash(self):
        """IOError silently caught."""
        brig_utils.HISTORY_FILE = Path("/proc/nonexistent/history.jsonl")
        brig_utils.log_operation("test")  # Should not raise.


class TestUtilsColorize(unittest.TestCase):
    """Tests for brig/utils.py colorize and status_color functions."""

    def setUp(self):
        """Enable colors for testing."""
        self._orig = brig_utils.COLOR_ENABLED
        brig_utils.COLOR_ENABLED = True

    def tearDown(self):
        """Restore color state."""
        brig_utils.COLOR_ENABLED = self._orig

    def test_colorize_known_color(self):
        """Returns ANSI-wrapped string."""
        result = brig_utils.colorize("hello", "green")
        self.assertIn("\033[32m", result)
        self.assertIn("hello", result)

    def test_colorize_unknown_color(self):
        """Returns plain string."""
        result = brig_utils.colorize("hello", "purple")
        self.assertEqual(result, "hello")

    def test_status_color_all_states(self):
        """All status states return a string."""
        for status in ("running", "paused", "exited", "stopped", "dead", "created", "unknown"):
            result = brig_utils.status_color(status)
            self.assertIsInstance(result, str)
            self.assertIn(status, result.lower().replace("\033[0m", "").replace("\033[32m", "").replace("\033[33m", "").replace("\033[31m", "").replace("\033[34m", ""))


class TestUtilsCache(unittest.TestCase):
    """Tests for brig/utils.py cache functions."""

    def setUp(self):
        """Clear cache."""
        brig_utils._cache.clear()

    def test_set_and_get_within_ttl(self):
        """Returns (True, value)."""
        brig_utils._set_cache("k", "v")
        hit, val = brig_utils._cached("k")
        self.assertTrue(hit)
        self.assertEqual(val, "v")

    def test_expired_returns_miss(self):
        """Returns (False, None)."""
        brig_utils._cache["k"] = (time.time() - 100, "v")
        hit, val = brig_utils._cached("k", ttl=1.0)
        self.assertFalse(hit)
        self.assertIsNone(val)

    def test_invalidate_cell_cache(self):
        """Removes both exists and running keys."""
        brig_utils._set_cache("cell_exists:app", True)
        brig_utils._set_cache("cell_running:app", True)
        brig_utils._set_cache("other", "val")
        brig_utils.invalidate_cell_cache("app")
        self.assertNotIn("cell_exists:app", brig_utils._cache)
        self.assertNotIn("cell_running:app", brig_utils._cache)
        self.assertIn("other", brig_utils._cache)


# ========== brig/container.py tests ==========

from brig import container


class TestContainerNames(unittest.TestCase):
    """Tests for container.py naming functions."""

    def test_container_name_format(self):
        """container_name adds brig- prefix."""
        self.assertEqual(container.container_name("x"), "brig-x")

    def test_network_name_format(self):
        """network_name adds brig- prefix."""
        self.assertEqual(container.network_name("x"), "brig-x")

    def test_valid_cell_names(self):
        """Valid DNS labels accepted."""
        for name in ["myapp", "my-app", "a1b2c3", "app.v2"]:
            self.assertTrue(container.CELL_NAME_PATTERN.match(name), f"{name} should be valid")

    def test_invalid_cell_names(self):
        """Rejects -start, empty, >63 chars, special chars."""
        for name in ["-start", "", "a" * 64, "has space", "has;semi"]:
            self.assertIsNone(container.CELL_NAME_PATTERN.match(name), f"{name} should be invalid")


class TestContainerCellPolicy(unittest.TestCase):
    """Tests for container.py policy file operations."""

    def setUp(self):
        """Redirect POLICY_DIR to temp."""
        self.temp_dir = tempfile.mkdtemp()
        self._orig = container.POLICY_DIR
        container.POLICY_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        container.POLICY_DIR = self._orig
        shutil.rmtree(self.temp_dir)

    def test_save_load_roundtrip(self):
        """Save dict, load it back, equal."""
        policy = {"allow": ["example.com"], "deny": ["evil.com"]}
        container.save_cell_policy("testcell", policy)
        loaded = container.load_cell_policy("testcell")
        self.assertEqual(loaded, policy)

    def test_load_nonexistent_returns_default(self):
        """Returns default empty policy."""
        result = container.load_cell_policy("nosuch")
        self.assertEqual(result, {"allow": [], "deny": []})

    def test_load_corrupted_json_returns_default(self):
        """Invalid JSON returns default."""
        policy_file = Path(self.temp_dir) / "bad.json"
        policy_file.write_text("not json{{{")
        result = container.load_cell_policy("bad")
        self.assertEqual(result, {"allow": [], "deny": []})

    def test_save_invalid_name_raises(self):
        """ValueError for path traversal."""
        with self.assertRaises(ValueError):
            container.save_cell_policy("../evil", {"allow": []})

    def test_delete_policy_exists(self):
        """File removed."""
        container.save_cell_policy("delme", {"allow": []})
        policy_file = Path(self.temp_dir) / "delme.json"
        self.assertTrue(policy_file.exists())
        container.delete_cell_policy("delme")
        self.assertFalse(policy_file.exists())

    def test_delete_policy_missing_no_error(self):
        """No crash when file missing."""
        container.delete_cell_policy("nonexistent")  # Should not raise.


# ========== Step 1a: Spinner context manager ==========


class TestSpinnerLifecycle(unittest.TestCase):
    """Tests for Spinner context manager lifecycle."""

    @patch.object(container, 'DEBUG', False)
    @patch('sys.stderr')
    def test_enter_starts_thread_on_tty(self, mock_stderr):
        """__enter__ starts spinner thread when stderr is a TTY."""
        mock_stderr.isatty.return_value = True
        spinner = container.Spinner("Loading")
        spinner.__enter__()
        self.assertTrue(spinner.running)
        self.assertIsNotNone(spinner.thread)
        spinner.__exit__(None, None, None)

    @patch.object(container, 'DEBUG', False)
    @patch('sys.stderr')
    def test_enter_no_thread_on_pipe(self, mock_stderr):
        """__enter__ skips thread when stderr is not a TTY."""
        mock_stderr.isatty.return_value = False
        spinner = container.Spinner("Loading")
        spinner.__enter__()
        self.assertFalse(spinner.running)
        self.assertIsNone(spinner.thread)
        spinner.__exit__(None, None, None)

    @patch.object(container, 'DEBUG', False)
    @patch('sys.stderr')
    def test_exit_clears_line_on_tty(self, mock_stderr):
        """__exit__ writes blanks to clear spinner on TTY."""
        mock_stderr.isatty.return_value = True
        spinner = container.Spinner("Test")
        spinner.__enter__()
        spinner.__exit__(None, None, None)
        self.assertFalse(spinner.running)
        # Should have written clear sequence.
        mock_stderr.write.assert_called()

    @patch('sys.stderr')
    def test_success_tty(self, mock_stderr):
        """success() prints green checkmark on TTY."""
        mock_stderr.isatty.return_value = True
        spinner = container.Spinner("Test")
        spinner.success("Done")
        self.assertFalse(spinner.running)
        written = "".join(call.args[0] for call in mock_stderr.write.call_args_list)
        self.assertIn("Done", written)

    @patch('sys.stderr')
    def test_success_no_output_on_pipe(self, mock_stderr):
        """success() produces no output when stderr is not a TTY."""
        mock_stderr.isatty.return_value = False
        spinner = container.Spinner("Test")
        spinner.success("Done")
        mock_stderr.write.assert_not_called()

    @patch('sys.stderr')
    def test_fail_tty(self, mock_stderr):
        """fail() prints red X on TTY."""
        mock_stderr.isatty.return_value = True
        spinner = container.Spinner("Test")
        spinner.fail("Failed")
        self.assertFalse(spinner.running)
        written = "".join(call.args[0] for call in mock_stderr.write.call_args_list)
        self.assertIn("Failed", written)

    @patch('sys.stderr')
    def test_fail_no_output_on_pipe(self, mock_stderr):
        """fail() produces no output when stderr is not a TTY."""
        mock_stderr.isatty.return_value = False
        spinner = container.Spinner("Test")
        spinner.fail("Failed")
        mock_stderr.write.assert_not_called()


# ========== Step 1b: cell_exists / cell_running / proxy_running ==========


class TestContainerCellExists(unittest.TestCase):
    """Tests for cell_exists, cell_running, proxy_running."""

    def setUp(self):
        """Clear cache between tests."""
        from brig import utils as brig_utils
        brig_utils._cache.clear()

    @patch('brig.container.run')
    def test_cell_exists_true(self, mock_run):
        """Returns True when container name is in stdout."""
        mock_run.return_value = MagicMock(stdout="brig-myapp\n", returncode=0)
        self.assertTrue(container.cell_exists("myapp"))

    @patch('brig.container.run')
    def test_cell_exists_false(self, mock_run):
        """Returns False when stdout is empty."""
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        self.assertFalse(container.cell_exists("myapp"))

    def test_cell_exists_invalid_name(self):
        """Returns False for names that fail regex."""
        self.assertFalse(container.cell_exists("../evil"))
        self.assertFalse(container.cell_exists("HAS_UPPER"))
        self.assertFalse(container.cell_exists(""))

    @patch('brig.container.run')
    def test_cell_running_true(self, mock_run):
        """Returns True when container is running."""
        mock_run.return_value = MagicMock(stdout="brig-myapp\n", returncode=0)
        self.assertTrue(container.cell_running("myapp"))

    @patch('brig.container.run')
    def test_cell_running_false(self, mock_run):
        """Returns False when container is not running."""
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        self.assertFalse(container.cell_running("myapp"))

    @patch('brig.container.run')
    def test_proxy_running_true(self, mock_run):
        """Returns True when proxy container is running."""
        mock_run.return_value = MagicMock(
            stdout=f"{container.PROXY_NAME}\n", returncode=0
        )
        self.assertTrue(container.proxy_running())

    @patch('brig.container.run')
    def test_proxy_running_false(self, mock_run):
        """Returns False when proxy is not running."""
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        self.assertFalse(container.proxy_running())

    @patch('brig.container.run')
    def test_cache_hit_skips_command(self, mock_run):
        """Second call returns cached value without running command."""
        mock_run.return_value = MagicMock(stdout="brig-myapp\n", returncode=0)
        container.cell_exists("myapp")
        container.cell_exists("myapp")
        # Only one subprocess call.
        mock_run.assert_called_once()


# ========== Step 1c: get_proxy_ip ==========


class TestContainerGetProxyIp(unittest.TestCase):
    """Tests for get_proxy_ip."""

    @patch('brig.container.run')
    def test_valid_network_returns_ip(self, mock_run):
        """Returns IP address for valid network."""
        mock_run.return_value = MagicMock(stdout="10.60.0.1\n", returncode=0)
        result = container.get_proxy_ip("brig-myapp")
        self.assertEqual(result, "10.60.0.1")

    def test_invalid_network_name_returns_empty(self):
        """Returns empty string for invalid network names."""
        self.assertEqual(container.get_proxy_ip("has/slash"), "")
        self.assertEqual(container.get_proxy_ip("has.dot"), "")
        self.assertEqual(container.get_proxy_ip(""), "")

    @patch('brig.container.run')
    def test_empty_stdout(self, mock_run):
        """Returns empty string when no IP found."""
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        result = container.get_proxy_ip("brig-myapp")
        self.assertEqual(result, "")


# ========== Step 1d: verify_image_signature ==========


class TestVerifyImageSignature(unittest.TestCase):
    """Tests for verify_image_signature."""

    @patch('brig.container.run')
    def test_cosign_success(self, mock_run):
        """Returns (True, msg) when cosign verifies."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which cosign
            MagicMock(returncode=0, stdout="verified"),  # cosign verify
        ]
        ok, msg = container.verify_image_signature("alpine:latest")
        self.assertTrue(ok)
        self.assertIn("cosign", msg)

    @patch('brig.container.run')
    def test_cosign_no_signatures(self, mock_run):
        """Returns (False, msg) when cosign finds no signatures."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # which cosign
            MagicMock(returncode=1, stderr="no matching signatures"),
        ]
        ok, msg = container.verify_image_signature("alpine:latest")
        self.assertFalse(ok)
        self.assertIn("no signature", msg.lower())

    @patch('brig.container.run')
    def test_cosign_unavailable_podman_accept(self, mock_run):
        """Falls back to podman trust, returns True if accept found."""
        mock_run.side_effect = [
            MagicMock(returncode=1),  # which cosign → not found
            MagicMock(returncode=0, stdout="default  accept"),  # podman trust
        ]
        ok, msg = container.verify_image_signature("alpine:latest")
        self.assertTrue(ok)
        self.assertIn("trusted", msg.lower())

    @patch('brig.container.run')
    def test_cosign_unavailable_podman_reject(self, mock_run):
        """Falls back to podman trust, returns False if no accept."""
        mock_run.side_effect = [
            MagicMock(returncode=1),  # which cosign → not found
            MagicMock(returncode=0, stdout="default  reject"),  # podman trust
        ]
        ok, msg = container.verify_image_signature("alpine:latest")
        self.assertFalse(ok)

    @patch('brig.container.run')
    def test_cosign_unavailable_podman_fails(self, mock_run):
        """Returns (False, msg) when both cosign and podman trust fail."""
        mock_run.side_effect = [
            MagicMock(returncode=1),  # which cosign
            MagicMock(returncode=1, stdout=""),  # podman trust fails
        ]
        ok, msg = container.verify_image_signature("alpine:latest")
        self.assertFalse(ok)


# ========== Step 5g: SDK path validation and JSON parsing ==========


class TestSdkPathValidation(unittest.TestCase):
    """Tests for SDK cp_in/cp_out path traversal checks."""

    def setUp(self):
        """Create test Brig and Cell."""
        from brig.sdk import Brig, Cell
        self.brig = Brig()
        self.cell = Cell("testcell", self.brig)

    def test_cp_in_local_traversal(self):
        """cp_in rejects .. in local_path."""
        from brig.utils import BrigError
        with self.assertRaises(BrigError):
            _async_run(self.cell.cp_in("../../etc/passwd", "/workspace/file"))

    def test_cp_in_cell_traversal(self):
        """cp_in rejects .. in cell_path."""
        from brig.utils import BrigError
        with self.assertRaises(BrigError):
            _async_run(self.cell.cp_in("/tmp/file", "../../../etc/shadow"))

    def test_cp_out_local_traversal(self):
        """cp_out rejects .. in local_path."""
        from brig.utils import BrigError
        with self.assertRaises(BrigError):
            _async_run(self.cell.cp_out("/workspace/file", "../../etc/passwd"))

    def test_cp_out_cell_traversal(self):
        """cp_out rejects .. in cell_path."""
        from brig.utils import BrigError
        with self.assertRaises(BrigError):
            _async_run(self.cell.cp_out("../../../etc/shadow", "/tmp/file"))


class TestSdkListJsonParsing(unittest.TestCase):
    """Tests for Brig.list() JSON parsing."""

    def setUp(self):
        """Create test Brig instance."""
        from brig.sdk import Brig
        self.brig = Brig()

    def test_list_json_parse_success(self):
        """Valid JSON produces CellInfo list."""
        mock_result = MagicMock(
            stdout=json.dumps([
                {"name": "app1", "status": "running", "image": "alpine"},
                {"name": "app2", "status": "exited", "image": "python:3.12"},
            ]),
            returncode=0,
        )
        with patch.object(self.brig, '_run_cmd', new_callable=AsyncMock,
                          return_value=mock_result):
            cells = _async_run(self.brig.list())
        self.assertEqual(len(cells), 2)
        self.assertEqual(cells[0].name, "app1")
        self.assertEqual(cells[1].status, "exited")

    def test_list_json_parse_failure(self):
        """Invalid JSON returns empty list."""
        mock_result = MagicMock(stdout="not json{{{", returncode=0)
        with patch.object(self.brig, '_run_cmd', new_callable=AsyncMock,
                          return_value=mock_result):
            cells = _async_run(self.brig.list())
        self.assertEqual(cells, [])


class TestSdkStatsFieldMapping(unittest.TestCase):
    """Tests for Brig.stats() field name resolution."""

    def setUp(self):
        """Create test Brig instance."""
        from brig.sdk import Brig
        self.brig = Brig()

    def test_stats_standard_fields(self):
        """Standard field names parsed correctly."""
        mock_result = MagicMock(
            stdout=json.dumps([{
                "cell": "app1",
                "cpu_percent": "5.2%",
                "mem_usage": "128MB",
                "mem_percent": "12%",
                "pids": "3",
            }]),
            returncode=0,
        )
        with patch.object(self.brig, '_run_cmd', new_callable=AsyncMock,
                          return_value=mock_result):
            stats = _async_run(self.brig.stats())
        self.assertEqual(len(stats), 1)
        self.assertEqual(stats[0].cell, "app1")
        self.assertEqual(stats[0].cpu_percent, "5.2%")

    def test_stats_alternate_fields(self):
        """Alternate field names (CPUPerc, MemUsage) resolved."""
        mock_result = MagicMock(
            stdout=json.dumps([{
                "Name": "app1",
                "CPUPerc": "5.2%",
                "MemUsage": "128MB",
                "MemPerc": "12%",
                "PIDs": "3",
            }]),
            returncode=0,
        )
        with patch.object(self.brig, '_run_cmd', new_callable=AsyncMock,
                          return_value=mock_result):
            stats = _async_run(self.brig.stats())
        self.assertEqual(stats[0].cell, "app1")
        self.assertEqual(stats[0].cpu_percent, "5.2%")
        self.assertEqual(stats[0].pids, "3")


# ========== Phase 11 Step 5c: brig_subnet.py state operations ==========


class TestBrigSubnetStateOps(unittest.TestCase):
    """Tests for brig_subnet.py pure state operations."""

    def setUp(self):
        """Set up temp directories for subnet state."""
        self.temp_dir = Path(tempfile.mkdtemp())
        import importlib.util
        subnet_path = Path(__file__).parent.parent / "src" / "brig_subnet.py"
        spec = importlib.util.spec_from_file_location("brig_subnet", subnet_path)
        self.subnet = importlib.util.module_from_spec(spec)
        # Override paths before exec_module to avoid touching real state.
        self.subnet.SUBNETS_FILE = self.temp_dir / "subnets.json"
        self.subnet.SUBNET_MAP_FILE = self.temp_dir / "subnet-map.json"
        self.subnet.LOCK_FILE = self.temp_dir / "allocator.lock"
        spec.loader.exec_module(self.subnet)
        # Re-override after exec (module-level constants may reset).
        self.subnet.SUBNETS_FILE = self.temp_dir / "subnets.json"
        self.subnet.SUBNET_MAP_FILE = self.temp_dir / "subnet-map.json"
        self.subnet.LOCK_FILE = self.temp_dir / "allocator.lock"

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_index_to_subnet(self):
        """Index converts to subnet string."""
        self.assertEqual(self.subnet.index_to_subnet(1), "10.60.1.0/24")
        self.assertEqual(self.subnet.index_to_subnet(254), "10.60.254.0/24")

    def test_validate_index_valid(self):
        """Valid indices return True."""
        self.assertTrue(self.subnet.validate_index(1))
        self.assertTrue(self.subnet.validate_index(127))
        self.assertTrue(self.subnet.validate_index(254))

    def test_validate_index_invalid(self):
        """Invalid indices return False."""
        self.assertFalse(self.subnet.validate_index(0))
        self.assertFalse(self.subnet.validate_index(255))
        self.assertFalse(self.subnet.validate_index(-1))

    def test_load_state_missing_file(self):
        """Missing state file returns default state."""
        state = self.subnet.load_state()
        self.assertEqual(state["next_index"], 1)
        self.assertEqual(state["allocated"], {})
        self.assertEqual(state["freed"], [])

    def test_validate_cell_name_valid(self):
        """Valid cell names do not raise."""
        for name in ["myapp", "my-app", "a1b2c3"]:
            self.subnet.validate_cell_name(name)  # Should not raise.

    def test_validate_cell_name_invalid(self):
        """Invalid cell names cause SystemExit."""
        for name in ["-bad", "../etc", "HAS SPACE"]:
            with self.assertRaises(SystemExit):
                self.subnet.validate_cell_name(name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
