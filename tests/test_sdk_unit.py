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
    Brig, Cell, BrigError, CellResult, CellInfo, CellRunResult,
    CellEvent, CellStats, WardenStatus, WardenHandle, _run_sync,
)


def _async_run(coro):
    """Run an async coroutine for testing."""
    return asyncio.get_event_loop().run_until_complete(coro)


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
            cell = _async_run(b.run(name="test", image="alpine"))

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
        """wait() returns CellResult with exit code."""
        b = Brig()
        c = Cell("test", b)
        with patch.object(b, '_run_cmd', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = MagicMock(
                stdout='{"cell":"test","exit_code":0}',
                returncode=0,
            )
            result = _async_run(c.wait())
            self.assertIsInstance(result, CellResult)
            self.assertEqual(result.exit_code, 0)

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
            for good_name in ["myapp", "my-app", "App1", "a1b2c3"]:
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
