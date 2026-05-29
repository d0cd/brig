"""User-facing diagnostics for `brig run`:
  - flag-after-image detection
  - directory-as-image catch
  - exit-cause diagnosis (read-only fs, missing bash)
"""

from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


def _args(**kw):
    defaults = dict(
        image=None, container_cmd=None, name=None, env=None, secret=None,
        memory=None, cpus=None, pids_limit=None, network=None, profile=None,
        file=None, policy_allow=None, policy_deny=None, label=None,
        timeout=None, workspace_quota=None, detach=False, rm=False,
        image_digest=None, workdir=None,
    )
    defaults.update(kw)
    return types.SimpleNamespace(**defaults)


class TestFlagAfterImageDetector(unittest.TestCase):
    def test_brig_flag_in_container_cmd_position_rejected(self):
        from brig.commands.lifecycle_cmd import cmd_run
        from brig.errors import BrigError
        with self.assertRaises(BrigError) as ctx:
            cmd_run(_args(image="alpine", container_cmd=["--memory", "256m", "sh"]))
        self.assertIn("looks like a brig flag", str(ctx.exception))

    def test_brig_flag_after_double_dash_separator_rejected(self):
        from brig.commands.lifecycle_cmd import cmd_run
        from brig.errors import BrigError
        with self.assertRaises(BrigError):
            cmd_run(_args(image="alpine", container_cmd=["--", "--detach"]))

    def test_legit_container_arg_starting_with_dash_allowed(self):
        # `ls -la` should not trigger — `-la` isn't a known brig flag.
        from brig.commands.lifecycle_cmd import cmd_run
        from brig.errors import BrigError
        # We expect this to proceed past the flag-detector; downstream
        # mocks will short-circuit so it doesn't actually run.
        with patch("brig.commands.lifecycle_cmd.run_cell") as mock_run:
            mock_run.return_value = MagicMock(success=True, container_id="abc")
            with patch("brig.ops.logging.Spinner"):
                with patch("brig.commands.lifecycle_cmd._check_immediate_exit"):
                    try:
                        cmd_run(_args(image="alpine", container_cmd=["ls", "-la"]))
                    except BrigError as e:
                        self.fail(f"unexpected BrigError: {e}")


class TestDirAsImageRefDetector(unittest.TestCase):
    def test_directory_argument_suggests_build(self):
        from brig.commands.lifecycle_cmd import cmd_run
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            ctx_dir = Path(td) / "my-cell"
            ctx_dir.mkdir()
            with self.assertRaises(BrigError) as ctx:
                cmd_run(_args(image=str(ctx_dir)))
            self.assertIn("is a directory", str(ctx.exception))
            self.assertIn("brig image build", str(ctx.exception.suggestion))

    def test_localhost_image_ref_not_caught(self):
        # `localhost/foo:latest` contains '/' but shouldn't be flagged.
        from brig.commands.lifecycle_cmd import cmd_run
        with patch("brig.commands.lifecycle_cmd.run_cell") as mock_run:
            mock_run.return_value = MagicMock(success=True, container_id="abc")
            with patch("brig.ops.logging.Spinner"):
                with patch("brig.commands.lifecycle_cmd._check_immediate_exit"):
                    cmd_run(_args(image="localhost/foo:latest"))
                    self.assertTrue(mock_run.called)


class TestDiagnoseExit(unittest.TestCase):
    """The exit-cause diagnoser pattern-matches container logs for
    common causes and suggests the fix."""

    def test_read_only_filesystem_suggests_writable_rootfs(self):
        from brig.commands.lifecycle_cmd import _diagnose_exit
        hint = _diagnose_exit(
            "mkdir: cannot create directory '/var/log/app': Read-only file system"
        )
        self.assertIn("writable_rootfs: true", hint)

    def test_read_only_filesystem_lists_writable_paths(self):
        """Feedback #4: the writable paths should appear in the hint so
        users know HOME=/tmp/home is the lighter fix than writable_rootfs."""
        from brig.commands.lifecycle_cmd import _diagnose_exit
        hint = _diagnose_exit(
            "mkdir: cannot create directory '/var/log/app': Read-only file system"
        )
        for path in ("/work", "/tmp", "/run"):
            self.assertIn(path, hint)
        self.assertIn("HOME=/tmp/home", hint)

    def test_errno_30_also_matches(self):
        from brig.commands.lifecycle_cmd import _diagnose_exit
        hint = _diagnose_exit("OSError: [Errno 30] Read-only file system: '/etc/foo'")
        self.assertIn("writable_rootfs", hint)

    def test_missing_bash_suggests_sh(self):
        from brig.commands.lifecycle_cmd import _diagnose_exit
        hint = _diagnose_exit(
            "executable file not found in $PATH: \"bash\""
        )
        self.assertIn("sh", hint)

    def test_unknown_pattern_returns_empty(self):
        from brig.commands.lifecycle_cmd import _diagnose_exit
        self.assertEqual(_diagnose_exit("something else exited 1"), "")


if __name__ == "__main__":
    unittest.main()
