"""Tests for the cmd_restart composite verb and the cmd_rm interactive
workspace-protection prompt.

- restart composes stop + start; refuses if the cell doesn't exist.
- rm prompts before deleting a non-empty workspace; refuses
  non-interactively unless --force or --keep-workspace was passed.
"""

from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


def _args(**kw):
    defaults = dict(name="alice", force=False, keep_workspace=False)
    defaults.update(kw)
    return types.SimpleNamespace(**defaults)


class TestRestart(unittest.TestCase):
    def test_restart_missing_cell_raises(self):
        from brig.commands.lifecycle_control import cmd_restart
        from brig.errors import BrigError
        observed = MagicMock(exists=False, running=False)
        with patch("brig.cell.lifecycle.observe", return_value=observed):
            with self.assertRaises(BrigError) as ctx:
                cmd_restart(_args(name="ghost"))
        self.assertIn("does not exist", str(ctx.exception))

    def test_restart_when_running_stops_then_starts(self):
        from brig.commands.lifecycle_control import cmd_restart
        observed = MagicMock(exists=True, running=True)
        with patch("brig.cell.lifecycle.observe", return_value=observed), \
             patch("brig.cell.lifecycle.stop_cell") as mock_stop, \
             patch("brig.commands.lifecycle_control.cmd_start", return_value=0) as mock_start:
            rc = cmd_restart(_args(name="alice"))
        mock_stop.assert_called_once_with("alice")
        mock_start.assert_called_once()
        self.assertEqual(rc, 0)

    def test_restart_when_stopped_skips_stop(self):
        from brig.commands.lifecycle_control import cmd_restart
        observed = MagicMock(exists=True, running=False)
        with patch("brig.cell.lifecycle.observe", return_value=observed), \
             patch("brig.cell.lifecycle.stop_cell") as mock_stop, \
             patch("brig.commands.lifecycle_control.cmd_start", return_value=0) as mock_start:
            cmd_restart(_args(name="alice"))
        mock_stop.assert_not_called()
        mock_start.assert_called_once()


class TestRmInteractivePrompt(unittest.TestCase):
    """rm with a non-empty workspace asks before deleting; the answer
    'keep' flips --keep-workspace on without aborting."""

    def _state_with_files(self, td: Path, cell_name: str) -> Path:
        cell_state = td / cell_name
        ws = cell_state / "workspace"
        ws.mkdir(parents=True)
        (ws / "data.txt").write_text("important")
        return cell_state

    def test_non_tty_refuses(self):
        from brig.commands.lifecycle_control import cmd_rm
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            self._state_with_files(Path(td), "alice")
            with patch("brig.config.HostPaths.STATE_DIR", Path(td)), \
                 patch("sys.stdin.isatty", return_value=False), \
                 patch("brig.commands.lifecycle_control.rm_cell") as mock_rm:
                with self.assertRaises(BrigError) as ctx:
                    cmd_rm(_args(name="alice"))
        self.assertIn("refusing to delete non-interactively", str(ctx.exception))
        mock_rm.assert_not_called()

    def test_prompt_yes_proceeds_with_delete(self):
        from brig.commands.lifecycle_control import cmd_rm
        with tempfile.TemporaryDirectory() as td:
            self._state_with_files(Path(td), "alice")
            with patch("brig.config.HostPaths.STATE_DIR", Path(td)), \
                 patch("sys.stdin.isatty", return_value=True), \
                 patch("builtins.input", return_value="y"), \
                 patch("brig.commands.lifecycle_control.rm_cell") as mock_rm:
                rc = cmd_rm(_args(name="alice"))
        self.assertEqual(rc, 0)
        mock_rm.assert_called_once_with("alice", force=False, keep_workspace=False)

    def test_prompt_keep_flips_keep_workspace(self):
        from brig.commands.lifecycle_control import cmd_rm
        with tempfile.TemporaryDirectory() as td:
            self._state_with_files(Path(td), "alice")
            with patch("brig.config.HostPaths.STATE_DIR", Path(td)), \
                 patch("sys.stdin.isatty", return_value=True), \
                 patch("builtins.input", return_value="keep"), \
                 patch("brig.commands.lifecycle_control.rm_cell") as mock_rm:
                rc = cmd_rm(_args(name="alice"))
        self.assertEqual(rc, 0)
        mock_rm.assert_called_once_with("alice", force=False, keep_workspace=True)

    def test_prompt_default_aborts(self):
        from brig.commands.lifecycle_control import cmd_rm
        with tempfile.TemporaryDirectory() as td:
            self._state_with_files(Path(td), "alice")
            with patch("brig.config.HostPaths.STATE_DIR", Path(td)), \
                 patch("sys.stdin.isatty", return_value=True), \
                 patch("builtins.input", return_value=""), \
                 patch("brig.commands.lifecycle_control.rm_cell") as mock_rm:
                rc = cmd_rm(_args(name="alice"))
        self.assertEqual(rc, 1)
        mock_rm.assert_not_called()

    def test_force_skips_prompt(self):
        from brig.commands.lifecycle_control import cmd_rm
        with tempfile.TemporaryDirectory() as td:
            self._state_with_files(Path(td), "alice")
            with patch("brig.config.HostPaths.STATE_DIR", Path(td)), \
                 patch("sys.stdin.isatty", return_value=False), \
                 patch("brig.commands.lifecycle_control.rm_cell") as mock_rm, \
                 patch("builtins.input") as mock_input:
                cmd_rm(_args(name="alice", force=True))
        mock_input.assert_not_called()
        mock_rm.assert_called_once()

    def test_empty_workspace_skips_prompt(self):
        from brig.commands.lifecycle_control import cmd_rm
        with tempfile.TemporaryDirectory() as td:
            with patch("brig.config.HostPaths.STATE_DIR", Path(td)), \
                 patch("brig.commands.lifecycle_control.rm_cell") as mock_rm, \
                 patch("builtins.input") as mock_input:
                cmd_rm(_args(name="ghost"))
        mock_input.assert_not_called()
        mock_rm.assert_called_once()


if __name__ == "__main__":
    unittest.main()
