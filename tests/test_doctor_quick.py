"""C5 from docs/plans/0.3-validation-plan.md: `brig system doctor --quick`
is the two-essentials check (formerly `brig health`, removed in the 0.3.0
CLI rename).
"""

from __future__ import annotations

import types
import unittest
from unittest.mock import patch


def _args(**kw) -> types.SimpleNamespace:
    return types.SimpleNamespace(**kw)


class TestDoctorQuickFlag(unittest.TestCase):
    @patch("brig.commands.system_cmd.vm_run")
    @patch("brig.network.proxy.proxy_running", return_value=True)
    def test_doctor_quick_runs_two_essentials(self, mock_pr, mock_vm):
        import subprocess
        mock_vm.return_value = subprocess.CompletedProcess([], 0, "linux\n", "")
        from brig.commands.system_cmd import cmd_doctor

        rc = cmd_doctor(_args(quick=True, format="table"))
        self.assertEqual(rc, 0)
        # Quick path must NOT call the heavy doctor (shutil.which loops, etc.)
        # — assert via small surface: vm_run was called exactly once (for the
        # podman info check, not the dozen other heavy checks).
        self.assertEqual(mock_vm.call_count, 1)

    @patch("brig.commands.system_cmd.vm_run")
    @patch("brig.network.proxy.proxy_running", return_value=False)
    def test_doctor_quick_returns_nonzero_on_failure(self, mock_pr, mock_vm):
        import subprocess
        mock_vm.return_value = subprocess.CompletedProcess([], 0, "linux\n", "")
        from brig.commands.system_cmd import cmd_doctor

        rc = cmd_doctor(_args(quick=True, format="table"))
        self.assertEqual(rc, 1)


class TestHealthRemoved(unittest.TestCase):
    """Hard-rename guard: `brig health` is gone, both as a CLI command
    and as an importable function."""

    def test_cmd_health_function_removed(self):
        from brig.commands import system_cmd
        self.assertFalse(
            hasattr(system_cmd, "cmd_health"),
            "cmd_health should have been removed; the replacement is "
            "_cmd_doctor_quick (private) exposed via `brig system doctor --quick`",
        )


if __name__ == "__main__":
    unittest.main()
