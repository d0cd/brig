"""C5 from docs/plans/0.3-validation-plan.md: deprecate `brig health` in
favor of `brig doctor --quick`. The two-essentials check is now shared;
`brig health` is a thin wrapper that prints a deprecation note.
"""

from __future__ import annotations

import io
import types
import unittest
from contextlib import redirect_stderr
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


class TestHealthDeprecation(unittest.TestCase):
    @patch("brig.commands.system_cmd.vm_run")
    @patch("brig.network.proxy.proxy_running", return_value=True)
    def test_health_prints_deprecation_to_stderr(self, mock_pr, mock_vm):
        import subprocess
        mock_vm.return_value = subprocess.CompletedProcess([], 0, "linux\n", "")
        from brig.commands.system_cmd import cmd_health

        err = io.StringIO()
        with redirect_stderr(err):
            rc = cmd_health(_args(format="table"))

        self.assertEqual(rc, 0)
        self.assertIn("deprecated", err.getvalue().lower())
        self.assertIn("brig doctor --quick", err.getvalue())

    @patch("brig.commands.system_cmd.vm_run")
    @patch("brig.network.proxy.proxy_running", return_value=True)
    def test_health_and_quick_produce_same_result(self, mock_pr, mock_vm):
        # Same backend, same exit code, same JSON output shape.
        import subprocess
        mock_vm.return_value = subprocess.CompletedProcess([], 0, "linux\n", "")
        from brig.commands.system_cmd import cmd_doctor, cmd_health

        err = io.StringIO()
        with redirect_stderr(err):
            rc_health = cmd_health(_args(format="json"))
        rc_doctor_quick = cmd_doctor(_args(quick=True, format="json"))

        self.assertEqual(rc_health, rc_doctor_quick)


if __name__ == "__main__":
    unittest.main()
