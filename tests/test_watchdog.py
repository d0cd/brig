"""Watchdog VM-awareness.

When warden is unreachable, the watchdog brings the *whole stack* up via
`brig system up` (which starts the Lima VM if the host slept and dropped it —
a bare warden restart can't). On the healthy path it just reconciles cells.
"""

import argparse
import unittest
from unittest.mock import patch


class _StopLoop(Exception):
    """Raised from a patched time.sleep to exit the watchdog after one tick."""


class TestWatchdogVmAware(unittest.TestCase):
    def _run_one_tick(self, *, proxy_up):
        from brig.commands.watchdog_cmd import cmd_watchdog

        with patch("brig.network.proxy.proxy_running", return_value=proxy_up), patch(
            "brig.commands.convenience_cmd.cmd_up", return_value=0
        ) as mock_up, patch(
            "brig.cell.lifecycle.restore_persisted_cells"
        ) as mock_restore, patch(
            "brig.cell.lifecycle.enforce_workspace_quotas", return_value=[]
        ), patch(
            "brig.commands.watchdog_cmd.time.sleep", side_effect=_StopLoop
        ):
            try:
                cmd_watchdog(argparse.Namespace(interval=1, max_restarts=5))
            except _StopLoop:
                pass
            return mock_up, mock_restore

    def test_warden_down_brings_whole_stack_up(self):
        # Warden unreachable → run `system up` (VM-aware), not a bare warden
        # restart, so a dropped Lima VM is restarted.
        mock_up, _ = self._run_one_tick(proxy_up=False)
        mock_up.assert_called_once()

    def test_healthy_reconciles_cells_without_bringup(self):
        # Warden reachable → cheap cell reconcile; no full bring-up.
        mock_up, mock_restore = self._run_one_tick(proxy_up=True)
        mock_up.assert_not_called()
        mock_restore.assert_called_once()

    def test_watchdog_runs_without_vm(self):
        # The supervisor must be exempt from the "VM is not running" preflight —
        # it brings the VM up itself, so it can't require the VM to already run.
        from brig.cli import _is_host_only

        args = argparse.Namespace(command="system", system_command="watchdog")
        self.assertTrue(_is_host_only(args))
