"""Audit fixes (batch 2) — lifecycle and cleanup gaps.

H2 — ingress-token failure rolls the cell back instead of leaving it
     running with no ingress
H3 — bridge rolled back if apply() fails or rolls back its actions
H4 — brig down enumerates and bootouts all loaded host_socket bridges
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestH3BridgeRollbackOnApplyFailure(unittest.TestCase):
    """When apply() returns success=False or raises, any bridges we
    started must be torn down so we don't leak a socat process for a
    cell that never finished starting."""

    def _spec(self):
        from brig.cell.spec import CellSpec
        return CellSpec(
            name="alice", image="alpine",
            host_sockets=[{"name": "pg", "host_path": "/tmp/x.sock",
                           "mount_point": "/run/host/pg.sock"}],
        )

    def _common_patches(self, apply_result):
        observed = MagicMock(exists=False, running=False, network_exists=False)
        return [
            patch("brig.cell.lifecycle.observe", return_value=observed),
            patch("brig.cell.lifecycle.check_rate_limit", return_value=True),
            patch("brig.cell.lifecycle.plan_run",
                  return_value=[MagicMock()]),  # nonempty so we don't bail
            patch("brig.cell.lifecycle.apply", return_value=apply_result),
        ]

    def test_apply_failure_tears_down_bridges(self):
        from brig.cell.lifecycle import run_cell
        from brig.errors import BrigError
        bad_apply = MagicMock(
            success=False,
            actions_failed=[(MagicMock(), "podman run failed")],
        )
        with patch("brig.cell.host_sockets_bridge.start_cell_bridges") as start_b, \
             patch("brig.cell.host_sockets_bridge.stop_cell_bridges") as stop_b:
            patches = self._common_patches(bad_apply)
            for p in patches:
                p.start()
            try:
                with self.assertRaises(BrigError):
                    run_cell(self._spec(), proxy_check=lambda: True)
            finally:
                for p in patches:
                    p.stop()
        start_b.assert_called_once_with("alice", unittest.mock.ANY)
        stop_b.assert_called_once_with("alice")

    def test_apply_exception_tears_down_bridges(self):
        from brig.cell.lifecycle import run_cell
        with patch("brig.cell.host_sockets_bridge.start_cell_bridges") as start_b, \
             patch("brig.cell.host_sockets_bridge.stop_cell_bridges") as stop_b:
            observed = MagicMock(exists=False, running=False, network_exists=False)
            with patch("brig.cell.lifecycle.observe", return_value=observed), \
                 patch("brig.cell.lifecycle.check_rate_limit", return_value=True), \
                 patch("brig.cell.lifecycle.plan_run", return_value=[MagicMock()]), \
                 patch("brig.cell.lifecycle.apply",
                       side_effect=RuntimeError("boom")):
                with self.assertRaises(RuntimeError):
                    run_cell(self._spec(), proxy_check=lambda: True)
        start_b.assert_called_once()
        stop_b.assert_called_once_with("alice")


class TestH2IngressTokenFailureRollsBackCell(unittest.TestCase):
    """If _register_cell_ingress raises (missing token), the cell —
    which is already running by that point — must be torn down. Leaving
    it running with no ingress = silent broken state."""

    def test_ingress_failure_calls_rm_cell(self):
        from brig.cell.lifecycle import run_cell
        from brig.cell.spec import CellSpec
        from brig.errors import BrigError
        spec = CellSpec(
            name="alice", image="alpine",
            ingress=[{"name": "api", "port": 8080,
                      "path_prefix": "/api", "auth": "token"}],
        )
        good_apply = MagicMock(
            success=True, actions_failed=[], container_id="abc",
        )
        observed = MagicMock(exists=False, running=False, network_exists=False)
        with patch("brig.cell.lifecycle.observe", return_value=observed), \
             patch("brig.cell.lifecycle.check_rate_limit", return_value=True), \
             patch("brig.cell.lifecycle.plan_run", return_value=[MagicMock()]), \
             patch("brig.cell.lifecycle.apply", return_value=good_apply), \
             patch("brig.cell.lifecycle._register_cell_ingress",
                   side_effect=BrigError("no token")), \
             patch("brig.cell.lifecycle.rm_cell") as mock_rm:
            with self.assertRaises(BrigError):
                run_cell(spec, proxy_check=lambda: True)
        mock_rm.assert_called_once_with("alice", force=True)


class TestH4BrigDownTearsDownAllBridges(unittest.TestCase):
    def test_enumerates_loaded_bridges_and_stops_each_cell(self):
        from brig.commands.convenience_cmd import _bootout_all_host_socket_bridges
        from brig.cell.host_sockets_bridge import LABEL_PREFIX
        with tempfile.TemporaryDirectory() as td:
            plist_dir = Path(td)
            (plist_dir / f"{LABEL_PREFIX}alice.pg.plist").write_text("x")
            (plist_dir / f"{LABEL_PREFIX}alice.redis.plist").write_text("x")
            (plist_dir / f"{LABEL_PREFIX}bob.pg.plist").write_text("x")
            (plist_dir / "com.other.label.plist").write_text("x")  # unrelated
            with patch("brig.cell.host_sockets_bridge.PLIST_DIR", plist_dir), \
                 patch("brig.cell.host_sockets_bridge.stop_cell_bridges") as stop_b:
                _bootout_all_host_socket_bridges()
        called_for = {call.args[0] for call in stop_b.call_args_list}
        self.assertEqual(called_for, {"alice", "bob"})

    def test_no_plists_no_op(self):
        from brig.commands.convenience_cmd import _bootout_all_host_socket_bridges
        with tempfile.TemporaryDirectory() as td:
            with patch("brig.cell.host_sockets_bridge.PLIST_DIR", Path(td)), \
                 patch("brig.cell.host_sockets_bridge.stop_cell_bridges") as stop_b:
                _bootout_all_host_socket_bridges()
        stop_b.assert_not_called()


if __name__ == "__main__":
    unittest.main()
