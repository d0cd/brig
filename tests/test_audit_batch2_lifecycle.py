"""Audit fixes (batch 2) — lifecycle and cleanup gaps.

H2 — ingress-token failure rolls the cell back instead of leaving it
     running with no ingress
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch


class TestH2IngressTokenFailureRollsBackCell(unittest.TestCase):
    """If register_ingress_for raises (missing token), the cell —
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
             patch("brig.cell.lifecycle.register_ingress_for",
                   side_effect=BrigError("no token")), \
             patch("brig.cell.lifecycle.rm_cell") as mock_rm:
            with self.assertRaises(BrigError):
                run_cell(spec, proxy_check=lambda: True)
        mock_rm.assert_called_once_with("alice", force=True, keep_workspace=True)


class TestKillCellStoppedCell(unittest.TestCase):
    """kill_cell on an existing-but-stopped cell must raise (like stop_cell)
    rather than deregister ingress and log a false 'kill' success when no
    PODMAN_KILL action actually runs."""

    def test_kill_stopped_cell_raises_and_leaves_ingress(self):
        from brig.cell.lifecycle import kill_cell
        from brig.errors import BrigError
        stopped = MagicMock(exists=True, running=False, status="exited")
        with patch("brig.cell.lifecycle.observe", return_value=stopped), \
             patch("brig.cell.lifecycle.apply") as mock_apply, \
             patch("brig.network.ingress.deregister_ingress") as mock_dereg:
            with self.assertRaises(BrigError):
                kill_cell("ghost")
        mock_apply.assert_not_called()
        mock_dereg.assert_not_called()

    def test_kill_running_cell_kills_and_deregisters(self):
        from brig.cell.lifecycle import kill_cell
        running = MagicMock(exists=True, running=True, status="running")
        good = MagicMock(success=True, actions_failed=[])
        with patch("brig.cell.lifecycle.observe", return_value=running), \
             patch("brig.cell.lifecycle.apply", return_value=good) as mock_apply, \
             patch("brig.network.ingress.deregister_ingress") as mock_dereg, \
             patch("brig.cell.lifecycle.log_operation"), \
             patch("brig.cell.lifecycle.log_lifecycle"):
            kill_cell("live")
        mock_apply.assert_called_once()
        mock_dereg.assert_called_once_with("live")


class TestEnforceWorkspaceQuotas(unittest.TestCase):
    """Reactive soft-quota: a running cell whose workspace exceeds its
    workspace_quota is stopped (halting further disk growth); under-quota and
    quota-less cells are left alone."""

    def _persist_quota(self, cell, quota):
        # Write REAL cell-metadata.json (as create does) rather than mocking a
        # reader — this is what catches the restart:always-only regression: the
        # metadata file is written for every cell, cell-spec.json is not.
        from brig.cell.metadata import write_metadata, _host_metadata_path
        _host_metadata_path(cell).parent.mkdir(parents=True, exist_ok=True)
        write_metadata(cell, "/work", workspace_quota=quota)

    def _enforce(self, quotas, sizes):
        from brig.cell.lifecycle import enforce_workspace_quotas
        for cell, quota in quotas.items():
            self._persist_quota(cell, quota)
        with patch("brig.cell.lifecycle.list_cell_containers",
                   return_value=[(c, {}) for c in quotas]), \
             patch("brig.workspace.workspace._get_workspace_size",
                   side_effect=lambda c: sizes.get(c, 0)), \
             patch("brig.cell.lifecycle.stop_cell") as stop:
            result = enforce_workspace_quotas()
        return result, stop

    def test_over_quota_default_restart_cell_stopped(self):
        # Regression for the audit finding: a default (restart:"no") cell has no
        # cell-spec.json, only cell-metadata.json. Quota MUST still be enforced.
        result, stop = self._enforce({"big": "1m"}, {"big": 5 * 1024 * 1024})
        stop.assert_called_once_with("big")
        self.assertEqual([r[0] for r in result], ["big"])

    def test_under_quota_not_stopped(self):
        result, stop = self._enforce({"small": "10m"}, {"small": 1 * 1024 * 1024})
        stop.assert_not_called()
        self.assertEqual(result, [])

    def test_no_quota_skipped(self):
        result, stop = self._enforce({"unbounded": None}, {"unbounded": 999 * 1024 * 1024})
        stop.assert_not_called()

    def test_unmeasurable_size_skipped(self):
        # du failure -> _get_workspace_size returns None -> best-effort skip
        # (don't stop a cell we can't measure).
        from brig.cell.lifecycle import enforce_workspace_quotas
        self._persist_quota("blip", "1m")
        with patch("brig.cell.lifecycle.list_cell_containers",
                   return_value=[("blip", {})]), \
             patch("brig.workspace.workspace._get_workspace_size",
                   return_value=None), \
             patch("brig.cell.lifecycle.stop_cell") as stop:
            result = enforce_workspace_quotas()
        stop.assert_not_called()
        self.assertEqual(result, [])

    def test_no_metadata_skipped(self):
        # Cell with no metadata file at all (predates the field / never written).
        from brig.cell.lifecycle import enforce_workspace_quotas
        with patch("brig.cell.lifecycle.list_cell_containers",
                   return_value=[("ghost", {})]), \
             patch("brig.workspace.workspace._get_workspace_size",
                   return_value=999 * 1024 * 1024), \
             patch("brig.cell.lifecycle.stop_cell") as stop:
            enforce_workspace_quotas()
        stop.assert_not_called()

    def test_stop_failure_still_reported(self):
        from brig.errors import BrigError
        from brig.cell.lifecycle import enforce_workspace_quotas
        self._persist_quota("big", "1m")
        with patch("brig.cell.lifecycle.list_cell_containers",
                   return_value=[("big", {})]), \
             patch("brig.workspace.workspace._get_workspace_size",
                   return_value=5 * 1024 * 1024), \
             patch("brig.cell.lifecycle.stop_cell",
                   side_effect=BrigError("already gone")):
            result = enforce_workspace_quotas()
        # Best-effort stop: a failure is swallowed but the breach is reported.
        self.assertEqual([r[0] for r in result], ["big"])


class TestIngressReplayUntrustedAuthNoneGate(unittest.TestCase):
    """The ingress-replay path (brig cell start) must re-apply the
    untrusted-profile auth:none gate using the persisted profile — a tampered
    cell-metadata.json can't hand an untrusted cell an unauthenticated route."""

    def _persist_profile(self, cell, profile):
        from brig.cell.metadata import write_metadata, _host_metadata_path
        _host_metadata_path(cell).parent.mkdir(parents=True, exist_ok=True)
        write_metadata(cell, "/work", profile=profile)

    def test_untrusted_auth_none_refused_on_replay(self):
        from brig.cell.lifecycle import register_ingress_for
        from brig.errors import BrigError
        self._persist_profile("adv", "untrusted")
        entry = {"name": "api", "port": 8642, "path_prefix": "/api", "auth": "none"}
        with self.assertRaises(BrigError) as ctx:
            register_ingress_for("adv", [entry])
        self.assertIn("auth: none is not allowed", str(ctx.exception))

    def test_trusted_auth_none_passes_the_gate(self):
        # A non-untrusted cell may use auth:none; the gate must NOT fire (it
        # proceeds and fails later on container inspect, a different error).
        from brig.cell.lifecycle import register_ingress_for
        from brig.errors import BrigError
        self._persist_profile("sup", "supervised")
        entry = {"name": "api", "port": 8642, "path_prefix": "/api", "auth": "none"}
        with patch("brig.cell.reconciler._podman_inspect_json", return_value=None):
            with self.assertRaises(BrigError) as ctx:
                register_ingress_for("sup", [entry])
        self.assertNotIn("auth: none is not allowed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
