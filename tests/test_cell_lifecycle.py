"""Tests for brig.cell.lifecycle — high-level lifecycle operations.

Covers invariant 9 (proxy must be running before cells start).
Uses proxy_check callable for clean testability — no subprocess mocking needed.
"""

import unittest
from unittest.mock import patch

from brig.cell.lifecycle import kill_cell, rm_cell, run_cell, stop_cell
from brig.cell.reconciler import CellState, ReconcileResult
from brig.cell.spec import CellSpec
from brig.errors import BrigError


class TestRunCell(unittest.TestCase):
    """Test run_cell() enforces invariants and delegates to reconciler."""

    @patch("brig.cell.lifecycle.check_rate_limit", return_value=True)
    def test_invariant_9_proxy_must_be_running(self, mock_rate):
        """Invariant 9: run_cell() fails if proxy is not running."""
        spec = CellSpec(name="test", image="alpine")
        with self.assertRaisesRegex(BrigError, "not running"):
            run_cell(spec, proxy_check=lambda: False)

    @patch("brig.cell.lifecycle.check_rate_limit", return_value=True)
    def test_airgapped_skips_proxy_check(self, mock_rate):
        """Airgapped cells skip proxy check."""
        spec = CellSpec(name="test", image="alpine", network="none")
        proxy_called = False
        def fake_proxy():
            nonlocal proxy_called
            proxy_called = True
            return True

        with patch("brig.cell.lifecycle.observe") as mock_observe, \
             patch("brig.cell.lifecycle.apply") as mock_apply:
            mock_observe.return_value = CellState()
            mock_apply.return_value = ReconcileResult(success=True, container_id="abc123")
            result = run_cell(spec, proxy_check=fake_proxy)
            self.assertTrue(result.success)
            self.assertFalse(proxy_called)

    @patch("brig.cell.lifecycle.check_rate_limit", return_value=True)
    def test_run_cell_syncs_per_cell_policy(self, mock_rate):
        """C-SDK-POLICY: run_cell must persist the per-cell policy (not just
        the CLI), or SDK-launched cells with a policy get default-denied."""
        spec = CellSpec(name="pol", image="alpine", policy_allow=["x.com"])
        with patch("brig.cell.lifecycle.observe") as mock_observe, \
             patch("brig.cell.lifecycle.apply") as mock_apply, \
             patch("brig.cell.lifecycle.sync_cell_policy") as mock_sync:
            mock_observe.return_value = CellState()
            mock_apply.return_value = ReconcileResult(success=True, container_id="abc")
            run_cell(spec, proxy_check=lambda: True)
        mock_sync.assert_called_once()
        self.assertEqual(mock_sync.call_args[0][0].name, "pol")

    @patch("brig.cell.lifecycle.check_rate_limit", return_value=False)
    def test_rate_limit_exceeded(self, mock_rate):
        spec = CellSpec(name="test", image="alpine")
        with self.assertRaisesRegex(BrigError, "Rate limit"):
            run_cell(spec, proxy_check=lambda: True)

    @patch("brig.cell.lifecycle.check_rate_limit", return_value=True)
    @patch("brig.cell.lifecycle.observe")
    def test_already_running(self, mock_observe, mock_rate):
        mock_observe.return_value = CellState(exists=True, running=True)
        spec = CellSpec(name="test", image="alpine")
        with self.assertRaisesRegex(BrigError, "already running"):
            run_cell(spec, proxy_check=lambda: True)

    @patch("brig.cell.lifecycle.check_rate_limit", return_value=True)
    @patch("brig.cell.lifecycle.apply")
    @patch("brig.cell.lifecycle.observe")
    def test_run_success_logs_policy(self, mock_observe, mock_apply, mock_rate):
        """Policy specified via CLI is logged in audit trail."""
        spec = CellSpec(
            name="test", image="alpine",
            policy_allow=["example.com"], policy_deny=["evil.com"],
        )
        mock_observe.return_value = CellState()
        mock_apply.return_value = ReconcileResult(success=True, container_id="abc")
        with patch("brig.cell.lifecycle.log_policy_change") as mock_log:
            run_cell(spec, proxy_check=lambda: True)
            mock_log.assert_called_once()
            call_args = mock_log.call_args
            self.assertEqual(call_args[0][0], "test")
            self.assertEqual(call_args[0][1], "create")


class TestApplyImageDigestPin(unittest.TestCase):
    """image_digest must be enforced, not silently accepted."""

    def test_invalid_digest_rejected(self):
        from brig.cell.lifecycle import _apply_image_digest_pin
        spec = CellSpec(name="t", image="alpine", image_digest="not-a-digest")
        with self.assertRaises(BrigError):
            _apply_image_digest_pin(spec)

    def test_short_digest_rejected(self):
        from brig.cell.lifecycle import _apply_image_digest_pin
        # 32 hex chars instead of 64 — must be rejected.
        spec = CellSpec(name="t", image="alpine", image_digest="sha256:" + "a" * 32)
        with self.assertRaises(BrigError):
            _apply_image_digest_pin(spec)

    def test_digest_appended_to_image(self):
        from brig.cell.lifecycle import _apply_image_digest_pin
        digest = "sha256:" + "f" * 64
        spec = CellSpec(name="t", image="alpine:3.19", image_digest=digest)
        _apply_image_digest_pin(spec)
        self.assertEqual(spec.image, f"alpine:3.19@{digest}")

    def test_conflicting_inline_digest_rejected(self):
        from brig.cell.lifecycle import _apply_image_digest_pin
        d1 = "sha256:" + "a" * 64
        d2 = "sha256:" + "b" * 64
        spec = CellSpec(name="t", image=f"alpine@{d1}", image_digest=d2)
        with self.assertRaises(BrigError):
            _apply_image_digest_pin(spec)

    def test_matching_inline_digest_accepted_no_change(self):
        from brig.cell.lifecycle import _apply_image_digest_pin
        d = "sha256:" + "a" * 64
        spec = CellSpec(name="t", image=f"alpine@{d}", image_digest=d)
        _apply_image_digest_pin(spec)
        self.assertEqual(spec.image, f"alpine@{d}")

    def test_no_digest_no_change(self):
        from brig.cell.lifecycle import _apply_image_digest_pin
        spec = CellSpec(name="t", image="alpine:3.19")
        _apply_image_digest_pin(spec)
        self.assertEqual(spec.image, "alpine:3.19")


class TestStopCell(unittest.TestCase):
    @patch("brig.cell.lifecycle.observe")
    def test_not_exists(self, mock_observe):
        mock_observe.return_value = CellState(exists=False)
        with self.assertRaisesRegex(BrigError, "does not exist"):
            stop_cell("test")

    @patch("brig.cell.lifecycle.observe")
    def test_not_running(self, mock_observe):
        mock_observe.return_value = CellState(exists=True, running=False)
        with self.assertRaisesRegex(BrigError, "not running"):
            stop_cell("test")

    @patch("brig.cell.lifecycle.apply")
    @patch("brig.cell.lifecycle.observe")
    def test_stop_success(self, mock_observe, mock_apply):
        mock_observe.return_value = CellState(exists=True, running=True)
        mock_apply.return_value = ReconcileResult(success=True)
        stop_cell("test")
        mock_apply.assert_called_once()


class TestKillCell(unittest.TestCase):
    @patch("brig.cell.lifecycle.observe")
    def test_not_exists(self, mock_observe):
        mock_observe.return_value = CellState(exists=False)
        with self.assertRaisesRegex(BrigError, "does not exist"):
            kill_cell("test")

    @patch("brig.cell.lifecycle.apply")
    @patch("brig.cell.lifecycle.observe")
    def test_kill_running(self, mock_observe, mock_apply):
        mock_observe.return_value = CellState(exists=True, running=True)
        mock_apply.return_value = ReconcileResult(success=True)
        kill_cell("test")
        mock_apply.assert_called_once()
        # A running cell is killed (non-empty action list).
        self.assertTrue(mock_apply.call_args[0][0])

    @patch("brig.cell.lifecycle.vm_run")
    @patch("brig.cell.lifecycle.apply")
    @patch("brig.cell.lifecycle.observe")
    def test_kill_paused_unpauses_then_kills(self, mock_observe, mock_apply, mock_vm):
        # observe() reports paused as running=False; kill must still act.
        mock_observe.return_value = CellState(
            exists=True, running=False, status="paused"
        )
        mock_apply.return_value = ReconcileResult(success=True)
        kill_cell("test")
        # Unpaused first (podman won't SIGKILL a paused container)...
        unpause_calls = [c for c in mock_vm.call_args_list
                         if c[0][0][:2] == ["podman", "unpause"]]
        self.assertEqual(len(unpause_calls), 1)
        # ...then a non-empty kill action list is applied.
        mock_apply.assert_called_once()
        self.assertTrue(mock_apply.call_args[0][0])


class TestRmCell(unittest.TestCase):
    @patch("brig.cell.lifecycle.observe")
    def test_not_exists(self, mock_observe):
        mock_observe.return_value = CellState(exists=False, network_exists=False)
        with self.assertRaisesRegex(BrigError, "does not exist"):
            rm_cell("test")

    @patch("brig.cell.lifecycle.observe")
    def test_running_without_force(self, mock_observe):
        mock_observe.return_value = CellState(exists=True, running=True, network_exists=True)
        with self.assertRaisesRegex(BrigError, "running"):
            rm_cell("test", force=False)

    @patch("brig.cell.lifecycle.apply")
    @patch("brig.cell.lifecycle.observe")
    def test_rm_with_force(self, mock_observe, mock_apply):
        mock_observe.return_value = CellState(
            exists=True, running=True, network_exists=True, proxy_connected=True,
        )
        mock_apply.return_value = ReconcileResult(success=True)
        rm_cell("test", force=True)
        mock_apply.assert_called_once()

    @patch("brig.cell.metadata.remove_cell_spec")
    @patch("brig.cell.lifecycle.apply")
    @patch("brig.cell.lifecycle.observe")
    def test_rm_drops_restart_spec_even_keeping_workspace(
        self, mock_observe, mock_apply, mock_remove_spec,
    ):
        # A removed cell must not be resurrected by restart:always, even when
        # the workspace is kept.
        mock_observe.return_value = CellState(
            exists=True, running=True, network_exists=True, proxy_connected=True,
        )
        mock_apply.return_value = ReconcileResult(success=True)
        rm_cell("test", force=True, keep_workspace=True)
        mock_remove_spec.assert_called_once_with("test")


class TestRunCellRateLimit(unittest.TestCase):
    @patch("brig.cell.lifecycle.record_rate_limit")
    @patch("brig.cell.lifecycle.check_rate_limit", return_value=False)
    @patch("brig.cell.lifecycle.apply")
    @patch("brig.cell.lifecycle.observe")
    def test_restore_path_bypasses_rate_limit(
        self, mock_observe, mock_apply, mock_check, mock_record,
    ):
        # count_against_rate_limit=False must skip BOTH the check (which would
        # raise) and the record (which would burn the operator's quota).
        mock_observe.return_value = CellState(exists=False, network_exists=False)
        mock_apply.return_value = ReconcileResult(success=True)
        spec = CellSpec(name="t", image="alpine", network="none")  # airgapped
        run_cell(spec, count_against_rate_limit=False)
        mock_check.assert_not_called()
        mock_record.assert_not_called()


class TestRestorePersistedCells(unittest.TestCase):
    """`brig system up` re-launches gone restart:always cells, not present ones."""

    _RAW = {"name": "sa", "image": "alpine", "restart": "always"}

    @patch("brig.cell.lifecycle.run_cell")
    @patch("brig.cell.lifecycle.observe")
    @patch("brig.cell.metadata.restorable_cell_specs")
    def test_restores_gone_cell(self, mock_specs, mock_observe, mock_run):
        from brig.cell.lifecycle import restore_persisted_cells
        mock_specs.return_value = [dict(self._RAW)]
        mock_observe.return_value = CellState(exists=False)
        restore_persisted_cells()
        mock_run.assert_called_once()
        self.assertEqual(mock_run.call_args[0][0].name, "sa")

    @patch("brig.cell.lifecycle.run_cell")
    @patch("brig.cell.lifecycle.observe")
    @patch("brig.cell.metadata.restorable_cell_specs")
    def test_skips_present_cell(self, mock_specs, mock_observe, mock_run):
        # A cell still present (running, or user-stopped → exited) is left alone.
        from brig.cell.lifecycle import restore_persisted_cells
        mock_specs.return_value = [dict(self._RAW)]
        mock_observe.return_value = CellState(exists=True, running=False)
        restore_persisted_cells()
        mock_run.assert_not_called()

    @patch("brig.cell.lifecycle.run_cell")
    @patch("brig.cell.lifecycle.observe")
    @patch("brig.cell.metadata.restorable_cell_specs")
    def test_skips_invalid_persisted_spec(self, mock_specs, mock_observe, mock_run):
        # A tampered/corrupt spec (state dir is untrusted) must be re-validated
        # and skipped, not launched.
        from brig.cell.lifecycle import restore_persisted_cells
        mock_specs.return_value = [{"name": "sa", "image": "alpine",
                                    "restart": "always", "network": "bridge"}]
        mock_observe.return_value = CellState(exists=False)
        restore_persisted_cells()
        mock_run.assert_not_called()
