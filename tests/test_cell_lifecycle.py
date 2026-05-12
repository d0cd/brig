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
        with self.assertRaises(BrigError, msg="not running"):
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

    @patch("brig.cell.lifecycle.check_rate_limit", return_value=False)
    def test_rate_limit_exceeded(self, mock_rate):
        spec = CellSpec(name="test", image="alpine")
        with self.assertRaises(BrigError, msg="Rate limit"):
            run_cell(spec, proxy_check=lambda: True)

    @patch("brig.cell.lifecycle.check_rate_limit", return_value=True)
    @patch("brig.cell.lifecycle.observe")
    def test_already_running(self, mock_observe, mock_rate):
        mock_observe.return_value = CellState(exists=True, running=True)
        spec = CellSpec(name="test", image="alpine")
        with self.assertRaises(BrigError, msg="already running"):
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


class TestStopCell(unittest.TestCase):
    @patch("brig.cell.lifecycle.observe")
    def test_not_exists(self, mock_observe):
        mock_observe.return_value = CellState(exists=False)
        with self.assertRaises(BrigError, msg="does not exist"):
            stop_cell("test")

    @patch("brig.cell.lifecycle.observe")
    def test_not_running(self, mock_observe):
        mock_observe.return_value = CellState(exists=True, running=False)
        with self.assertRaises(BrigError, msg="not running"):
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
        with self.assertRaises(BrigError, msg="does not exist"):
            kill_cell("test")

    @patch("brig.cell.lifecycle.apply")
    @patch("brig.cell.lifecycle.observe")
    def test_kill_running(self, mock_observe, mock_apply):
        mock_observe.return_value = CellState(exists=True, running=True)
        mock_apply.return_value = ReconcileResult(success=True)
        kill_cell("test")
        mock_apply.assert_called_once()


class TestRmCell(unittest.TestCase):
    @patch("brig.cell.lifecycle.observe")
    def test_not_exists(self, mock_observe):
        mock_observe.return_value = CellState(exists=False, network_exists=False)
        with self.assertRaises(BrigError, msg="does not exist"):
            rm_cell("test")

    @patch("brig.cell.lifecycle.observe")
    def test_running_without_force(self, mock_observe):
        mock_observe.return_value = CellState(exists=True, running=True, network_exists=True)
        with self.assertRaises(BrigError, msg="running"):
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
