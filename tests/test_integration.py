"""Integration tests — multi-step flows with mocked VM layer.

Tests composition of modules, not individual functions.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from brig.cell.lifecycle import run_cell, rm_cell
from brig.cell.reconciler import (
    ActionType, CellState, ReconcileResult,
    build_run_command, plan_destroy, plan_run,
)
from brig.cell.spec import CellSpec
from brig.config import CONTAINER_PREFIX, RUNTIME
from brig.errors import BrigError
from brig.network.subnet import allocate, free, get, list_all


class TestRunThroughReconciler(unittest.TestCase):
    """Test the full run path: spec → plan → build_command → verify invariants."""

    def test_fresh_cell_plan_is_complete(self):
        """A fresh cell (nothing exists) needs all 4 phases."""
        spec = CellSpec(name="test", image="alpine")
        actual = CellState()
        actions = plan_run(spec, actual)
        types = [a.type for a in actions]
        self.assertEqual(types, [
            ActionType.ALLOCATE_SUBNET,
            ActionType.CREATE_NETWORK,
            ActionType.CONNECT_PROXY,
            ActionType.PODMAN_RUN,
        ])

    def test_stopped_cell_cleans_up_first(self):
        """A stopped container from a previous run gets removed before re-run."""
        spec = CellSpec(name="test", image="alpine")
        actual = CellState(exists=True, running=False, network_exists=True, proxy_connected=True)
        actions = plan_run(spec, actual)
        types = [a.type for a in actions]
        self.assertEqual(types[0], ActionType.PODMAN_RM)
        self.assertEqual(types[-1], ActionType.PODMAN_RUN)

    def test_build_command_has_all_security_flags(self):
        """The podman run command includes all security hardening flags."""
        spec = CellSpec(name="test", image="alpine", memory="1g", cpus="2", pids_limit=256)
        cmd = build_run_command(spec, "10.60.1.1")

        # Invariant 5: gVisor runtime.
        self.assertIn("--runtime", cmd)
        self.assertEqual(cmd[cmd.index("--runtime") + 1], RUNTIME)

        # Security hardening.
        self.assertIn("--cap-drop", cmd)
        self.assertIn("ALL", cmd)
        self.assertIn("no-new-privileges", cmd)

        # Proxy env.
        cmd_str = " ".join(cmd)
        self.assertIn("http_proxy=http://10.60.1.1:8080", cmd_str)
        self.assertIn("https_proxy=http://10.60.1.1:8080", cmd_str)

        # Resource limits.
        self.assertIn("--memory", cmd)
        self.assertIn("--pids-limit", cmd)

    def test_build_command_rejects_all_proxy_env_overrides(self):
        """All 5 proxy env var names × 3 case forms are rejected."""
        for var in ["http_proxy", "https_proxy", "no_proxy", "all_proxy", "ftp_proxy"]:
            for form in [var, var.upper(), var.capitalize()]:
                spec = CellSpec(name="t", image="a", env=[f"{form}=evil"])
                with self.assertRaises(ValueError):
                    build_run_command(spec, "10.60.1.1")


class TestSubnetLifecycle(unittest.TestCase):
    """Test allocate → use → free → reuse flow."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state = Path(self.tmpdir) / "subnets.json"
        self.lock = Path(self.tmpdir) / "allocator.lock"

    def test_allocate_free_reuse(self):
        info1 = allocate("cell-a", self.state, self.lock)
        info2 = allocate("cell-b", self.state, self.lock)
        self.assertEqual(info1.index, 1)
        self.assertEqual(info2.index, 2)

        free("cell-a", self.state, self.lock)
        self.assertIsNone(get("cell-a", self.state, self.lock))

        # Reuse freed index.
        info3 = allocate("cell-c", self.state, self.lock)
        self.assertEqual(info3.index, 1)

        # cell-b still at index 2.
        self.assertEqual(get("cell-b", self.state, self.lock).index, 2)

    def test_full_destroy_plan(self):
        """Destroying a running cell produces all cleanup actions in order."""
        actual = CellState(
            exists=True, running=True,
            network_exists=True, proxy_connected=True,
        )
        actions = plan_destroy("test", actual)
        types = [a.type for a in actions]
        self.assertEqual(types, [
            ActionType.PODMAN_KILL,
            ActionType.PODMAN_RM,
            ActionType.DISCONNECT_PROXY,
            ActionType.REMOVE_NETWORK,
            ActionType.FREE_SUBNET,
        ])


class TestRunCellWithProxyCheck(unittest.TestCase):
    """Test run_cell with injected proxy_check — no subprocess mocking needed."""

    @patch("brig.cell.lifecycle.check_rate_limit", return_value=True)
    @patch("brig.cell.lifecycle.apply")
    @patch("brig.cell.lifecycle.observe")
    def test_full_run_flow(self, mock_observe, mock_apply, mock_rate):
        mock_observe.return_value = CellState()
        mock_apply.return_value = ReconcileResult(success=True, container_id="abc123")

        spec = CellSpec(name="test", image="alpine")
        result = run_cell(spec, proxy_check=lambda: True)

        self.assertTrue(result.success)
        self.assertEqual(result.container_id, "abc123")
        mock_apply.assert_called_once()

        # Verify the plan passed to apply has the right actions.
        actions = mock_apply.call_args[0][0]
        types = [a.type for a in actions]
        self.assertIn(ActionType.PODMAN_RUN, types)
