"""Tests for reconciler apply() and _execute_action() with mocked vm_run.

Proves the full action sequence fires correct podman commands,
and rollback cleans up on failure.
"""

import json
import subprocess
import unittest
from unittest.mock import patch

from brig.cell.reconciler import (
    Action,
    ActionType,
    ReconcileResult,
    _execute_action,
    apply,
    plan_run,
)
from brig.cell.spec import CellSpec
from brig.config import CONTAINER_PREFIX, PROXY_NAME


class TestApplyFiresCorrectCommands(unittest.TestCase):
    """Test that apply() fires the right podman commands in order."""

    @patch("brig.cell.ca_bundle.vm_run")
    @patch("brig.cell.reconciler.vm_run")
    @patch("brig.network.subnet.get")
    @patch("brig.network.subnet.allocate")
    def test_full_create_sequence(self, mock_allocate, mock_get,
                                   mock_vm_run, mock_ca_vm_run):
        """Fresh cell: allocate → create network → connect proxy → run."""
        from brig.network.subnet import SubnetInfo
        subnet_info = SubnetInfo(
            cell_name="test", index=42, subnet="10.60.42.0/24",
            allocated_at="2026-01-01T00:00:00Z",
        )
        mock_allocate.return_value = subnet_info
        mock_get.return_value = subnet_info

        # Track all vm_run calls.
        calls = []
        def fake_vm_run(cmd, **kwargs):
            calls.append(cmd)
            # Return proxy inspect JSON for the PODMAN_RUN proxy IP lookup.
            if "inspect" in cmd and PROXY_NAME in cmd:
                data = [{"NetworkSettings": {"Networks": {
                    f"{CONTAINER_PREFIX}test": {"IPAddress": "10.60.42.1"}
                }}}]
                return subprocess.CompletedProcess(cmd, 0, json.dumps(data), "")
            return subprocess.CompletedProcess(cmd, 0, "container-id-abc\n", "")

        mock_vm_run.side_effect = fake_vm_run
        mock_ca_vm_run.return_value = subprocess.CompletedProcess([], 0, "", "")

        spec = CellSpec(name="test", image="alpine", command=["echo", "hi"])
        from brig.cell.reconciler import CellState
        actions = plan_run(spec, CellState())

        result = apply(actions)
        self.assertTrue(result.success)
        self.assertEqual(len(result.actions_failed), 0)

        # Verify the commands fired.
        cmd_strs = [" ".join(c) for c in calls]

        # Network create with --internal.
        network_creates = [c for c in cmd_strs if "network create" in c]
        self.assertEqual(len(network_creates), 1)
        self.assertIn("--internal", network_creates[0])
        self.assertIn("10.60.42.0/24", network_creates[0])

        # Proxy connect.
        proxy_connects = [c for c in cmd_strs if "network connect" in c]
        self.assertEqual(len(proxy_connects), 1)
        self.assertIn(PROXY_NAME, proxy_connects[0])

        # Podman run with security flags.
        podman_runs = [c for c in cmd_strs if c.startswith("podman run")]
        self.assertEqual(len(podman_runs), 1)
        run_cmd = podman_runs[0]
        self.assertIn("--runtime runsc", run_cmd)
        self.assertIn("--cap-drop ALL", run_cmd)
        self.assertIn("no-new-privileges", run_cmd)
        self.assertIn("http_proxy=http://warden:8080", run_cmd)


class TestApplyRollbackOnFailure(unittest.TestCase):
    """Test that apply() rolls back completed actions when an action fails."""

    @patch("brig.cell.reconciler.vm_run")
    @patch("brig.network.subnet.get")
    @patch("brig.network.subnet.allocate")
    @patch("brig.network.subnet.free")
    def test_rollback_cleans_up_on_run_failure(self, mock_free, mock_allocate, mock_get, mock_vm_run):
        """If PODMAN_RUN fails, rollback should disconnect proxy, remove network, free subnet."""
        from brig.network.subnet import SubnetInfo
        subnet_info = SubnetInfo(
            cell_name="test", index=1, subnet="10.60.1.0/24",
            allocated_at="2026-01-01T00:00:00Z",
        )
        mock_allocate.return_value = subnet_info
        mock_get.return_value = subnet_info

        calls = []
        call_count = [0]
        def fake_vm_run(cmd, **kwargs):
            calls.append(cmd)
            call_count[0] += 1
            # Make the podman run fail.
            if cmd[0] == "podman" and cmd[1] == "run":
                return subprocess.CompletedProcess(cmd, 1, "", "image not found")
            # Proxy inspect for IP lookup.
            if "inspect" in cmd and PROXY_NAME in cmd:
                data = [{"NetworkSettings": {"Networks": {
                    f"{CONTAINER_PREFIX}test": {"IPAddress": "10.60.1.1"}
                }}}]
                return subprocess.CompletedProcess(cmd, 0, json.dumps(data), "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        mock_vm_run.side_effect = fake_vm_run

        spec = CellSpec(name="test", image="alpine")
        from brig.cell.reconciler import CellState
        actions = plan_run(spec, CellState())

        result = apply(actions)

        # Should have failed.
        self.assertFalse(result.success)
        self.assertEqual(len(result.actions_failed), 1)
        self.assertEqual(result.actions_failed[0][0].type, ActionType.PODMAN_RUN)

        # Rollback should have fired.
        cmd_strs = [" ".join(c) for c in calls]

        # Network disconnect (rollback of CONNECT_PROXY).
        disconnects = [c for c in cmd_strs if "network disconnect" in c]
        self.assertTrue(len(disconnects) >= 1)

        # Network rm (rollback of CREATE_NETWORK).
        net_rms = [c for c in cmd_strs if "network rm" in c]
        self.assertTrue(len(net_rms) >= 1)

        # Subnet free (rollback of ALLOCATE_SUBNET).
        mock_free.assert_called()

    @patch("brig.cell.reconciler.vm_run")
    @patch("brig.network.subnet.allocate")
    def test_network_create_failure_rolls_back_subnet(self, mock_allocate, mock_vm_run):
        """If CREATE_NETWORK fails, only the subnet allocation is rolled back."""
        from brig.network.subnet import SubnetInfo
        mock_allocate.return_value = SubnetInfo(
            cell_name="test", index=1, subnet="10.60.1.0/24",
            allocated_at="2026-01-01T00:00:00Z",
        )

        def fake_vm_run(cmd, **kwargs):
            if "network" in cmd and "create" in cmd:
                return subprocess.CompletedProcess(cmd, 1, "", "network already exists")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        mock_vm_run.side_effect = fake_vm_run

        # Manually build actions (allocate + create network).
        actions = [
            Action(ActionType.ALLOCATE_SUBNET, "test"),
            Action(ActionType.CREATE_NETWORK, "test"),
        ]

        with patch("brig.network.subnet.get") as mock_get, \
             patch("brig.network.subnet.free") as mock_free:
            mock_get.return_value = SubnetInfo(
                cell_name="test", index=1, subnet="10.60.1.0/24",
                allocated_at="2026-01-01T00:00:00Z",
            )
            result = apply(actions)

        self.assertFalse(result.success)
        # Allocate succeeded, create failed → rollback frees the subnet.
        mock_free.assert_called_with("test")


class TestExecuteActionWorkspace(unittest.TestCase):
    """Test that PODMAN_RUN creates the workspace directory."""

    @patch("brig.cell.ca_bundle.vm_run")
    @patch("brig.cell.reconciler.vm_run")
    def test_workspace_dir_created_before_run(self, mock_vm_run, mock_ca_vm_run):
        """mkdir -p for the workspace should be called before podman run."""
        calls = []
        def fake_vm_run(cmd, **kwargs):
            calls.append(cmd)
            if "inspect" in cmd and PROXY_NAME in cmd:
                data = [{"NetworkSettings": {"Networks": {
                    f"{CONTAINER_PREFIX}test": {"IPAddress": "10.60.1.1"}
                }}}]
                return subprocess.CompletedProcess(cmd, 0, json.dumps(data), "")
            return subprocess.CompletedProcess(cmd, 0, "abc\n", "")

        mock_vm_run.side_effect = fake_vm_run
        mock_ca_vm_run.return_value = subprocess.CompletedProcess([], 0, "", "")

        spec = CellSpec(name="test", image="alpine")
        result = ReconcileResult(success=True)
        action = Action(ActionType.PODMAN_RUN, "test", {"spec": spec})
        _execute_action(action, result)

        cmd_strs = [" ".join(c) for c in calls]
        mkdirs = [c for c in cmd_strs if "mkdir" in c]
        self.assertTrue(len(mkdirs) >= 1)
        self.assertTrue(any("workspace" in m for m in mkdirs))

        # mkdir should come before podman run.
        mkdir_idx = next(i for i, c in enumerate(calls) if "mkdir" in c)
        run_idx = next(i for i, c in enumerate(calls) if c[0] == "podman" and c[1] == "run")
        self.assertLess(mkdir_idx, run_idx)
