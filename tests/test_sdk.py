"""Tests for brig.sdk — programmatic interface."""

import unittest
from unittest.mock import patch

from brig.errors import BrigError
from brig.sdk import Brig, Cell, CellNotFoundError, ProfileError


class TestBrigRunSync(unittest.TestCase):
    """Test Brig.run_sync() validation and delegation."""

    @patch("brig.sdk.run_cell")
    @patch("brig.sdk.observe")
    def test_run_creates_cell(self, mock_observe, mock_run):
        from brig.cell.reconciler import ReconcileResult
        mock_run.return_value = ReconcileResult(success=True, container_id="abc123")

        b = Brig()
        cell = b.run_sync(name="test", image="alpine")
        self.assertEqual(cell.name, "test")
        mock_run.assert_called_once()

    def test_run_invalid_name_raises(self):
        b = Brig()
        with self.assertRaises(BrigError):
            b.run_sync(name="INVALID!", image="alpine")

    @patch("brig.sdk.run_cell")
    @patch("brig.sdk.observe")
    def test_run_with_profile(self, mock_observe, mock_run):
        from brig.cell.reconciler import ReconcileResult
        mock_run.return_value = ReconcileResult(success=True, container_id="abc")

        b = Brig()
        cell = b.run_sync(name="test", image="alpine", profile="untrusted")
        self.assertEqual(cell.name, "test")

    def test_run_unknown_profile_raises(self):
        b = Brig()
        with self.assertRaises(ProfileError):
            b.run_sync(name="test", image="alpine", profile="nonexistent")

    @patch("warden.proxy.get_bound_tcp_ports", return_value=[5432])
    @patch("brig.sdk.run_cell")
    @patch("brig.sdk.observe")
    def test_run_accepts_ingress_host_services_and_policy(
        self, mock_observe, mock_run, mock_bound
    ):
        """SDK accepts the cell-yaml surface beyond the basic spec."""
        from brig.cell.reconciler import ReconcileResult
        mock_run.return_value = ReconcileResult(success=True, container_id="abc")

        b = Brig()
        b.run_sync(
            name="net", image="alpine",
            ingress=[{"name": "api", "port": 8000,
                      "path_prefix": "/api", "auth": "token"}],
            host_services=[{"name": "db", "port": 5432, "protocol": "tcp"}],
            policy_allow=["api.openai.com"],
            policy_deny=["*.ngrok.io"],
        )
        spec = mock_run.call_args[0][0]
        self.assertEqual(len(spec.ingress), 1)
        self.assertEqual(spec.ingress[0]["name"], "api")
        self.assertEqual(len(spec.host_services), 1)
        self.assertIn("api.openai.com", spec.policy_allow)
        self.assertIn("*.ngrok.io", spec.policy_deny)

    @patch("warden.proxy.get_bound_tcp_ports", return_value=[])
    @patch("brig.sdk.run_cell")
    @patch("brig.sdk.observe")
    def test_run_raises_when_tcp_listener_unbound(
        self, mock_observe, mock_run, mock_bound
    ):
        """SDK has no operator to prompt for a warden restart, so a TCP
        host_service with no bound listener must raise, not return a Cell
        whose service can't work."""
        b = Brig()
        with self.assertRaises(BrigError) as ctx:
            b.run_sync(
                name="net", image="alpine",
                host_services=[{"name": "db", "port": 5432, "protocol": "tcp"}],
            )
        self.assertIn("5432", str(ctx.exception))
        mock_run.assert_not_called()

    def test_untrusted_profile_rejects_host_services_via_sdk(self):
        """The untrusted-profile guard must fire on SDK calls — without
        the validator refolding flat fields into nested policy/host_services
        shapes, this check wouldn't trigger."""
        b = Brig()
        with self.assertRaises(BrigError):
            b.run_sync(
                name="bad", image="alpine", profile="untrusted",
                host_services=[{"name": "db", "port": 5432}],
            )

    def test_untrusted_profile_rejects_passthrough_via_sdk(self):
        b = Brig()
        with self.assertRaises(BrigError):
            b.run_sync(
                name="bad", image="alpine", profile="untrusted",
                policy_allow=["chatgpt.com"],
                policy_passthrough_tls=["chatgpt.com"],
            )

    @patch("brig.sdk.run_cell")
    @patch("brig.sdk.observe")
    def test_image_digest_pin_via_sdk(self, mock_observe, mock_run):
        from brig.cell.reconciler import ReconcileResult
        mock_run.return_value = ReconcileResult(success=True, container_id="abc")

        b = Brig()
        digest = "sha256:" + "a" * 64
        b.run_sync(name="pinned", image="alpine:3.19", image_digest=digest)
        spec = mock_run.call_args[0][0]
        self.assertEqual(spec.image_digest, digest)


class TestBrigListSync(unittest.TestCase):
    @patch("brig.cell.lifecycle.vm_run")
    def test_list_empty(self, mock_run):
        import subprocess
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")

        b = Brig()
        cells = b.list_sync()
        self.assertEqual(cells, [])

    @patch("brig.cell.lifecycle.vm_run")
    def test_list_with_cells(self, mock_run):
        import json
        import subprocess
        containers = [
            {"Names": ["brig-cell1"], "State": "running", "Image": "alpine"},
            {"Names": ["warden"], "State": "running", "Image": "mitmproxy"},
        ]
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, json.dumps(containers), "",
        )

        b = Brig()
        cells = b.list_sync()
        self.assertEqual(len(cells), 1)
        self.assertEqual(cells[0].name, "cell1")


class TestBrigCell(unittest.TestCase):
    @patch("brig.sdk.observe")
    def test_cell_not_found(self, mock_observe):
        from brig.cell.reconciler import CellState
        mock_observe.return_value = CellState(exists=False)

        b = Brig()
        with self.assertRaises(CellNotFoundError):
            b.cell("nonexistent")

    @patch("brig.sdk.observe")
    def test_cell_found(self, mock_observe):
        from brig.cell.reconciler import CellState
        mock_observe.return_value = CellState(exists=True, running=True)

        b = Brig()
        cell = b.cell("test")
        self.assertEqual(cell.name, "test")


class TestCell(unittest.TestCase):
    @patch("brig.sdk.observe")
    def test_is_alive_running(self, mock_observe):
        from brig.cell.reconciler import CellState
        mock_observe.return_value = CellState(running=True)

        cell = Cell("test")
        self.assertTrue(cell.is_alive())

    @patch("brig.sdk.observe")
    def test_is_alive_stopped(self, mock_observe):
        from brig.cell.reconciler import CellState
        mock_observe.return_value = CellState(running=False)

        cell = Cell("test")
        self.assertFalse(cell.is_alive())

    @patch("brig.sdk.vm_run")
    def test_logs_sync(self, mock_run):
        import subprocess
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "hello world\n", "",
        )

        cell = Cell("test")
        logs = cell.logs_sync()
        self.assertIn("hello world", logs)


class TestExecuteSync(unittest.TestCase):
    """Test Brig.execute_sync() — the single-call agent API."""

    @patch("brig.sdk.vm_run")
    @patch("brig.sdk.run_cell")
    @patch("brig.sdk.rm_cell")
    def test_execute_returns_result(self, mock_rm, mock_run, mock_vm_run):
        import subprocess
        from brig.cell.reconciler import ReconcileResult
        mock_run.return_value = ReconcileResult(success=True, container_id="abc")
        mock_vm_run.side_effect = [
            # wait
            subprocess.CompletedProcess([], 0, "0\n", ""),
            # logs (stdout)
            subprocess.CompletedProcess([], 0, "hello\n", ""),
            # logs (stderr)
            subprocess.CompletedProcess([], 0, "", "some warning\n"),
        ]

        b = Brig()
        result = b.execute_sync("alpine", ["echo", "hello"], timeout="30s")

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.success)
        self.assertIn("hello", result.stdout)
        mock_rm.assert_called_once()

    @patch("brig.sdk.vm_run")
    @patch("brig.sdk.run_cell")
    @patch("brig.sdk.rm_cell")
    def test_execute_cleans_up_on_failure(self, mock_rm, mock_run, mock_vm_run):
        import subprocess
        from brig.cell.reconciler import ReconcileResult
        mock_run.return_value = ReconcileResult(success=True, container_id="abc")
        mock_vm_run.side_effect = [
            # wait — non-zero exit
            subprocess.CompletedProcess([], 0, "1\n", ""),
            # logs
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "", "error\n"),
        ]

        b = Brig()
        result = b.execute_sync("alpine", ["false"], timeout="10s")

        self.assertEqual(result.exit_code, 1)
        self.assertFalse(result.success)
        # Cell cleaned up even on failure.
        mock_rm.assert_called_once()
