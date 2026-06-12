"""Tests for warden.proxy — proxy container lifecycle."""

import subprocess
import unittest
from unittest.mock import patch

from warden.proxy import container_exists, get_status, is_running, reload_policy, stop


class TestIsRunning(unittest.TestCase):
    @patch("warden.proxy.vm_run")
    def test_running(self, mock_run):
        # Inspect returns the State.Status directly.
        mock_run.return_value = subprocess.CompletedProcess([], 0, "running\n", "")
        self.assertTrue(is_running())

    @patch("warden.proxy.vm_run")
    def test_exited_container_reports_not_running(self, mock_run):
        # Container exists but is stopped — must not be reported as running,
        # so cmd_up's recovery path kicks in instead of falsely returning OK.
        mock_run.return_value = subprocess.CompletedProcess([], 0, "exited\n", "")
        self.assertFalse(is_running())

    @patch("warden.proxy.vm_run")
    def test_no_such_container(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 125, "", "no such container")
        self.assertFalse(is_running())

    @patch("warden.proxy.vm_run")
    def test_inspect_command_shape(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "running\n", "")
        is_running()
        args = mock_run.call_args[0][0]
        # Must inspect by exact name (not a substring filter), and read State.Status.
        self.assertEqual(args[:2], ["podman", "inspect"])
        self.assertIn("{{.State.Status}}", args)


class TestPodmanFilterIsAnchored(unittest.TestCase):
    @patch("warden.proxy.vm_run")
    def test_filter_is_regex_anchored(self, mock_run):
        # container_exists() uses _podman_ps under the hood; the filter must
        # be ^warden$ so a stray container named "warden-old" doesn't match.
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        container_exists()
        args = mock_run.call_args[0][0]
        filter_args = [a for i, a in enumerate(args) if i and args[i - 1] == "--filter"]
        self.assertTrue(any(f == "name=^warden$" for f in filter_args),
                        f"expected name=^warden$ in --filter values, got {filter_args}")


class TestContainerExists(unittest.TestCase):
    @patch("warden.proxy.vm_run")
    def test_exists(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "warden\n", "")
        self.assertTrue(container_exists())

    @patch("warden.proxy.vm_run")
    def test_not_exists(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "\n", "")
        self.assertFalse(container_exists())


class TestStop(unittest.TestCase):
    @patch("warden.proxy.vm_run")
    def test_stop_is_idempotent(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.assertTrue(stop())


class TestReloadPolicy(unittest.TestCase):
    @patch("warden.proxy.vm_run")
    def test_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.assertTrue(reload_policy())

    @patch("warden.proxy.vm_run")
    def test_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "error")
        self.assertFalse(reload_policy())


class TestGetStatus(unittest.TestCase):
    @patch("warden.proxy.vm_run")
    def test_running_status(self, mock_run):
        import json
        data = [{"State": {"Status": "running"}, "NetworkSettings": {"Networks": {"proxy-external": {}}}}]
        mock_run.return_value = subprocess.CompletedProcess([], 0, json.dumps(data), "")
        status = get_status()
        self.assertTrue(status["running"])
        self.assertIn("proxy-external", status["networks"])

    @patch("warden.proxy.vm_run")
    def test_not_found(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 125, "", "no such container")
        status = get_status()
        self.assertFalse(status["running"])
        self.assertFalse(status["exists"])


class TestEnsureWardenCaExists(unittest.TestCase):
    """Invariant 12 readiness gate: warden start waits for mitmproxy's CA to
    exist (else cells get an empty CA bundle -> fail-closed self-DoS)."""

    @patch("warden.proxy.vm_run")
    def test_ca_present_returns_true_fast(self, mock_run):
        from warden.proxy import _ensure_warden_ca_exists
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.assertTrue(_ensure_warden_ca_exists(timeout_s=5))

    @patch("warden.proxy.time.sleep", lambda s: None)
    @patch("warden.proxy.vm_run")
    def test_ca_absent_times_out_false(self, mock_run):
        from warden.proxy import _ensure_warden_ca_exists
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        self.assertFalse(_ensure_warden_ca_exists(timeout_s=0.05))
