"""Tests for brig.security.verify — security invariant checks.

Covers invariants 1, 5, 6, 7, 8, 9.
"""

import json
import subprocess
import unittest
from unittest.mock import patch

from brig.security.verify import (
    CheckResult,
    verify_cell_network_members,
    verify_gvisor_runtime,
    verify_network_isolation,
    verify_proxy_network,
    verify_proxy_running,
    verify_single_homed,
)


class TestVerifyProxyRunning(unittest.TestCase):
    """Invariant 9: Proxy must be running before cells start."""

    @patch("brig.security.verify._run")
    def test_running(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "running\n", "")
        result = verify_proxy_running()
        self.assertTrue(result.passed)

    @patch("brig.security.verify._run")
    def test_not_running(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "exited\n", "")
        result = verify_proxy_running()
        self.assertFalse(result.passed)

    @patch("brig.security.verify._run")
    def test_container_missing(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 125, "", "no such container")
        result = verify_proxy_running()
        self.assertFalse(result.passed)


class TestVerifyProxyNetwork(unittest.TestCase):
    """Invariant 6: Only infrastructure containers on proxy-external."""

    @patch("brig.security.verify._run")
    def test_on_proxy_external(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "proxy-external brig-cell1 ", "")
        result = verify_proxy_network()
        self.assertTrue(result.passed)

    @patch("brig.security.verify._run")
    def test_not_on_proxy_external(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "brig-cell1 ", "")
        result = verify_proxy_network()
        self.assertFalse(result.passed)


class TestVerifyGvisorRuntime(unittest.TestCase):
    """Invariant 5: gVisor must be active."""

    @patch("brig.security.verify._run")
    def test_no_cells(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = verify_gvisor_runtime()
        self.assertTrue(result.passed)

    @patch("brig.security.verify._run")
    def test_all_gvisor(self, mock_run):
        containers = [{"Names": ["brig-cell1"]}]
        inspect = [{"Name": "brig-cell1", "HostConfig": {"Runtime": "runsc"}}]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, json.dumps(containers), ""),
            subprocess.CompletedProcess([], 0, json.dumps(inspect), ""),
        ]
        result = verify_gvisor_runtime()
        self.assertTrue(result.passed)

    @patch("brig.security.verify._run")
    def test_runtime_downgrade(self, mock_run):
        containers = [{"Names": ["brig-cell1"]}]
        inspect = [{"Name": "brig-cell1", "HostConfig": {"Runtime": "crun"}}]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, json.dumps(containers), ""),
            subprocess.CompletedProcess([], 0, json.dumps(inspect), ""),
        ]
        result = verify_gvisor_runtime()
        self.assertFalse(result.passed)
        self.assertTrue(any("crun" in d for d in result.details))


class TestVerifyNetworkIsolation(unittest.TestCase):
    """Invariant 1: No east-west traffic."""

    @patch("brig.security.verify._run")
    def test_all_internal(self, mock_run):
        networks = [{"name": "brig-cell1", "internal": True}]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "brig-cell1\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps(networks), ""),
        ]
        result = verify_network_isolation()
        self.assertTrue(result.passed)

    @patch("brig.security.verify._run")
    def test_non_internal_network(self, mock_run):
        networks = [{"name": "brig-cell1", "internal": False}]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "brig-cell1\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps(networks), ""),
        ]
        result = verify_network_isolation()
        self.assertFalse(result.passed)


class TestVerifySingleHomed(unittest.TestCase):
    """Invariant 8: Cells must be single-homed."""

    @patch("brig.security.verify._run")
    def test_single_network(self, mock_run):
        containers = [{"Names": ["brig-cell1"]}]
        inspect = [{
            "Name": "brig-cell1",
            "NetworkSettings": {"Networks": {"brig-cell1": {}}},
        }]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, json.dumps(containers), ""),
            subprocess.CompletedProcess([], 0, json.dumps(inspect), ""),
        ]
        result = verify_single_homed()
        self.assertTrue(result.passed)

    @patch("brig.security.verify._run")
    def test_multi_homed(self, mock_run):
        containers = [{"Names": ["brig-cell1"]}]
        inspect = [{
            "Name": "brig-cell1",
            "NetworkSettings": {"Networks": {"brig-cell1": {}, "other": {}}},
        }]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, json.dumps(containers), ""),
            subprocess.CompletedProcess([], 0, json.dumps(inspect), ""),
        ]
        result = verify_single_homed()
        self.assertFalse(result.passed)


class TestVerifyCellNetworkMembers(unittest.TestCase):
    """Invariant 7: No privileged services on cell networks."""

    @patch("brig.security.verify._run")
    def test_only_warden_and_cell(self, mock_run):
        networks = [{
            "name": "brig-cell1",
            "containers": {
                "abc": {"name": "warden"},
                "def": {"name": "brig-cell1"},
            },
        }]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "brig-cell1\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps(networks), ""),
        ]
        result = verify_cell_network_members()
        self.assertTrue(result.passed)

    @patch("brig.security.verify._run")
    def test_foreign_container(self, mock_run):
        networks = [{
            "name": "brig-cell1",
            "containers": {
                "abc": {"name": "warden"},
                "def": {"name": "brig-cell1"},
                "ghi": {"name": "postgres"},
            },
        }]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "brig-cell1\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps(networks), ""),
        ]
        result = verify_cell_network_members()
        self.assertFalse(result.passed)
        self.assertTrue(any("postgres" in d for d in result.details))

    @patch("brig.security.verify._run")
    def test_no_cell_networks(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "podman\nproxy-external\n", "")
        result = verify_cell_network_members()
        self.assertTrue(result.passed)
