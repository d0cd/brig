"""Tests for brig.security.verify — security invariant checks.

Covers invariants 1, 5, 6, 7, 8, 9.
"""

import json
import subprocess
import unittest
from unittest.mock import patch

from brig.security.verify import (
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

    # Members are read from `podman ps --filter network` (newline-separated
    # names), not the network-inspect `.containers` map (unpopulated under
    # netavark). The second mocked _run is that ps output.
    @patch("brig.security.verify._run")
    def test_on_proxy_external_only_infra(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "proxy-external brig-cell1 ", ""),
            subprocess.CompletedProcess([], 0, "warden\nbrig-otel\n", ""),
        ]
        result = verify_proxy_network()
        self.assertTrue(result.passed)

    @patch("brig.security.verify._run")
    def test_not_on_proxy_external(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "brig-cell1 ", "")
        result = verify_proxy_network()
        self.assertFalse(result.passed)

    @patch("brig.security.verify._run")
    def test_rogue_container_on_proxy_external_fails(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "proxy-external ", ""),
            subprocess.CompletedProcess([], 0, "warden\nbrig-evil\n", ""),
        ]
        result = verify_proxy_network()
        self.assertFalse(result.passed)
        self.assertIn("brig-evil", " ".join(result.details or []))

    @patch("brig.security.verify._run")
    def test_member_query_failure_fails_closed(self, mock_run):
        # If `podman ps` can't enumerate members, the check must fail (closed),
        # never vacuously pass.
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "proxy-external ", ""),
            subprocess.CompletedProcess([], 1, "", "boom"),
        ]
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
        # podman exposes the named runtime in the top-level OCIRuntime field;
        # HostConfig.Runtime is the category ("oci") and cannot distinguish
        # runsc from a crun downgrade.
        containers = [{"Names": ["brig-cell1"]}]
        inspect = [{"Name": "brig-cell1", "OCIRuntime": "runsc",
                    "HostConfig": {"Runtime": "oci"}}]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, json.dumps(containers), ""),
            subprocess.CompletedProcess([], 0, json.dumps(inspect), ""),
        ]
        result = verify_gvisor_runtime()
        self.assertTrue(result.passed)

    @patch("brig.security.verify._run")
    def test_runtime_downgrade(self, mock_run):
        containers = [{"Names": ["brig-cell1"]}]
        inspect = [{"Name": "brig-cell1", "OCIRuntime": "crun",
                    "HostConfig": {"Runtime": "oci"}}]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, json.dumps(containers), ""),
            subprocess.CompletedProcess([], 0, json.dumps(inspect), ""),
        ]
        result = verify_gvisor_runtime()
        self.assertFalse(result.passed)
        self.assertTrue(any("crun" in d for d in result.details))

    @patch("brig.security.verify._run")
    def test_empty_runtime_is_violation(self, mock_run):
        """An empty/absent runtime field must not pass — that would let a
        silent gVisor downgrade report as compliant (invariant 5)."""
        containers = [{"Names": ["brig-cell1"]}]
        inspect = [{"Name": "brig-cell1", "OCIRuntime": ""}]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, json.dumps(containers), ""),
            subprocess.CompletedProcess([], 0, json.dumps(inspect), ""),
        ]
        result = verify_gvisor_runtime()
        self.assertFalse(result.passed)

    def test_real_podman_inspect_shape(self):
        """Drive the check with a real `podman inspect` fixture so the field
        name can't silently regress: real podman reports OCIRuntime, not
        HostConfig.Runtime (which is always 'oci')."""
        import pathlib
        fixture = json.loads(
            (pathlib.Path(__file__).parent
             / "fixtures/podman/4.9/inspect_warden.json").read_text()
        )
        info = fixture[0] if isinstance(fixture, list) else fixture
        self.assertEqual(info.get("HostConfig", {}).get("Runtime"), "oci")
        # This fixture ran under crun — reading the real field must flag it.
        crun_info = dict(info, Name="brig-cell1")
        self.assertFalse(verify_gvisor_runtime([crun_info]).passed)
        # Same shape under runsc must pass.
        runsc_info = dict(info, Name="brig-cell1", OCIRuntime="runsc")
        self.assertTrue(verify_gvisor_runtime([runsc_info]).passed)


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

    def test_capitalized_internal_key_accepted(self):
        # A podman/netavark shape change to "Internal" (capital) must not turn
        # a correctly-internal network into a spurious isolation violation.
        result = verify_network_isolation([{"name": "brig-cell1", "Internal": True}])
        self.assertTrue(result.passed)

    def test_missing_internal_key_is_violation(self):
        result = verify_network_isolation([{"name": "brig-cell1"}])
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

    @patch("brig.security.verify._run")
    def test_airgapped_zero_networks_compliant(self, mock_run):
        # --network none cells have 0 networks and are strictly more isolated
        # than single-homed; they must not be flagged as a violation.
        containers = [{"Names": ["brig-air"]}]
        inspect = [{"Name": "brig-air", "NetworkSettings": {"Networks": {}}}]
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, json.dumps(containers), ""),
            subprocess.CompletedProcess([], 0, json.dumps(inspect), ""),
        ]
        result = verify_single_homed()
        self.assertTrue(result.passed)


class TestVerifyCellNetworkMembers(unittest.TestCase):
    """Invariant 7: No privileged services on cell networks."""

    # _get_cell_networks runs `network ls` then `network inspect` (for names);
    # membership then comes from a `podman ps --filter network` call per net.
    @patch("brig.security.verify._run")
    def test_only_warden_and_cell(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "brig-cell1\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps([{"name": "brig-cell1"}]), ""),
            subprocess.CompletedProcess([], 0, "warden\nbrig-cell1\n", ""),
        ]
        result = verify_cell_network_members()
        self.assertTrue(result.passed)

    @patch("brig.security.verify._run")
    def test_foreign_container(self, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "brig-cell1\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps([{"name": "brig-cell1"}]), ""),
            subprocess.CompletedProcess([], 0, "warden\nbrig-cell1\npostgres\n", ""),
        ]
        result = verify_cell_network_members()
        self.assertFalse(result.passed)
        self.assertTrue(any("postgres" in d for d in result.details))

    @patch("brig.security.verify._run")
    def test_no_cell_networks(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "podman\nproxy-external\n", "")
        result = verify_cell_network_members()
        self.assertTrue(result.passed)

    @patch("brig.security.verify._run")
    def test_member_query_failure_fails_closed(self, mock_run):
        # If `podman ps` can't enumerate a cell network's members, the check
        # must fail (closed), not vacuously pass.
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "brig-cell1\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps([{"name": "brig-cell1"}]), ""),
            subprocess.CompletedProcess([], 1, "", "boom"),
        ]
        result = verify_cell_network_members()
        self.assertFalse(result.passed)
        self.assertTrue(any("enumerate" in d for d in result.details))
