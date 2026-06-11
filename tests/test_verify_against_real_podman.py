"""B1 from docs/plans/0.3-validation-plan.md: schema-pin podman output.

The rest of the test suite mocks vm_run with hand-crafted JSON shaped
the way brig *expects* podman to behave. If podman changes a field name
or capitalization in a version bump, unit tests still pass — only E2E
catches it. This file runs verify_* functions against real `podman ps -a
--format json` and `podman inspect` snapshots checked into
tests/fixtures/podman/<version>/. To rotate fixtures on a podman bump:

    limactl shell brig -- sudo podman ps -a --format json \
        > tests/fixtures/podman/<new-version>/ps_all.json
    limactl shell brig -- sudo podman inspect warden \
        > tests/fixtures/podman/<new-version>/inspect_warden.json

Then update FIXTURE_PODMAN_VERSION below.
"""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

FIXTURE_PODMAN_VERSION = "4.9"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "podman" / FIXTURE_PODMAN_VERSION


def _load(name: str) -> str:
    return (FIXTURE_DIR / name).read_text()


def _completed(stdout: str, rc: int = 0):
    return subprocess.CompletedProcess([], rc, stdout, "")


class TestVerifyAgainstRealPodman(unittest.TestCase):
    """Drive brig.security.verify against real podman output shapes,
    not hand-crafted JSON. A podman bump that renames a field will fail
    here even if hand-crafted unit tests still pass."""

    def test_verify_proxy_running_with_real_inspect(self):
        from brig.security.verify import verify_proxy_running

        inspect_out = _load("inspect_warden.json")
        # podman inspect <name> --format '{{.State.Status}}' returns just
        # "running\n", not the full JSON. verify_proxy_running calls that
        # form; assert that pulling .State.Status out of our real fixture
        # gives the expected value (sanity-check the fixture isn't stale).
        data = json.loads(inspect_out)[0]
        self.assertEqual(data["State"]["Status"], "running",
            "fixture has wrong state; re-snapshot when warden is running")

        # Now exercise verify_proxy_running with that as the inspect output.
        with patch("brig.security.verify.vm_run") as mock_vm:
            mock_vm.return_value = _completed(data["State"]["Status"] + "\n")
            result = verify_proxy_running()
            self.assertTrue(result.passed, msg=result.message)

    def test_verify_proxy_network_with_real_inspect(self):
        from brig.security.verify import verify_proxy_network

        # verify_proxy_network uses a Go template to extract just the
        # network names. Derive the equivalent output from the real
        # inspect JSON so a podman bump that renames
        # NetworkSettings.Networks would still break this test.
        inspect = json.loads(_load("inspect_warden.json"))[0]
        networks = list(inspect["NetworkSettings"]["Networks"].keys())
        template_output = " ".join(networks)
        # Second call enumerates proxy-external members; only warden (infra)
        # is attached in a healthy system.
        members_output = json.dumps([
            {"name": "proxy-external", "containers": {"abc": {"name": "warden"}}}
        ])
        with patch("brig.security.verify.vm_run") as mock_vm:
            mock_vm.side_effect = [
                _completed(template_output),
                _completed(members_output),
            ]
            result = verify_proxy_network()
            self.assertTrue(result.passed, msg=result.message)


class TestPodmanFixtureShape(unittest.TestCase):
    """Catch fixture rot: assert the recorded JSON still has the field
    paths brig depends on. If podman ever renames `NetworkSettings.Networks`
    or `State.Status`, this test fails before any production code drifts."""

    def test_inspect_has_expected_keys(self):
        data = json.loads(_load("inspect_warden.json"))
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)
        c = data[0]
        for key in ("Id", "Created", "State", "Image", "ImageName",
                    "NetworkSettings"):
            self.assertIn(key, c, f"podman inspect missing {key}")
        self.assertIn("Status", c["State"])
        self.assertIn("Networks", c["NetworkSettings"])

    def test_ps_all_has_expected_keys(self):
        data = json.loads(_load("ps_all.json"))
        self.assertIsInstance(data, list)
        if data:  # ps may be empty in a clean VM
            row = data[0]
            for key in ("Id", "Image", "Names", "State"):
                self.assertIn(key, row, f"podman ps row missing {key}")


if __name__ == "__main__":
    unittest.main()
