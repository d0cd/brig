"""When cell yaml declares policy.allow with *.host.brig domains for
services registered globally, brig run auto-adds them to the per-cell
ACL with a loud log line.

Feedback #3 from aitelier — was: declare in yaml → get cryptic warden
error → manually run `brig policy set --host-service`. Now: declare
in yaml → auto-granted with revoke pointer.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _spec(policy_allow):
    from brig.cell.spec import CellSpec
    return CellSpec(name="alice", image="alpine", policy_allow=policy_allow)


class TestAutoGrant(unittest.TestCase):
    def _run(self, policy_allow, global_services, prior_cell=None, config=None):
        from brig.commands.lifecycle_cmd import _auto_grant_host_services
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            policy_dir = td / "policies"
            policy_dir.mkdir()
            if prior_cell is not None:
                (policy_dir / "alice.json").write_text(json.dumps(prior_cell))
            global_pol = {"allow": [], "deny": [], "host_services": global_services}
            global_path = td / "network-policy.json"
            global_path.write_text(json.dumps(global_pol))
            config_path = td / "config.json"
            if config is not None:
                config_path.write_text(json.dumps(config))
            logs: list[str] = []
            # POLICY_DIR is captured as a default arg at import time;
            # rebind the path-builder to always emit into the test dir.
            with patch("brig.config.HostPaths.NETWORK_POLICY", global_path), \
                 patch("brig.policy.policy.get_cell_policy_path",
                       side_effect=lambda name, *a, **kw: policy_dir / f"{name}.json"), \
                 patch("brig.config.CONFIG_FILE", config_path), \
                 patch("brig.commands.lifecycle_cmd.info",
                       side_effect=logs.append):
                _auto_grant_host_services(_spec(policy_allow))
            after = None
            cell_file = policy_dir / "alice.json"
            if cell_file.exists():
                after = json.loads(cell_file.read_text())
            return after, logs

    def test_auto_grants_registered_service(self):
        after, logs = self._run(
            policy_allow=["db.host.brig"],
            global_services=[{"name": "db", "port": 5432}],
        )
        self.assertIsNotNone(after)
        self.assertIn("db", after["host_services"])
        self.assertTrue(any("auto-granted" in line for line in logs))
        # Revoke pointer included.
        self.assertTrue(any("brig policy set alice" in line for line in logs))

    def test_unregistered_service_not_granted(self):
        after, logs = self._run(
            policy_allow=["unknown.host.brig"],
            global_services=[],
        )
        self.assertIsNone(after)  # No policy file written.
        self.assertEqual(logs, [])

    def test_existing_grant_not_re_logged(self):
        after, logs = self._run(
            policy_allow=["db.host.brig"],
            global_services=[{"name": "db", "port": 5432}],
            prior_cell={"allow": [], "deny": [], "host_services": ["db"]},
        )
        self.assertEqual(after["host_services"], ["db"])
        self.assertEqual(logs, [])

    def test_non_host_brig_domain_ignored(self):
        after, logs = self._run(
            policy_allow=["api.github.com"],
            global_services=[{"name": "db", "port": 5432}],
        )
        self.assertIsNone(after)
        self.assertEqual(logs, [])

    def test_config_disables_auto_grant(self):
        after, logs = self._run(
            policy_allow=["db.host.brig"],
            global_services=[{"name": "db", "port": 5432}],
            config={"auto_grant_host_services": False},
        )
        self.assertIsNone(after)
        self.assertEqual(logs, [])

    def test_wildcard_host_brig_not_granted(self):
        """*.host.brig must not auto-grant — that would grant every
        registered host service. Only literal names."""
        after, logs = self._run(
            policy_allow=["*.host.brig"],
            global_services=[
                {"name": "db", "port": 5432},
                {"name": "litellm", "port": 4000},
            ],
        )
        self.assertIsNone(after)
        self.assertEqual(logs, [])


if __name__ == "__main__":
    unittest.main()
