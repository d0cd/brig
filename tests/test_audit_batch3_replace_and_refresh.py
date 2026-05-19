"""Audit fixes (batch 3):

H5 — auto-grant uses REPLACE semantics. Re-running with a yaml that
     no longer mentions a service revokes the prior grant.
M1 — metadata refresh no longer fabricates `host_path: ""` placeholders.
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


# ----- H5: replace semantics -----

class TestH5ReplaceSemantics(unittest.TestCase):
    def _run(self, policy_allow, global_services, prior_cell):
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
            logs: list[str] = []
            with patch("brig.config.HostPaths.NETWORK_POLICY", global_path), \
                 patch("brig.policy.policy.get_cell_policy_path",
                       side_effect=lambda name, *a, **kw: policy_dir / f"{name}.json"), \
                 patch("brig.config.CONFIG_FILE", td / "config.json"), \
                 patch("brig.commands.lifecycle_cmd.info",
                       side_effect=logs.append):
                _auto_grant_host_services(_spec(policy_allow))
            after = None
            cell_file = policy_dir / "alice.json"
            if cell_file.exists():
                after = json.loads(cell_file.read_text())
            return after, logs

    def test_removing_from_yaml_revokes_prior_grant(self):
        after, logs = self._run(
            policy_allow=["db.host.brig"],
            global_services=[{"name": "db", "port": 5432},
                             {"name": "litellm", "port": 4000}],
            prior_cell={"allow": [], "deny": [], "host_services": ["db", "litellm"]},
        )
        # litellm should be revoked, db preserved.
        self.assertEqual(after["host_services"], ["db"])
        self.assertTrue(any("auto-revoked" in line and "litellm" in line
                            for line in logs))

    def test_manual_grant_for_unregistered_service_preserved(self):
        """If the cell has a host_services entry for a name that's NOT
        currently in the global registry, leave it alone — it might
        be a manual grant the operator added for a service they're
        about to register."""
        after, logs = self._run(
            policy_allow=["db.host.brig"],
            global_services=[{"name": "db", "port": 5432}],
            prior_cell={"allow": [], "deny": [],
                        "host_services": ["db", "ssh-agent"]},
        )
        # ssh-agent is preserved (not in registry → not an auto-grant
        # candidate, so the replace-mode logic leaves it alone).
        self.assertIn("ssh-agent", after["host_services"])
        self.assertIn("db", after["host_services"])

    def test_steady_state_no_writes_no_logs(self):
        after, logs = self._run(
            policy_allow=["db.host.brig"],
            global_services=[{"name": "db", "port": 5432}],
            prior_cell={"allow": [], "deny": [], "host_services": ["db"]},
        )
        self.assertEqual(after["host_services"], ["db"])
        self.assertEqual(logs, [])

    def test_yaml_drops_all_revokes_all_auto(self):
        after, logs = self._run(
            policy_allow=[],  # no host.brig entries
            global_services=[{"name": "db", "port": 5432}],
            prior_cell={"allow": [], "deny": [], "host_services": ["db"]},
        )
        self.assertEqual(after["host_services"], [])
        self.assertTrue(any("auto-revoked" in line for line in logs))


# ----- M1: metadata refresh no placeholder -----

class TestM1MetadataRefreshNoPlaceholder(unittest.TestCase):
    def test_refresh_does_not_fabricate_host_path(self):
        """Round-trip through refresh_metadata_if_present must not
        introduce empty-string placeholders. The on-disk projection
        only contains {name, mount_point} and that's what we keep."""
        from brig.cell.metadata import (
            refresh_metadata_if_present, _host_metadata_path,
        )
        with tempfile.TemporaryDirectory() as td:
            state_dir = Path(td)
            cell_state = state_dir / "alice"
            cell_state.mkdir()
            initial = {
                "version": 2, "name": "alice",
                "started_at": "2026-05-18T10:00:00Z",
                "workspace": {"mount_point": "/work"},
                "host_sockets": [
                    {"name": "pg", "mount_point": "/run/host/pg.sock"},
                ],
                "policy": {"host_services": []},
            }
            (cell_state / "cell-metadata.json").write_text(json.dumps(initial))
            with patch("brig.config.HostPaths.STATE_DIR", state_dir):
                refresh_metadata_if_present("alice")
                after = json.loads(_host_metadata_path("alice").read_text())
        for entry in after["host_sockets"]:
            self.assertNotIn("host_path", entry,
                "refresh should not introduce host_path keys")
            self.assertEqual(set(entry.keys()), {"name", "mount_point"})

    def test_build_metadata_filters_malformed_entries(self):
        """build_metadata must skip entries missing required keys
        instead of crashing on a KeyError."""
        from brig.cell.metadata import build_metadata
        payload = build_metadata("c", "/work", host_sockets=[
            {"name": "ok", "mount_point": "/run/host/ok.sock"},
            {"name": "missing_mount"},  # malformed → skipped
            "not even a dict",          # type-wrong → skipped
        ])
        self.assertEqual(len(payload["host_sockets"]), 1)
        self.assertEqual(payload["host_sockets"][0]["name"], "ok")


if __name__ == "__main__":
    unittest.main()
