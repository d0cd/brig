"""Phase 2 of host_services flattening: spec.host_services flows into
the per-cell policy file as full {name, port} dicts, and the Policy
class parses them into a host_services_map for enforce.py.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _spec(host_services=None):
    from brig.cell.spec import CellSpec
    return CellSpec(
        name="alice", image="alpine",
        host_services=host_services or [],
    )


class TestPolicyParsesFlattenedShape(unittest.TestCase):
    def test_dict_shape_populates_map(self):
        import sys
        sys.path.insert(0, "src/addons")
        try:
            from _policy import Policy
            p = Policy(host_services=[
                {"name": "db", "port": 5432},
                {"name": "litellm", "port": 4000},
            ])
        finally:
            sys.path.pop(0)
        self.assertEqual(p.host_services_map, {"db": 5432, "litellm": 4000})
        self.assertEqual(p.host_services_allowed, {"db", "litellm"})

    def test_legacy_bare_name_shape_still_loads(self):
        import sys
        sys.path.insert(0, "src/addons")
        try:
            from _policy import Policy
            p = Policy(host_services=["db", "redis"])
        finally:
            sys.path.pop(0)
        # Legacy shape: ports unknown.
        self.assertEqual(p.host_services_map, {"db": None, "redis": None})
        self.assertEqual(p.host_services_allowed, {"db", "redis"})

    def test_none_means_no_grant(self):
        import sys
        sys.path.insert(0, "src/addons")
        try:
            from _policy import Policy
            p = Policy(host_services=None)
        finally:
            sys.path.pop(0)
        self.assertIsNone(p.host_services_map)
        self.assertIsNone(p.host_services_allowed)


class TestSyncHostServicesPolicy(unittest.TestCase):
    def _run(self, host_services, prior=None):
        from brig.commands.lifecycle_cmd import _sync_host_services_policy
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            policy_dir = td / "policies"
            policy_dir.mkdir()
            if prior is not None:
                (policy_dir / "alice.json").write_text(json.dumps(prior))
            logs: list[str] = []
            with patch("brig.policy.policy.get_cell_policy_path",
                       side_effect=lambda name, *a, **kw: policy_dir / f"{name}.json"), \
                 patch("brig.commands.lifecycle_cmd.info",
                       side_effect=logs.append):
                _sync_host_services_policy(_spec(host_services=host_services))
            after = None
            f = policy_dir / "alice.json"
            if f.exists():
                after = json.loads(f.read_text())
            return after, logs

    def test_writes_flattened_shape(self):
        after, logs = self._run([{"name": "db", "port": 5432}])
        self.assertEqual(after["host_services"], [{"name": "db", "port": 5432}])
        self.assertTrue(any("granted" in line and "db" in line for line in logs))

    def test_replace_semantics_revokes_removed(self):
        after, logs = self._run(
            host_services=[{"name": "db", "port": 5432}],
            prior={"allow": [], "deny": [],
                   "host_services": [{"name": "db", "port": 5432},
                                     {"name": "litellm", "port": 4000}]},
        )
        names = {e["name"] for e in after["host_services"]}
        self.assertEqual(names, {"db"})
        self.assertTrue(any("revoked" in line and "litellm" in line for line in logs))

    def test_steady_state_no_writes(self):
        prior = {"allow": [], "deny": [],
                 "host_services": [{"name": "db", "port": 5432}]}
        after, logs = self._run(
            host_services=[{"name": "db", "port": 5432}],
            prior=prior,
        )
        self.assertEqual(after, prior)  # unchanged
        self.assertEqual(logs, [])

    def test_port_change_triggers_write(self):
        after, logs = self._run(
            host_services=[{"name": "db", "port": 5433}],
            prior={"allow": [], "deny": [],
                   "host_services": [{"name": "db", "port": 5432}]},
        )
        self.assertEqual(after["host_services"], [{"name": "db", "port": 5433}])


if __name__ == "__main__":
    unittest.main()
