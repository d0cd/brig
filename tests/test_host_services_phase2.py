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
        sys.path.insert(0, "src/brig/warden_addons")
        try:
            from _policy import Policy
            p = Policy(host_services=[
                {"name": "db", "port": 5432},
                {"name": "litellm", "port": 4000},
            ])
        finally:
            sys.path.pop(0)
        self.assertEqual(p.host_services_map, {"db": 5432, "litellm": 4000})

    def test_bare_name_entries_dropped(self):
        import sys
        sys.path.insert(0, "src/brig/warden_addons")
        try:
            from _policy import Policy
            p = Policy(host_services=["db", "redis"])
        finally:
            sys.path.pop(0)
        self.assertEqual(p.host_services_map, {})

    def test_none_means_no_grant(self):
        import sys
        sys.path.insert(0, "src/brig/warden_addons")
        try:
            from _policy import Policy
            p = Policy(host_services=None)
        finally:
            sys.path.pop(0)
        self.assertIsNone(p.host_services_map)

    def test_out_of_range_and_reserved_http_ports_dropped(self):
        """The on-disk policy is untrusted (invariant 4): a tampered file
        must not rewrite a .host.brig request to an arbitrary or reserved
        host port (Warden-as-gateway). Bad entries are dropped."""
        import sys
        sys.path.insert(0, "src/brig/warden_addons")
        try:
            from _policy import Policy
            p = Policy(host_services=[
                {"name": "zero", "port": 0, "protocol": "http"},
                {"name": "negative", "port": -1, "protocol": "http"},
                {"name": "huge", "port": 70000, "protocol": "http"},
                {"name": "proxy", "port": 8080, "protocol": "http"},
                {"name": "ingress", "port": 8443, "protocol": "http"},
                {"name": "ok", "port": 4000, "protocol": "http"},
            ])
        finally:
            sys.path.pop(0)
        # Out-of-range and warden-reserved ports are dropped; valid survives.
        self.assertEqual(p.host_services_map, {"ok": 4000})

    def test_out_of_range_and_reserved_tcp_ports_dropped(self):
        import sys
        sys.path.insert(0, "src/brig/warden_addons")
        try:
            from _policy import Policy
            p = Policy(host_services=[
                {"name": "bad", "port": 99999, "protocol": "tcp"},
                {"name": "ingress", "port": 8443, "protocol": "tcp"},
                {"name": "ok", "port": 5432, "protocol": "tcp"},
            ])
        finally:
            sys.path.pop(0)
        self.assertEqual(p.tcp_host_services_map, {"ok": 5432})


class TestSyncHostServicesPolicy(unittest.TestCase):
    def _run(self, host_services, prior=None):
        from brig.commands.lifecycle_run import _sync_cell_policy
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            policy_dir = td / "policies"
            policy_dir.mkdir()
            if prior is not None:
                (policy_dir / "alice.json").write_text(json.dumps(prior))
            logs: list[str] = []
            with patch("brig.policy.policy.get_cell_policy_path",
                       side_effect=lambda name, *a, **kw: policy_dir / f"{name}.json"), \
                 patch("brig.cell.lifecycle.info",
                       side_effect=logs.append):
                _sync_cell_policy(_spec(host_services=host_services))
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
