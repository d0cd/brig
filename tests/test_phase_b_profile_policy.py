"""Phase B of the flattening: cell yaml's `policy.allow/deny` and
profile `policy.allow/deny` both flow into per-cell policy file.
"""

from __future__ import annotations

import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock


def _args(**kw):
    defaults = dict(
        image=None, container_cmd=None, name=None, env=None, secret=None,
        memory=None, cpus=None, pids_limit=None, network=None, profile=None,
        file=None, policy_allow=None, policy_deny=None, label=None,
        timeout=None, workspace_quota=None, detach=False, rm=False,
        image_digest=None, workdir=None,
    )
    defaults.update(kw)
    return types.SimpleNamespace(**defaults)


def _captured_spec(args):
    from brig.commands import lifecycle_cmd
    captured: dict = {}
    def fake_run_cell(spec):
        captured["spec"] = spec
        r = MagicMock(success=True, container_id="abc")
        return r
    with patch.object(lifecycle_cmd, "run_cell", fake_run_cell), \
         patch("brig.ops.logging.Spinner"), \
         patch.object(lifecycle_cmd, "_sync_cell_policy"), \
         patch.object(lifecycle_cmd, "_check_immediate_exit"):
        lifecycle_cmd.cmd_run(args)
    return captured["spec"]


class TestPolicyFromYaml(unittest.TestCase):
    def test_yaml_policy_allow_reaches_spec(self):
        with tempfile.TemporaryDirectory() as td:
            yml = Path(td) / "cell.json"
            yml.write_text(json.dumps({
                "name": "alice", "image": "alpine",
                "policy": {"allow": ["api.github.com", "*.example.com"]},
            }))
            spec = _captured_spec(_args(file=str(yml)))
        self.assertEqual(spec.policy_allow,
                         ["api.github.com", "*.example.com"])

    def test_yaml_policy_deny_reaches_spec(self):
        with tempfile.TemporaryDirectory() as td:
            yml = Path(td) / "cell.json"
            yml.write_text(json.dumps({
                "name": "alice", "image": "alpine",
                "policy": {"deny": ["evil.com"]},
            }))
            spec = _captured_spec(_args(file=str(yml)))
        self.assertEqual(spec.policy_deny, ["evil.com"])

    def test_profile_policy_prepends(self):
        """Profile's policy.allow becomes the baseline; yaml additions
        extend it."""
        with tempfile.TemporaryDirectory() as td:
            yml = Path(td) / "cell.json"
            yml.write_text(json.dumps({
                "name": "alice", "image": "alpine",
                "policy": {"allow": ["pypi.org"]},
            }))
            from brig.cell import profiles
            with patch.object(profiles, "BUILTIN_PROFILES", {
                "dev": {"policy": {"allow": ["api.github.com"]}}
            }):
                spec = _captured_spec(_args(file=str(yml), profile="dev"))
        self.assertEqual(spec.policy_allow, ["api.github.com", "pypi.org"])


class TestSyncCellPolicy(unittest.TestCase):
    def _run(self, *, policy_allow=None, policy_deny=None,
             host_services=None, prior=None):
        from brig.commands.lifecycle_cmd import _sync_cell_policy
        from brig.cell.spec import CellSpec
        spec = CellSpec(
            name="alice", image="alpine",
            policy_allow=policy_allow or [],
            policy_deny=policy_deny or [],
            host_services=host_services or [],
        )
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            if prior is not None:
                (td / "alice.json").write_text(json.dumps(prior))
            with patch("brig.policy.policy.get_cell_policy_path",
                       side_effect=lambda n, *a, **kw: td / f"{n}.json"):
                _sync_cell_policy(spec)
            f = td / "alice.json"
            return json.loads(f.read_text()) if f.exists() else None

    def test_writes_allow_deny_and_host_services(self):
        after = self._run(
            policy_allow=["api.github.com"], policy_deny=["evil.com"],
            host_services=[{"name": "db", "port": 5432}],
        )
        self.assertEqual(after["allow"], ["api.github.com"])
        self.assertEqual(after["deny"], ["evil.com"])
        self.assertEqual(after["host_services"],
                         [{"name": "db", "port": 5432}])

    def test_replace_drops_removed_allow(self):
        after = self._run(
            policy_allow=["a.com"],
            prior={"allow": ["a.com", "b.com"], "deny": [], "host_services": []},
        )
        self.assertEqual(after["allow"], ["a.com"])

    def test_preserves_unknown_keys(self):
        """Other keys in the cell policy file (e.g. rate_limits) survive
        a sync — we only touch allow / deny / host_services."""
        after = self._run(
            policy_allow=["api.x"],
            prior={"allow": [], "deny": [], "host_services": [],
                   "rate_limits": {"default": {"rate": 100}}},
        )
        self.assertEqual(after["rate_limits"], {"default": {"rate": 100}})

    def test_steady_state_no_write(self):
        prior = {"allow": ["api.x"], "deny": [], "host_services": []}
        after = self._run(policy_allow=["api.x"], prior=prior)
        self.assertEqual(after, prior)


if __name__ == "__main__":
    unittest.main()
