"""`brig policy test <cell> <domain>` simulates a request against
the cell's per-cell policy, honoring --path and --method (not just
domain matching).
"""

from __future__ import annotations

import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def _args(**kw):
    return types.SimpleNamespace(**kw)


class TestPolicyTestRespectsMethodAndPath(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        (self.td / "alice.json").write_text(json.dumps({
            "allow": [
                {"domain": "api.x", "methods": ["GET"], "paths": ["/v1/models"]},
            ],
            "deny": [],
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.td, ignore_errors=True)

    def _run(self, **kw):
        from brig.commands.policy_cmd import cmd_policy_test
        with patch("brig.policy.policy.get_cell_policy_path",
                   side_effect=lambda n, *a, **kw: self.td / f"{n}.json"):
            return cmd_policy_test(_args(name="alice", **kw))

    def test_allow_when_method_and_path_match(self):
        self.assertEqual(self._run(domain="api.x", method="GET",
                                    path="/v1/models"), 0)

    def test_block_when_method_mismatch(self):
        self.assertEqual(self._run(domain="api.x", method="POST",
                                    path="/v1/models"), 1)

    def test_block_when_path_mismatch(self):
        self.assertEqual(self._run(domain="api.x", method="GET",
                                    path="/v1/chat"), 1)

    def test_block_when_domain_mismatch(self):
        self.assertEqual(self._run(domain="other.x", method="GET",
                                    path="/v1/models"), 1)


class TestPolicyTestStringRules(unittest.TestCase):
    """String-form allow rules match any path/method."""

    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        (self.td / "alice.json").write_text(
            json.dumps({"allow": ["api.x"], "deny": []})
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.td, ignore_errors=True)

    def test_string_rule_allows_any_method_and_path(self):
        from brig.commands.policy_cmd import cmd_policy_test
        with patch("brig.policy.policy.get_cell_policy_path",
                   side_effect=lambda n, *a, **kw: self.td / f"{n}.json"):
            for method in ("GET", "POST", "DELETE"):
                for path in ("/", "/anything", "/v1/chat"):
                    rc = cmd_policy_test(_args(
                        name="alice", domain="api.x",
                        method=method, path=path,
                    ))
                    self.assertEqual(rc, 0)


class TestPolicyTestMissingCell(unittest.TestCase):
    def test_cell_with_no_policy_blocks(self):
        from brig.commands.policy_cmd import cmd_policy_test
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            with patch("brig.policy.policy.get_cell_policy_path",
                       side_effect=lambda n, *a, **kw: td / f"{n}.json"):
                rc = cmd_policy_test(_args(
                    name="ghost", domain="api.x", method="GET", path="/",
                ))
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
