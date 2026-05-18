"""C2 from docs/plans/0.3-validation-plan.md: `brig policy test` must
honor --path and --method, not just --domain.

Today the flags were accepted but ignored. A user trying to debug
"why was POST /v1/chat blocked when GET /v1/models works" got no
answer because the matcher only looked at domain.
"""

from __future__ import annotations

import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def _args(**kw) -> types.SimpleNamespace:
    return types.SimpleNamespace(**kw)


class TestPolicyTestRespectsMethodAndPath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        policy = {
            "allow": [
                {"domain": "api.x", "methods": ["GET"], "paths": ["/v1/models"]},
            ],
            "deny": [],
        }
        json.dump(policy, self.tmp)
        self.tmp.close()
        self.policy_path = Path(self.tmp.name)

    def tearDown(self):
        self.policy_path.unlink(missing_ok=True)

    def _run(self, **kw):
        from brig.commands.policy_cmd import cmd_policy_test
        with patch("brig.commands.policy_cmd.HostPaths") as host_paths:
            host_paths.NETWORK_POLICY = self.policy_path
            return cmd_policy_test(_args(**kw))

    def test_allow_when_method_and_path_match(self):
        rc = self._run(domain="api.x", method="GET", path="/v1/models")
        self.assertEqual(rc, 0)

    def test_block_when_method_mismatch(self):
        # POST is not in the allow rule's methods list — must block.
        rc = self._run(domain="api.x", method="POST", path="/v1/models")
        self.assertEqual(rc, 1)

    def test_block_when_path_mismatch(self):
        rc = self._run(domain="api.x", method="GET", path="/v1/chat")
        self.assertEqual(rc, 1)

    def test_block_when_domain_mismatch(self):
        rc = self._run(domain="other.x", method="GET", path="/v1/models")
        self.assertEqual(rc, 1)


class TestPolicyTestBackwardCompat(unittest.TestCase):
    """String-form rules (no methods/paths) still work the old way:
    domain match alone is sufficient. Ensures the C2 change didn't
    regress string-rule semantics."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        json.dump({"allow": ["api.x"], "deny": []}, self.tmp)
        self.tmp.close()
        self.policy_path = Path(self.tmp.name)

    def tearDown(self):
        self.policy_path.unlink(missing_ok=True)

    def _run(self, **kw):
        from brig.commands.policy_cmd import cmd_policy_test
        with patch("brig.commands.policy_cmd.HostPaths") as host_paths:
            host_paths.NETWORK_POLICY = self.policy_path
            return cmd_policy_test(_args(**kw))

    def test_string_rule_allows_any_method_and_path(self):
        for method in ("GET", "POST", "DELETE"):
            for path in ("/", "/anything", "/v1/chat/completions"):
                rc = self._run(domain="api.x", method=method, path=path)
                self.assertEqual(rc, 0,
                    f"expected ALLOW for {method} {path} under string rule")


if __name__ == "__main__":
    unittest.main()
