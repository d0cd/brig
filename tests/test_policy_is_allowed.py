"""Behavioral tests for Policy.is_allowed — the per-cell egress decision
(invariant 2: default-deny, deny-takes-precedence, path/method narrowing).

These guard the substrate of the egress allowlist directly, so a regression
that ignored the deny list or silently widened an allow rule to all
paths/methods is caught by the unit suite — not only the nested-virt-gated
e2e that hosted CI skips.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "brig", "warden_addons"))

from _policy import Policy  # noqa: E402


class TestIsAllowed(unittest.TestCase):
    def test_default_deny_when_no_allow_match(self):
        p = Policy(allow=["example.com"], deny=[])
        allowed, reason, _ = p.is_allowed("evil.com", "/", "GET")
        self.assertFalse(allowed)
        self.assertIn("not in allowlist", reason)

    def test_plain_allow_permits_any_path_and_method(self):
        p = Policy(allow=["example.com"], deny=[])
        for method in ("GET", "POST", "DELETE"):
            allowed, _, _ = p.is_allowed("example.com", "/anything", method)
            self.assertTrue(allowed, method)

    def test_deny_takes_precedence_over_allow(self):
        # Host present in BOTH allow and deny must be denied.
        p = Policy(allow=["example.com"], deny=["example.com"])
        allowed, reason, _ = p.is_allowed("example.com", "/", "GET")
        self.assertFalse(allowed)
        self.assertIn("denied by rule", reason)

    def test_path_narrowing(self):
        p = Policy(allow=[{"domain": "api.example.com", "paths": ["/v1/*"]}], deny=[])
        ok, _, _ = p.is_allowed("api.example.com", "/v1/data", "GET")
        self.assertTrue(ok)
        blocked, reason, _ = p.is_allowed("api.example.com", "/v2/data", "GET")
        self.assertFalse(blocked)
        self.assertIn("not in allowlist", reason)

    def test_method_narrowing(self):
        p = Policy(allow=[{"domain": "api.example.com", "methods": ["GET"]}], deny=[])
        ok, _, _ = p.is_allowed("api.example.com", "/", "GET")
        self.assertTrue(ok)
        blocked, _, _ = p.is_allowed("api.example.com", "/", "POST")
        self.assertFalse(blocked)

    def test_deny_narrowed_by_path_only_blocks_that_path(self):
        # A path-scoped deny must not block other paths on the same host.
        p = Policy(
            allow=["api.example.com"],
            deny=[{"domain": "api.example.com", "paths": ["/admin/*"]}],
        )
        blocked, reason, _ = p.is_allowed("api.example.com", "/admin/keys", "GET")
        self.assertFalse(blocked)
        self.assertIn("denied by rule", reason)
        ok, _, _ = p.is_allowed("api.example.com", "/public", "GET")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
