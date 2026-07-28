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


class TestIsHostAllowed(unittest.TestCase):
    """Host-level CONNECT gate: path/method are inside the not-yet-established
    TLS tunnel, so a path/method-scoped allow must NOT block the CONNECT (it's
    enforced per-request after MITM). An UNSCOPED deny still blocks."""

    def test_plain_allow_permits_connect(self):
        p = Policy(allow=["example.com"], deny=[])
        ok, _ = p.is_host_allowed("example.com")
        self.assertTrue(ok)

    def test_path_scoped_allow_permits_connect(self):
        # Regression: is_allowed(host, "/", "CONNECT") returned False here and
        # broke ALL HTTPS to a host whose allow rule was path-scoped.
        p = Policy(allow=[{"domain": "api.example.com", "paths": ["/v1/*"]}], deny=[])
        ok, _ = p.is_host_allowed("api.example.com")
        self.assertTrue(ok)

    def test_method_scoped_allow_permits_connect(self):
        p = Policy(allow=[{"domain": "api.example.com", "methods": ["GET"]}], deny=[])
        ok, _ = p.is_host_allowed("api.example.com")
        self.assertTrue(ok)

    def test_non_allowlisted_host_blocked(self):
        p = Policy(allow=["example.com"], deny=[])
        ok, reason = p.is_host_allowed("evil.com")
        self.assertFalse(ok)
        self.assertIn("not in allowlist", reason)

    def test_unscoped_deny_blocks_connect(self):
        p = Policy(allow=["example.com"], deny=["example.com"])
        ok, reason = p.is_host_allowed("example.com")
        self.assertFalse(ok)
        self.assertIn("denied by rule", reason)

    def test_empty_methods_allow_grants_all(self):
        # matches_method treats [] as no-restriction (this round's change), so a
        # `methods: []` ALLOW grants every method — consistent with `paths: []`
        # and with the deny direction. Locks the new semantics.
        p = Policy(allow=[{"domain": "x.com", "methods": []}], deny=[])
        for m in ("GET", "POST", "DELETE"):
            ok, _, _ = p.is_allowed("x.com", "/", m)
            self.assertTrue(ok, m)

    def test_empty_paths_allow_grants_all(self):
        p = Policy(allow=[{"domain": "x.com", "paths": []}], deny=[])
        ok, _, _ = p.is_allowed("x.com", "/anything/deep", "GET")
        self.assertTrue(ok)

    def test_empty_methods_deny_blocks_http_and_connect(self):
        # A `methods: []` deny is unscoped (empty = no restriction), so it must
        # block every method per-request AND block the CONNECT — not be a no-op
        # on HTTP while blocking HTTPS.
        p = Policy(allow=["x.com"], deny=[{"domain": "x.com", "methods": []}])
        for method in ("GET", "POST", "DELETE"):
            blocked, _, _ = p.is_allowed("x.com", "/", method)
            self.assertFalse(blocked, method)
        ok, reason = p.is_host_allowed("x.com")
        self.assertFalse(ok)
        self.assertIn("denied by rule", reason)

    def test_empty_paths_deny_blocks_connect(self):
        # An empty paths list means "all paths" in is_allowed (matches_path
        # returns True), so a `paths: []` deny blocks all HTTP — is_host_allowed
        # must block the CONNECT too, matching is_allowed rather than mistaking
        # the empty list for a scoped rule.
        p = Policy(allow=["x.com"], deny=[{"domain": "x.com", "paths": []}])
        # Sanity: is_allowed denies a concrete request under this rule.
        blocked, _, _ = p.is_allowed("x.com", "/anything", "GET")
        self.assertFalse(blocked)
        ok, reason = p.is_host_allowed("x.com")
        self.assertFalse(ok)
        self.assertIn("denied by rule", reason)

    def test_path_scoped_deny_does_not_block_connect(self):
        # A path-scoped deny can't be evaluated at CONNECT (path unknown) — it
        # is enforced per-request after MITM, so the CONNECT itself proceeds.
        p = Policy(
            allow=["api.example.com"],
            deny=[{"domain": "api.example.com", "paths": ["/admin/*"]}],
        )
        ok, _ = p.is_host_allowed("api.example.com")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
