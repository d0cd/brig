"""TCP host_services (aitelier wishlist #2): host_services entries
gain an optional `protocol: tcp` field that opts into L4 forwarding
through warden instead of L7 mitmproxy rewriting. Schema phase —
warden listener registration lands in a follow-up.
"""

from __future__ import annotations

import sys
import unittest
from unittest.mock import MagicMock


def _base():
    return {"name": "alice", "image": "alpine"}


class TestProtocolFieldAccepted(unittest.TestCase):
    def test_http_is_default(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": [
            {"name": "api", "port": 4000},
        ]})
        self.assertEqual(errs, [])

    def test_explicit_http_accepted(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": [
            {"name": "api", "port": 4000, "protocol": "http"},
        ]})
        self.assertEqual(errs, [])

    def test_tcp_accepted(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": [
            {"name": "db", "port": 5432, "protocol": "tcp"},
        ]})
        self.assertEqual(errs, [])

    def test_invalid_protocol_rejected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": [
            {"name": "db", "port": 5432, "protocol": "quic"},
        ]})
        self.assertTrue(any("protocol" in e and "http" in e for e in errs))


class TestUntrustedProfileRejectsTcp(unittest.TestCase):
    """Untrusted cells don't get TCP side channels. host_services overall
    is already
    rejected for the untrusted profile, but this test pins the
    behavior so a future relaxation of HTTP host_services for
    untrusted doesn't accidentally also unlock TCP."""

    def test_untrusted_rejects_tcp_host_services(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            "name": "adversarial", "image": "alpine",
            "profile": "untrusted",
            "host_services": [
                {"name": "db", "port": 5432, "protocol": "tcp"},
            ],
        })
        self.assertTrue(
            any("untrusted profile" in e for e in errs), errs,
        )


class TestPolicyParsesProtocol(unittest.TestCase):
    """warden_addons/_policy.py:Policy splits host_services into HTTP and TCP
    maps so enforce.py can dispatch correctly."""

    def _Policy(self):
        for _mod in (
            "mitmproxy", "mitmproxy.http", "mitmproxy.ctx",
            "mitmproxy.connection",
        ):
            sys.modules.setdefault(_mod, MagicMock())
        sys.path.insert(0, "src/brig/warden_addons")
        try:
            from _policy import Policy
        finally:
            sys.path.pop(0)
        return Policy

    def test_http_default_routes_to_http_map(self):
        Policy = self._Policy()
        p = Policy(host_services=[{"name": "api", "port": 4000}])
        self.assertEqual(p.host_services_map, {"api": 4000})
        self.assertEqual(p.tcp_host_services_map, {})

    def test_tcp_routes_to_tcp_map(self):
        Policy = self._Policy()
        p = Policy(host_services=[
            {"name": "db", "port": 5432, "protocol": "tcp"},
        ])
        self.assertEqual(p.tcp_host_services_map, {"db": 5432})
        self.assertEqual(p.host_services_map, {})

    def test_mixed_protocols_split(self):
        Policy = self._Policy()
        p = Policy(host_services=[
            {"name": "api", "port": 4000},
            {"name": "db", "port": 5432, "protocol": "tcp"},
            {"name": "redis", "port": 6379, "protocol": "tcp"},
        ])
        self.assertEqual(p.host_services_map, {"api": 4000})
        self.assertEqual(p.tcp_host_services_map, {"db": 5432, "redis": 6379})

    def test_none_host_services_means_no_maps(self):
        Policy = self._Policy()
        p = Policy(host_services=None)
        self.assertIsNone(p.host_services_map)
        self.assertIsNone(p.tcp_host_services_map)


if __name__ == "__main__":
    unittest.main()
