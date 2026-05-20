"""TLS passthrough — invariant 11 surfaces (Phases 1-3).

  - Policy.is_passthrough requires the host to match BOTH passthrough
    AND allow rules (defense in depth against tampered policy files).
  - Wildcard semantics on passthrough rules mirror allow/deny.
  - Untrusted profile cannot declare tls_passthrough (informed-consent
    trade-off; untrusted cells must remain inspectable).
  - _sync_cell_policy persists tls_passthrough to the per-cell JSON
    so warden can read it from disk.
  - brig cell network --otel renders passthrough lines distinctly.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _addon_policy_class():
    sys.path.insert(0, "src/addons")
    try:
        from _policy import Policy
    finally:
        sys.path.pop(0)
    return Policy


class TestPolicyIsPassthrough(unittest.TestCase):
    def test_host_in_both_lists_is_passthrough(self):
        Policy = _addon_policy_class()
        p = Policy(allow=["chatgpt.com"], tls_passthrough=["chatgpt.com"])
        self.assertTrue(p.is_passthrough("chatgpt.com"))

    def test_host_only_in_passthrough_is_not(self):
        """Defense in depth: a tampered policy file that lists a host
        ONLY in tls_passthrough must not bypass allow."""
        Policy = _addon_policy_class()
        p = Policy(allow=["api.openai.com"], tls_passthrough=["chatgpt.com"])
        self.assertFalse(p.is_passthrough("chatgpt.com"))

    def test_host_only_in_allow_is_not_passthrough(self):
        Policy = _addon_policy_class()
        p = Policy(allow=["api.anthropic.com"], tls_passthrough=[])
        self.assertFalse(p.is_passthrough("api.anthropic.com"))

    def test_wildcard_passthrough_matches_subdomain(self):
        Policy = _addon_policy_class()
        p = Policy(
            allow=["*.openai.com"],
            tls_passthrough=["*.openai.com"],
        )
        self.assertTrue(p.is_passthrough("auth.openai.com"))
        self.assertTrue(p.is_passthrough("chat.openai.com"))

    def test_wildcard_passthrough_does_not_match_bare_domain(self):
        """Same dot-boundary semantics as allow/deny — *.openai.com
        doesn't match openai.com itself."""
        Policy = _addon_policy_class()
        p = Policy(
            allow=["*.openai.com"],
            tls_passthrough=["*.openai.com"],
        )
        self.assertFalse(p.is_passthrough("openai.com"))

    def test_empty_passthrough_returns_false_fast(self):
        Policy = _addon_policy_class()
        p = Policy(allow=["api.anthropic.com"])
        self.assertFalse(p.is_passthrough("api.anthropic.com"))


class TestPassthroughAllowWildcardCoverage(unittest.TestCase):
    """Audit H1: validator must accept passthrough hosts covered by an
    allow wildcard, not just exact-string allow entries. Runtime
    is_passthrough() uses wildcard-aware lookup; exact-string-only
    parse-time validation diverged from runtime and rejected legitimate
    configs (e.g. allow: ['*.openai.com'] + tls_passthrough:
    ['auth.openai.com'])."""

    def test_passthrough_subdomain_covered_by_wildcard_accepted(self):
        from brig.cell.spec import validate_cell_definition
        errors = validate_cell_definition({
            "name": "codex", "image": "alpine",
            "policy": {
                "allow": ["*.openai.com"],
                "tls_passthrough": ["auth.openai.com"],
            },
        })
        self.assertEqual(errors, [])

    def test_passthrough_wildcard_matching_allow_wildcard_accepted(self):
        from brig.cell.spec import validate_cell_definition
        errors = validate_cell_definition({
            "name": "codex", "image": "alpine",
            "policy": {
                "allow": ["*.openai.com"],
                "tls_passthrough": ["*.openai.com"],
            },
        })
        self.assertEqual(errors, [])

    def test_passthrough_bare_domain_not_covered_by_wildcard_rejected(self):
        """Wildcard *.openai.com does NOT cover openai.com itself
        (dot-boundary, same as runtime). Passthrough of openai.com
        must be rejected when only *.openai.com is allowed."""
        from brig.cell.spec import validate_cell_definition
        errors = validate_cell_definition({
            "name": "codex", "image": "alpine",
            "policy": {
                "allow": ["*.openai.com"],
                "tls_passthrough": ["openai.com"],
            },
        })
        self.assertTrue(
            any("must be covered by an entry in 'policy.allow'" in e
                for e in errors),
            errors,
        )


class TestUntrustedProfileRejectsPassthrough(unittest.TestCase):
    def test_untrusted_profile_rejects_tls_passthrough(self):
        """Invariant 11: untrusted profile cannot declare passthrough."""
        from brig.cell.spec import validate_cell_definition
        errors = validate_cell_definition({
            "name": "u", "image": "alpine",
            "profile": "untrusted",
            "policy": {
                "allow": ["chatgpt.com"],
                "tls_passthrough": ["chatgpt.com"],
            },
        })
        self.assertTrue(
            any("untrusted profile" in e and "tls_passthrough" in e
                for e in errors),
            errors,
        )

    def test_untrusted_profile_without_passthrough_is_fine(self):
        from brig.cell.spec import validate_cell_definition
        errors = validate_cell_definition({
            "name": "u", "image": "alpine",
            "profile": "untrusted",
            "policy": {"allow": ["api.anthropic.com"]},
        })
        self.assertEqual(errors, [])


class TestSyncCellPolicyPersistsPassthrough(unittest.TestCase):
    """_sync_cell_policy writes tls_passthrough to the per-cell JSON so
    warden's enforce.py can read it from disk and feed it to Policy."""

    def test_passthrough_written_to_per_cell_policy(self):
        from brig.cell.spec import CellSpec
        from brig.commands.lifecycle_cmd import _sync_cell_policy
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            policy_dir = td / "policies"
            policy_dir.mkdir()
            spec = CellSpec(
                name="codex", image="alpine",
                policy_allow=["chatgpt.com", "api.openai.com"],
                policy_passthrough_tls=["chatgpt.com"],
            )
            with patch("brig.policy.policy.get_cell_policy_path",
                       side_effect=lambda name, *a, **kw: policy_dir / f"{name}.json"), \
                 patch("brig.commands.lifecycle_cmd.info"):
                _sync_cell_policy(spec)
            on_disk = json.loads((policy_dir / "codex.json").read_text())
            self.assertEqual(on_disk["tls_passthrough"], ["chatgpt.com"])
            self.assertEqual(on_disk["allow"], ["chatgpt.com", "api.openai.com"])


class TestPrintNetworkLineRendersPassthrough(unittest.TestCase):
    def test_passthrough_log_line_distinct(self):
        from brig.commands.network_cmd import _print_network_line
        captured: list[str] = []
        with patch("brig.commands.network_cmd.output",
                   side_effect=captured.append):
            _print_network_line({
                "ts": "2026-05-19T21:00:00Z",
                "tls_mode": "passthrough",
                "host": "chatgpt.com",
                "bytes_in": 1024,
                "bytes_out": 2048,
            })
        self.assertEqual(len(captured), 1)
        line = captured[0]
        self.assertIn("PASSTHROUGH", line)
        self.assertIn("chatgpt.com", line)
        self.assertIn("1024B in", line)
        self.assertIn("2048B out", line)
        # Must NOT contain method/path/status — they're unknowable for
        # passthrough flows. Sanity-check the absence so a future
        # refactor that accidentally adds them gets caught.
        self.assertNotIn("GET", line)
        self.assertNotIn("OUT:", line)


class TestTlsClientHelloFailsClosed(unittest.TestCase):
    """Audit C1: tls_clienthello MUST NOT flip passthrough when the
    CONNECT host can't be read (e.g. mitmproxy didn't populate
    context.server.address). Otherwise a malicious cell could ship
    arbitrary SNI through warden as a tunnel after CONNECTing to an
    allowed host."""

    def _enforcer(self):
        import sys
        sys.path.insert(0, "src/addons")
        try:
            from enforce import PolicyEnforcer
            from _policy import Policy
        finally:
            sys.path.pop(0)
        enf = PolicyEnforcer()
        enf.cell_policies["codex"] = Policy(
            allow=["chatgpt.com"], tls_passthrough=["chatgpt.com"],
        )
        enf.subnets = type("S", (), {
            "get_cell_name": staticmethod(lambda ip: "codex"),
        })()
        return enf

    def _make_data(self, sni, connect_host):
        """Build a mitmproxy-shaped ClientHelloData mock. Pass
        connect_host=None to simulate the missing-address case."""
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        client = MagicMock()
        client.peername = ("10.60.1.5", 54321)
        client.metadata = {}
        client.tls_passthrough = False
        server = SimpleNamespace(
            address=(connect_host, 443) if connect_host else None,
        )
        context = SimpleNamespace(client=client, server=server)
        hello = SimpleNamespace(sni=sni)
        return SimpleNamespace(client_hello=hello, context=context), client

    def test_passthrough_flips_when_sni_matches_connect(self):
        enf = self._enforcer()
        data, client = self._make_data("chatgpt.com", "chatgpt.com")
        enf.tls_clienthello(data)
        self.assertTrue(client.tls_passthrough)
        self.assertEqual(client.metadata.get("tls_mode"), "passthrough")

    def test_passthrough_not_flipped_when_connect_host_missing(self):
        """Fail closed: no CONNECT host = can't verify, don't flip."""
        enf = self._enforcer()
        data, client = self._make_data("chatgpt.com", None)
        enf.tls_clienthello(data)
        self.assertFalse(client.tls_passthrough)
        self.assertNotIn("tls_mode", client.metadata)

    def test_passthrough_not_flipped_on_sni_connect_mismatch(self):
        enf = self._enforcer()
        # Cell CONNECTs to allowed host but ships SNI of disallowed host.
        data, client = self._make_data("attacker.com", "chatgpt.com")
        enf.tls_clienthello(data)
        self.assertFalse(client.tls_passthrough)


if __name__ == "__main__":
    unittest.main()
