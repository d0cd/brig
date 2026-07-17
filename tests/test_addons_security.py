"""Tests for security-critical mitmproxy addon behavior.

Covers:
  - Webhook URL SSRF prevention (notifier.py)

Imports the real mitmproxy (installed via the dev extras) so an API
drift in mitmproxy surfaces as a unit-test failure instead of an E2E
surprise. Tests skip if mitmproxy is unavailable — `uv pip install -e
'.[dev]'` to enable.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("mitmproxy", reason="install dev extras: uv pip install -e '.[dev]'")

# Addons call `mitmproxy.ctx.log.*`; `ctx` is populated by a running master, so
# stub it for unit tests (mirrors test_security_audit.py).
import mitmproxy.ctx  # noqa: E402
if not hasattr(mitmproxy.ctx, "log"):
    mitmproxy.ctx.log = MagicMock()

# Add addons directory to sys.path so we can import directly.
_addons_dir = str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons")
if _addons_dir not in sys.path:
    sys.path.insert(0, _addons_dir)

from notifier import _resolve_webhook_url, Notifier  # noqa: E402


class TestOtelPathRedaction(unittest.TestCase):
    """The OTel log sink must redact query-string secrets, matching the JSONL
    sink — otherwise `?api_key=...` lands in the collector log in cleartext."""

    def test_response_redacts_query_secret(self):
        from types import SimpleNamespace
        import otel_export
        exporter = otel_export.OtelExporter()
        # Wire just enough so response() runs and emits a log record.
        for attr in ("requests_total", "request_duration_ms", "blocked_total",
                     "bytes_in_total", "bytes_out_total"):
            setattr(exporter, attr, MagicMock())
        captured = {}
        logger = MagicMock()
        logger.emit = lambda rec: captured.update(
            body=rec.body, attrs=dict(rec.attributes))
        exporter.logger = logger

        req = SimpleNamespace(method="GET", host="api.example.com",
                              path="/v1/data?api_key=SECRET&x=1", content=b"")
        resp = SimpleNamespace(status_code=200, content=b"ok")
        flow = SimpleNamespace(request=req, response=resp,
                               metadata={"cell": "codex"})
        # LogRecord is only imported when the OTel SDK is installed; stub it so
        # the test exercises redaction regardless of the dev env.
        def _fake_logrecord(**kw):
            return SimpleNamespace(**kw)
        with patch.object(otel_export, "LogRecord", _fake_logrecord, create=True):
            exporter.response(flow)

        self.assertNotIn("SECRET", captured["body"])
        self.assertNotIn("SECRET", captured["attrs"]["path"])
        self.assertIn("REDACTED", captured["attrs"]["path"])

    def test_log_record_has_zero_span_ids(self):
        # Span-less records must carry int 0 ids, not None — else the OTLP
        # encoder's _encode_span_id(None) throws and floods warden's log.
        from types import SimpleNamespace
        import otel_export
        exporter = otel_export.OtelExporter()
        for attr in ("requests_total", "request_duration_ms", "blocked_total",
                     "bytes_in_total", "bytes_out_total"):
            setattr(exporter, attr, MagicMock())
        captured = {}
        logger = MagicMock()
        logger.emit = lambda rec: captured.update(
            span_id=rec.span_id, trace_id=rec.trace_id, trace_flags=rec.trace_flags)
        exporter.logger = logger
        flow = SimpleNamespace(
            request=SimpleNamespace(method="GET", host="api.x", path="/v1/x", content=b""),
            response=SimpleNamespace(status_code=200, content=b"ok"),
            metadata={"cell": "c"})
        with patch.object(otel_export, "LogRecord",
                          lambda **kw: SimpleNamespace(**kw), create=True):
            exporter.response(flow)
        self.assertEqual(captured["span_id"], 0)
        self.assertEqual(captured["trace_id"], 0)
        self.assertEqual(captured["trace_flags"], 0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_flow(host="example.com", port=443, path="/", method="GET",
               headers=None, client_ip="10.60.1.2", body=None):
    """Build a minimal mock HTTPFlow."""
    flow = MagicMock()
    flow.request.host = host
    flow.request.port = port
    flow.request.path = path
    flow.request.url = f"https://{host}{path}"
    flow.request.method = method
    flow.request.headers = dict(headers or {})
    flow.request.get_content.return_value = body.encode() if body else None
    flow.client_conn.peername = (client_ip, 12345)
    flow.metadata = {}
    flow.response = None
    return flow


# 2. Notifier webhook security (notifier.py)
# ---------------------------------------------------------------------------

class TestResolveWebhookUrl(unittest.TestCase):
    """Test _resolve_webhook_url SSRF prevention."""

    @patch("_notifier_state._socket.getaddrinfo")
    def test_valid_public_url(self, mock_getaddrinfo):
        """Valid public URL resolves correctly."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
        ]
        safe, ip, hostname, port = _resolve_webhook_url("https://example.com/webhook")

        self.assertTrue(safe)
        self.assertEqual(ip, "93.184.216.34")
        self.assertEqual(hostname, "example.com")
        self.assertEqual(port, 443)

    @patch("_notifier_state._socket.getaddrinfo")
    def test_rejects_rfc1918_10(self, mock_getaddrinfo):
        """URL resolving to 10.0.0.0/8 is rejected."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("10.0.0.1", 443)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://internal.example.com/webhook")
        self.assertFalse(safe)

    @patch("_notifier_state._socket.getaddrinfo")
    def test_rejects_rfc1918_172(self, mock_getaddrinfo):
        """URL resolving to 172.16.0.0/12 is rejected."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("172.16.0.1", 443)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://internal.example.com/webhook")
        self.assertFalse(safe)

    @patch("_notifier_state._socket.getaddrinfo")
    def test_rejects_rfc1918_192(self, mock_getaddrinfo):
        """URL resolving to 192.168.0.0/16 is rejected."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.168.1.1", 443)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://internal.example.com/webhook")
        self.assertFalse(safe)

    @patch("_notifier_state._socket.getaddrinfo")
    def test_rejects_localhost(self, mock_getaddrinfo):
        """URL resolving to 127.0.0.1 is rejected."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 80)),
        ]
        safe, _, _, _ = _resolve_webhook_url("http://localhost/webhook")
        self.assertFalse(safe)

    @patch("_notifier_state._socket.getaddrinfo")
    def test_rejects_cgnat(self, mock_getaddrinfo):
        """URL resolving to CGNAT range 100.64.0.0/10 is rejected."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("100.64.0.1", 443)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://cgnat.example.com/webhook")
        self.assertFalse(safe)

    @patch("_notifier_state._socket.getaddrinfo")
    def test_rejects_ipv6_loopback(self, mock_getaddrinfo):
        """URL resolving to ::1 is rejected (IPv6 sockaddr is 4-tuple)."""
        mock_getaddrinfo.return_value = [
            (10, 1, 6, "", ("::1", 443, 0, 0)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://v6.example.com/webhook")
        self.assertFalse(safe)

    @patch("_notifier_state._socket.getaddrinfo")
    def test_rejects_ipv6_link_local(self, mock_getaddrinfo):
        """URL resolving to fe80::/10 is rejected."""
        mock_getaddrinfo.return_value = [
            (10, 1, 6, "", ("fe80::1", 443, 0, 0)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://v6.example.com/webhook")
        self.assertFalse(safe)

    @patch("_notifier_state._socket.getaddrinfo")
    def test_rejects_nat64_prefix(self, mock_getaddrinfo):
        """URL resolving into the NAT64 well-known prefix is rejected."""
        mock_getaddrinfo.return_value = [
            (10, 1, 6, "", ("64:ff9b::7f00:1", 443, 0, 0)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://nat64.example.com/webhook")
        self.assertFalse(safe)

    @patch("_notifier_state._socket.getaddrinfo")
    def test_rejects_when_any_resolved_address_is_internal(self, mock_getaddrinfo):
        """A mixed answer set with one internal address is rejected outright."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (10, 1, 6, "", ("::1", 443, 0, 0)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://mixed.example.com/webhook")
        self.assertFalse(safe)

    def test_rejects_file_scheme(self):
        """file:// URL is rejected (non-HTTP scheme)."""
        safe, _, _, _ = _resolve_webhook_url("file:///etc/passwd")
        self.assertFalse(safe)

    def test_rejects_ftp_scheme(self):
        """ftp:// URL is rejected (non-HTTP scheme)."""
        safe, _, _, _ = _resolve_webhook_url("ftp://evil.com/data")
        self.assertFalse(safe)

    def test_rejects_empty_hostname(self):
        """URL with no hostname is rejected."""
        safe, _, _, _ = _resolve_webhook_url("https:///path")
        self.assertFalse(safe)


class TestSendHttpRequestSSRF(unittest.TestCase):
    """Test _send_http_request uses resolved IP to prevent DNS rebinding."""

    def setUp(self):
        self.notifier = Notifier()
        self.notifier.config.webhook_url = "https://webhook.example.com/notify"

    @patch("notifier.URLLIB3_AVAILABLE", False)
    @patch("notifier.urllib.request.build_opener")
    def test_uses_resolved_ip_in_url(self, mock_build_opener):
        """HTTP request URL uses the resolved IP, not the original hostname.

        Now uses an opener (with redirect-disabling handler — H2). Verify the
        Request that gets opened still uses the resolved IP and original
        Host header.
        """
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_response
        mock_build_opener.return_value = mock_opener

        data = b'{"test": true}'
        self.notifier._send_http_request(data, "93.184.216.34", "webhook.example.com", 443)

        request_obj = mock_opener.open.call_args[0][0]
        self.assertIn("93.184.216.34", request_obj.full_url)
        self.assertNotIn("webhook.example.com", request_obj.full_url)
        self.assertEqual(request_obj.get_header("Host"), "webhook.example.com")


class TestNovelHelpers(unittest.TestCase):
    """Path templating + query-exfil heuristic (pure functions)."""

    def test_normalize_collapses_high_cardinality_segments(self):
        from notifier import normalize_path_template as nt
        self.assertEqual(nt("/users/12345/posts/67"), "/users/{id}/posts/{id}")
        self.assertEqual(nt("/v1/3fa85f64-5717-4562-b3fc-2c963f66afa6"), "/v1/{id}")
        self.assertEqual(nt("/repos/deadbeefcafe1234"), "/repos/{id}")  # long hex
        self.assertEqual(nt("/api/messages?api_key=secret"), "/api/messages")  # query stripped
        self.assertEqual(nt("/static/app.js"), "/static/app.js")  # short segments stay

    def test_normalize_collapses_colon_joined_credential(self):
        # A colon-joined API token rides IN the path; the colon must not let it leak.
        from notifier import normalize_path_template as nt
        self.assertEqual(
            nt("/bot0000000000:FAKEfakeFAKEfakeFAKEfakeFAKEfake000/getUpdates"),
            "/{id}/getUpdates")

    def test_entropy_helper_thresholds(self):
        from _notifier_state import _high_entropy_segment as hi
        self.assertTrue(hi("ABCDEFGHIJKLMNOPqrstuvwxyz012345"))  # 32 distinct -> 5.0 bits
        self.assertFalse(hi("aZ3kP9xQ"))                         # 8 chars < len floor
        self.assertFalse(hi("a" * 20))                           # long but 0 entropy

    def test_entropy_fallback_collapses_unknown_token(self):
        # The recall net: an unenumerated high-entropy token (e.g. base64 with
        # +/= that the regexes miss) still collapses, so it can't leak.
        from notifier import normalize_path_template as nt
        self.assertEqual(nt("/d/ABCDEFGHIJKLMNOPqrstuvwxyz012345"), "/d/{id}")

    def test_entropy_keeps_meaningful_segments(self):
        # Tuned against brig's real logs — these must NOT collapse (false positive).
        from notifier import normalize_path_template as nt
        for p in ("/v1/models/model-catalog.json", "/repos/NousResearch",
                  "/api/setMyCommands"):
            self.assertEqual(nt(p), p, p)

    def test_query_exfil_signal(self):
        from notifier import query_exfil_signal as q
        self.assertTrue(q("/x?dump=" + "a" * 100, 50))
        self.assertFalse(q("/x?p=ab", 50))
        self.assertFalse(q("/x", 50))  # no query


class TestNovelAllowed(unittest.TestCase):
    """First-seen detection on allow-listed hosts (the detection complement)."""

    def _flow(self, host="api.anthropic.com", path="/v1/messages",
              method="POST", blocked=False, cell="sa"):
        flow = MagicMock()
        flow.metadata = {"blocked": blocked, "cell": cell}
        flow.request.host = host
        flow.request.path = path
        flow.request.method = method
        flow.client_conn.peername = ("10.60.1.2", 1234)
        return flow

    def _notifier(self, **na_kw):
        from _notifier_state import NotificationConfig, NovelAllowedConfig
        n = Notifier()
        n.config = NotificationConfig(
            novel_allowed=NovelAllowedConfig(enabled=True, **na_kw))
        return n

    @patch("notifier.Notifier._reload_config")
    def test_first_seen_path_is_novel(self, _):
        n = self._notifier()
        n.response(self._flow(path="/v1/messages"))
        notif = n.notification_queue.get_nowait()
        self.assertEqual(notif["event"], "novel_allowed")
        self.assertEqual(notif["reason"], "novel_path")
        self.assertEqual(notif["host"], "api.anthropic.com")

    @patch("notifier.Notifier._reload_config")
    def test_repeat_and_id_variants_are_not_novel(self, _):
        n = self._notifier()
        n.response(self._flow(host="api.x", path="/users/123"))
        n.notification_queue.get_nowait()  # drain the first (novel) alert
        n.response(self._flow(host="api.x", path="/users/123"))   # exact repeat
        n.response(self._flow(host="api.x", path="/users/456"))   # same template
        self.assertTrue(n.notification_queue.empty())

    @patch("notifier.Notifier._reload_config")
    def test_dry_run_does_not_enqueue(self, _):
        n = self._notifier(dry_run=True)
        n.response(self._flow())
        self.assertTrue(n.notification_queue.empty())

    @patch("notifier.Notifier._reload_config")
    def test_ignore_host_suffix(self, _):
        n = self._notifier(ignore_hosts=("anthropic.com",))
        n.response(self._flow(host="api.anthropic.com"))
        self.assertTrue(n.notification_queue.empty())

    @patch("notifier.Notifier._reload_config")
    def test_cells_filter_scopes_detection(self, _):
        n = self._notifier(cells=["other-cell"])
        n.response(self._flow(cell="sa"))
        self.assertTrue(n.notification_queue.empty())

    @patch("notifier.Notifier._reload_config")
    def test_suspicious_query_on_known_path_without_leaking_payload(self, _):
        import json as _json
        n = self._notifier(max_query_len=10)
        n.response(self._flow(path="/v1/messages"))          # novel_path
        n.notification_queue.get_nowait()
        n.response(self._flow(path="/v1/messages?leak=" + "x" * 50))
        notif = n.notification_queue.get_nowait()
        self.assertEqual(notif["reason"], "suspicious_query")
        self.assertIn("query_length", notif)
        self.assertNotIn("leak", _json.dumps(notif))  # payload never recorded

    @patch("notifier.Notifier._reload_config")
    def test_blocked_path_still_alerts_after_refactor(self, _):
        n = self._notifier()
        n.config.enabled = True
        n.config.min_interval_seconds = 0
        n.response(self._flow(blocked=True))
        notif = n.notification_queue.get_nowait()
        self.assertEqual(notif["event"], "request_blocked")

    def test_reload_config_parses_novel_allowed_block(self):
        # Exercises the real _reload_config parse path (compiles ignore_paths),
        # which the _reload_config-patched tests above don't cover.
        import json as _json
        import os
        import tempfile
        from pathlib import Path
        fd, name = tempfile.mkstemp(suffix=".json")
        os.write(fd, _json.dumps({"notifications": {"novel_allowed": {
            "enabled": True, "cells": ["sa"], "ignore_hosts": ["pypi.org"],
            "ignore_paths": ["^/v1/acp/"], "dry_run": True, "max_query_len": 256,
        }}}).encode())
        os.close(fd)
        try:
            n = Notifier()
            with patch("notifier.POLICY_FILE", Path(name)):
                n._reload_config(force=True)
            na = n.config.novel_allowed
            self.assertIsNotNone(na)
            self.assertTrue(na.enabled and na.dry_run)
            self.assertEqual(na.cells, ["sa"])
            self.assertEqual(na.max_query_len, 256)
            self.assertEqual(na.ignore_hosts, ("pypi.org",))
            self.assertTrue(any(p.search("/v1/acp/x") for p in na.ignore_paths))
        finally:
            os.unlink(name)


class TestUnifiedRedaction(unittest.TestCase):
    """All sinks share one classifier (_common), so a secret masked in one
    channel can't leak in another — regression for a secret-in-path leak that
    was redacted in novel_allowed but verbatim in the logger + OTel sinks."""

    TOKEN_PATH = "/bot0000000000:FAKEfakeFAKEfakeFAKEfakeFAKEfake000/getUpdates"

    def test_redact_path_masks_secret_keeps_id_scrubs_query(self):
        from _common import redact_path
        self.assertEqual(redact_path(self.TOKEN_PATH), "/[REDACTED]/getUpdates")
        self.assertEqual(redact_path("/users/12345/posts"), "/users/12345/posts")  # id kept
        self.assertEqual(redact_path("/v1/x?api_key=SECRET"), "/v1/x?api_key=REDACTED")

    def test_all_sinks_close_the_token_leak(self):
        import _log_writer
        import _notifier_state as ns
        for fn in (_log_writer._redact_path,           # logger + otel
                   ns._redact_notification_path,       # notifier blocked alert
                   ns.normalize_path_template):        # novel_allowed template
            self.assertNotIn("FAKEfake", fn(self.TOKEN_PATH), fn.__name__)


class TestQueryValueRedaction(unittest.TestCase):
    """Query values are redacted both for known-sensitive names and for any
    value that classifies as a secret segment (unenumerated param names)."""

    def test_extra_named_params_redacted(self):
        from _common import redact_path
        self.assertIn("session=REDACTED", redact_path("/a?session=abcdef0123456789"))
        self.assertIn("sig=REDACTED", redact_path("/a?sig=AAAAAAAAAAAAAAAA"))

    def test_high_entropy_unlisted_param_redacted(self):
        from _common import redact_path
        out = redact_path("/a?nonce=AKIAIOSFODNN7EXAMPLE1234567890")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)

    def test_short_benign_values_kept(self):
        from _common import redact_path
        self.assertEqual(redact_path("/a?page=2&size=10"), "/a?page=2&size=10")


class TestPathFilterQueryStrip(unittest.TestCase):
    """Path filters match on the path WITHOUT the query string."""

    def test_query_stripped_before_match(self):
        from _policy import PolicyRule
        rule = PolicyRule({"domain": "api.example.com", "paths": ["/v1/x"]})
        self.assertTrue(rule.matches_path("/v1/x?token=abc"))
        self.assertTrue(rule.matches_path("/v1/x"))
        self.assertFalse(rule.matches_path("/v2/x"))


class TestBlockedLogRedaction(unittest.TestCase):
    """The BLOCKED ctx.log line is captured as warden container stdout — the
    same trust level as the structured sinks — so secrets in the path/query
    must be redacted there too. Regression: ctx.log was the one sink the
    redaction pipeline missed on the blocked branch."""

    def test_block_log_redacts_secret_query(self):
        import mitmproxy.ctx as ctx
        from enforce import PolicyEnforcer
        ctx.log = MagicMock()
        enf = PolicyEnforcer()
        flow = MagicMock()
        flow.request.host = "evil.example.com"
        flow.request.path = "/x?api_key=sk-SUPERSECRETVALUE0123456789"
        enf._block(flow, "blocked for test")
        logged = " ".join(str(c) for c in ctx.log.info.call_args_list)
        self.assertNotIn("SUPERSECRETVALUE", logged)


class TestRequestEgressEnforcement(unittest.TestCase):
    """The core egress decision in PolicyEnforcer.request(): default-deny,
    per-cell allow/deny (deny wins), port + internal/literal-IP guards, and
    fail-closed when a cell has no policy. Unit-covers the path the
    nested-virt e2e gates so a regression surfaces without a running VM."""

    def _enforcer(self, cell="sa", policy=None):
        from enforce import PolicyEnforcer
        enf = PolicyEnforcer()
        enf._check_reload = lambda: None
        enf.subnets = type("S", (), {"get_cell_name": staticmethod(lambda ip: cell)})()
        if policy is not None:
            enf.cell_policies[cell] = policy
        return enf

    def _policy(self, allow=None, deny=None):
        from _policy import Policy
        return Policy(allow=allow or [], deny=deny or [])

    def _flow(self, host="api.anthropic.com", port=443, path="/v1/messages",
              method="POST", listen_port=8080):
        flow = MagicMock()
        flow.client_conn.sockname = ("10.60.1.1", listen_port)
        flow.client_conn.peername = ("10.60.1.5", 1234)
        flow.request.host = host
        flow.request.port = port
        flow.request.path = path
        flow.request.method = method
        flow.request.headers = {}
        flow.metadata = {}
        flow.response = None
        return flow

    def test_allowed_host_passes(self):
        enf = self._enforcer(policy=self._policy(allow=["api.anthropic.com"]))
        flow = self._flow()
        enf.request(flow)
        self.assertIsNone(flow.response)
        self.assertFalse(flow.metadata.get("blocked", False))
        self.assertIn("cell:", flow.metadata.get("policy_reason", ""))

    def test_non_allowlisted_host_blocked(self):
        enf = self._enforcer(policy=self._policy(allow=["api.anthropic.com"]))
        flow = self._flow(host="evil.example.com")
        enf.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertTrue(flow.metadata.get("blocked"))
        self.assertIn("not in allowlist", flow.metadata.get("block_reason", ""))

    def test_deny_takes_precedence(self):
        enf = self._enforcer(policy=self._policy(
            allow=["api.anthropic.com"], deny=["api.anthropic.com"]))
        flow = self._flow()
        enf.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertIn("denied by rule", flow.metadata.get("block_reason", ""))

    def test_disallowed_port_blocked(self):
        enf = self._enforcer(policy=self._policy(allow=["api.anthropic.com"]))
        flow = self._flow(port=22)
        enf.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertIn("port 22", flow.metadata.get("block_reason", ""))

    def test_literal_ip_blocked(self):
        # Blocked by the literal-IP guard before the allowlist is even consulted.
        enf = self._enforcer(policy=self._policy(allow=["93.184.216.34"]))
        flow = self._flow(host="93.184.216.34")
        enf.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertIn("literal IP", flow.metadata.get("block_reason", ""))

    def test_no_cell_policy_fails_closed(self):
        enf = self._enforcer(policy=None)  # cell resolves but no policy loaded
        flow = self._flow()
        enf.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertIn("no per-cell policy", flow.metadata.get("block_reason", ""))

    def test_ingress_port_unhandled_blocked(self):
        # A request arriving on the ingress port without the ingress addon's
        # metadata flag must be blocked (fail closed).
        enf = self._enforcer(policy=self._policy(allow=["api.anthropic.com"]))
        flow = self._flow(listen_port=8443)
        enf.request(flow)
        self.assertIsNotNone(flow.response)


class TestReloadCellPolicies(unittest.TestCase):
    """_reload_cell_policies: fail-closed size cap, LRU eviction, deleted drop —
    the untrusted-state-dir (invariant 4) defenses on the policy loader."""

    def _enforcer(self):
        import mitmproxy.ctx as ctx
        from enforce import PolicyEnforcer
        ctx.log = MagicMock()
        return PolicyEnforcer()

    def _write_policy(self, d, name, pad=0):
        import json as _json
        data = {"allow": ["example.com"], "deny": []}
        if pad:
            data["_pad"] = "x" * pad
        (d / f"{name}.json").write_text(_json.dumps(data))

    def test_oversized_policy_skipped_failing_closed(self):
        import tempfile as _tf
        import enforce as enforce_mod
        with _tf.TemporaryDirectory() as td:
            d = Path(td)
            self._write_policy(d, "small")
            self._write_policy(d, "big", pad=1000)
            enf = self._enforcer()
            with patch.object(enforce_mod, "CELL_POLICY_DIR", d), \
                 patch.object(enforce_mod, "MAX_POLICY_FILE_BYTES", 200):
                enf._reload_cell_policies()
            self.assertIn("small", enf.cell_policies)
            self.assertNotIn("big", enf.cell_policies)  # over cap -> not loaded

    def test_lru_eviction_bounds_cache(self):
        import tempfile as _tf
        import enforce as enforce_mod
        with _tf.TemporaryDirectory() as td:
            d = Path(td)
            for n in ("a", "b", "c"):
                self._write_policy(d, n)
            enf = self._enforcer()
            with patch.object(enforce_mod, "CELL_POLICY_DIR", d), \
                 patch.object(enforce_mod, "MAX_CACHED_CELL_POLICIES", 2):
                enf._reload_cell_policies()
            self.assertEqual(len(enf.cell_policies), 2)

    def test_deleted_policy_dropped_from_cache(self):
        import tempfile as _tf
        import enforce as enforce_mod
        with _tf.TemporaryDirectory() as td:
            d = Path(td)
            self._write_policy(d, "gone")
            enf = self._enforcer()
            with patch.object(enforce_mod, "CELL_POLICY_DIR", d):
                enf._reload_cell_policies()
                self.assertIn("gone", enf.cell_policies)
                (d / "gone.json").unlink()
                enf._reload_cell_policies()
                self.assertNotIn("gone", enf.cell_policies)


if __name__ == "__main__":
    unittest.main()
