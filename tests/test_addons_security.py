"""Tests for security-critical mitmproxy addon behavior.

Covers:
  - Canary token detection and cell kill (canary.py)
  - Webhook URL SSRF prevention (notifier.py)
  - Signed audit log batching (signer.py)
"""

import base64
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

# Mock mitmproxy before importing addons — it is not installed in the test
# environment. The mock must be in sys.modules before any addon import.
_mock_mitmproxy = MagicMock()
sys.modules.setdefault("mitmproxy", _mock_mitmproxy)
sys.modules.setdefault("mitmproxy.ctx", _mock_mitmproxy.ctx)
sys.modules.setdefault("mitmproxy.http", _mock_mitmproxy.http)

# Add addons directory to sys.path so we can import directly.
_addons_dir = str(Path(__file__).parent.parent / "src" / "addons")
if _addons_dir not in sys.path:
    sys.path.insert(0, _addons_dir)

from canary import CanaryDetector  # noqa: E402
from notifier import _resolve_webhook_url, Notifier, BLOCKED_NETWORKS  # noqa: E402

# signer uses module-level globals, import after mock setup.
import signer  # noqa: E402


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


# ---------------------------------------------------------------------------
# 1. Canary token detection (canary.py)
# ---------------------------------------------------------------------------

class TestCanaryLoadTokens(unittest.TestCase):
    """Test CanaryDetector canary token loading from policy files."""

    def setUp(self):
        self.detector = CanaryDetector()
        self.tmpdir = tempfile.mkdtemp()

    def test_load_canaries_from_policy(self):
        """Canary tokens are loaded from per-cell JSON policy files."""
        policy_dir = Path(self.tmpdir) / "policies"
        policy_dir.mkdir()
        policy = {"canary_tokens": {"db_cred": "SECRET_TOKEN_123"}}
        (policy_dir / "my-cell.json").write_text(json.dumps(policy))

        with patch("canary.CELL_POLICY_DIR", policy_dir):
            self.detector._load_canaries()

        self.assertIn("my-cell", self.detector.cell_canaries)
        self.assertEqual(self.detector.cell_canaries["my-cell"]["db_cred"], "SECRET_TOKEN_123")

    def test_load_canaries_empty_tokens(self):
        """Cell with empty canary_tokens dict is not tracked."""
        policy_dir = Path(self.tmpdir) / "policies"
        policy_dir.mkdir()
        policy = {"canary_tokens": {}}
        (policy_dir / "empty-cell.json").write_text(json.dumps(policy))

        with patch("canary.CELL_POLICY_DIR", policy_dir):
            self.detector._load_canaries()

        self.assertNotIn("empty-cell", self.detector.cell_canaries)


class TestCanaryDetectionBody(unittest.TestCase):
    """Test canary detection in request body."""

    def setUp(self):
        self.detector = CanaryDetector()
        self.detector.cell_canaries = {
            "test-cell": {"api_key": "CANARY_VALUE_ABC"}
        }
        self.detector.subnet_map = {"10.60.1.0/24": "test-cell"}

    def test_canary_in_body_detected(self):
        """Canary token in request body triggers detection and blocks request."""
        flow = _make_flow(
            client_ip="10.60.1.2",
            body="payload containing CANARY_VALUE_ABC in body"
        )
        flow.metadata = {}

        self.detector._reload_pending = False
        with patch.object(self.detector, "_load_subnet_map"), \
             patch.object(self.detector, "_load_canaries"), \
             patch.object(self.detector, "_kill_cell") as mock_kill:
            self.detector.request(flow)

        self.assertIn("canary_detected", flow.metadata)
        self.assertIn("api_key", flow.metadata["canary_detected"])
        mock_kill.assert_called_once_with("test-cell")

    def test_no_canary_passes(self):
        """Request without canary tokens passes through."""
        flow = _make_flow(client_ip="10.60.1.2", body="safe payload")
        flow.metadata = {}

        self.detector._reload_pending = False
        with patch.object(self.detector, "_load_subnet_map"), \
             patch.object(self.detector, "_load_canaries"), \
             patch.object(self.detector, "_kill_cell") as mock_kill:
            self.detector.request(flow)

        self.assertNotIn("canary_detected", flow.metadata)
        mock_kill.assert_not_called()


class TestCanaryDetectionPathHeaders(unittest.TestCase):
    """Test canary detection in request path and headers."""

    def setUp(self):
        self.detector = CanaryDetector()
        self.detector.cell_canaries = {
            "test-cell": {"secret": "LEAKED_SECRET_XYZ"}
        }
        self.detector.subnet_map = {"10.60.1.0/24": "test-cell"}

    def test_canary_in_url_path(self):
        """Canary token in URL path triggers detection."""
        flow = _make_flow(
            host="evil.com",
            path="/exfil/LEAKED_SECRET_XYZ",
            client_ip="10.60.1.2",
        )
        flow.request.url = "https://evil.com/exfil/LEAKED_SECRET_XYZ"
        flow.metadata = {}

        self.detector._reload_pending = False
        with patch.object(self.detector, "_load_subnet_map"), \
             patch.object(self.detector, "_load_canaries"), \
             patch.object(self.detector, "_kill_cell"):
            self.detector.request(flow)

        self.assertIn("canary_detected", flow.metadata)

    def test_canary_in_header_value(self):
        """Canary token in request header value triggers detection."""
        flow = _make_flow(
            client_ip="10.60.1.2",
            headers={"Authorization": "Bearer LEAKED_SECRET_XYZ"},
        )
        flow.metadata = {}

        self.detector._reload_pending = False
        with patch.object(self.detector, "_load_subnet_map"), \
             patch.object(self.detector, "_load_canaries"), \
             patch.object(self.detector, "_kill_cell"):
            self.detector.request(flow)

        self.assertIn("canary_detected", flow.metadata)


class TestCanaryCellIdentification(unittest.TestCase):
    """Test cell identification from client IP via subnet map."""

    def setUp(self):
        self.detector = CanaryDetector()
        self.detector.subnet_map = {
            "10.60.1.0/24": "cell-alpha",
            "10.60.2.0/24": "cell-beta",
        }

    def test_ip_in_subnet_resolves(self):
        """Client IP within a known subnet resolves to correct cell name."""
        self.assertEqual(self.detector._identify_cell_ip("10.60.1.5"), "cell-alpha")
        self.assertEqual(self.detector._identify_cell_ip("10.60.2.100"), "cell-beta")

    def test_ip_outside_subnets_returns_none(self):
        """Client IP not in any known subnet returns None."""
        self.assertIsNone(self.detector._identify_cell_ip("192.168.1.1"))

    def test_invalid_ip_returns_none(self):
        """Invalid IP string returns None without crashing."""
        self.assertIsNone(self.detector._identify_cell_ip("not-an-ip"))


class TestCanaryDeregisterIngress(unittest.TestCase):
    """Test _deregister_ingress route removal on cell kill."""

    def setUp(self):
        self.detector = CanaryDetector()
        self.tmpdir = tempfile.mkdtemp()
        self.routes_file = Path(self.tmpdir) / "ingress-routes.json"

    def test_removes_killed_cell_routes(self):
        """Routes for the killed cell are removed, other cells preserved."""
        routes_data = {
            "routes": [
                {"cell": "cell-a", "port": 8080},
                {"cell": "cell-b", "port": 9090},
                {"cell": "cell-a", "port": 8081},
            ]
        }
        self.routes_file.write_text(json.dumps(routes_data))

        with patch("canary.INGRESS_ROUTES_FILE", self.routes_file):
            self.detector._deregister_ingress("cell-a")

        result = json.loads(self.routes_file.read_text())
        self.assertEqual(len(result["routes"]), 1)
        self.assertEqual(result["routes"][0]["cell"], "cell-b")

    def test_preserves_other_cells(self):
        """Deregistering a cell does not affect other cells' routes."""
        routes_data = {
            "routes": [
                {"cell": "cell-x", "port": 80},
                {"cell": "cell-y", "port": 443},
            ]
        }
        self.routes_file.write_text(json.dumps(routes_data))

        with patch("canary.INGRESS_ROUTES_FILE", self.routes_file):
            self.detector._deregister_ingress("cell-z")

        result = json.loads(self.routes_file.read_text())
        self.assertEqual(len(result["routes"]), 2)

    def test_missing_routes_file(self):
        """Missing routes file is handled gracefully (no crash)."""
        missing = Path(self.tmpdir) / "nonexistent.json"
        with patch("canary.INGRESS_ROUTES_FILE", missing):
            self.detector._deregister_ingress("cell-a")  # Should not raise.

    def test_empty_routes_file(self):
        """Routes file with empty routes list is handled gracefully."""
        self.routes_file.write_text(json.dumps({"routes": []}))

        with patch("canary.INGRESS_ROUTES_FILE", self.routes_file):
            self.detector._deregister_ingress("cell-a")  # Should not raise.

    def test_atomic_write_via_rename(self):
        """Deregister uses temp file + rename (atomic write)."""
        routes_data = {
            "routes": [
                {"cell": "cell-a", "port": 8080},
                {"cell": "cell-b", "port": 9090},
            ]
        }
        self.routes_file.write_text(json.dumps(routes_data))

        with patch("canary.INGRESS_ROUTES_FILE", self.routes_file):
            self.detector._deregister_ingress("cell-a")

        # After rename, the .tmp file should not exist.
        tmp_file = self.routes_file.with_suffix(".tmp")
        self.assertFalse(tmp_file.exists(), "Temp file must not remain after atomic rename")
        # The final file must be valid JSON.
        result = json.loads(self.routes_file.read_text())
        self.assertIsInstance(result, dict)


# ---------------------------------------------------------------------------
# 2. Notifier webhook security (notifier.py)
# ---------------------------------------------------------------------------

class TestResolveWebhookUrl(unittest.TestCase):
    """Test _resolve_webhook_url SSRF prevention."""

    @patch("notifier._socket.getaddrinfo")
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

    @patch("notifier._socket.getaddrinfo")
    def test_rejects_rfc1918_10(self, mock_getaddrinfo):
        """URL resolving to 10.0.0.0/8 is rejected."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("10.0.0.1", 443)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://internal.example.com/webhook")
        self.assertFalse(safe)

    @patch("notifier._socket.getaddrinfo")
    def test_rejects_rfc1918_172(self, mock_getaddrinfo):
        """URL resolving to 172.16.0.0/12 is rejected."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("172.16.0.1", 443)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://internal.example.com/webhook")
        self.assertFalse(safe)

    @patch("notifier._socket.getaddrinfo")
    def test_rejects_rfc1918_192(self, mock_getaddrinfo):
        """URL resolving to 192.168.0.0/16 is rejected."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.168.1.1", 443)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://internal.example.com/webhook")
        self.assertFalse(safe)

    @patch("notifier._socket.getaddrinfo")
    def test_rejects_localhost(self, mock_getaddrinfo):
        """URL resolving to 127.0.0.1 is rejected."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 80)),
        ]
        safe, _, _, _ = _resolve_webhook_url("http://localhost/webhook")
        self.assertFalse(safe)

    @patch("notifier._socket.getaddrinfo")
    def test_rejects_cgnat(self, mock_getaddrinfo):
        """URL resolving to CGNAT range 100.64.0.0/10 is rejected."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("100.64.0.1", 443)),
        ]
        safe, _, _, _ = _resolve_webhook_url("https://cgnat.example.com/webhook")
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
    @patch("notifier.urllib.request.urlopen")
    def test_uses_resolved_ip_in_url(self, mock_urlopen):
        """HTTP request URL uses the resolved IP, not the original hostname."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        data = b'{"test": true}'
        self.notifier._send_http_request(data, "93.184.216.34", "webhook.example.com", 443)

        # Verify the Request was created with the resolved IP in the URL.
        request_obj = mock_urlopen.call_args[0][0]
        self.assertIn("93.184.216.34", request_obj.full_url)
        self.assertNotIn("webhook.example.com", request_obj.full_url)
        # But the Host header must be the original hostname.
        self.assertEqual(request_obj.get_header("Host"), "webhook.example.com")


# ---------------------------------------------------------------------------
# 3. Signer addon (signer.py)
# ---------------------------------------------------------------------------

class TestSignerDisabled(unittest.TestCase):
    """Test signer behavior when cryptography is not available."""

    def setUp(self):
        # Save original module state.
        self._orig_enabled = signer._signing_enabled
        self._orig_key = signer._signing_key
        self._orig_entries = signer._batch_entries
        self._orig_start_time = signer._batch_start_time
        self._orig_start_mono = signer._batch_start_mono

    def tearDown(self):
        # Restore module state.
        signer._signing_enabled = self._orig_enabled
        signer._signing_key = self._orig_key
        signer._batch_entries = self._orig_entries
        signer._batch_start_time = self._orig_start_time
        signer._batch_start_mono = self._orig_start_mono

    def test_signing_disabled_when_no_cryptography(self):
        """_signing_enabled is False when cryptography import fails."""
        with patch.dict("sys.modules", {"cryptography": None,
                                         "cryptography.hazmat.primitives": None,
                                         "cryptography.hazmat.primitives.serialization": None,
                                         "cryptography.hazmat.primitives.asymmetric.ed25519": None}):
            result = signer._generate_keypair()
            self.assertFalse(result)

    def test_add_entry_skips_when_disabled(self):
        """add_entry returns immediately when signing is disabled (no crash)."""
        signer._signing_enabled = False
        signer._batch_entries = []

        signer.add_entry({"action": "test", "host": "example.com"})

        # Entry must not be added when signing is disabled.
        self.assertEqual(len(signer._batch_entries), 0)


class TestSignerBatching(unittest.TestCase):
    """Test entry batching behavior."""

    def setUp(self):
        self._orig_enabled = signer._signing_enabled
        self._orig_key = signer._signing_key
        self._orig_entries = signer._batch_entries
        self._orig_start_time = signer._batch_start_time
        self._orig_start_mono = signer._batch_start_mono
        self._orig_counter = signer._batch_counter

    def tearDown(self):
        signer._signing_enabled = self._orig_enabled
        signer._signing_key = self._orig_key
        signer._batch_entries = self._orig_entries
        signer._batch_start_time = self._orig_start_time
        signer._batch_start_mono = self._orig_start_mono
        signer._batch_counter = self._orig_counter

    def test_entries_accumulate_until_batch_size(self):
        """Entries accumulate in _batch_entries until BATCH_SIZE is reached."""
        signer._signing_enabled = True
        signer._batch_entries = []
        signer._batch_start_time = None
        signer._batch_start_mono = None

        with patch("signer._flush_batch") as mock_flush:
            # Add entries below BATCH_SIZE threshold.
            for i in range(signer.BATCH_SIZE - 1):
                signer.add_entry({"seq": i})

            mock_flush.assert_not_called()
            self.assertEqual(len(signer._batch_entries), signer.BATCH_SIZE - 1)

    def test_flush_triggered_at_batch_size(self):
        """Flush is triggered when BATCH_SIZE entries are accumulated."""
        signer._signing_enabled = True
        signer._batch_entries = []
        signer._batch_start_time = None
        signer._batch_start_mono = None

        with patch("signer._flush_batch") as mock_flush:
            for i in range(signer.BATCH_SIZE):
                signer.add_entry({"seq": i})

            mock_flush.assert_called_once()

    def test_uses_monotonic_for_batch_interval(self):
        """Batch interval check uses time.monotonic, not time.time."""
        signer._signing_enabled = True
        signer._batch_entries = []
        signer._batch_start_time = None
        signer._batch_start_mono = None

        with patch("signer.time.monotonic") as mock_monotonic, \
             patch("signer.time.time", return_value=1000.0):
            # First call sets _batch_start_mono.
            mock_monotonic.return_value = 100.0
            signer.add_entry({"seq": 0})
            self.assertEqual(signer._batch_start_mono, 100.0)

            # Second call: monotonic returns value within interval, no flush.
            mock_monotonic.return_value = 100.0 + signer.BATCH_INTERVAL - 1
            with patch("signer._flush_batch") as mock_flush:
                signer.add_entry({"seq": 1})
                mock_flush.assert_not_called()


class TestSignerSignData(unittest.TestCase):
    """Test _sign_data output."""

    def test_sign_data_produces_valid_base64(self):
        """_sign_data output can be base64-encoded to valid string."""
        # Create a mock signing key.
        mock_key = MagicMock()
        mock_key.sign.return_value = b"\x00\x01\x02\x03" * 16  # 64 bytes

        orig_key = signer._signing_key
        try:
            signer._signing_key = mock_key
            signature = signer._sign_data(b"test data")
            # Verify the signature can be base64-encoded.
            encoded = base64.b64encode(signature).decode()
            self.assertIsInstance(encoded, str)
            self.assertTrue(len(encoded) > 0)
            # Verify round-trip.
            decoded = base64.b64decode(encoded)
            self.assertEqual(decoded, signature)
        finally:
            signer._signing_key = orig_key

    def test_sign_data_raises_without_key(self):
        """_sign_data raises RuntimeError when key is not initialized."""
        orig_key = signer._signing_key
        try:
            signer._signing_key = None
            with self.assertRaises(RuntimeError):
                signer._sign_data(b"test data")
        finally:
            signer._signing_key = orig_key


if __name__ == "__main__":
    unittest.main()
