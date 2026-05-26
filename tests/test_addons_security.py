"""Tests for security-critical mitmproxy addon behavior.

Covers:
  - Webhook URL SSRF prevention (notifier.py)
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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

from notifier import _resolve_webhook_url, Notifier  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
