"""Passthrough flows must carry the real cell label in metrics + logs.

tcp_start in enforce returns early for passthrough flows before it would set
flow.metadata["cell"], so the cell is stamped on the client connection's
metadata in tls_clienthello and read back by otel_export's tcp_end. Without
this every passthrough connection/byte/duration metric and audit line is
attributed to cell="unknown", collapsing all tenants' opaque-tunnel traffic.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import mitmproxy.ctx

if not hasattr(mitmproxy.ctx, "log"):
    mitmproxy.ctx.log = MagicMock()

_ADDONS = str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons")
if _ADDONS not in sys.path:
    sys.path.insert(0, _ADDONS)


class TestEnforceStampsCellOnPassthrough(unittest.TestCase):
    def _enforcer(self):
        from enforce import PolicyEnforcer
        from _policy import Policy
        enf = PolicyEnforcer()
        enf.cell_policies["codex"] = Policy(
            allow=["chatgpt.com"], tls_passthrough=["chatgpt.com"],
        )
        enf.subnets = type("S", (), {
            "get_cell_name": staticmethod(lambda ip: "codex"),
        })()
        return enf

    def test_cell_stamped_on_client_metadata(self):
        enf = self._enforcer()
        client = MagicMock()
        client.peername = ("10.60.1.5", 54321)
        client.metadata = {}
        server = SimpleNamespace(address=("chatgpt.com", 443))
        context = SimpleNamespace(client=client, server=server)
        hello = SimpleNamespace(sni="chatgpt.com")
        data = SimpleNamespace(client_hello=hello, context=context)

        with patch("socket.getaddrinfo",
                   return_value=[(2, 1, 6, "", ("104.18.0.1", 0))]):
            enf.tls_clienthello(data)

        # Passthrough engaged via ignore_connection (the switch mitmproxy reads).
        self.assertTrue(getattr(data, "ignore_connection", False))
        self.assertEqual(client.metadata.get("cell"), "codex")
        self.assertEqual(client.metadata.get("passthrough_sni"), "chatgpt.com")


# NOTE: there is intentionally NO test exercising otel_export.tcp_end for
# passthrough. Passthrough engages via data.ignore_connection, which makes
# mitmproxy build an ignored TCPLayer (flow=None) so tcp_start/message/end
# never fire for passthrough — a test that called tcp_end directly would pass
# against a code path that cannot run in production (false confidence). The
# real passthrough audit is the connection-level PASSTHROUGH log line, and the
# enforce-side engagement is covered by TestEnforceStampsCellOnPassthrough
# above and tests/test_passthrough_tls.py.


if __name__ == "__main__":
    unittest.main()
