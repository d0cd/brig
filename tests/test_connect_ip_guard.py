"""Connect-time destination-IP guard (enforce.server_connect).

Closes the SSRF / DNS-rebinding gap on the egress paths the response-only
check missed: the MITM request path (request forwarded before the
responseheaders IP check) and raw-TCP passthrough tunnels (no HTTP response,
so responseheaders never fires). The guard resolves the destination before
the connection is used and refuses it via data.server.error if it resolves
into a blocked range, while exempting warden's own internal routing
(host_service rewrite to the host IP, ingress reverse-proxy to a cell IP).

These exercise the hook logic against real mitmproxy data classes. Whether
mitmproxy invokes server_connect for passthrough flows and what address it
carries is covered by E2E against the pinned image.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("mitmproxy")

import mitmproxy.ctx  # noqa: E402

if not hasattr(mitmproxy.ctx, "log"):
    mitmproxy.ctx.log = MagicMock()

_ADDONS = str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons")
if _ADDONS not in sys.path:
    sys.path.insert(0, _ADDONS)

from mitmproxy import connection  # noqa: E402
from mitmproxy.proxy import server_hooks  # noqa: E402


def _enforcer(host_ip: str = "192.168.5.2"):
    from enforce import PolicyEnforcer
    enf = PolicyEnforcer()
    enf._host_ip = host_ip
    enf.subnets = type("S", (), {"get_cell_name": staticmethod(lambda ip: "codex")})()
    return enf


def _data(dest_host: str, listen_port: int = 8080):
    server = connection.Server(address=(dest_host, 443))
    client = connection.Client(
        peername=("10.60.1.5", 54321),
        sockname=("10.60.1.1", listen_port),
        timestamp_start=0.0,
    )
    return server_hooks.ServerConnectionHookData(server=server, client=client)


class TestConnectIpGuard(unittest.TestCase):

    def test_public_resolution_allowed(self):
        enf = _enforcer()
        data = _data("example.com")
        with patch("socket.getaddrinfo",
                   return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            enf.server_connect(data)
        self.assertIsNone(data.server.error)

    def test_metadata_ip_resolution_blocked(self):
        enf = _enforcer()
        data = _data("rebind.evil.example")
        with patch("socket.getaddrinfo",
                   return_value=[(2, 1, 6, "", ("169.254.169.254", 0))]):
            enf.server_connect(data)
        self.assertIsNotNone(data.server.error)

    def test_rfc1918_resolution_blocked(self):
        enf = _enforcer()
        data = _data("internal.example")
        with patch("socket.getaddrinfo",
                   return_value=[(2, 1, 6, "", ("10.0.0.5", 0))]):
            enf.server_connect(data)
        self.assertIsNotNone(data.server.error)

    def test_split_answer_with_one_internal_is_refused(self):
        # A resolution set that mixes a public and an internal answer is
        # refused outright (rebinding-resistant).
        enf = _enforcer()
        data = _data("mixed.example")
        with patch("socket.getaddrinfo", return_value=[
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]):
            enf.server_connect(data)
        self.assertIsNotNone(data.server.error)

    def test_literal_blocked_ip_destination_refused(self):
        enf = _enforcer()
        data = _data("169.254.169.254")
        enf.server_connect(data)  # no DNS — literal IP validated directly
        self.assertIsNotNone(data.server.error)

    def test_host_service_target_exempt(self):
        # host_service rewrites point at the (internal) macOS host IP; allowed.
        enf = _enforcer(host_ip="192.168.5.2")
        data = _data("192.168.5.2")
        enf.server_connect(data)
        self.assertIsNone(data.server.error)

    def test_ingress_flow_exempt(self):
        # Ingress reverse-proxy flows arrive on :8443; warden→cell is expected
        # even though the cell IP is internal.
        enf = _enforcer()
        data = _data("10.60.2.7", listen_port=8443)
        enf.server_connect(data)
        self.assertIsNone(data.server.error)

    def test_unresolvable_host_fails_closed(self):
        import socket as _socket
        enf = _enforcer()
        data = _data("nope.invalid")
        with patch("socket.getaddrinfo", side_effect=_socket.gaierror("nxdomain")):
            enf.server_connect(data)
        self.assertIsNotNone(data.server.error)

    def test_tcp_host_service_reverse_upstream_exempt(self):
        # A TCP host_service flow dials host.lima.internal:<port>, which
        # resolves to the (internal) Lima host IP. It must NOT be blocked when
        # the requesting cell declared that port as a TCP host_service.
        from _policy import Policy
        enf = _enforcer()
        enf.cell_policies["codex"] = Policy(
            allow=[], host_services=[{"name": "db", "port": 5432, "protocol": "tcp"}],
        )
        data = _data("host.lima.internal")
        data.server.address = ("host.lima.internal", 5432)
        with patch("socket.getaddrinfo",
                   return_value=[(2, 1, 6, "", ("192.168.5.2", 0))]):
            enf.server_connect(data)
        self.assertIsNone(data.server.error)

    def test_host_lima_internal_blocked_when_not_a_declared_tcp_service(self):
        # Same upstream host but the cell did NOT declare port 9999 — the
        # exemption must not fire, and the internal resolution is blocked.
        from _policy import Policy
        enf = _enforcer()
        enf.cell_policies["codex"] = Policy(
            allow=["host.lima.internal"],
            host_services=[{"name": "db", "port": 5432, "protocol": "tcp"}],
        )
        data = _data("host.lima.internal")
        data.server.address = ("host.lima.internal", 9999)
        with patch("socket.getaddrinfo",
                   return_value=[(2, 1, 6, "", ("192.168.5.2", 0))]):
            enf.server_connect(data)
        self.assertIsNotNone(data.server.error)


if __name__ == "__main__":
    unittest.main()
