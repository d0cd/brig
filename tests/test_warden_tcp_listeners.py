"""TCP host_services Phase 2 — warden binds `--mode reverse:tcp`
listeners per declared port, and enforce.py's tcp_start hook gates
per-cell access via the cell's per-cell policy.

Covers:
  - _collect_tcp_host_service_ports walks POLICY_DIR, returns sorted
    unique ports, excludes warden's reserved ones
  - Spec validator rejects TCP on reserved ports
  - tcp_start access control: allows declared ports, denies others,
    skips passthrough flows
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestCollectTcpPorts(unittest.TestCase):
    """warden.proxy._collect_tcp_host_service_ports() walks the policy
    dir and returns the union of TCP ports cells have declared.
    Sorted + deduplicated; reserved ports excluded."""

    def _collect(self, policies: dict):
        from warden.proxy import _collect_tcp_host_service_ports
        with tempfile.TemporaryDirectory() as td:
            policy_dir = Path(td)
            for cell_name, content in policies.items():
                (policy_dir / f"{cell_name}.json").write_text(
                    json.dumps(content)
                )
            with patch("brig.config.HostPaths.POLICY_DIR", policy_dir):
                return _collect_tcp_host_service_ports()

    def test_no_policies_returns_empty(self):
        self.assertEqual(self._collect({}), [])

    def test_collects_tcp_ports_only(self):
        ports = self._collect({"alice": {
            "host_services": [
                {"name": "api", "port": 4000},                     # http
                {"name": "db", "port": 5432, "protocol": "tcp"},
                {"name": "redis", "port": 6379, "protocol": "tcp"},
            ],
        }})
        self.assertEqual(ports, [5432, 6379])

    def test_deduplicates_across_cells(self):
        """Two cells declaring the same TCP port share one listener."""
        ports = self._collect({
            "alice": {"host_services": [
                {"name": "db", "port": 5432, "protocol": "tcp"},
            ]},
            "bob": {"host_services": [
                {"name": "pg", "port": 5432, "protocol": "tcp"},
            ]},
        })
        self.assertEqual(ports, [5432])

    def test_excludes_warden_reserved_ports(self):
        """Defense in depth: a tampered policy file with port 8080
        must not poison warden's startup (validator rejects, but
        we re-check at collect time per invariant 4)."""
        ports = self._collect({"alice": {
            "host_services": [
                {"name": "bad1", "port": 8080, "protocol": "tcp"},
                {"name": "bad2", "port": 8443, "protocol": "tcp"},
                {"name": "ok", "port": 5432, "protocol": "tcp"},
            ],
        }})
        self.assertEqual(ports, [5432])

    def test_skips_malformed_entries(self):
        ports = self._collect({"alice": {
            "host_services": [
                {"protocol": "tcp"},                # missing port
                "string_not_dict",
                {"name": "x", "port": "5432", "protocol": "tcp"},  # str
                {"name": "ok", "port": 5432, "protocol": "tcp"},
            ],
        }})
        self.assertEqual(ports, [5432])

    def test_skips_unreadable_policy_files(self):
        from warden.proxy import _collect_tcp_host_service_ports
        with tempfile.TemporaryDirectory() as td:
            policy_dir = Path(td)
            (policy_dir / "bad.json").write_text("not json{{{")
            (policy_dir / "good.json").write_text(json.dumps({
                "host_services": [
                    {"name": "db", "port": 5432, "protocol": "tcp"},
                ],
            }))
            with patch("brig.config.HostPaths.POLICY_DIR", policy_dir):
                self.assertEqual(
                    _collect_tcp_host_service_ports(), [5432],
                )


class TestSpecRejectsReservedPorts(unittest.TestCase):
    def test_reject_tcp_on_8080(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            "name": "alice", "image": "alpine",
            "host_services": [
                {"name": "x", "port": 8080, "protocol": "tcp"},
            ],
        })
        self.assertTrue(any("reserved by warden" in e for e in errs), errs)

    def test_reject_tcp_on_8443(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            "name": "alice", "image": "alpine",
            "host_services": [
                {"name": "x", "port": 8443, "protocol": "tcp"},
            ],
        })
        self.assertTrue(any("reserved by warden" in e for e in errs), errs)

    def test_http_on_8080_still_accepted(self):
        """8080 is reserved for TCP only — operators may legitimately
        forward HTTP from a cell to a host service running on host:8080."""
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            "name": "alice", "image": "alpine",
            "host_services": [
                {"name": "x", "port": 8080},  # HTTP (default)
            ],
        })
        self.assertEqual(errs, [])


def _enforcer():
    for _mod in (
        "mitmproxy", "mitmproxy.http", "mitmproxy.ctx",
        "mitmproxy.connection",
    ):
        sys.modules.setdefault(_mod, MagicMock())
    sys.path.insert(0, "src/brig/warden_addons")
    try:
        from enforce import PolicyEnforcer
        from _policy import Policy
    finally:
        sys.path.pop(0)
    enf = PolicyEnforcer()
    # Wire a single cell with a TCP host_service for db on 5432.
    enf.cell_policies["alice"] = Policy(
        host_services=[{"name": "db", "port": 5432, "protocol": "tcp"}],
    )
    enf.subnets = type("S", (), {
        "get_cell_name": staticmethod(
            lambda ip: "alice" if ip == "10.60.1.5" else None,
        ),
    })()
    return enf


def _make_tcp_flow(peer_ip, listen_port, *, passthrough=False):
    flow = MagicMock()
    flow.client_conn.peername = (peer_ip, 54321)
    flow.client_conn.metadata = (
        {"tls_mode": "passthrough"} if passthrough else {}
    )
    flow.server_conn.address = ("host.lima.internal", listen_port)
    flow.metadata = {}
    return flow


class TestTcpStartAccessControl(unittest.TestCase):
    def test_declared_port_for_known_cell_allowed(self):
        enf = _enforcer()
        flow = _make_tcp_flow("10.60.1.5", 5432)
        enf.tcp_start(flow)
        self.assertFalse(flow.metadata.get("blocked"))
        self.assertEqual(flow.metadata.get("cell"), "alice")
        self.assertEqual(flow.metadata.get("host_service"), "db")
        self.assertEqual(flow.metadata.get("host_service_protocol"), "tcp")

    def test_undeclared_port_blocked(self):
        enf = _enforcer()
        # alice declared port 5432; trying 6379 must fail.
        flow = _make_tcp_flow("10.60.1.5", 6379)
        enf.tcp_start(flow)
        flow.kill.assert_called()
        self.assertTrue(flow.metadata.get("blocked"))
        self.assertIn("did not declare", flow.metadata.get("block_reason"))

    def test_unknown_cell_blocked(self):
        enf = _enforcer()
        # No cell mapping for 10.60.2.5.
        flow = _make_tcp_flow("10.60.2.5", 5432)
        enf.tcp_start(flow)
        flow.kill.assert_called()
        self.assertIn(
            "no per-cell policy", flow.metadata.get("block_reason"),
        )

    def test_passthrough_flow_skipped(self):
        """TLS passthrough flows (invariant 11) get tagged in
        tls_clienthello; tcp_start must NOT re-gate them as
        host_service flows — different mechanism."""
        enf = _enforcer()
        flow = _make_tcp_flow("10.60.1.5", 443, passthrough=True)
        enf.tcp_start(flow)
        flow.kill.assert_not_called()
        self.assertFalse(flow.metadata.get("blocked"))

    def test_no_peer_ip_blocked(self):
        enf = _enforcer()
        flow = MagicMock()
        flow.client_conn.peername = None
        flow.client_conn.metadata = {}
        flow.server_conn.address = ("host.lima.internal", 5432)
        flow.metadata = {}
        enf.tcp_start(flow)
        flow.kill.assert_called()


if __name__ == "__main__":
    unittest.main()
