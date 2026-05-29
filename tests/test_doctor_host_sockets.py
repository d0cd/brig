"""`brig system doctor` enumerates loaded launchd host_socket bridges
and reports per-bridge socket presence. This catches "plist loaded but
socat crashed" partial-up states before they show up as cryptic
cell-start failures.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class TestDoctorHostSocketCheck(unittest.TestCase):
    def test_no_plists_no_op(self):
        from brig.commands.system_cmd import _check_host_socket_bridges
        calls = []
        def check(label, ok, **kw): calls.append((label, ok))
        with tempfile.TemporaryDirectory() as td:
            with patch("brig.cell.host_sockets_bridge.PLIST_DIR", Path(td)):
                _check_host_socket_bridges(check)
        self.assertEqual(calls, [])

    def test_plist_without_bridge_socket_reports_fail(self):
        from brig.commands.system_cmd import _check_host_socket_bridges
        calls = []
        def check(label, ok, **kw): calls.append((label, ok))
        with tempfile.TemporaryDirectory() as td:
            plist_dir = Path(td) / "agents"
            plist_dir.mkdir()
            (plist_dir / "com.brig.host-socket.alice.pg.plist").write_text("x")
            sockets_dir = Path(td) / "host-sockets"
            with patch("brig.cell.host_sockets_bridge.PLIST_DIR", plist_dir), \
                 patch("brig.config.HostPaths.HOST_SOCKETS_DIR", sockets_dir):
                _check_host_socket_bridges(check)
        labels = {label: ok for label, ok in calls}
        # socat check fires
        self.assertIn("socat installed (host_socket bridges)", labels)
        # bridge socket check fires + fails (bridge file absent)
        self.assertIn("bridge socket: alice/pg", labels)
        self.assertFalse(labels["bridge socket: alice/pg"])

    def test_plist_with_bridge_socket_passes(self):
        from brig.commands.system_cmd import _check_host_socket_bridges
        calls = []
        def check(label, ok, **kw): calls.append((label, ok))
        with tempfile.TemporaryDirectory() as td:
            plist_dir = Path(td) / "agents"
            plist_dir.mkdir()
            (plist_dir / "com.brig.host-socket.alice.pg.plist").write_text("x")
            sockets_dir = Path(td) / "host-sockets"
            cell_dir = sockets_dir / "alice"
            cell_dir.mkdir(parents=True)
            (cell_dir / "pg.sock").touch()
            with patch("brig.cell.host_sockets_bridge.PLIST_DIR", plist_dir), \
                 patch("brig.config.HostPaths.HOST_SOCKETS_DIR", sockets_dir):
                _check_host_socket_bridges(check)
        labels = {label: ok for label, ok in calls}
        self.assertTrue(labels.get("bridge socket: alice/pg"))


if __name__ == "__main__":
    unittest.main()
