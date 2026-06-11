"""macOS-side launchd bridge for host_sockets.

Each declared host_socket needs a long-running process that listens on
the bridge socket and forwards to the operator's host_path. We use
`socat UNIX-LISTEN:bridge,fork UNIX-CONNECT:target` under launchd,
which gets us:
  - restart-on-crash (KeepAlive=true)
  - clean lifecycle via launchctl bootstrap/bootout
  - one process per declared socket — no shared daemon to debug

Tests here mock out launchctl invocations; integration against a real
launchd lives in tests/test_host_sockets_e2e.sh (gated on macOS).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from conftest import make_unix_socket as _real_socket


def _socket_entry(name="pg", host_path="/tmp/postgres.sock"):
    return {
        "name": name,
        "host_path": host_path,
        "mount_point": f"/run/host/{name}.sock",
        "mode": "rw",
    }


class TestPlistGeneration(unittest.TestCase):
    def test_contains_required_keys(self):
        from brig.cell.host_sockets_bridge import generate_plist
        xml = generate_plist(
            label="com.brig.host-socket.alice.pg",
            socat_bin="/opt/homebrew/bin/socat",
            bridge_path="/Users/x/.brig/state/system/host-sockets/alice/pg.sock",
            target_path="/tmp/postgres.sock",
        )
        for needle in (
            "<key>Label</key>",
            "com.brig.host-socket.alice.pg",
            "<key>KeepAlive</key>",
            "<key>ProgramArguments</key>",
            "UNIX-LISTEN:",
            "/Users/x/.brig/state/system/host-sockets/alice/pg.sock",
            "UNIX-CONNECT:/tmp/postgres.sock",
        ):
            self.assertIn(needle, xml, f"missing: {needle}")

    def test_xml_is_well_formed(self):
        import xml.etree.ElementTree as ET
        from brig.cell.host_sockets_bridge import generate_plist
        xml = generate_plist(
            label="com.brig.host-socket.x.y",
            socat_bin="/opt/homebrew/bin/socat",
            bridge_path="/tmp/b.sock",
            target_path="/tmp/t.sock",
        )
        # Strip the DOCTYPE so ET can parse it.
        stripped = "\n".join(
            line for line in xml.splitlines() if not line.startswith("<!DOCTYPE")
        )
        try:
            ET.fromstring(stripped)
        except ET.ParseError as e:
            self.fail(f"plist not well-formed: {e}\n{xml}")


class TestStartBridges(unittest.TestCase):
    def test_socat_not_installed_raises(self):
        from brig.cell.host_sockets_bridge import start_cell_bridges
        from brig.errors import BrigError
        with patch("brig.cell.host_sockets_bridge._find_socat", return_value=None):
            with self.assertRaises(BrigError) as ctx:
                start_cell_bridges("alice", [_socket_entry()])
        self.assertIn("socat", str(ctx.exception).lower())
        # BrigError.suggestion is separate from the message — check both.
        suggestion = (ctx.exception.suggestion or "").lower()
        self.assertIn("brew install socat", suggestion)

    def test_target_must_exist_and_be_socket(self):
        from brig.cell.host_sockets_bridge import start_cell_bridges
        from brig.errors import BrigError
        with patch("brig.cell.host_sockets_bridge._find_socat",
                   return_value="/opt/homebrew/bin/socat"):
            with self.assertRaises(BrigError) as ctx:
                start_cell_bridges("alice", [_socket_entry(
                    host_path="/tmp/does-not-exist-xyz.sock"
                )])
        msg = str(ctx.exception).lower()
        self.assertTrue("not found" in msg or "no such" in msg, ctx.exception)

    def test_target_is_regular_file_rejected(self):
        from brig.cell.host_sockets_bridge import start_cell_bridges
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            regular = Path(td) / "not-a-sock"
            regular.write_text("x")
            with patch("brig.cell.host_sockets_bridge._find_socat",
                       return_value="/opt/homebrew/bin/socat"):
                with self.assertRaises(BrigError) as ctx:
                    start_cell_bridges("alice", [_socket_entry(
                        host_path=str(regular)
                    )])
            self.assertIn("socket", str(ctx.exception).lower())

    def test_validate_target_returns_canonical_realpath(self):
        from brig.cell.host_sockets_bridge import _validate_target
        import os
        with tempfile.TemporaryDirectory() as td:
            real_dir = Path(td) / "realdir"
            real_dir.mkdir()
            sock = _real_socket(real_dir, "pg.sock")
            link_dir = Path(td) / "linkdir"
            link_dir.symlink_to(real_dir)
            # Access via the symlinked PARENT (leaf is not a symlink, so it
            # passes the leaf-symlink ban) — the returned value must be the
            # canonical realpath with the parent symlink collapsed.
            returned = _validate_target(str(link_dir / "pg.sock"))
            self.assertEqual(returned, os.path.realpath(str(sock)))
            self.assertNotIn("linkdir", returned)

    def test_validate_target_rejects_leaf_symlink(self):
        """A symlink AT the target path (not just a parent) is refused —
        the lstat S_ISLNK ban, distinct from the realpath parent-collapse."""
        from brig.cell.host_sockets_bridge import _validate_target
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            sock = _real_socket(Path(td), "real.sock")
            link = Path(td) / "link.sock"
            link.symlink_to(sock)
            with self.assertRaises(BrigError) as ctx:
                _validate_target(str(link))
            self.assertIn("symlink", str(ctx.exception).lower())

    def test_plist_freezes_value_validate_target_returned(self):
        """The plist must bake the EXACT value _validate_target returned, not a
        realpath re-derived at write time — that's the validate→freeze TOCTOU
        the change closes. We make _validate_target return a sentinel and a
        write-time recompute (the old behavior) return something different; the
        plist must contain the sentinel and never the recomputed value."""
        from brig.cell.host_sockets_bridge import start_cell_bridges
        FROZEN = "/validated/at/check/time.sock"
        SWAPPED = "/swapped/after/validation.sock"
        with tempfile.TemporaryDirectory() as td:
            plist_dir = Path(td) / "LaunchAgents"
            bridge_root = Path(td) / "host-sockets"
            mock_run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
            with patch("brig.cell.host_sockets_bridge._find_socat",
                       return_value="/opt/homebrew/bin/socat"), \
                 patch("brig.cell.host_sockets_bridge._validate_target",
                       return_value=FROZEN) as vt, \
                 patch("os.path.realpath", return_value=SWAPPED), \
                 patch("brig.cell.host_sockets_bridge._launchctl", mock_run), \
                 patch("brig.cell.host_sockets_bridge.PLIST_DIR", plist_dir), \
                 patch("brig.cell.host_sockets_bridge._bridge_dir_for_cell",
                       return_value=bridge_root / "alice"), \
                 patch("brig.cell.host_sockets_bridge._bridge_path",
                       return_value=bridge_root / "alice" / "pg.sock"), \
                 patch("brig.cell.host_sockets_bridge._wait_for_socket",
                       return_value=True):
                start_cell_bridges("alice", [_socket_entry(
                    host_path="/tmp/whatever.sock"
                )])
            vt.assert_called_once_with("/tmp/whatever.sock")
            plist = (plist_dir / "com.brig.host-socket.alice.pg.plist").read_text()
            self.assertIn(FROZEN, plist)        # the validated value is frozen
            self.assertNotIn(SWAPPED, plist)    # NOT a write-time recompute

    def test_engine_socket_target_still_blocked(self):
        """Defense in depth — spec-layer denylist already rejects, but
        if someone bypasses spec validation (SDK direct call), the
        bridge must also refuse."""
        from brig.cell.host_sockets_bridge import start_cell_bridges
        from brig.errors import BrigError
        with patch("brig.cell.host_sockets_bridge._find_socat",
                   return_value="/opt/homebrew/bin/socat"):
            with self.assertRaises(BrigError) as ctx:
                start_cell_bridges("alice", [_socket_entry(
                    host_path="/var/run/docker.sock"
                )])
        self.assertIn("engine", str(ctx.exception).lower())

    def test_writes_plist_and_calls_launchctl(self):
        from brig.cell.host_sockets_bridge import start_cell_bridges
        with tempfile.TemporaryDirectory() as td:
            target = _real_socket(Path(td), "pg.sock")
            plist_dir = Path(td) / "LaunchAgents"
            bridge_root = Path(td) / "host-sockets"
            mock_run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
            with patch("brig.cell.host_sockets_bridge._find_socat",
                       return_value="/opt/homebrew/bin/socat"), \
                 patch("brig.cell.host_sockets_bridge._launchctl",
                       mock_run), \
                 patch("brig.cell.host_sockets_bridge.PLIST_DIR", plist_dir), \
                 patch("brig.config.HostPaths.HOST_SOCKETS_DIR", bridge_root), \
                 patch("brig.cell.host_sockets_bridge._bridge_dir_for_cell",
                       return_value=bridge_root / "alice"), \
                 patch("brig.cell.host_sockets_bridge._bridge_path",
                       return_value=bridge_root / "alice" / "pg.sock"), \
                 patch("brig.cell.host_sockets_bridge._wait_for_socket",
                       return_value=True):
                start_cell_bridges("alice", [_socket_entry(
                    host_path=str(target)
                )])
            # Plist file written, and it wires socat from the bridge socket
            # (cell side) to the host target (so a wrong-target regression fails).
            plist = plist_dir / "com.brig.host-socket.alice.pg.plist"
            self.assertTrue(plist.exists())
            content = plist.read_text()
            self.assertIn(str(target), content)                            # CONNECT: host socket
            self.assertIn(str(bridge_root / "alice" / "pg.sock"), content)  # LISTEN: cell-side bridge
            self.assertIn("com.brig.host-socket.alice.pg", content)        # label
            # launchctl was invoked with this plist (the load).
            self.assertTrue(
                any(str(plist) in str(call) for call in mock_run.call_args_list),
                "launchctl was not invoked with the plist path",
            )


class TestStopBridges(unittest.TestCase):
    def test_removes_plist_and_calls_launchctl_unload(self):
        from brig.cell.host_sockets_bridge import stop_cell_bridges
        with tempfile.TemporaryDirectory() as td:
            plist_dir = Path(td) / "LaunchAgents"
            plist_dir.mkdir()
            plist = plist_dir / "com.brig.host-socket.alice.pg.plist"
            plist.write_text("<plist/>")
            mock_run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
            with patch("brig.cell.host_sockets_bridge._launchctl",
                       mock_run), \
                 patch("brig.cell.host_sockets_bridge.PLIST_DIR", plist_dir):
                stop_cell_bridges("alice")
            self.assertFalse(plist.exists())
            self.assertTrue(mock_run.called)

    def test_idempotent_when_no_bridges(self):
        """Stop on a cell that never had bridges shouldn't raise."""
        from brig.cell.host_sockets_bridge import stop_cell_bridges
        with tempfile.TemporaryDirectory() as td:
            plist_dir = Path(td) / "LaunchAgents"
            plist_dir.mkdir()
            with patch("brig.cell.host_sockets_bridge.PLIST_DIR", plist_dir):
                stop_cell_bridges("never-existed")
            # No exception = pass.


if __name__ == "__main__":
    unittest.main()
