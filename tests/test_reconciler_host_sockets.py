"""Reconciler emits correct `--volume` args for host_sockets, and
runs the TOCTOU defense at command-build time.

Static spec validation runs at parse time (test_host_sockets_spec.py).
The runtime check here is the second layer: at cell start, re-resolve
host_path to a real path, confirm it's still S_ISSOCK and unchanged,
then emit the bind mount. If the source isn't present in the VM
(launchd bridge isn't up), refuse cell start with a clear error.

These tests exercise build_run_command directly — no podman, no VM.
"""

from __future__ import annotations

import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _sock(td: Path, name: str = "svc.sock") -> Path:
    p = td / name
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(p))
    s.close()
    return p


def _spec(host_sockets=None, **kw):
    from brig.cell.spec import CellSpec
    defaults = dict(name="c", image="alpine", host_sockets=host_sockets or [])
    defaults.update(kw)
    return CellSpec(**defaults)


class TestNoHostSocketsBackwardCompat(unittest.TestCase):
    """Cells with no host_sockets get byte-identical podman commands."""

    def test_empty_list_emits_no_host_socket_volume(self):
        from brig.cell.reconciler import build_run_command
        cmd = build_run_command(_spec(), proxy_ip="10.0.0.1")
        joined = " ".join(cmd)
        self.assertNotIn("/run/host/", joined)


class TestHostSocketVolumeEmitted(unittest.TestCase):
    """When host_sockets are declared and the bridge socket exists,
    a --volume arg is emitted with the right shape."""

    def test_volume_emitted_with_correct_shape(self):
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            bridge_dir = Path(td)
            _sock(bridge_dir, "pg.sock")
            with patch("brig.config.VMPaths.HOST_SOCKETS_DIR", bridge_dir):
                spec = _spec(host_sockets=[{
                    "name": "pg", "host_path": "/tmp/postgres.sock",
                    "mount_point": "/run/host/pg.sock", "mode": "rw",
                }])
                cmd = build_run_command(spec, proxy_ip="10.0.0.1")
                joined = " ".join(cmd)
                self.assertIn(str(bridge_dir / "pg.sock"), joined)
                self.assertIn("/run/host/pg.sock", joined)
                self.assertIn(":rw", joined)

    def test_default_mode_is_ro(self):
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            bridge_dir = Path(td)
            _sock(bridge_dir, "pg.sock")
            with patch("brig.config.VMPaths.HOST_SOCKETS_DIR", bridge_dir):
                spec = _spec(host_sockets=[{
                    "name": "pg", "host_path": "/tmp/postgres.sock",
                    "mount_point": "/run/host/pg.sock",
                }])
                cmd = build_run_command(spec, proxy_ip="10.0.0.1")
                joined = " ".join(cmd)
                # Find the host-socket volume arg specifically.
                self.assertIn("/run/host/pg.sock:ro", joined)


class TestRuntimeTOCTOUDefense(unittest.TestCase):
    """The runtime check runs at command-build time (right before podman
    exec). It defends against the bridge socket being missing, replaced
    with a non-socket, or symlinked away between yaml parse and start."""

    def test_missing_bridge_socket_refuses_start(self):
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            bridge_dir = Path(td)  # empty — no socket file
            with patch("brig.config.VMPaths.HOST_SOCKETS_DIR", bridge_dir):
                spec = _spec(host_sockets=[{
                    "name": "pg", "host_path": "/tmp/postgres.sock",
                    "mount_point": "/run/host/pg.sock",
                }])
                with self.assertRaises(Exception) as ctx:
                    build_run_command(spec, proxy_ip="10.0.0.1")
                msg = str(ctx.exception).lower()
                self.assertTrue(
                    "pg" in msg and ("not" in msg or "missing" in msg),
                    f"unexpected error: {ctx.exception}",
                )

    def test_bridge_path_is_regular_file_rejected(self):
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            bridge_dir = Path(td)
            (bridge_dir / "pg.sock").write_text("not a socket")
            with patch("brig.config.VMPaths.HOST_SOCKETS_DIR", bridge_dir):
                spec = _spec(host_sockets=[{
                    "name": "pg", "host_path": "/tmp/postgres.sock",
                    "mount_point": "/run/host/pg.sock",
                }])
                with self.assertRaises(Exception) as ctx:
                    build_run_command(spec, proxy_ip="10.0.0.1")
                self.assertIn("socket", str(ctx.exception).lower())

    def test_bridge_path_is_symlink_rejected(self):
        """Symlinks at the bridge path could redirect to anywhere on the
        host. Reject — the launchd bridge writes a real socket file."""
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            bridge_dir = Path(td)
            target = _sock(bridge_dir, "real.sock")
            link = bridge_dir / "pg.sock"
            os.symlink(target, link)
            with patch("brig.config.VMPaths.HOST_SOCKETS_DIR", bridge_dir):
                spec = _spec(host_sockets=[{
                    "name": "pg", "host_path": "/tmp/postgres.sock",
                    "mount_point": "/run/host/pg.sock",
                }])
                with self.assertRaises(Exception) as ctx:
                    build_run_command(spec, proxy_ip="10.0.0.1")
                msg = str(ctx.exception).lower()
                self.assertTrue("symlink" in msg or "link" in msg, ctx.exception)


class TestMultipleSockets(unittest.TestCase):
    def test_two_sockets_two_volume_args(self):
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            bridge_dir = Path(td)
            _sock(bridge_dir, "pg.sock")
            _sock(bridge_dir, "redis.sock")
            with patch("brig.config.VMPaths.HOST_SOCKETS_DIR", bridge_dir):
                spec = _spec(host_sockets=[
                    {"name": "pg", "host_path": "/tmp/pg.sock",
                     "mount_point": "/run/host/pg.sock", "mode": "rw"},
                    {"name": "redis", "host_path": "/tmp/redis.sock",
                     "mount_point": "/run/host/redis.sock"},
                ])
                cmd = build_run_command(spec, proxy_ip="10.0.0.1")
                joined = " ".join(cmd)
                self.assertIn("/run/host/pg.sock:rw", joined)
                self.assertIn("/run/host/redis.sock:ro", joined)


if __name__ == "__main__":
    unittest.main()
