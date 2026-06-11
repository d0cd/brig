"""Reconciler emits correct `--volume` args for host_sockets, and
runs the TOCTOU defense at command-build time.

Static spec validation runs at parse time (test_host_sockets_spec.py).
The runtime check here is the second layer: at cell start, re-resolve
the bridge socket to a real path, confirm it's still S_ISSOCK and not a
symlink, then emit the bind mount. If the source isn't present, refuse.

CRITICAL host/VM split (this code runs on the macOS host): validation
must `lstat` the HOST path (`HostPaths.HOST_SOCKETS_DIR`, the same inode
shared into the VM via virtio-fs), while the `-v` mount SOURCE must be
the VM-namespace path (`VMPaths.HOST_SOCKETS_DIR`, what podman-in-VM
sees). These tests patch both to distinct dirs to prove that split.

These tests exercise build_run_command directly — no podman, no VM.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from conftest import make_unix_socket as _sock

# A VM-namespace path distinct from any host tempdir, so a test that
# asserts the mount source proves it used VMPaths, not HostPaths.
_VM_ROOT = Path("/state/system/host-sockets")


def _spec(host_sockets=None, **kw):
    from brig.cell.spec import CellSpec
    defaults = dict(name="c", image="alpine", host_sockets=host_sockets or [])
    defaults.update(kw)
    return CellSpec(**defaults)


def _patch_paths(host_root: Path):
    """Patch the HOST validation dir to host_root and the VM mount dir to a
    fixed distinct path."""
    return (
        patch("brig.config.HostPaths.HOST_SOCKETS_DIR", host_root),
        patch("brig.config.VMPaths.HOST_SOCKETS_DIR", _VM_ROOT),
    )


class TestNoHostSocketsBackwardCompat(unittest.TestCase):
    """Cells with no host_sockets get byte-identical podman commands."""

    def test_empty_list_emits_no_host_socket_volume(self):
        from brig.cell.reconciler import build_run_command
        cmd = build_run_command(_spec(), proxy_ip="10.0.0.1")
        self.assertNotIn("/run/host/", " ".join(cmd))


class TestHostSocketVolumeEmitted(unittest.TestCase):
    """When the bridge socket exists at the HOST path, a --volume arg is
    emitted whose SOURCE is the VM path."""

    def test_validates_host_path_mounts_vm_path(self):
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            host_root = Path(td)
            (host_root / "c").mkdir()
            _sock(host_root / "c", "pg.sock")
            p1, p2 = _patch_paths(host_root)
            with p1, p2:
                spec = _spec(host_sockets=[{
                    "name": "pg", "host_path": "/tmp/postgres.sock",
                    "mount_point": "/run/host/pg.sock", "mode": "rw",
                }])
                joined = " ".join(build_run_command(spec, proxy_ip="10.0.0.1"))
                # Mount SOURCE is the VM path...
                self.assertIn(f"{_VM_ROOT}/c/pg.sock:/run/host/pg.sock:rw", joined)
                # ...and NOT the host tempdir path (proves the split).
                self.assertNotIn(str(host_root), joined)

    def test_default_mode_is_ro(self):
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            host_root = Path(td)
            (host_root / "c").mkdir()
            _sock(host_root / "c", "pg.sock")
            p1, p2 = _patch_paths(host_root)
            with p1, p2:
                spec = _spec(host_sockets=[{
                    "name": "pg", "host_path": "/tmp/postgres.sock",
                    "mount_point": "/run/host/pg.sock",
                }])
                self.assertIn(
                    "/run/host/pg.sock:ro",
                    " ".join(build_run_command(spec, proxy_ip="10.0.0.1")),
                )


class TestRuntimeTOCTOUDefense(unittest.TestCase):
    """The runtime check (against the HOST path) defends against the bridge
    socket being missing, replaced with a non-socket, or symlinked away."""

    def test_missing_bridge_socket_refuses_start(self):
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            host_root = Path(td)  # empty — no socket
            p1, p2 = _patch_paths(host_root)
            with p1, p2:
                spec = _spec(host_sockets=[{
                    "name": "pg", "host_path": "/tmp/postgres.sock",
                    "mount_point": "/run/host/pg.sock",
                }])
                with self.assertRaises(Exception) as ctx:
                    build_run_command(spec, proxy_ip="10.0.0.1")
                msg = str(ctx.exception).lower()
                self.assertTrue("pg" in msg and ("not" in msg or "missing" in msg),
                                f"unexpected error: {ctx.exception}")

    def test_bridge_path_is_regular_file_rejected(self):
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            host_root = Path(td)
            (host_root / "c").mkdir()
            (host_root / "c" / "pg.sock").write_text("not a socket")
            p1, p2 = _patch_paths(host_root)
            with p1, p2:
                spec = _spec(host_sockets=[{
                    "name": "pg", "host_path": "/tmp/postgres.sock",
                    "mount_point": "/run/host/pg.sock",
                }])
                with self.assertRaises(Exception) as ctx:
                    build_run_command(spec, proxy_ip="10.0.0.1")
                self.assertIn("socket", str(ctx.exception).lower())

    def test_bridge_path_is_symlink_rejected(self):
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            host_root = Path(td)
            (host_root / "c").mkdir()
            target = _sock(host_root / "c", "real.sock")
            os.symlink(target, host_root / "c" / "pg.sock")
            p1, p2 = _patch_paths(host_root)
            with p1, p2:
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
            host_root = Path(td)
            (host_root / "c").mkdir()
            _sock(host_root / "c", "pg.sock")
            _sock(host_root / "c", "redis.sock")
            p1, p2 = _patch_paths(host_root)
            with p1, p2:
                spec = _spec(host_sockets=[
                    {"name": "pg", "host_path": "/tmp/pg.sock",
                     "mount_point": "/run/host/pg.sock", "mode": "rw"},
                    {"name": "redis", "host_path": "/tmp/redis.sock",
                     "mount_point": "/run/host/redis.sock"},
                ])
                joined = " ".join(build_run_command(spec, proxy_ip="10.0.0.1"))
                self.assertIn(f"{_VM_ROOT}/c/pg.sock:/run/host/pg.sock:rw", joined)
                self.assertIn(f"{_VM_ROOT}/c/redis.sock:/run/host/redis.sock:ro", joined)


if __name__ == "__main__":
    unittest.main()
