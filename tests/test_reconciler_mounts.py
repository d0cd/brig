"""Reconciler wiring for `mounts:` — host_path -> VM-path translation, the
runtime containment re-check, and the symlink-hardening gate.

See docs/design/host-mounts.md.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from brig.cell.reconciler import (
    _attach_mounts,
    _mount_bind_arg,
    _resolved_mount_roots,
)
from brig.cell.spec import CellSpec
from brig.errors import BrigError


class TestMountBindArg(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.root = Path(self._tmp) / "work"
        self.repo = self.root / "repo"
        self.repo.mkdir(parents=True)

    def _roots(self):
        from brig.config import mount_root_slug
        import os.path
        return [(os.path.realpath(str(self.root)), mount_root_slug(str(self.root)))]

    def test_translates_to_vm_path(self):
        arg = _mount_bind_arg(
            {"host_path": str(self.repo), "mount_point": "/workspace", "mode": "rw"},
            self._roots(),
        )
        # /mnt/host/<slug-of-work>/repo:/workspace:rw
        self.assertEqual(arg, "/mnt/host/work/repo:/workspace:rw")

    def test_root_itself_has_no_trailing_rel(self):
        arg = _mount_bind_arg(
            {"host_path": str(self.root), "mount_point": "/data", "mode": "ro"},
            self._roots(),
        )
        self.assertEqual(arg, "/mnt/host/work:/data:ro")

    def test_default_mode_ro(self):
        arg = _mount_bind_arg(
            {"host_path": str(self.repo), "mount_point": "/w"}, self._roots(),
        )
        self.assertTrue(arg.endswith(":ro"))

    def test_outside_roots_raises(self):
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(BrigError):
                _mount_bind_arg(
                    {"host_path": other, "mount_point": "/w", "mode": "ro"},
                    self._roots(),
                )


class TestResolvedMountRoots(unittest.TestCase):
    def test_reads_config(self):
        root = Path(tempfile.mkdtemp()) / "work"
        root.mkdir()
        with patch("brig.config.mount_roots", return_value=[str(root)]):
            roots = _resolved_mount_roots()
        self.assertEqual(roots[0][1], "work")  # slug

    def test_invalid_root_raises(self):
        with patch("brig.config.mount_roots", return_value=["/"]):
            with self.assertRaises(BrigError):
                _resolved_mount_roots()


class TestAttachGate(unittest.TestCase):
    def _spec(self, mounts):
        return CellSpec(name="c", image="alpine", mounts=mounts)

    def test_no_mounts_is_noop(self):
        cmd = []
        _attach_mounts(self._spec([]), cmd)
        self.assertEqual(cmd, [])

    def test_attach_emits_volume_args(self):
        tmp = tempfile.mkdtemp()
        root = Path(tmp) / "work"
        repo = root / "repo"
        repo.mkdir(parents=True)
        spec = self._spec([
            {"name": "r", "host_path": str(repo), "mount_point": "/workspace", "mode": "rw"},
        ])
        cmd = []
        with patch("brig.config.mount_roots", return_value=[str(root)]):
            _attach_mounts(spec, cmd)
        self.assertEqual(cmd, ["-v", "/mnt/host/work/repo:/workspace:rw"])


if __name__ == "__main__":
    unittest.main()
