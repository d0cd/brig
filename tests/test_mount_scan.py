"""Host-side escaping-symlink guard for `mounts:` (brig cell mount-scan)."""

import os
import tempfile
import unittest
from pathlib import Path

from brig.workspace.workspace import (
    find_escaping_symlinks,
    quarantine_escaping_symlinks,
)


class TestFindEscapingSymlinks(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()) / "shared"
        self.root.mkdir()
        (self.root / "real.txt").write_text("data")
        # safe: symlink pointing inside the root
        os.symlink(self.root / "real.txt", self.root / "safe_link")
        # escaping: absolute to an out-of-root path
        os.symlink("/etc/passwd", self.root / "abs_escape")
        # escaping: relative climb out of root
        os.symlink("../../../../etc/hosts", self.root / "rel_escape")
        # escaping + dangling (planted, target doesn't exist yet)
        os.symlink("/Users/nobody/.ssh/id_rsa", self.root / "dangling_escape")

    def test_finds_only_escaping(self):
        found = {p.name for p, _ in find_escaping_symlinks(self.root)}
        self.assertEqual(found, {"abs_escape", "rel_escape", "dangling_escape"})
        self.assertNotIn("safe_link", found)

    def test_quarantine_removes_escaping_keeps_safe(self):
        removed = {p.name for p in quarantine_escaping_symlinks(self.root)}
        self.assertEqual(removed, {"abs_escape", "rel_escape", "dangling_escape"})
        self.assertTrue((self.root / "safe_link").exists())
        self.assertTrue((self.root / "real.txt").exists())
        self.assertEqual(find_escaping_symlinks(self.root), [])

    def test_nested_escaping_found(self):
        sub = self.root / "a" / "b"
        sub.mkdir(parents=True)
        os.symlink("/etc/shadow", sub / "deep_escape")
        names = {p.name for p, _ in find_escaping_symlinks(self.root)}
        self.assertIn("deep_escape", names)


class TestCmdMountScan(unittest.TestCase):
    """End-to-end: inspect -> /mnt/host translation -> host-side scan."""

    def setUp(self):
        from types import SimpleNamespace
        self._ns = SimpleNamespace
        self.root = Path(tempfile.mkdtemp()) / "work"
        self.repo = self.root / "repo"
        self.repo.mkdir(parents=True)
        os.symlink("/etc/passwd", self.repo / "escape")  # escaping
        import json as _json
        # podman inspect → one bind from /mnt/host/work/repo
        self._inspect = _json.dumps([{"Mounts": [
            {"Type": "bind", "Source": "/mnt/host/work/repo", "Destination": "/workspace"},
        ]}])

    def _run(self, quarantine=False):
        from unittest.mock import MagicMock, patch
        from brig.commands import lifecycle_inspect as li
        result = MagicMock(returncode=0, stdout=self._inspect)
        captured = []
        with (
            patch("brig.commands.lifecycle_inspect.vm_run", return_value=result),
            patch("brig.config.mount_roots", return_value=[str(self.root)]),
            patch("brig.commands.lifecycle_inspect.output", side_effect=captured.append),
        ):
            rc = li.cmd_mount_scan(self._ns(name="c", quarantine=quarantine))
        return rc, "\n".join(captured)

    def test_reports_escape_nonzero(self):
        rc, text = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("ESCAPES", text)
        self.assertIn("escape", text)
        self.assertTrue((self.repo / "escape").is_symlink())  # not removed in report mode

    def test_quarantine_removes_and_zero(self):
        rc, text = self._run(quarantine=True)
        self.assertEqual(rc, 0)
        self.assertIn("QUARANTINING", text)
        self.assertFalse((self.repo / "escape").exists())

    def test_same_source_bound_twice_counted_once(self):
        # One host_path bound at two mount points must be scanned once, not
        # double-counted in the report.
        import json as _json
        self._inspect = _json.dumps([{"Mounts": [
            {"Type": "bind", "Source": "/mnt/host/work/repo", "Destination": "/a"},
            {"Type": "bind", "Source": "/mnt/host/work/repo", "Destination": "/b"},
        ]}])
        rc, text = self._run()
        self.assertEqual(rc, 1)
        self.assertEqual(text.count("ESCAPES"), 1)
        self.assertIn("1 escaping symlink(s) found", text)


class TestSafeMountName(unittest.TestCase):
    """Export re-derives `mounts.name` from the mount point; it must round-trip
    through the cell-definition validator (MOUNT_NAME_PATTERN)."""

    def test_derived_names_are_valid_and_unique(self):
        from brig.cell.validators import MOUNT_NAME_PATTERN
        from brig.commands.lifecycle_inspect import _safe_mount_name
        used: set[str] = set()
        cases = ["/MyData", "/work/my_data", "/" + "x" * 40, "/data", "/data", "/"]
        for dst in cases:
            name = _safe_mount_name(dst, used)
            self.assertTrue(MOUNT_NAME_PATTERN.match(name), f"{dst!r} -> {name!r}")
        self.assertEqual(len(used), len(cases))  # all unique


if __name__ == "__main__":
    unittest.main()
