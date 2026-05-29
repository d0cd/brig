"""Tests for the workspace sanitize / quarantine / size helpers.

These run host-side with no VM dependency. They cover the parts of
brig.workspace.workspace that weren't exercised by test_workspace.py.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from brig.workspace.workspace import (
    _apply_quarantine,
    _get_path_size,
    _sanitize_file,
    _sanitize_tree,
)
from brig.errors import BrigError


class TestSanitizeFile(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_safe_file_passes(self):
        f = Path(self.tmpdir) / "ok.txt"
        f.write_text("hello")
        _sanitize_file(f)  # No raise.

    def test_unsafe_extension_blocked(self):
        f = Path(self.tmpdir) / "evil.app"
        f.write_text("x")
        with self.assertRaises(BrigError) as ctx:
            _sanitize_file(f)
        self.assertIn(".app", str(ctx.exception))

    def test_unsafe_extension_case_insensitive(self):
        f = Path(self.tmpdir) / "EVIL.EXE"
        f.write_text("x")
        with self.assertRaises(BrigError):
            _sanitize_file(f)

    def test_strips_executable_bits(self):
        f = Path(self.tmpdir) / "script.py"
        f.write_text("print('hi')")
        f.chmod(0o755)
        _sanitize_file(f)
        # After: u+x, g+x, o+x all removed.
        mode = f.stat().st_mode & 0o777
        self.assertEqual(mode & 0o111, 0o000)

    def test_chmod_failure_is_swallowed(self):
        # File deleted between stat and chmod — shouldn't crash.
        f = Path(self.tmpdir) / "vanishing.txt"
        f.write_text("x")
        with patch.object(Path, "chmod", side_effect=OSError("gone")):
            _sanitize_file(f)  # No raise.


class TestSanitizeTree(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def test_clean_tree_passes(self):
        (self.tmpdir / "a.txt").write_text("x")
        (self.tmpdir / "sub").mkdir()
        (self.tmpdir / "sub" / "b.txt").write_text("y")
        _sanitize_tree(self.tmpdir)  # No raise.

    def test_unsafe_file_in_tree_raises(self):
        (self.tmpdir / "bad.dmg").write_text("x")
        with self.assertRaises(BrigError):
            _sanitize_tree(self.tmpdir)

    def test_symlink_inside_tree_kept(self):
        (self.tmpdir / "real.txt").write_text("x")
        (self.tmpdir / "link.txt").symlink_to("real.txt")
        _sanitize_tree(self.tmpdir)  # Symlink within tree is allowed.
        self.assertTrue((self.tmpdir / "link.txt").exists())

    def test_symlink_escaping_tree_removed(self):
        outside = Path(tempfile.mkdtemp()) / "outside.txt"
        outside.write_text("secret")
        (self.tmpdir / "escape").symlink_to(outside)
        _sanitize_tree(self.tmpdir)
        # Escape link must be gone; outside file untouched.
        self.assertFalse((self.tmpdir / "escape").exists())
        self.assertTrue(outside.exists())


class TestApplyQuarantine(unittest.TestCase):
    def test_no_raise_when_xattr_missing(self):
        # _apply_quarantine swallows OSError on platforms without `xattr`.
        with patch("subprocess.run", side_effect=OSError("no xattr")):
            _apply_quarantine(Path("/tmp/whatever"))  # No raise.

    def test_calls_xattr_with_quarantine_value(self):
        with patch("subprocess.run") as mock_run:
            _apply_quarantine(Path("/tmp/x"))
            args = mock_run.call_args[0][0]
            self.assertEqual(args[0], "xattr")
            self.assertIn("com.apple.quarantine", args)


class TestGetPathSize(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def test_single_file_size(self):
        f = self.tmpdir / "a.txt"
        f.write_text("hello")
        self.assertEqual(_get_path_size(f), 5)

    def test_directory_recursive_size(self):
        (self.tmpdir / "a.txt").write_text("abc")  # 3
        sub = self.tmpdir / "sub"
        sub.mkdir()
        (sub / "b.txt").write_text("defgh")  # 5
        self.assertEqual(_get_path_size(self.tmpdir), 8)

    def test_empty_directory(self):
        self.assertEqual(_get_path_size(self.tmpdir), 0)

    def test_unreadable_file_skipped(self):
        f = self.tmpdir / "x.txt"
        f.write_text("hi")
        with patch("os.path.getsize", side_effect=OSError("no")):
            # Should not crash; unreadable file contributes 0.
            self.assertEqual(_get_path_size(self.tmpdir), 0)


if __name__ == "__main__":
    unittest.main()
