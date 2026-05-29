"""Tests for brig.workspace — file safety, sanitization, quarantine.

Proves extension blocking, symlink escape detection, and quota enforcement.
"""

import os
import tempfile
import unittest
from pathlib import Path

from brig.config import UNSAFE_EXTENSIONS
from brig.errors import BrigError
from brig.workspace.workspace import (
    _get_path_size,
    _sanitize_file,
    _sanitize_tree,
)


class TestSanitizeFile(unittest.TestCase):
    """Test _sanitize_file blocks unsafe extensions and strips exec bits."""

    def test_blocks_command_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".command", delete=False) as f:
            f.write(b"#!/bin/sh\necho pwned")
            f.flush()
            with self.assertRaises(BrigError) as ctx:
                _sanitize_file(Path(f.name))
            self.assertIn(".command", str(ctx.exception))
            os.unlink(f.name)

    def test_blocks_app_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".app", delete=False) as f:
            f.write(b"fake app")
            f.flush()
            with self.assertRaises(BrigError):
                _sanitize_file(Path(f.name))
            os.unlink(f.name)

    def test_blocks_all_unsafe_extensions(self):
        """Every extension in UNSAFE_EXTENSIONS is blocked."""
        for ext in UNSAFE_EXTENSIONS:
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as f:
                f.write(b"x")
                f.flush()
                try:
                    with self.assertRaises(BrigError, msg=f"{ext} should be blocked"):
                        _sanitize_file(Path(f.name))
                finally:
                    os.unlink(f.name)

    def test_allows_safe_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"safe content")
            f.flush()
            os.chmod(f.name, 0o755)
            _sanitize_file(Path(f.name))
            # Exec bits should be stripped.
            mode = os.stat(f.name).st_mode
            self.assertFalse(mode & 0o111)
            os.unlink(f.name)

    def test_strips_executable_bits(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b'{"data": 1}')
            f.flush()
            os.chmod(f.name, 0o755)
            _sanitize_file(Path(f.name))
            mode = os.stat(f.name).st_mode
            self.assertEqual(mode & 0o111, 0)
            os.unlink(f.name)


class TestSanitizeTree(unittest.TestCase):
    """Test _sanitize_tree walks directories and catches unsafe files."""

    def test_blocks_unsafe_file_in_tree(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "safe.txt").write_text("ok")
            (root / "evil.command").write_text("pwned")
            with self.assertRaises(BrigError):
                _sanitize_tree(root)

    def test_removes_symlink_escaping_tree(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "export"
            root.mkdir()
            outside = Path(tmpdir) / "outside"
            outside.write_text("secret")
            link = root / "escape"
            link.symlink_to(outside)

            _sanitize_tree(root)

            # Symlink should be removed.
            self.assertFalse(link.exists())
            # Outside file should still exist.
            self.assertTrue(outside.exists())

    def test_allows_symlink_within_tree(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            real = root / "real.txt"
            real.write_text("content")
            link = root / "alias.txt"
            link.symlink_to(real)

            _sanitize_tree(root)

            # Both should still exist.
            self.assertTrue(real.exists())
            self.assertTrue(link.exists())

    def test_safe_tree_passes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "data.json").write_text('{"ok": true}')
            (root / "readme.txt").write_text("hello")
            sub = root / "sub"
            sub.mkdir()
            (sub / "nested.csv").write_text("a,b,c")

            _sanitize_tree(root)  # Should not raise.


class TestGetPathSize(unittest.TestCase):
    """Test _get_path_size for files and directories."""

    def test_file_size(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 100)
            f.flush()
            self.assertEqual(_get_path_size(Path(f.name)), 100)
            os.unlink(f.name)

    def test_directory_size(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "a.txt").write_text("hello")
            (Path(tmpdir) / "b.txt").write_text("world")
            size = _get_path_size(Path(tmpdir))
            self.assertEqual(size, 10)
