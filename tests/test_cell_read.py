"""`brig cell read <cell> <relpath>` — the language-agnostic safe-read
primitive that replaces v1's workspace.host_path.

Streams a workspace file to stdout via safe_open; refuses symlinks
anywhere in the path (so a cell can't trick a shell consumer into
following a symlink to a host secret).
"""

from __future__ import annotations

import io
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def _make_workspace(base: Path, cell: str) -> Path:
    ws = base / "state" / cell / "workspace"
    ws.mkdir(parents=True)
    return ws


def _patched_state(base: Path):
    state = base / "state"
    state.mkdir(parents=True, exist_ok=True)
    return patch("brig.workspace.validation.HostPaths.STATE_DIR", state)


class TestCellRead(unittest.TestCase):

    def _run(self, name: str, path: str) -> tuple[int, bytes]:
        from brig.commands.lifecycle_inspect import cmd_read
        # Capture stdout bytes (cmd_read writes to sys.stdout.buffer).
        captured = io.BytesIO()
        original_stdout = sys.stdout
        try:
            class _Stdout:
                buffer = captured
            sys.stdout = _Stdout()
            rc = cmd_read(types.SimpleNamespace(name=name, path=path))
        finally:
            sys.stdout = original_stdout
        return rc, captured.getvalue()

    def test_reads_a_workspace_file(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = _make_workspace(base, "c1")
            (ws / "hello.txt").write_text("hi from the cell")
            with _patched_state(base):
                rc, out = self._run("c1", "hello.txt")
        self.assertEqual(rc, 0)
        self.assertEqual(out, b"hi from the cell")

    def test_reads_a_nested_file(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = _make_workspace(base, "c1")
            (ws / "sub").mkdir()
            (ws / "sub" / "data.bin").write_bytes(b"\x00\x01\x02")
            with _patched_state(base):
                rc, out = self._run("c1", "sub/data.bin")
        self.assertEqual(rc, 0)
        self.assertEqual(out, b"\x00\x01\x02")

    def test_refuses_symlink_escape(self):
        """THE security test: the same exploit shape the schema break
        exists to prevent. If a cell plants a symlink to a host secret
        and a shell consumer does `brig cell read`, the read must fail
        rather than leak the secret."""
        from brig.errors import BrigError

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = _make_workspace(base, "c1")
            secret = base / "host-secret"
            secret.write_text("PRIVATE-KEY")
            (ws / "innocuous.txt").symlink_to(secret)

            with _patched_state(base):
                with self.assertRaises(BrigError) as cm:
                    self._run("c1", "innocuous.txt")
            self.assertIn("Refused", str(cm.exception))

    def test_refuses_dotdot(self):
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _make_workspace(base, "c1")
            with _patched_state(base):
                with self.assertRaises(BrigError):
                    self._run("c1", "../../etc/passwd")

    def test_missing_file_returns_clear_error(self):
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _make_workspace(base, "c1")
            with _patched_state(base):
                with self.assertRaises(BrigError) as cm:
                    self._run("c1", "no-such.txt")
            self.assertIn("Not found", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
