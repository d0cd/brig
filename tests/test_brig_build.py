"""C1 from docs/plans/0.3-validation-plan.md: `brig build <dir>` wraps
the awkward `limactl shell brig -- sudo podman build` invocation so
agent-cell authors don't have to remember the VM boundary.

These tests cover the validation + flag-routing behavior — the actual
podman invocation is e2e-only (`brig build cells/hermes` in a real VM).
"""

from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


def _args(**kw) -> types.SimpleNamespace:
    kw.setdefault("tag", None)
    kw.setdefault("build_arg", None)
    return types.SimpleNamespace(**kw)


class TestBrigBuildValidation(unittest.TestCase):
    def test_rejects_missing_directory(self):
        from brig.commands.image_cmd import cmd_build
        from brig.errors import BrigError
        with self.assertRaises(BrigError) as ctx:
            cmd_build(_args(context="/nonexistent/path"))
        self.assertIn("not a directory", str(ctx.exception))

    def test_rejects_directory_without_containerfile(self):
        from brig.commands.image_cmd import cmd_build
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(BrigError) as ctx:
                cmd_build(_args(context=td))
            self.assertIn("Containerfile", str(ctx.exception))

    def test_accepts_directory_with_containerfile(self):
        from brig.commands.image_cmd import cmd_build
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Containerfile").write_text("FROM alpine\n")
            with patch("brig.commands.image_cmd.subprocess.Popen") as mock_popen:
                # tar + podman build both succeed.
                mock_proc = MagicMock()
                mock_proc.wait.return_value = 0
                mock_proc.stdout = MagicMock()
                mock_popen.return_value = mock_proc
                rc = cmd_build(_args(context=td))
                self.assertEqual(rc, 0)

    def test_accepts_directory_with_dockerfile(self):
        from brig.commands.image_cmd import cmd_build
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Dockerfile").write_text("FROM alpine\n")
            with patch("brig.commands.image_cmd.subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.wait.return_value = 0
                mock_proc.stdout = MagicMock()
                mock_popen.return_value = mock_proc
                rc = cmd_build(_args(context=td))
                self.assertEqual(rc, 0)

    def test_rejects_unsafe_tag(self):
        from brig.commands.image_cmd import cmd_build
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Containerfile").write_text("FROM alpine\n")
            with self.assertRaises(BrigError) as ctx:
                cmd_build(_args(context=td, tag="; rm -rf /"))
            self.assertIn("Invalid image tag", str(ctx.exception))


class TestBrigBuildCommandShape(unittest.TestCase):
    """Assert the produced podman build command has the right flags."""

    def test_default_tag_derived_from_dir_name(self):
        from brig.commands.image_cmd import cmd_build
        with tempfile.TemporaryDirectory() as parent:
            ctx = Path(parent) / "my-agent"
            ctx.mkdir()
            (ctx / "Containerfile").write_text("FROM alpine\n")
            with patch("brig.commands.image_cmd.subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.wait.return_value = 0
                mock_proc.stdout = MagicMock()
                mock_popen.return_value = mock_proc
                cmd_build(_args(context=str(ctx)))

            # Second Popen call is the podman build invocation.
            build_call = mock_popen.call_args_list[1][0][0]
            # Tag flag and derived name must appear.
            self.assertIn("-t", build_call)
            tag_idx = build_call.index("-t")
            self.assertEqual(build_call[tag_idx + 1], "localhost/my-agent:latest")
            # Stdin marker (last positional arg) must be "-".
            self.assertEqual(build_call[-1], "-")

    def test_explicit_tag_overrides_default(self):
        from brig.commands.image_cmd import cmd_build
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Containerfile").write_text("FROM alpine\n")
            with patch("brig.commands.image_cmd.subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.wait.return_value = 0
                mock_proc.stdout = MagicMock()
                mock_popen.return_value = mock_proc
                cmd_build(_args(context=td, tag="localhost/custom:dev"))

            build_call = mock_popen.call_args_list[1][0][0]
            tag_idx = build_call.index("-t")
            self.assertEqual(build_call[tag_idx + 1], "localhost/custom:dev")

    def test_build_args_passed_through(self):
        from brig.commands.image_cmd import cmd_build
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Containerfile").write_text("FROM alpine\n")
            with patch("brig.commands.image_cmd.subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.wait.return_value = 0
                mock_proc.stdout = MagicMock()
                mock_popen.return_value = mock_proc
                cmd_build(_args(
                    context=td,
                    build_arg=["HERMES_SOURCE=local", "FOO=bar"],
                ))

            build_call = mock_popen.call_args_list[1][0][0]
            # Each --build-arg appears with its KEY=VALUE pair.
            for ba in ("HERMES_SOURCE=local", "FOO=bar"):
                self.assertIn(ba, build_call,
                              f"--build-arg {ba} should be in {build_call}")


if __name__ == "__main__":
    unittest.main()
