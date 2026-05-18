"""C1 + hermes-team feedback: `brig image build <dir>` wraps the awkward
`limactl shell brig -- sudo podman build` invocation, honors
.containerignore / .dockerignore, supports --file/-f, and supports
--build-arg.

These tests cover validation + flag-routing + ignore-pattern matching.
The actual podman invocation is e2e-only.
"""

from __future__ import annotations

import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


def _args(**kw) -> types.SimpleNamespace:
    kw.setdefault("tag", None)
    kw.setdefault("file", None)
    kw.setdefault("build_arg", None)
    return types.SimpleNamespace(**kw)


def _ok_run(*a, **kw):
    return subprocess.CompletedProcess([], 0, "", "")


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
            with patch("brig.commands.image_cmd.subprocess.run", side_effect=_ok_run):
                rc = cmd_build(_args(context=td))
                self.assertEqual(rc, 0)

    def test_accepts_directory_with_dockerfile(self):
        from brig.commands.image_cmd import cmd_build
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Dockerfile").write_text("FROM alpine\n")
            with patch("brig.commands.image_cmd.subprocess.run", side_effect=_ok_run):
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

    def test_rejects_explicit_containerfile_not_found(self):
        from brig.commands.image_cmd import cmd_build
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Containerfile").write_text("FROM alpine\n")  # exists
            with self.assertRaises(BrigError) as ctx:
                cmd_build(_args(context=td, file="MissingFile"))
            self.assertIn("Containerfile not found", str(ctx.exception))


class TestBrigBuildCommandShape(unittest.TestCase):
    """Assert the produced podman build command has the right flags."""

    def test_default_tag_derived_from_dir_name(self):
        from brig.commands.image_cmd import cmd_build
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess([], 0, "", "")

        with tempfile.TemporaryDirectory() as parent:
            ctx = Path(parent) / "my-agent"
            ctx.mkdir()
            (ctx / "Containerfile").write_text("FROM alpine\n")
            with patch("brig.commands.image_cmd.subprocess.run", side_effect=fake_run):
                cmd_build(_args(context=str(ctx)))

        cmd = captured["cmd"]
        self.assertIn("-t", cmd)
        self.assertEqual(cmd[cmd.index("-t") + 1], "localhost/my-agent:latest")
        # Last positional arg must be "-" (stdin context).
        self.assertEqual(cmd[-1], "-")

    def test_explicit_tag_overrides_default(self):
        from brig.commands.image_cmd import cmd_build
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess([], 0, "", "")

        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Containerfile").write_text("FROM alpine\n")
            with patch("brig.commands.image_cmd.subprocess.run", side_effect=fake_run):
                cmd_build(_args(context=td, tag="localhost/custom:dev"))

        cmd = captured["cmd"]
        self.assertEqual(cmd[cmd.index("-t") + 1], "localhost/custom:dev")

    def test_build_args_passed_through(self):
        from brig.commands.image_cmd import cmd_build
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess([], 0, "", "")

        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Containerfile").write_text("FROM alpine\n")
            with patch("brig.commands.image_cmd.subprocess.run", side_effect=fake_run):
                cmd_build(_args(
                    context=td,
                    build_arg=["HERMES_SOURCE=local", "FOO=bar"],
                ))

        cmd = captured["cmd"]
        for ba in ("HERMES_SOURCE=local", "FOO=bar"):
            self.assertIn(ba, cmd, f"--build-arg {ba} missing from {cmd}")

    def test_file_flag_passes_dash_f_to_podman(self):
        from brig.commands.image_cmd import cmd_build
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess([], 0, "", "")

        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Containerfile").write_text("FROM alpine\n")  # auto-detect target
            (Path(td) / "Containerfile.dev").write_text("FROM alpine\n")
            with patch("brig.commands.image_cmd.subprocess.run", side_effect=fake_run):
                cmd_build(_args(context=td, file="Containerfile.dev"))

        cmd = captured["cmd"]
        self.assertIn("-f", cmd)
        self.assertEqual(cmd[cmd.index("-f") + 1], "Containerfile.dev")


class TestContainerIgnore(unittest.TestCase):
    """Hermes-team feedback: build context must honor .containerignore /
    .dockerignore. Otherwise hermes-src/.git, node_modules, etc. ship into
    the image."""

    def test_ignore_excludes_matching_paths(self):
        from brig.commands.image_cmd import _path_excluded, _load_ignore_patterns
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / ".containerignore").write_text(
                "# comment\n"
                "\n"
                ".git\n"
                "node_modules\n"
                "**/*.pyc\n"
                "**/__pycache__\n"
                "build/\n"
            )
            patterns = _load_ignore_patterns(tdp)
            self.assertGreaterEqual(len(patterns), 5)

            # Excluded: exact match
            self.assertTrue(_path_excluded(".git", patterns))
            self.assertTrue(_path_excluded(".git/HEAD", patterns))
            self.assertTrue(_path_excluded("node_modules", patterns))
            self.assertTrue(_path_excluded("node_modules/foo/bar.js", patterns))
            # Excluded: **/*.pyc
            self.assertTrue(_path_excluded("foo/bar.pyc", patterns))
            self.assertTrue(_path_excluded("a/b/c/d.pyc", patterns))
            # Excluded: **/__pycache__
            self.assertTrue(_path_excluded("src/__pycache__", patterns))
            self.assertTrue(_path_excluded("a/b/__pycache__/x.pyc", patterns))
            # Excluded: build/
            self.assertTrue(_path_excluded("build", patterns))

            # Not excluded
            self.assertFalse(_path_excluded("src/main.py", patterns))
            self.assertFalse(_path_excluded("Containerfile", patterns))
            self.assertFalse(_path_excluded("README.md", patterns))

    def test_dockerignore_fallback(self):
        from brig.commands.image_cmd import _load_ignore_patterns
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            # No .containerignore, but .dockerignore present.
            (tdp / ".dockerignore").write_text(".git\n")
            patterns = _load_ignore_patterns(tdp)
            self.assertEqual(patterns, [".git"])

    def test_containerignore_wins_over_dockerignore(self):
        from brig.commands.image_cmd import _load_ignore_patterns
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / ".containerignore").write_text("from-container\n")
            (tdp / ".dockerignore").write_text("from-docker\n")
            patterns = _load_ignore_patterns(tdp)
            self.assertEqual(patterns, ["from-container"])

    def test_no_ignore_file_returns_empty(self):
        from brig.commands.image_cmd import _load_ignore_patterns
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(_load_ignore_patterns(Path(td)), [])

    def test_stream_tar_context_drops_excluded(self):
        """Integration: tar a dir with excluded files; assert they're gone."""
        from brig.commands.image_cmd import _stream_tar_context, _load_ignore_patterns
        import io as _io
        import tarfile as _tarfile

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "Containerfile").write_text("FROM alpine\n")
            (tdp / ".containerignore").write_text(".git\nbuild/\n")
            (tdp / ".git").mkdir()
            (tdp / ".git" / "HEAD").write_text("ref: refs/heads/main")
            (tdp / "build").mkdir()
            (tdp / "build" / "out.bin").write_bytes(b"x" * 100)
            (tdp / "src").mkdir()
            (tdp / "src" / "main.py").write_text("print('hi')")

            patterns = _load_ignore_patterns(tdp)
            data = _stream_tar_context(tdp, patterns)
            with _tarfile.open(fileobj=_io.BytesIO(data)) as tf:
                names = tf.getnames()

            self.assertIn("Containerfile", names)
            self.assertIn("src/main.py", names)
            self.assertIn("src", names)
            for excluded in (".git", ".git/HEAD", "build", "build/out.bin"):
                self.assertNotIn(excluded, names,
                    f"{excluded} should have been excluded, names: {names}")


class TestBrigImageLoad(unittest.TestCase):
    """`brig image load <tarball>` — side-load a prebuilt image."""

    def test_rejects_missing_tarball(self):
        from brig.commands.image_cmd import cmd_load
        from brig.errors import BrigError
        with self.assertRaises(BrigError) as ctx:
            cmd_load(types.SimpleNamespace(tarball="/nonexistent.tar"))
        self.assertIn("not found", str(ctx.exception))

    def test_calls_podman_load_with_stdin(self):
        from brig.commands.image_cmd import cmd_load
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
            f.write(b"fake tar data")
            path = f.name
        try:
            captured = {}

            def fake_run(cmd, **kw):
                captured["cmd"] = cmd
                captured["has_stdin"] = "stdin" in kw
                return subprocess.CompletedProcess(
                    [], 0, "Loaded image: localhost/foo:latest\n", "",
                )

            with patch("brig.commands.image_cmd.subprocess.run", side_effect=fake_run):
                rc = cmd_load(types.SimpleNamespace(tarball=path))

            self.assertEqual(rc, 0)
            self.assertIn("podman", captured["cmd"])
            self.assertIn("load", captured["cmd"])
            self.assertTrue(captured["has_stdin"])
        finally:
            Path(path).unlink(missing_ok=True)

    def test_returns_nonzero_on_podman_failure(self):
        from brig.commands.image_cmd import cmd_load
        from brig.errors import BrigError
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
            f.write(b"bogus")
            path = f.name
        try:
            with patch("brig.commands.image_cmd.subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    [], 1, "", "Error: not a valid image tar",
                )
                with self.assertRaises(BrigError):
                    cmd_load(types.SimpleNamespace(tarball=path))
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
