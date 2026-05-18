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

    def test_uses_crun_not_runsc(self):
        """Issue 2 from brig-image-build-feedback.md v2: the VM defaults to
        runsc (gVisor); buildah can't run under it. Build must explicitly
        pass --runtime crun."""
        from brig.commands.image_cmd import cmd_build
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess([], 0, "", "")

        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Containerfile").write_text("FROM alpine\n")
            with patch("brig.commands.image_cmd.subprocess.run", side_effect=fake_run):
                cmd_build(_args(context=td))

        cmd = captured["cmd"]
        self.assertIn("--runtime", cmd)
        self.assertEqual(cmd[cmd.index("--runtime") + 1], "crun")
        # runsc must NOT appear (would mean the default leaked through).
        self.assertNotIn("runsc", cmd)

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

    def test_anchored_pattern_matches_only_at_root(self):
        """Audit M1 bug #1: leading-slash patterns (`/.git`, `/build`)
        previously matched nothing because paths from relative_to() never
        start with /. Now they should anchor to the context root."""
        from brig.commands.image_cmd import _path_excluded
        patterns = ["/build"]
        self.assertTrue(_path_excluded("build", patterns))
        self.assertTrue(_path_excluded("build/out.bin", patterns))
        # Non-root `build/` directory should NOT match an anchored pattern.
        self.assertFalse(_path_excluded("src/build", patterns))
        self.assertFalse(_path_excluded("vendor/build/x", patterns))

    def test_unanchored_pattern_matches_anywhere(self):
        from brig.commands.image_cmd import _path_excluded
        patterns = ["node_modules"]
        self.assertTrue(_path_excluded("node_modules", patterns))
        self.assertTrue(_path_excluded("src/node_modules", patterns))
        self.assertTrue(_path_excluded("a/b/c/node_modules/foo", patterns))

    def test_double_star_matches_zero_components(self):
        """Audit M1 bug #2: `a/**/b` should match `a/b` (zero intermediate),
        not only `a/x/b` or deeper."""
        from brig.commands.image_cmd import _path_excluded
        patterns = ["a/**/b"]
        self.assertTrue(_path_excluded("a/b", patterns), "zero-component case")
        self.assertTrue(_path_excluded("a/x/b", patterns), "one-component case")
        self.assertTrue(_path_excluded("a/x/y/z/b", patterns), "many-component case")
        self.assertFalse(_path_excluded("a/c", patterns))

    def test_negation_reincludes(self):
        """Audit M1 bug #3: negation (!pattern) re-includes a previously-
        excluded path. Last matching rule wins."""
        from brig.commands.image_cmd import _path_excluded
        patterns = ["*.log", "!important.log"]
        self.assertTrue(_path_excluded("debug.log", patterns))
        self.assertFalse(_path_excluded("important.log", patterns),
            "negation should re-include important.log")

    def test_negation_only_overrides_when_later(self):
        """Order matters: !pattern BEFORE the exclude doesn't help."""
        from brig.commands.image_cmd import _path_excluded
        patterns = ["!important.log", "*.log"]
        self.assertTrue(_path_excluded("important.log", patterns),
            "later *.log should still exclude")

    def test_bounded_regex_no_redos(self):
        """Audit M1 ReDoS: matching a non-matching path against many `**`
        segments completes promptly (sub-second). Previous `.*`-based
        translation took ~10s per path under similar inputs."""
        import time
        from brig.commands.image_cmd import _path_excluded
        # Many `**` segments, no match.
        pattern = "a/" + "/".join(["**"] * 15) + "/foo"
        start = time.monotonic()
        for _ in range(100):
            _path_excluded("not-the-target/path/that/wont/match", [pattern])
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 1.0, f"100 matches took {elapsed:.2f}s — ReDoS risk")

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


class TestBuildContextSymlinkSafety(unittest.TestCase):
    """Audit H1: a symlink in the build context pointing outside the
    context can exfiltrate host secrets (the resolved file contents
    end up in the tar / become readable inside the build container).
    The tar filter must reject these."""

    def test_symlink_escaping_context_is_dropped(self):
        from brig.commands.image_cmd import _stream_tar_context
        import io as _io
        import tarfile as _tarfile

        with tempfile.TemporaryDirectory() as outer:
            outer_p = Path(outer)
            # Host secret OUTSIDE the build context.
            secret = outer_p / "host-secret"
            secret.write_text("PRIVATE-KEY")

            ctx = outer_p / "build-ctx"
            ctx.mkdir()
            (ctx / "Containerfile").write_text("FROM alpine\n")
            # Hostile symlink pointing OUT.
            (ctx / "innocuous.txt").symlink_to(secret)

            data = _stream_tar_context(ctx, patterns=[])
            with _tarfile.open(fileobj=_io.BytesIO(data)) as tf:
                names = tf.getnames()
                # The symlink must NOT have made it into the tar.
                self.assertNotIn("innocuous.txt", names,
                    f"escaping symlink was bundled; tar contains {names}")
            # And the secret content must not appear anywhere in the bytes.
            self.assertNotIn(b"PRIVATE-KEY", data,
                "host secret contents leaked into build tar")

    def test_symlink_staying_inside_context_is_preserved(self):
        """Don't over-restrict: a symlink that points to another file
        inside the build context is fine and should be preserved as
        a symlink in the tar (podman replicates this in the image)."""
        from brig.commands.image_cmd import _stream_tar_context
        import io as _io
        import tarfile as _tarfile

        with tempfile.TemporaryDirectory() as td:
            ctx = Path(td)
            (ctx / "Containerfile").write_text("FROM alpine\n")
            (ctx / "real.txt").write_text("hello")
            (ctx / "link.txt").symlink_to("real.txt")

            data = _stream_tar_context(ctx, patterns=[])
            with _tarfile.open(fileobj=_io.BytesIO(data)) as tf:
                names = tf.getnames()
                self.assertIn("link.txt", names)
                member = tf.getmember("link.txt")
                self.assertTrue(member.issym(),
                    "in-context symlink should be preserved as symlink, "
                    f"got type byte {member.type!r}")


class TestBuildContextSizeCap(unittest.TestCase):
    """Audit M2: a runaway build context should fail with a clear error
    rather than OOM the host."""

    def test_oversized_context_refused(self):
        from brig.commands import image_cmd
        from brig.errors import BrigError

        with tempfile.TemporaryDirectory() as td:
            ctx = Path(td)
            (ctx / "Containerfile").write_text("FROM alpine\n")
            # Lower the abort cap to something quick to trip.
            with patch.object(image_cmd, "_TAR_ABORT_BYTES", 4 * 1024), \
                 patch.object(image_cmd, "_TAR_WARN_BYTES", 1):
                # Create one chunky file that pushes us past the cap.
                (ctx / "big.bin").write_bytes(b"x" * 8 * 1024)
                with self.assertRaises(BrigError) as cm:
                    image_cmd._stream_tar_context(ctx, patterns=[])
                self.assertIn("exceeded", str(cm.exception))


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
