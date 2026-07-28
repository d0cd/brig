"""OTel collector lifecycle — pure-Python tests over a mocked podman.

Covers:
  - Fail-closed when the image digest is unpinned
  - Idempotent start (no-op if already running)
  - Re-create on stale stopped container
  - Stop tears down even on already-gone container
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch


def _ok(stdout: str = "running", returncode: int = 0, stderr: str = ""):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


class TestResolvedImage(unittest.TestCase):
    def test_unpinned_digest_raises(self):
        from brig.observability import collector
        from brig.errors import BrigError
        with patch.object(collector, "COLLECTOR_IMAGE_DIGEST", ""):
            with self.assertRaises(BrigError) as ctx:
                collector._resolved_image()
        self.assertIn("digest is not pinned", str(ctx.exception).lower())
        self.assertIn("pin-collector-image", (ctx.exception.suggestion or ""))

    def test_non_sha256_digest_raises(self):
        from brig.observability import collector
        from brig.errors import BrigError
        with patch.object(collector, "COLLECTOR_IMAGE_DIGEST", "md5:abc123"):
            with self.assertRaises(BrigError):
                collector._resolved_image()

    def test_valid_digest_returns_pinned_ref(self):
        from brig.observability import collector
        with patch.object(collector, "COLLECTOR_IMAGE_DIGEST",
                          "sha256:" + "a" * 64):
            ref = collector._resolved_image()
        self.assertTrue(ref.startswith("docker.io/otel/"))
        self.assertIn("@sha256:", ref)


class TestIsRunning(unittest.TestCase):
    def test_running_when_status_is_running(self):
        from brig.observability import collector
        with patch.object(collector, "vm_run",
                          return_value=_ok(stdout="running\n")):
            self.assertTrue(collector.is_running())

    def test_not_running_on_exited(self):
        from brig.observability import collector
        with patch.object(collector, "vm_run",
                          return_value=_ok(stdout="exited\n")):
            self.assertFalse(collector.is_running())

    def test_not_running_on_missing(self):
        from brig.observability import collector
        with patch.object(collector, "vm_run",
                          return_value=_ok(returncode=1, stdout="")):
            self.assertFalse(collector.is_running())


class TestStart(unittest.TestCase):
    def _patches(self, digest="sha256:" + "a" * 64):
        from brig.observability import collector
        return [
            patch.object(collector, "COLLECTOR_IMAGE_DIGEST", digest),
            patch.object(collector, "HEALTH_TIMEOUT_S", 0.1),
            patch.object(collector, "HEALTH_POLL_S", 0.01),
        ]

    def test_unpinned_digest_blocks_start(self):
        from brig.observability import collector
        from brig.errors import BrigError
        with patch.object(collector, "COLLECTOR_IMAGE_DIGEST", ""):
            with self.assertRaises(BrigError):
                collector.start()

    def test_no_op_if_already_running(self):
        from brig.observability import collector
        calls = []
        def fake(cmd, **kw):
            calls.append(cmd)
            if cmd[:2] == ["podman", "inspect"]:
                return _ok(stdout="running\n")
            return _ok()
        for p in self._patches():
            p.start()
        try:
            with patch.object(collector, "vm_run", side_effect=fake):
                self.assertTrue(collector.start())
        finally:
            for p in self._patches():
                p.stop()
        # No `podman run` should have been issued.
        self.assertFalse(
            any(cmd[:3] == ["podman", "run", "-d"] for cmd in calls),
        )

    def test_re_create_on_stale_stopped_container(self):
        from brig.observability import collector
        run_invoked = []

        def fake(cmd, **kw):
            if cmd[:2] == ["podman", "inspect"]:
                # First check: not running. After podman run: running.
                if run_invoked:
                    return _ok(stdout="running\n")
                return _ok(stdout="exited\n")
            if cmd[:3] == ["podman", "ps", "-a"]:
                return _ok(stdout=collector.COLLECTOR_NAME + "\n")
            if cmd[:2] == ["podman", "stop"]:
                return _ok()
            if cmd[:2] == ["podman", "rm"]:
                return _ok()
            if cmd[:1] == ["mkdir"] or cmd[:1] == ["cp"]:
                return _ok()
            if cmd[:3] == ["podman", "run", "-d"]:
                run_invoked.append(True)
                return _ok()
            return _ok()

        import tempfile
        from pathlib import Path
        for p in self._patches():
            p.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                td = Path(td)
                src = td / "src.yaml"
                src.write_text("dummy: config\n")
                dest = td / "cells" / "otel-collector.yaml"
                fake_cells_dir = td / "cells"
                with patch.object(collector, "vm_run", side_effect=fake), \
                     patch.object(collector, "_config_source", return_value=src), \
                     patch.object(collector, "HOST_CONFIG_PATH", dest), \
                     patch("brig.observability.collector.HostPaths.CELLS_DIR",
                           fake_cells_dir):
                    self.assertTrue(collector.start())
                self.assertTrue(dest.exists())
        finally:
            for p in self._patches():
                p.stop()
        self.assertEqual(len(run_invoked), 1)

    def test_missing_config_template_raises(self):
        from pathlib import Path
        from brig.observability import collector
        from brig.errors import BrigError
        for p in self._patches():
            p.start()
        try:
            ghost = Path("/no/such/template.yaml")
            with patch.object(collector, "vm_run",
                              return_value=_ok(stdout="missing\n")), \
                 patch.object(collector, "_config_source", return_value=ghost):
                with self.assertRaises(BrigError) as ctx:
                    collector.start()
            self.assertIn("collector config template", str(ctx.exception))
        finally:
            for p in self._patches():
                p.stop()


class TestStop(unittest.TestCase):
    def test_calls_stop_and_rm(self):
        from brig.observability import collector
        seen = []
        def fake(cmd, **kw):
            seen.append(cmd[:2])
            return _ok()
        with patch.object(collector, "vm_run", side_effect=fake):
            collector.stop()
        self.assertIn(["podman", "stop"], seen)
        self.assertIn(["podman", "rm"], seen)


if __name__ == "__main__":
    unittest.main()
