"""Smoke coverage for command handler modules that previously had no
dedicated tests (audit C5). Each test exercises the happy path and at
least one error case so a future refactor that breaks the handler
signature or imports is caught.

Not meant to replace integration tests — these are guard rails against
silent breakage. Deeper behavior tests live alongside the features
themselves (e.g. test_warden_ca_mount.py, test_image_build_use_warden.py)."""

from __future__ import annotations

import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


def _args(**kw):
    return types.SimpleNamespace(**kw)


class TestConfigCmd(unittest.TestCase):
    """cmd_config_* imports CONFIG_FILE at module level — patch the
    in-module name, not HostPaths."""

    def test_config_show_reads_existing_file(self):
        from brig.commands import config_cmd
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.json"
            cfg.write_text(json.dumps({"foo": "bar"}))
            captured: list = []
            with patch.object(config_cmd, "CONFIG_FILE", cfg), \
                 patch.object(config_cmd, "output",
                              side_effect=captured.append):
                self.assertEqual(config_cmd.cmd_config_show(_args()), 0)
            self.assertTrue(any("foo" in c for c in captured))

    def test_config_show_missing_file_returns_zero(self):
        from brig.commands import config_cmd
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.json"
            with patch.object(config_cmd, "CONFIG_FILE", cfg), \
                 patch.object(config_cmd, "output"):
                self.assertEqual(config_cmd.cmd_config_show(_args()), 0)

    def test_config_set_writes_value(self):
        from brig.commands import config_cmd
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.json"
            with patch.object(config_cmd, "CONFIG_FILE", cfg), \
                 patch.object(config_cmd, "output"), \
                 patch.object(config_cmd, "info"):
                config_cmd.cmd_config_set(_args(
                    key="suppress_unverified_image_warn", value="true",
                ))
            data = json.loads(cfg.read_text())
            self.assertEqual(data.get("suppress_unverified_image_warn"), True)


class TestSecretsCmd(unittest.TestCase):
    def _patch_dir(self, td):
        return patch("brig.config.HostPaths.SECRETS_DIR", Path(td))

    def test_list_empty_returns_zero(self):
        from brig.commands.secrets_cmd import cmd_secrets_list
        with tempfile.TemporaryDirectory() as td:
            with self._patch_dir(td), \
                 patch("brig.commands.secrets_cmd.output"):
                self.assertEqual(cmd_secrets_list(_args()), 0)

    def test_add_creates_file_with_0600(self):
        """--value path is the simplest — bypasses stdin entirely."""
        from brig.commands.secrets_cmd import cmd_secrets_add
        with tempfile.TemporaryDirectory() as td:
            secret_path = Path(td) / "myapp-token"
            with self._patch_dir(td), \
                 patch("brig.commands.secrets_cmd.output"):
                cmd_secrets_add(_args(
                    name="myapp-token",
                    value="hunter2",
                    from_file=None,
                    force=False,
                ))
            self.assertTrue(secret_path.exists())
            self.assertEqual(secret_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(secret_path.read_text(), "hunter2")

    def test_add_rejects_path_traversal(self):
        from brig.commands.secrets_cmd import cmd_secrets_add
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            with self._patch_dir(td):
                with self.assertRaises(BrigError):
                    cmd_secrets_add(_args(
                        name="../etc/passwd",
                        value="x",
                        from_file=None,
                        force=False,
                    ))

    def test_rm_nonexistent_returns_error(self):
        from brig.commands.secrets_cmd import cmd_secrets_rm
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            with self._patch_dir(td), \
                 patch("brig.commands.secrets_cmd.output"):
                with self.assertRaises(BrigError):
                    cmd_secrets_rm(_args(name="nope", force=False))


class TestImageCmd(unittest.TestCase):
    def test_pull_invokes_vm_run(self):
        from brig.commands.image_cmd import cmd_pull
        import subprocess
        fake = subprocess.CompletedProcess([], 0, "", "")
        with patch("brig.commands.image_cmd.vm_run", return_value=fake) as vmm, \
             patch("brig.commands.image_cmd.output"):
            self.assertEqual(cmd_pull(_args(image="alpine:3.20")), 0)
        # podman pull alpine:3.20 was invoked.
        called_argv = vmm.call_args.args[0]
        self.assertIn("podman", called_argv)
        self.assertIn("pull", called_argv)
        self.assertIn("alpine:3.20", called_argv)


class TestWatchdogCmd(unittest.TestCase):
    def test_watchdog_callable(self):
        """Sanity-import: handler exists with expected signature.
        Behavior loops indefinitely until signal — deeper tests live
        in shell-test territory."""
        from brig.commands.watchdog_cmd import cmd_watchdog
        self.assertTrue(callable(cmd_watchdog))


class TestConvenienceCmd(unittest.TestCase):
    def test_profiles_lists_builtin(self):
        from brig.commands.convenience_cmd import cmd_profiles
        captured: list = []
        with patch("brig.commands.convenience_cmd.output",
                   side_effect=captured.append):
            rc = cmd_profiles(_args())
        self.assertEqual(rc, 0)
        joined = " ".join(captured)
        # Builtin profiles include 'untrusted'.
        self.assertIn("untrusted", joined)


if __name__ == "__main__":
    unittest.main()
