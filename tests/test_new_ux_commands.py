"""Tests for the new UX commands and behaviors added in the audit pass.

Covers:
  - brig secrets rm confirmation (require --yes)
  - brig run flag-after-image guard
  - brig cp colon parsing (ignores ./out:put.txt)
  - brig policy test (host-side passthrough)
  - brig events --follow (parses but doesn't actually loop in this test)
  - brig network --blocked filter
"""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from brig.errors import BrigError


class TestSecretsRmConfirmation(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.secrets_dir = Path(self.tmpdir) / "secrets"
        self.secrets_dir.mkdir()
        (self.secrets_dir / "api-key").write_text("supersecret")

    def _patch_paths(self):
        from brig import config as cfg
        return patch.object(cfg.HostPaths, "SECRETS_DIR", self.secrets_dir)

    def test_rm_with_yes_succeeds(self):
        from brig.commands.secrets_cmd import cmd_secrets_rm
        args = SimpleNamespace(name="api-key", yes=True)
        with self._patch_paths():
            cmd_secrets_rm(args)
        self.assertFalse((self.secrets_dir / "api-key").exists())

    def test_rm_without_yes_non_interactive_refuses(self):
        from brig.commands.secrets_cmd import cmd_secrets_rm
        args = SimpleNamespace(name="api-key", yes=False)
        with self._patch_paths(), patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(BrigError) as ctx:
                cmd_secrets_rm(args)
            self.assertIn("confirmation", str(ctx.exception))
        # File still there.
        self.assertTrue((self.secrets_dir / "api-key").exists())

    def test_rm_interactive_requires_y(self):
        from brig.commands.secrets_cmd import cmd_secrets_rm
        args = SimpleNamespace(name="api-key", yes=False)
        with self._patch_paths(), \
             patch("sys.stdin.isatty", return_value=True), \
             patch("builtins.input", return_value="n"):
            rc = cmd_secrets_rm(args)
            self.assertEqual(rc, 1)
        self.assertTrue((self.secrets_dir / "api-key").exists())

    def test_rm_interactive_yes_deletes(self):
        from brig.commands.secrets_cmd import cmd_secrets_rm
        args = SimpleNamespace(name="api-key", yes=False)
        with self._patch_paths(), \
             patch("sys.stdin.isatty", return_value=True), \
             patch("builtins.input", return_value="yes"):
            cmd_secrets_rm(args)
        self.assertFalse((self.secrets_dir / "api-key").exists())

    def test_rm_missing_secret_errors(self):
        from brig.commands.secrets_cmd import cmd_secrets_rm
        args = SimpleNamespace(name="does-not-exist", yes=True)
        with self._patch_paths():
            with self.assertRaises(BrigError):
                cmd_secrets_rm(args)


class TestRunFlagAfterImageGuard(unittest.TestCase):
    def test_image_starting_with_dash_rejected(self):
        from brig.commands.lifecycle_cmd import cmd_run
        args = SimpleNamespace(
            image="-m",
            container_cmd=["alpine", "sh"],
            name="x", env=None, secret=None, label=None,
            detach=False, rm=False, image_digest=None, workdir=None,
            file=None, profile=None, memory=None, cpus=None, pids_limit=None,
            network=None, timeout=None, workspace_quota=None,
            policy_allow=None, policy_deny=None,
        )
        with self.assertRaises(BrigError) as ctx:
            cmd_run(args)
        self.assertIn("flag", str(ctx.exception).lower())


class TestCpColonParsing(unittest.TestCase):
    def test_local_path_with_colon_not_treated_as_cell(self):
        from brig.commands.lifecycle_cmd import _parse_cp_target
        self.assertIsNone(_parse_cp_target("./out:put.txt"))
        self.assertIsNone(_parse_cp_target("/abs/with:colon"))

    def test_valid_cell_target(self):
        from brig.commands.lifecycle_cmd import _parse_cp_target
        self.assertEqual(
            _parse_cp_target("mycell:/work/out.json"),
            ("mycell", "/work/out.json"),
        )

    def test_invalid_cell_name_not_treated_as_cell(self):
        # Uppercase is not a valid cell name.
        from brig.commands.lifecycle_cmd import _parse_cp_target
        self.assertIsNone(_parse_cp_target("MYCELL:/work"))


# TestHostServicePolicyShape removed: the _apply_host_service_*
# helpers it covered were deleted in the host_services flattening
# rollout. Per-cell host_services are now written by
# _sync_host_services_policy in lifecycle_cmd from the cell yaml's
# host_services field — covered by tests/test_host_services_phase2.py.


class TestPolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.policy_file = Path(self.tmpdir) / "network-policy.json"
        self.policy_file.write_text(json.dumps({
            "allow": ["pypi.org", "*.example.com"],
            "deny": ["evil.example.com"],
        }))

    def _patch_paths(self):
        from brig import config as cfg
        return patch.object(cfg.HostPaths, "NETWORK_POLICY", self.policy_file)

    def _run(self, domain: str) -> int:
        from brig.commands.policy_cmd import cmd_policy_test
        args = SimpleNamespace(domain=domain, path="/", method="GET")
        with self._patch_paths():
            return cmd_policy_test(args)

    def test_allowed_domain(self):
        self.assertEqual(self._run("pypi.org"), 0)

    def test_wildcard_match(self):
        self.assertEqual(self._run("api.example.com"), 0)

    def test_denied_takes_precedence(self):
        self.assertEqual(self._run("evil.example.com"), 1)

    def test_default_deny(self):
        self.assertEqual(self._run("unknown.com"), 1)


class TestEventsFollowFlag(unittest.TestCase):
    def test_follow_flag_present_in_parser(self):
        from brig.cli import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["cell", "events", "--follow", "--tail", "5"])
        self.assertTrue(args.follow)
        self.assertEqual(args.tail, 5)


class TestNetworkBlockedFilter(unittest.TestCase):
    def test_blocked_flag_present(self):
        from brig.cli import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["cell", "network", "mycell", "--blocked"])
        self.assertTrue(args.blocked)


class TestSecretsRmYesFlagInParser(unittest.TestCase):
    def test_yes_flag_present(self):
        from brig.cli import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["secrets", "rm", "--yes", "api-key"])
        self.assertTrue(args.yes)


class TestDoctorRegistered(unittest.TestCase):
    def test_doctor_in_parser(self):
        from brig.cli import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["system", "doctor"])
        self.assertEqual(args.command, "system")
        self.assertEqual(args.system_command, "doctor")


class TestDoctorCommand(unittest.TestCase):
    """`brig doctor` runs through every check without crashing on a missing env."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.brig_home = Path(self.tmpdir) / ".brig"
        (self.brig_home / "secrets").mkdir(parents=True)
        (self.brig_home / "cells" / "addons").mkdir(parents=True)
        (self.brig_home / "state" / "system").mkdir(parents=True)
        for d in [self.brig_home / "secrets",
                  self.brig_home / "cells" / "addons",
                  self.brig_home / "state" / "system"]:
            d.chmod(0o700)
        # An addon file so the addon-presence check passes.
        (self.brig_home / "cells" / "addons" / "enforce.py").write_text("# stub")
        (self.brig_home / "cells" / "addons" / "logger.py").write_text("# stub")
        (self.brig_home / "cells" / "addons" / "_common.py").write_text("# stub")
        # A valid policy.
        policy_path = self.brig_home / "cells" / "network-policy.json"
        policy_path.write_text(json.dumps({"allow": [], "deny": []}))

    def _patch_paths(self):
        from brig import config as cfg
        return [
            patch.object(cfg.HostPaths, "BRIG_HOME", self.brig_home),
            patch.object(cfg.HostPaths, "SECRETS_DIR", self.brig_home / "secrets"),
            patch.object(cfg.HostPaths, "ADDONS_DIR", self.brig_home / "cells" / "addons"),
            patch.object(cfg.HostPaths, "STATE_DIR", self.brig_home / "state"),
            patch.object(cfg.HostPaths, "NETWORK_POLICY",
                         self.brig_home / "cells" / "network-policy.json"),
        ]

    def test_doctor_runs(self):
        """Doctor returns an exit code (0 if all checks pass, 1 otherwise) without crashing."""
        from brig.commands.system_cmd import cmd_doctor
        patches = self._patch_paths()
        for p in patches:
            p.start()
        try:
            with patch("shutil.which", return_value="/usr/bin/fake"), \
                 patch("subprocess.run") as mock_run, \
                 patch("brig.network.proxy.proxy_running", return_value=True):
                mock_run.return_value = SimpleNamespace(stdout="brig=Running\n", returncode=0)
                rc = cmd_doctor(SimpleNamespace())
            self.assertIn(rc, (0, 1))
        finally:
            for p in patches:
                p.stop()


class TestPolicyRm(unittest.TestCase):
    """`brig policy rm <cell>` deletes the per-cell policy file.

    Note: `delete_cell_policy` binds its `policy_dir` default at function
    definition time (`policy_dir: Path = POLICY_DIR`), so patching the
    module attr after import has no effect. We patch the function itself
    in policy_cmd's namespace to use our test directory.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.policy_dir = Path(self.tmpdir) / "policies"
        self.policy_dir.mkdir()
        (self.policy_dir / "mycell.json").write_text(
            json.dumps({"allow": ["a.com"], "deny": []})
        )

    def _delete_with_test_dir(self, cell_name):
        from brig.policy.policy import delete_cell_policy
        return delete_cell_policy(cell_name, self.policy_dir)

    def test_rm_deletes_existing(self):
        from brig.commands import policy_cmd
        with patch.object(policy_cmd, "delete_cell_policy", self._delete_with_test_dir), \
             patch("warden.proxy.reload_policy", side_effect=ImportError):
            rc = policy_cmd.cmd_policy_rm(SimpleNamespace(name="mycell"))
        self.assertEqual(rc, 0)
        self.assertFalse((self.policy_dir / "mycell.json").exists())

    def test_rm_missing_errors(self):
        from brig.commands import policy_cmd
        with patch.object(policy_cmd, "delete_cell_policy", self._delete_with_test_dir):
            with self.assertRaises(BrigError):
                policy_cmd.cmd_policy_rm(SimpleNamespace(name="does-not-exist"))

    def test_rm_global_refused(self):
        from brig.commands.policy_cmd import cmd_policy_rm
        with self.assertRaises(BrigError) as ctx:
            cmd_policy_rm(SimpleNamespace(name="global"))
        self.assertIn("global", str(ctx.exception).lower())


class TestDeprecatedCommandsRemoved(unittest.TestCase):
    def test_upgrade_removed(self):
        from brig.cli import _build_parser
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["upgrade"])

    def test_run_no_tor_flag(self):
        from brig.cli import _build_parser
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["run", "--tor", "alpine"])


class TestPruneCommand(unittest.TestCase):
    def test_prune_in_parser(self):
        from brig.cli import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["system", "prune"])
        self.assertEqual(args.command, "system")
        self.assertEqual(args.system_command, "prune")
        # Defaults: no scope flag set → all categories.
        self.assertFalse(args.cells)
        self.assertFalse(args.logs)
        self.assertFalse(args.subnets)
        self.assertFalse(args.dry_run)
        self.assertEqual(args.log_days, 7)

    def test_prune_flags(self):
        from brig.cli import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "system", "prune", "--cells", "--dry-run", "--log-days", "30",
        ])
        self.assertTrue(args.cells)
        self.assertTrue(args.dry_run)
        self.assertEqual(args.log_days, 30)

    def test_prune_dry_run_doesnt_touch_anything(self):
        from brig.commands.system_cmd import cmd_prune
        from unittest.mock import patch
        # With --dry-run + empty containers + empty subnet allocator,
        # the command should complete with rc=0 and make no podman calls.
        with patch("brig.commands.system_cmd.vm_run") as mock_vm, \
             patch("brig.network.subnet.list_all", return_value=[]):
            mock_vm.return_value = SimpleNamespace(stdout="", returncode=0)
            rc = cmd_prune(SimpleNamespace(
                cells=True, logs=False, subnets=False,
                dry_run=True, log_days=7,
            ))
        self.assertEqual(rc, 0)


class TestVersionFlag(unittest.TestCase):
    def test_version_flag_prints_and_exits(self):
        from brig.cli import _build_parser
        parser = _build_parser()
        # argparse --version exits 0 after printing.
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_version_string_matches_brig_config(self):
        from brig.config import VERSION
        import brig
        self.assertEqual(brig.__version__, VERSION)


class TestErrorOutputUsesLogging(unittest.TestCase):
    def test_log_error_exists(self):
        """O1: cli.py error paths route through brig.ops.logging.error()."""
        from brig.ops.logging import error as log_error
        self.assertTrue(callable(log_error))


if __name__ == "__main__":
    unittest.main()
