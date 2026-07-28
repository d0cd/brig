"""`brig run --profile untrusted` must enforce the untrusted-profile guards.

The CLI run path validates the cell definition; if the --profile flag's name
isn't recorded where the validator can see it, the untrusted guards
(host_services, tls_passthrough) are silently skipped and a cell the operator
believes is locked down can declare those side channels.
"""

from __future__ import annotations

import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def _args(**kw) -> types.SimpleNamespace:
    defaults = dict(
        image=None, container_cmd=None, name=None, env=None, secret=None,
        memory=None, cpus=None, pids_limit=None, network=None, profile=None,
        file=None, policy_allow=None, policy_deny=None, label=None,
        timeout=None, workspace_quota=None, detach=False, rm=False,
        image_digest=None, workdir=None,
    )
    defaults.update(kw)
    return types.SimpleNamespace(**defaults)


def _write(d: Path, **fields) -> Path:
    path = d / "cell.json"
    path.write_text(json.dumps(fields))
    return path


class TestUntrustedProfileCliEnforcement(unittest.TestCase):

    def _run_expecting_error(self, **fields) -> str:
        from brig.commands import lifecycle_run
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            yml = _write(Path(td), **fields)
            args = _args(file=str(yml), profile="untrusted")
            with patch.object(lifecycle_run, "run_cell") as run_cell, \
                 patch("brig.ops.logging.Spinner"):
                with self.assertRaises(BrigError) as ctx:
                    lifecycle_run.cmd_run(args)
            # Must reject at validation, before reconciliation.
            run_cell.assert_not_called()
            return str(ctx.exception)

    def test_cli_untrusted_blocks_tls_passthrough(self):
        msg = self._run_expecting_error(
            name="u", image="alpine",
            policy={"allow": ["chatgpt.com"], "tls_passthrough": ["chatgpt.com"]},
        )
        self.assertIn("untrusted profile", msg)

    def test_cli_untrusted_blocks_host_services(self):
        msg = self._run_expecting_error(
            name="u", image="alpine",
            host_services=[{"name": "api", "port": 8000}],
        )
        self.assertIn("untrusted profile", msg)


class TestCliFlagOnlyRunValidatesMergedSpec(unittest.TestCase):
    """A flag-only `brig run` (no --file) must still validate the merged spec,
    mirroring the SDK — otherwise --policy-allow/etc. bypass the schema."""

    def test_flag_only_run_validates_policy_allow(self):
        from brig.commands import lifecycle_run
        from brig.errors import BrigError
        args = _args(image="alpine", policy_allow=["bad domain!!"])
        with patch.object(lifecycle_run, "run_cell") as run_cell, \
             patch("brig.ops.logging.Spinner"), \
             patch("brig.commands.lifecycle_run.info"):
            with self.assertRaises(BrigError):
                lifecycle_run.cmd_run(args)
        run_cell.assert_not_called()


class TestYamlProfileAppliesHardening(unittest.TestCase):
    """A `profile:` declared in the yaml (no --profile flag) must be
    apply_profile()'d, not merely recorded by name — otherwise the profile's
    hardening defaults are silently dropped."""

    def test_yaml_profile_applies_defaults(self):
        from brig.commands import lifecycle_run
        with tempfile.TemporaryDirectory() as td:
            yml = _write(Path(td), name="u", image="alpine", profile="untrusted")
            args = _args(file=str(yml))
            with patch.object(lifecycle_run, "run_cell") as run_cell, \
                 patch("brig.ops.logging.Spinner"), \
                 patch("brig.commands.lifecycle_run.info"):
                lifecycle_run.cmd_run(args)
            run_cell.assert_called_once()
            spec = run_cell.call_args[0][0]
            self.assertEqual(spec.profile, "untrusted")
            # Hardening defaults from the untrusted profile (differ from the
            # CellSpec defaults of 2g / 512), proving apply_profile actually ran.
            self.assertEqual(spec.memory, "512m")
            self.assertEqual(spec.pids_limit, 256)

    def test_yaml_labels_block_does_not_disarm_trust_marker(self):
        # Regression: a --file run with profile: untrusted AND its own labels:
        # block used to clobber the profile-merged labels, dropping the trust
        # marker. Drive the real chain and assert the emitted podman command
        # still carries brig.profile=untrusted (the ingress replay gate needs it).
        from brig.commands import lifecycle_run
        from brig.cell.reconciler import build_run_command
        with tempfile.TemporaryDirectory() as td:
            yml = _write(Path(td), name="u", image="alpine",
                         profile="untrusted", labels={"team": "red"})
            args = _args(file=str(yml))
            with patch.object(lifecycle_run, "run_cell") as run_cell, \
                 patch("brig.ops.logging.Spinner"), \
                 patch("brig.commands.lifecycle_run.info"):
                lifecycle_run.cmd_run(args)
            spec = run_cell.call_args[0][0]
            cmd = build_run_command(spec, "10.60.1.1")
            markers = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--label"
                       and cmd[i + 1].startswith("brig.profile")]
            self.assertEqual(markers, ["brig.profile=untrusted"])
            # The user's own label survived the merge too.
            self.assertIn("team=red", [cmd[i + 1] for i, a in enumerate(cmd)
                                       if a == "--label"])


if __name__ == "__main__":
    unittest.main()
