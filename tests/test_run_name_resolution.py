"""Issue 3 from brig-image-build-feedback.md v2: `brig run --file <yaml>`
must honor the yaml's `name:` field. Previously cmd_run auto-generated a
name before the yaml was loaded, so `--file foo.yaml` always got
`fair-ivy-41`-style names instead of the declared `name: my-cell`.

Resolution order: --name flag → yaml `name:` field → auto-generate.
"""

from __future__ import annotations

import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


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


def _write_cell_yaml(d: Path, **fields) -> Path:
    """Write a minimal cell definition as YAML (or JSON — load_cell_definition
    accepts either) for the test."""
    path = d / "cell.json"
    path.write_text(json.dumps(fields))
    return path


class TestNameResolution(unittest.TestCase):

    def _captured_spec(self, args) -> dict:
        """Run cmd_run with `run_cell` stubbed out; return the CellSpec dict."""
        from brig.commands import lifecycle_cmd
        captured: dict = {}

        def fake_run_cell(spec):
            captured["spec"] = spec
            r = MagicMock()
            r.success = True
            return r

        with patch.object(lifecycle_cmd, "run_cell", fake_run_cell), \
             patch("brig.ops.logging.Spinner"):
            lifecycle_cmd.cmd_run(args)
        return captured["spec"]

    def test_yaml_name_used_when_no_flag(self):
        with tempfile.TemporaryDirectory() as td:
            yml = _write_cell_yaml(Path(td), name="my-cell", image="alpine")
            args = _args(file=str(yml))
            spec = self._captured_spec(args)
            self.assertEqual(spec.name, "my-cell",
                "yaml name: should be used when --name flag is absent")

    def test_explicit_flag_overrides_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            yml = _write_cell_yaml(Path(td), name="my-cell", image="alpine")
            args = _args(file=str(yml), name="other")
            spec = self._captured_spec(args)
            self.assertEqual(spec.name, "other",
                "--name flag must win over yaml name:")

    def test_autogenerate_when_neither(self):
        # No --file, no --name → must auto-generate (the old behavior on the
        # bare `brig run alpine` path).
        args = _args(image="alpine")
        spec = self._captured_spec(args)
        self.assertTrue(spec.name, "name should not be empty")
        # Auto-generated names follow the adjective-noun-N pattern.
        self.assertRegex(spec.name, r"^[a-z]+-[a-z]+-\d+$")

    def test_yaml_without_name_field_autogenerates(self):
        with tempfile.TemporaryDirectory() as td:
            yml = _write_cell_yaml(Path(td), image="alpine")  # no name:
            args = _args(file=str(yml))
            spec = self._captured_spec(args)
            self.assertRegex(spec.name, r"^[a-z]+-[a-z]+-\d+$")


class TestYamlFieldsActuallyMerge(unittest.TestCase):
    """Pre-existing bug exposed by adding `workspace_mount`: cmd_run only
    pulled `image`, `name`, `command`, `env`, `ingress` from the yaml.
    Other CellSpec-valid fields (memory, cpus, workspace_*, secrets,
    labels) were validated but then silently dropped. Fixed via a generic
    merge over all CellSpec field names."""

    def _captured_spec(self, args):
        from brig.commands import lifecycle_cmd
        captured: dict = {}
        def fake_run_cell(spec):
            captured["spec"] = spec
            r = MagicMock()
            r.success = True
            return r
        with patch.object(lifecycle_cmd, "run_cell", fake_run_cell), \
             patch("brig.ops.logging.Spinner"):
            lifecycle_cmd.cmd_run(args)
        return captured["spec"]

    def test_yaml_memory_honored(self):
        with tempfile.TemporaryDirectory() as td:
            yml = _write_cell_yaml(Path(td), image="alpine", memory="4g")
            spec = self._captured_spec(_args(file=str(yml)))
            self.assertEqual(spec.memory, "4g")

    def test_yaml_cpus_honored(self):
        with tempfile.TemporaryDirectory() as td:
            yml = _write_cell_yaml(Path(td), image="alpine", cpus="4")
            spec = self._captured_spec(_args(file=str(yml)))
            self.assertEqual(spec.cpus, "4")

    def test_yaml_workspace_mount_honored(self):
        with tempfile.TemporaryDirectory() as td:
            yml = _write_cell_yaml(
                Path(td), image="alpine", workspace_mount="/workspace",
            )
            spec = self._captured_spec(_args(file=str(yml)))
            self.assertEqual(spec.workspace_mount, "/workspace")

    def test_yaml_secrets_honored(self):
        with tempfile.TemporaryDirectory() as td:
            yml = _write_cell_yaml(
                Path(td), image="alpine", secrets=["api-key", "token"],
            )
            spec = self._captured_spec(_args(file=str(yml)))
            self.assertEqual(spec.secrets, ["api-key", "token"])

    def test_cli_flag_overrides_yaml(self):
        """Precedence: --flag > yaml. The CLI flag check fires after the
        yaml merge, so passing both gives the flag."""
        with tempfile.TemporaryDirectory() as td:
            yml = _write_cell_yaml(Path(td), image="alpine", memory="4g")
            spec = self._captured_spec(_args(file=str(yml), memory="8g"))
            self.assertEqual(spec.memory, "8g")

    def test_yaml_unknown_field_silently_ignored(self):
        """Unknown yaml keys (typos, future fields) don't crash CellSpec
        construction — the generic merge filters by CellSpec field name,
        and the existing valid-fields filter at the end catches anything
        that slipped through. (The validator doesn't currently reject
        unknown keys; rejecting them is a separate UX question.)"""
        with tempfile.TemporaryDirectory() as td:
            yml = _write_cell_yaml(
                Path(td), image="alpine", random_unknown_field="x",
            )
            spec = self._captured_spec(_args(file=str(yml)))
            self.assertEqual(spec.image, "alpine")
            self.assertFalse(hasattr(spec, "random_unknown_field"))


if __name__ == "__main__":
    unittest.main()
