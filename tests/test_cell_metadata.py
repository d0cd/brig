"""Cell metadata file — `/run/brig/cell.json` (downward API).

Cells need to know their own identity (name,
workspace host path, policy ACL) for agent-delegation flows. Brig writes
a JSON file on the host and bind-mounts it read-only into the cell.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


class TestBuildMetadata(unittest.TestCase):
    """build_metadata is a pure function — exercise the shape directly."""

    def test_minimal_shape(self):
        from brig.cell.metadata import build_metadata, SCHEMA_VERSION

        # Patch the per-cell policy lookup to return nothing.
        with patch("brig.cell.metadata.load_cell_policy", return_value=None):
            m = build_metadata("test-cell", "/work")

        self.assertEqual(m["version"], SCHEMA_VERSION)
        self.assertEqual(m["name"], "test-cell")
        self.assertEqual(m["workspace"]["mount_point"], "/work")
        self.assertTrue(m["workspace"]["host_path"].endswith("/state/test-cell/workspace"),
            f"host_path should end with /state/test-cell/workspace, got {m['workspace']['host_path']}")
        self.assertEqual(m["policy"]["host_services"], [])

    def test_started_at_is_rfc3339_utc(self):
        from brig.cell.metadata import build_metadata
        fixed = datetime(2026, 5, 18, 17, 30, 0, tzinfo=timezone.utc)
        with patch("brig.cell.metadata.load_cell_policy", return_value=None):
            m = build_metadata("c", "/work", started_at=fixed)
        self.assertEqual(m["started_at"], "2026-05-18T17:30:00Z")

    def test_workspace_mount_override_honored(self):
        from brig.cell.metadata import build_metadata
        with patch("brig.cell.metadata.load_cell_policy", return_value=None):
            m = build_metadata("c", "/workspace")
        self.assertEqual(m["workspace"]["mount_point"], "/workspace")

    def test_host_services_from_per_cell_policy(self):
        from brig.cell.metadata import build_metadata
        policy = {"allow": [], "deny": [], "host_services": ["svcA", "svcB"]}
        with patch("brig.cell.metadata.load_cell_policy", return_value=policy):
            m = build_metadata("c", "/work")
        self.assertEqual(sorted(m["policy"]["host_services"]), ["svcA", "svcB"])

    def test_host_services_strips_non_string_entries(self):
        """Defense against a hand-edited policy that mixes the global shape
        (dicts with name+port) into per-cell."""
        from brig.cell.metadata import build_metadata
        policy = {"host_services": ["ok", {"name": "wrong", "port": 80}, 42]}
        with patch("brig.cell.metadata.load_cell_policy", return_value=policy):
            m = build_metadata("c", "/work")
        self.assertEqual(m["policy"]["host_services"], ["ok"])


class TestWriteMetadata(unittest.TestCase):
    """write_metadata atomically writes the JSON to the host-side path."""

    def test_round_trip(self):
        from brig.cell import metadata
        with tempfile.TemporaryDirectory() as td:
            with patch("brig.cell.metadata.HostPaths") as host_paths, \
                 patch("brig.cell.metadata.load_cell_policy", return_value=None):
                host_paths.STATE_DIR = Path(td)
                target = metadata.write_metadata("test-cell", "/work")
                self.assertTrue(target.exists())
                payload = json.loads(target.read_text())

        self.assertEqual(payload["name"], "test-cell")
        self.assertEqual(payload["workspace"]["mount_point"], "/work")
        self.assertIn("started_at", payload)
        self.assertEqual(payload["version"], 1)

    def test_metadata_file_is_world_readable_inside_cell(self):
        """The file gets bind-mounted into the cell, which may run as any uid.
        Make sure the file mode allows non-owner reads (0o644)."""
        from brig.cell import metadata
        with tempfile.TemporaryDirectory() as td:
            with patch("brig.cell.metadata.HostPaths") as host_paths, \
                 patch("brig.cell.metadata.load_cell_policy", return_value=None):
                host_paths.STATE_DIR = Path(td)
                target = metadata.write_metadata("test-cell", "/work")
                mode = target.stat().st_mode & 0o777
                # Other-readable bit must be set.
                self.assertTrue(mode & 0o004,
                    f"metadata file should be other-readable, got 0o{mode:o}")


class TestReconcilerBindMountsMetadata(unittest.TestCase):
    """build_run_command must include the `-v <metadata>:/run/brig/cell.json:ro`
    bind so the cell can read the file."""

    def test_metadata_mount_in_run_command(self):
        from brig.cell.reconciler import build_run_command
        from brig.cell.spec import CellSpec

        spec = CellSpec(name="test-cell", image="alpine", network="none")
        cmd = build_run_command(spec, proxy_ip=None)
        # Find the -v entry matching /run/brig/cell.json:ro
        v_pairs = [(cmd[i + 1]) for i, a in enumerate(cmd) if a == "-v"]
        match = [v for v in v_pairs if v.endswith(":/run/brig/cell.json:ro")]
        self.assertEqual(len(match), 1,
            f"expected exactly one /run/brig/cell.json mount, got {v_pairs}")
        # Source path must include the cell name.
        self.assertIn("test-cell", match[0])


if __name__ == "__main__":
    unittest.main()
