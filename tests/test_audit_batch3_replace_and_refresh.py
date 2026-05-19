"""Audit fix batch 3:

M1 — metadata refresh no longer fabricates `host_path: ""` placeholders.

(The H5 replace-semantics tests previously here covered
_auto_grant_host_services, which has been deleted in the host_services
flattening rollout. Replace-mode behavior is now exercised by
test_host_services_phase2.py::TestSyncHostServicesPolicy.)
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


# ----- M1: metadata refresh no placeholder -----

class TestM1MetadataRefreshNoPlaceholder(unittest.TestCase):
    def test_refresh_does_not_fabricate_host_path(self):
        """Round-trip through refresh_metadata_if_present must not
        introduce empty-string placeholders. The on-disk projection
        only contains {name, mount_point} and that's what we keep."""
        from brig.cell.metadata import (
            refresh_metadata_if_present, _host_metadata_path,
        )
        with tempfile.TemporaryDirectory() as td:
            state_dir = Path(td)
            cell_state = state_dir / "alice"
            cell_state.mkdir()
            initial = {
                "version": 2, "name": "alice",
                "started_at": "2026-05-18T10:00:00Z",
                "workspace": {"mount_point": "/work"},
                "host_sockets": [
                    {"name": "pg", "mount_point": "/run/host/pg.sock"},
                ],
                "policy": {"host_services": []},
            }
            (cell_state / "cell-metadata.json").write_text(json.dumps(initial))
            with patch("brig.config.HostPaths.STATE_DIR", state_dir):
                refresh_metadata_if_present("alice")
                after = json.loads(_host_metadata_path("alice").read_text())
        for entry in after["host_sockets"]:
            self.assertNotIn("host_path", entry,
                "refresh should not introduce host_path keys")
            self.assertEqual(set(entry.keys()), {"name", "mount_point"})

    def test_build_metadata_filters_malformed_entries(self):
        """build_metadata must skip entries missing required keys
        instead of crashing on a KeyError."""
        from brig.cell.metadata import build_metadata
        payload = build_metadata("c", "/work", host_sockets=[
            {"name": "ok", "mount_point": "/run/host/ok.sock"},
            {"name": "missing_mount"},  # malformed → skipped
            "not even a dict",          # type-wrong → skipped
        ])
        self.assertEqual(len(payload["host_sockets"]), 1)
        self.assertEqual(payload["host_sockets"][0]["name"], "ok")


if __name__ == "__main__":
    unittest.main()
