"""Cell metadata (`/run/brig/cell.json`) includes the host_sockets
array so cells can introspect what's mounted without globbing /run/host/.

Each entry: {"name": "<name>", "mount_point": "<path>"}.
host_path is intentionally NOT published — same reasoning as
workspace.host_path being dropped in v2 (no host paths in the
downward-API surface).
"""

from __future__ import annotations

import unittest


class TestMetadataHostSockets(unittest.TestCase):
    def test_default_empty_list(self):
        from brig.cell.metadata import build_metadata
        payload = build_metadata("c", "/work")
        self.assertEqual(payload.get("host_sockets"), [])

    def test_includes_name_and_mount_point_only(self):
        from brig.cell.metadata import build_metadata
        payload = build_metadata("c", "/work", host_sockets=[
            {"name": "pg", "host_path": "/tmp/pg.sock",
             "mount_point": "/run/host/pg.sock", "mode": "rw"},
        ])
        self.assertEqual(payload["host_sockets"], [
            {"name": "pg", "mount_point": "/run/host/pg.sock"},
        ])

    def test_does_not_leak_host_path(self):
        from brig.cell.metadata import build_metadata
        payload = build_metadata("c", "/work", host_sockets=[
            {"name": "pg", "host_path": "/tmp/SHOULD-NOT-APPEAR.sock",
             "mount_point": "/run/host/pg.sock"},
        ])
        import json
        self.assertNotIn("SHOULD-NOT-APPEAR", json.dumps(payload))
        self.assertNotIn("host_path", payload["host_sockets"][0])


if __name__ == "__main__":
    unittest.main()
