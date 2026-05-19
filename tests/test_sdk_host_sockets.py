"""Programmatic SDK accepts host_sockets and threads them into CellSpec.

The CLI parses cell yaml; the SDK builds CellSpec directly. Both paths
must reach the same reconciler with the same args.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch


class TestSDKHostSockets(unittest.TestCase):
    def test_run_sync_threads_host_sockets(self):
        from brig.sdk import Brig
        captured = {}
        def fake_run_cell(spec):
            captured["host_sockets"] = list(spec.host_sockets)
            class _R:
                success = True
                container_id = "abc"
            return _R()
        with patch("brig.sdk.run_cell", side_effect=fake_run_cell):
            Brig().run_sync(
                name="alice", image="alpine",
                host_sockets=[{"name": "pg", "host_path": "/tmp/pg.sock",
                               "mount_point": "/run/host/pg.sock", "mode": "rw"}],
            )
        self.assertEqual(len(captured["host_sockets"]), 1)
        self.assertEqual(captured["host_sockets"][0]["name"], "pg")

    def test_default_no_host_sockets(self):
        from brig.sdk import Brig
        captured = {}
        def fake_run_cell(spec):
            captured["host_sockets"] = list(spec.host_sockets)
            class _R:
                success = True
                container_id = "abc"
            return _R()
        with patch("brig.sdk.run_cell", side_effect=fake_run_cell):
            Brig().run_sync(name="alice", image="alpine")
        self.assertEqual(captured["host_sockets"], [])


if __name__ == "__main__":
    unittest.main()
