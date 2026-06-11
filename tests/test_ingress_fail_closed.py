"""register_ingress_for must fail closed.

A cell that declares ingress but whose container is uninspectable or has no
IP must NOT report a successful start with zero routes registered — the
declared service would be silently unreachable. The function raises so the
run_cell rollback path engages instead of treating the silent return as
success.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from brig.cell import lifecycle
from brig.errors import BrigError

_INGRESS = [{"name": "web", "port": 8000, "path_prefix": "/api", "auth": "token"}]


class TestRegisterIngressFailsClosed(unittest.TestCase):

    def test_no_ingress_is_noop(self):
        # No declared ingress: nothing to register, must not raise.
        lifecycle.register_ingress_for("c", [])

    def test_uninspectable_container_raises(self):
        with patch("brig.cell.reconciler._podman_inspect_json", return_value=None):
            with self.assertRaises(BrigError) as ctx:
                lifecycle.register_ingress_for("c", _INGRESS)
        self.assertIn("ingress", str(ctx.exception).lower())

    def test_empty_cell_ip_raises(self):
        info = {"NetworkSettings": {"Networks": {"brig-c": {"IPAddress": ""}}}}
        with patch("brig.cell.reconciler._podman_inspect_json", return_value=info):
            with self.assertRaises(BrigError) as ctx:
                lifecycle.register_ingress_for("c", _INGRESS)
        self.assertIn("ingress", str(ctx.exception).lower())

    def test_replay_enforces_max_ingress_cap(self):
        # The start-time replay reads ingress from untrusted metadata; it must
        # apply the same per-cell count cap as parse-time _v_ingress, not just
        # the per-entry shape check.
        from brig.config import MAX_INGRESS_PER_CELL
        too_many = [
            {"name": f"svc{i}", "port": 8000 + i,
             "path_prefix": f"/p{i}", "auth": "token"}
            for i in range(MAX_INGRESS_PER_CELL + 1)
        ]
        with self.assertRaises(BrigError) as ctx:
            lifecycle.register_ingress_for("c", too_many)
        self.assertIn("too many", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
