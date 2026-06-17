"""Audit fixes (batch 2) — lifecycle and cleanup gaps.

H2 — ingress-token failure rolls the cell back instead of leaving it
     running with no ingress
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch


class TestH2IngressTokenFailureRollsBackCell(unittest.TestCase):
    """If register_ingress_for raises (missing token), the cell —
    which is already running by that point — must be torn down. Leaving
    it running with no ingress = silent broken state."""

    def test_ingress_failure_calls_rm_cell(self):
        from brig.cell.lifecycle import run_cell
        from brig.cell.spec import CellSpec
        from brig.errors import BrigError
        spec = CellSpec(
            name="alice", image="alpine",
            ingress=[{"name": "api", "port": 8080,
                      "path_prefix": "/api", "auth": "token"}],
        )
        good_apply = MagicMock(
            success=True, actions_failed=[], container_id="abc",
        )
        observed = MagicMock(exists=False, running=False, network_exists=False)
        with patch("brig.cell.lifecycle.observe", return_value=observed), \
             patch("brig.cell.lifecycle.check_rate_limit", return_value=True), \
             patch("brig.cell.lifecycle.plan_run", return_value=[MagicMock()]), \
             patch("brig.cell.lifecycle.apply", return_value=good_apply), \
             patch("brig.cell.lifecycle.register_ingress_for",
                   side_effect=BrigError("no token")), \
             patch("brig.cell.lifecycle.rm_cell") as mock_rm:
            with self.assertRaises(BrigError):
                run_cell(spec, proxy_check=lambda: True)
        mock_rm.assert_called_once_with("alice", force=True, keep_workspace=True)


if __name__ == "__main__":
    unittest.main()
