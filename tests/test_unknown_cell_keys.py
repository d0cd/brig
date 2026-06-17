"""Unknown cell-yaml keys are surfaced (warning) instead of silently ignored.

brig builds CellSpec by filtering cell_def to known fields, so a typo'd or
removed key (e.g. a stale `host_sockets:`) is dropped without a word. The
`unknown_cell_keys` helper powers a warning at the CLI yaml entry points.
"""

from __future__ import annotations

import unittest

from brig.cell.validators import unknown_cell_keys


class TestUnknownCellKeys(unittest.TestCase):
    def test_all_known_keys_returns_empty(self):
        cell_def = {
            "name": "c", "image": "alpine", "command": ["sh"],
            "memory": "2g", "network": "default",
            "policy_allow": ["api.github.com"], "policy_deny": [],
            "host_services": [{"name": "db", "port": 5432}],
            "ingress": [], "mounts": [], "labels": [],
            "workspace_mount": "/work", "restart": "always", "user": "0",
        }
        self.assertEqual(unknown_cell_keys(cell_def), [])

    def test_nested_policy_alias_is_known(self):
        # The yaml `policy: {allow, deny, tls_passthrough}` form is valid even
        # though it isn't a CellSpec field (it's folded into policy_*).
        self.assertEqual(
            unknown_cell_keys({"name": "c", "image": "alpine",
                               "policy": {"allow": ["x.com"]}}),
            [],
        )

    def test_removed_host_sockets_is_flagged(self):
        self.assertEqual(
            unknown_cell_keys({"name": "c", "image": "alpine",
                               "host_sockets": [{"name": "pg"}]}),
            ["host_sockets"],
        )

    def test_typo_is_flagged(self):
        self.assertEqual(
            unknown_cell_keys({"name": "c", "image": "alpine",
                               "memroy": "2g", "policy_alow": []}),
            ["memroy", "policy_alow"],  # sorted
        )

    def test_known_set_tracks_cellspec_fields(self):
        # The known set must be derived from CellSpec, not hardcoded, so it
        # can't drift when a field is added/removed.
        import dataclasses
        from brig.cell.spec import CellSpec
        for f in dataclasses.fields(CellSpec):
            self.assertEqual(
                unknown_cell_keys({f.name: None}), [],
                f"CellSpec field {f.name!r} should be a known cell-yaml key",
            )


if __name__ == "__main__":
    unittest.main()
