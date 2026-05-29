"""host_services cell-yaml spec + validation (single-tenant flattened
model). Each entry is {name, port}; the cell yaml is the sole source of
authorization, no separate global registry.
"""

from __future__ import annotations

import unittest


def _base():
    return {"name": "alice", "image": "alpine"}


class TestHostServicesAccepted(unittest.TestCase):
    def test_minimal_entry(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": [
            {"name": "db", "port": 5432},
        ]})
        self.assertEqual(errs, [])

    def test_construction_into_cellspec(self):
        from brig.cell.spec import CellSpec
        spec = CellSpec(
            name="alice", image="alpine",
            host_services=[{"name": "db", "port": 5432}],
        )
        self.assertEqual(len(spec.host_services), 1)
        self.assertEqual(spec.host_services[0]["port"], 5432)


class TestHostServicesNameValidation(unittest.TestCase):
    def test_missing_name_rejected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": [
            {"port": 5432},
        ]})
        self.assertTrue(any("name" in e for e in errs), errs)

    def test_uppercase_name_rejected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": [
            {"name": "DB", "port": 5432},
        ]})
        self.assertTrue(any("lowercase" in e or "pattern" in e for e in errs), errs)

    def test_duplicate_names_rejected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": [
            {"name": "db", "port": 5432},
            {"name": "db", "port": 5433},
        ]})
        self.assertTrue(any("Duplicate" in e or "duplicate" in e for e in errs), errs)


class TestHostServicesPortValidation(unittest.TestCase):
    def test_missing_port_rejected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": [
            {"name": "db"},
        ]})
        self.assertTrue(any("port" in e for e in errs), errs)

    def test_out_of_range_port_rejected(self):
        from brig.cell.spec import validate_cell_definition
        for bad in (0, -1, 65536, 99999):
            errs = validate_cell_definition({**_base(), "host_services": [
                {"name": "db", "port": bad},
            ]})
            self.assertTrue(errs, f"port={bad} accepted")

    def test_non_int_port_rejected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": [
            {"name": "db", "port": "5432"},
        ]})
        self.assertTrue(errs)


class TestCountLimit(unittest.TestCase):
    def test_too_many_rejected(self):
        from brig.cell.spec import validate_cell_definition
        entries = [{"name": f"s{i}", "port": 5000 + i} for i in range(20)]
        errs = validate_cell_definition({**_base(), "host_services": entries})
        self.assertTrue(any("Too many" in e or "max" in e for e in errs), errs)


class TestUntrustedProfileRejection(unittest.TestCase):
    def test_untrusted_profile_with_host_services_rejected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            **_base(), "profile": "untrusted", "host_services": [
                {"name": "db", "port": 5432},
            ],
        })
        self.assertTrue(any("untrusted" in e.lower() for e in errs), errs)

    def test_supervised_profile_ok(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            **_base(), "profile": "supervised", "host_services": [
                {"name": "db", "port": 5432},
            ],
        })
        self.assertEqual(errs, [])


class TestTypeShape(unittest.TestCase):
    def test_not_a_list_rejected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": "db"})
        self.assertTrue(errs)

    def test_entry_not_a_dict_rejected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({**_base(), "host_services": ["db"]})
        self.assertTrue(errs)


if __name__ == "__main__":
    unittest.main()
