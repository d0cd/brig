"""_v_cpus must reject non-finite and boolean cpu values.

float('inf')/float('nan') parse without raising and bool is an int
subclass, so the old isinstance+float() gate let them through to
`podman run --cpus`, which fails opaquely at container-create time.
"""

import unittest

from brig.cell.spec import validate_cell_definition


def _errs(cpus):
    return validate_cell_definition({"name": "alice", "image": "alpine", "cpus": cpus})


class TestVCpus(unittest.TestCase):
    def test_valid_values_pass(self):
        for v in (1, 2.5, "4", "0.5"):
            self.assertEqual(
                [e for e in _errs(v) if "cpus" in e.lower()], [],
                f"{v!r} should be a valid cpus value",
            )

    def test_infinity_rejected(self):
        for v in ("inf", "1e999", float("inf")):
            self.assertTrue(
                any("cpus" in e.lower() for e in _errs(v)),
                f"{v!r} should be rejected",
            )

    def test_nan_rejected(self):
        self.assertTrue(any("cpus" in e.lower() for e in _errs(float("nan"))))
        self.assertTrue(any("cpus" in e.lower() for e in _errs("nan")))

    def test_non_positive_rejected(self):
        for v in (0, -1, "0", "-2"):
            self.assertTrue(
                any("cpus" in e.lower() for e in _errs(v)),
                f"{v!r} should be rejected",
            )

    def test_bool_rejected(self):
        self.assertTrue(any("cpus" in e.lower() for e in _errs(True)))


if __name__ == "__main__":
    unittest.main()
