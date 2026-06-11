"""Tests for brig.policy.policy — per-cell policy CRUD and domain matching."""

import tempfile
import unittest
from pathlib import Path

from brig.policy.policy import (
    delete_cell_policy,
    domain_matches_rule,
    load_cell_policy,
    save_cell_policy,
)


class TestCellPolicyCRUD(unittest.TestCase):
    """Test load/save/delete cell policies."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.policy_dir = Path(self.tmpdir)

    def test_save_and_load(self):
        policy = {"allow": ["example.com"], "deny": []}
        save_cell_policy("my-cell", policy, self.policy_dir)
        loaded = load_cell_policy("my-cell", self.policy_dir)
        self.assertEqual(loaded, policy)

    def test_load_nonexistent(self):
        self.assertIsNone(load_cell_policy("nope", self.policy_dir))

    def test_delete(self):
        save_cell_policy("my-cell", {"allow": []}, self.policy_dir)
        self.assertTrue(delete_cell_policy("my-cell", self.policy_dir))
        self.assertIsNone(load_cell_policy("my-cell", self.policy_dir))

    def test_delete_nonexistent(self):
        self.assertFalse(delete_cell_policy("nope", self.policy_dir))


class TestDomainMatchesRuleIDN(unittest.TestCase):
    """domain_matches_rule must IDN-encode just like the addon
    matches_domain so the host-side validator and the runtime evaluator
    agree on unicode inputs.
    """

    def test_ascii_exact(self):
        self.assertTrue(domain_matches_rule("example.com", "example.com"))
        self.assertFalse(domain_matches_rule("example.com", "evil.com"))

    def test_ascii_wildcard(self):
        self.assertTrue(domain_matches_rule("*.example.com", "sub.example.com"))
        self.assertFalse(domain_matches_rule("*.example.com", "example.com"))

    def test_unicode_normalizes_to_punycode(self):
        # Unicode rule and unicode host should match after IDN encoding.
        self.assertTrue(domain_matches_rule("bücher.de", "bücher.de"))

    def test_punycode_rule_matches_unicode_host(self):
        # Punycode form of bücher.de.
        self.assertTrue(domain_matches_rule("xn--bcher-kva.de", "bücher.de"))

    def test_unicode_rule_matches_punycode_host(self):
        self.assertTrue(domain_matches_rule("bücher.de", "xn--bcher-kva.de"))

    def test_unicode_wildcard(self):
        self.assertTrue(
            domain_matches_rule("*.bücher.de", "katalog.bücher.de")
        )


class TestSaveCellPolicyConcurrentSafe(unittest.TestCase):
    """save_cell_policy serializes via fcntl.flock so two concurrent
    writers can't lose updates.
    """

    def test_lock_file_created(self):
        with tempfile.TemporaryDirectory() as td:
            policy_dir = Path(td)
            save_cell_policy("a", {"allow": ["x.com"]}, policy_dir)
            # _locked_policy_dir creates `.lock` on first use.
            self.assertTrue((policy_dir / ".lock").exists())

    def test_serial_writes_preserve_data(self):
        """Sanity: two sequential saves both land on disk."""
        with tempfile.TemporaryDirectory() as td:
            policy_dir = Path(td)
            save_cell_policy("a", {"allow": ["x.com"]}, policy_dir)
            save_cell_policy("b", {"allow": ["y.com"]}, policy_dir)
            self.assertEqual(load_cell_policy("a", policy_dir), {"allow": ["x.com"]})
            self.assertEqual(load_cell_policy("b", policy_dir), {"allow": ["y.com"]})
