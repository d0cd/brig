"""Tests for brig.policy.policy — policy CRUD and validation."""

import json
import tempfile
import unittest
from pathlib import Path

from brig.policy.policy import (
    delete_cell_policy,
    domain_matches_rule,
    load_cell_policy,
    load_policy_file,
    save_cell_policy,
    validate_policy,
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


class TestLoadPolicyFile(unittest.TestCase):
    """Test loading policy from JSON and YAML files."""

    def test_json_file(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"allow": ["example.com"]}, f)
            f.flush()
            result = load_policy_file(Path(f.name))
            self.assertEqual(result["allow"], ["example.com"])

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write("not json{{{")
            f.flush()
            with self.assertRaises(ValueError, msg="Failed to parse JSON"):
                load_policy_file(Path(f.name))

    def test_json_non_object(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(["a", "b"], f)
            f.flush()
            with self.assertRaises(ValueError, msg="must contain a JSON object"):
                load_policy_file(Path(f.name))


class TestValidatePolicy(unittest.TestCase):
    """Test validate_policy() catches errors."""

    def test_valid_policy(self):
        errors = validate_policy({"allow": ["example.com", "*.github.com"], "deny": []})
        self.assertEqual(errors, [])

    def test_allow_not_list(self):
        errors = validate_policy({"allow": "example.com"})
        self.assertIn("'allow' must be a list", errors[0])

    def test_invalid_domain(self):
        errors = validate_policy({"allow": ["not a domain!!!"]})
        self.assertTrue(any("Invalid domain" in e for e in errors))

    def test_suspicious_domain_in_allow(self):
        errors = validate_policy({"allow": ["*.localhost"]})
        self.assertTrue(any("Security:" in e for e in errors))

    def test_dict_rule_without_domain(self):
        errors = validate_policy({"allow": [{"paths": ["/v1/*"]}]})
        self.assertTrue(any("missing 'domain'" in e for e in errors))

    def test_non_dict(self):
        errors = validate_policy("not a dict")  # type: ignore[arg-type]
        self.assertEqual(errors, ["Policy must be a dict"])

    def test_empty_policy(self):
        errors = validate_policy({})
        self.assertEqual(errors, [])


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
