#!/usr/bin/env python3
"""
Input fuzzing tests for Brig.

Tests handling of random, malformed, and edge-case inputs:
    - Random strings and bytes
    - Boundary conditions
    - Malformed JSON/YAML
    - Special characters and encoding
    - Type confusion attacks

Run with: python3 tests/test_fuzzing.py
"""

import importlib.util
import json
import os
import random
import string
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Import brig.py directly (not the brig/ package).
brig_path = Path(__file__).parent.parent / "src" / "brig.py"
spec = importlib.util.spec_from_file_location("brig_module", brig_path)
brig = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brig)

# Mock mitmproxy for addon imports.
sys.modules['mitmproxy'] = MagicMock()
sys.modules['mitmproxy.http'] = MagicMock()
sys.modules['mitmproxy.ctx'] = MagicMock()

# Add addons to path.
ADDONS_DIR = Path(__file__).parent.parent / "src" / "addons"
sys.path.insert(0, str(ADDONS_DIR))


def random_string(length, charset=None):
    """Generate a random string."""
    if charset is None:
        charset = string.printable
    return ''.join(random.choice(charset) for _ in range(length))


def random_bytes(length):
    """Generate random bytes."""
    return bytes(random.getrandbits(8) for _ in range(length))


class TestColorizeFuzzing(unittest.TestCase):
    """Fuzzing tests for colorize function."""

    def test_empty_string(self):
        """Empty string doesn't crash."""
        result = brig.colorize("", "green")
        self.assertIsInstance(result, str)

    def test_very_long_string(self):
        """Very long strings don't crash."""
        long_text = "x" * 100000
        result = brig.colorize(long_text, "green")
        self.assertIn(long_text, result)

    def test_null_bytes(self):
        """Strings with null bytes don't crash."""
        text = "hello\x00world"
        result = brig.colorize(text, "green")
        self.assertIn("hello", result)

    def test_unicode_strings(self):
        """Unicode strings don't crash."""
        unicode_texts = [
            "Hello 世界",
            "مرحبا بالعالم",
            "🎉🎊🎈",
            "\u0000\u0001\u0002",
        ]
        for text in unicode_texts:
            result = brig.colorize(text, "green")
            self.assertIsInstance(result, str)

    def test_random_colors(self):
        """Random color names don't crash."""
        for _ in range(100):
            color = random_string(10)
            result = brig.colorize("test", color)
            self.assertIn("test", result)


class TestContainerNameFuzzing(unittest.TestCase):
    """Fuzzing tests for container_name function."""

    def test_empty_string(self):
        """Empty string is handled."""
        result = brig.container_name("")
        self.assertEqual(result, "brig-")

    def test_special_characters(self):
        """Special characters don't crash."""
        special_names = [
            "../../../etc/passwd",
            "; rm -rf /",
            "$(whoami)",
            "`id`",
            "${HOME}",
            "name\x00hidden",
            "name\nline2",
            "name\ttab",
        ]
        for name in special_names:
            result = brig.container_name(name)
            self.assertTrue(result.startswith("brig-"))

    def test_very_long_name(self):
        """Very long names don't crash."""
        long_name = "x" * 10000
        result = brig.container_name(long_name)
        self.assertTrue(result.startswith("brig-"))


class TestCellDefinitionFuzzing(unittest.TestCase):
    """Fuzzing tests for validate_cell_definition."""

    def test_empty_dict(self):
        """Empty dict doesn't crash."""
        errors = brig.validate_cell_definition({})
        self.assertIsInstance(errors, list)

    def test_none_values(self):
        """None values don't crash."""
        cell_def = {
            "image": None,
            "command": None,
            "env": None,
        }
        errors = brig.validate_cell_definition(cell_def)
        self.assertIsInstance(errors, list)

    def test_wrong_types(self):
        """Wrong types don't crash."""
        wrong_type_defs = [
            {"image": 12345},
            {"image": ["alpine"]},
            {"image": {"name": "alpine"}},
            {"command": 123},
            {"command": {"cmd": "echo"}},
            {"env": "FOO=bar"},
            {"env": 123},
            {"secrets": "secret1"},
            {"secrets": {"key": "value"}},
            {"memory": []},
            {"cpus": []},
            {"pids_limit": "100"},
        ]
        for cell_def in wrong_type_defs:
            cell_def["image"] = "alpine"  # Add valid image.
            errors = brig.validate_cell_definition(cell_def)
            self.assertIsInstance(errors, list)

    def test_deeply_nested_structure(self):
        """Deeply nested structures don't crash."""
        nested = {"image": "alpine"}
        current = nested
        for i in range(100):
            current["nested"] = {}
            current = current["nested"]
        errors = brig.validate_cell_definition(nested)
        self.assertIsInstance(errors, list)

    def test_large_arrays(self):
        """Large arrays don't crash."""
        cell_def = {
            "image": "alpine",
            "secrets": [f"secret-{i}" for i in range(10000)],
        }
        errors = brig.validate_cell_definition(cell_def)
        self.assertIsInstance(errors, list)

    def test_binary_in_strings(self):
        """Binary data in strings doesn't crash."""
        cell_def = {
            "image": "alpine",
            "name": random_bytes(50).decode('latin-1'),
        }
        try:
            errors = brig.validate_cell_definition(cell_def)
            self.assertIsInstance(errors, list)
        except UnicodeError:
            pass  # OK to fail on invalid encoding.


class TestPolicyRuleFuzzing(unittest.TestCase):
    """Fuzzing tests for PolicyRule class."""

    @classmethod
    def setUpClass(cls):
        """Import PolicyRule with mocked mitmproxy."""
        from enforce import PolicyRule
        cls.PolicyRule = PolicyRule

    def test_empty_domain(self):
        """Empty domain doesn't crash."""
        rule = self.PolicyRule("")
        result = rule.matches_domain("example.com")
        self.assertFalse(result)

    def test_wildcard_only(self):
        """Wildcard-only pattern doesn't crash."""
        rule = self.PolicyRule("*")
        # Behavior depends on implementation - just verify no crash.
        result = rule.matches_domain("example.com")
        self.assertIsInstance(result, bool)

    def test_many_wildcards(self):
        """Multiple wildcards don't crash."""
        rule = self.PolicyRule("*.*.*.example.com")
        result = rule.matches_domain("a.b.c.example.com")
        self.assertIsInstance(result, bool)

    def test_special_characters_in_domain(self):
        """Special characters in domain don't crash."""
        special_domains = [
            "example.com:8080",
            "example.com/path",
            "user@example.com",
            "example.com?query=1",
            "example.com#fragment",
            "<script>alert(1)</script>.com",
        ]
        for domain in special_domains:
            try:
                rule = self.PolicyRule(domain)
                result = rule.matches_domain("example.com")
                self.assertIsInstance(result, bool)
            except ValueError:
                pass  # OK to reject invalid patterns.

    def test_unicode_domains(self):
        """Unicode domains don't crash."""
        unicode_domains = [
            "例え.jp",
            "مثال.مصر",
            "пример.рф",
        ]
        for domain in unicode_domains:
            try:
                rule = self.PolicyRule(domain)
                result = rule.matches_domain(domain)
                self.assertIsInstance(result, bool)
            except ValueError:
                pass

    def test_dict_rule_missing_fields(self):
        """Dict rules with missing fields don't crash."""
        partial_rules = [
            {},
            {"paths": ["/v1/*"]},
            {"methods": ["GET"]},
            {"domain": ""},
        ]
        for rule_dict in partial_rules:
            try:
                rule = self.PolicyRule(rule_dict)
                result = rule.matches("example.com", "/", "GET")
                self.assertIsInstance(result, bool)
            except (ValueError, KeyError):
                pass  # OK to reject invalid rules.

    def test_empty_arrays_in_rule(self):
        """Empty arrays in rules don't crash."""
        rule = self.PolicyRule({
            "domain": "example.com",
            "paths": [],
            "methods": [],
        })
        # Empty paths/methods might match all or none - verify no crash.
        result = rule.matches("example.com", "/", "GET")
        self.assertIsInstance(result, bool)


class TestCacheFuzzing(unittest.TestCase):
    """Fuzzing tests for cache functions."""

    def setUp(self):
        """Clear cache before each test."""
        brig._cache.clear()

    def test_empty_key(self):
        """Empty key doesn't crash."""
        brig._set_cache("", "value")
        hit, value = brig._cached("")
        self.assertTrue(hit)

    def test_very_long_key(self):
        """Very long keys don't crash."""
        long_key = "x" * 100000
        brig._set_cache(long_key, "value")
        hit, value = brig._cached(long_key)
        self.assertTrue(hit)

    def test_unicode_keys(self):
        """Unicode keys don't crash."""
        keys = ["key_世界", "مفتاح", "🔑"]
        for key in keys:
            brig._set_cache(key, "value")
            hit, value = brig._cached(key)
            self.assertTrue(hit)

    def test_complex_values(self):
        """Complex values don't crash."""
        values = [
            None,
            True,
            False,
            0,
            -1,
            float('inf'),
            float('-inf'),
            [],
            {},
            [1, [2, [3]]],
            {"a": {"b": {"c": 1}}},
        ]
        for i, value in enumerate(values):
            brig._set_cache(f"key_{i}", value)
            hit, result = brig._cached(f"key_{i}")
            self.assertTrue(hit)
            self.assertEqual(result, value)


class TestSuspiciousDomainFuzzing(unittest.TestCase):
    """Fuzzing tests for is_suspicious_domain function."""

    def test_empty_domain(self):
        """Empty domain doesn't crash."""
        result = brig.is_suspicious_domain("")
        self.assertIsInstance(result, str)

    def test_very_long_domain(self):
        """Very long domain doesn't crash."""
        long_domain = "x" * 10000 + ".com"
        result = brig.is_suspicious_domain(long_domain)
        self.assertIsInstance(result, str)

    def test_random_domains(self):
        """Random domain strings don't crash."""
        for _ in range(100):
            domain = random_string(50, string.ascii_lowercase + ".-*")
            result = brig.is_suspicious_domain(domain)
            self.assertIsInstance(result, str)

    def test_numeric_domains(self):
        """Numeric-only domains don't crash."""
        numeric_domains = [
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "8.8.8.8",
            "256.256.256.256",  # Invalid IP.
            "1.2.3.4.5.6",     # Too many octets.
        ]
        for domain in numeric_domains:
            result = brig.is_suspicious_domain(domain)
            self.assertIsInstance(result, str)


class TestLoadCellDefinitionFuzzing(unittest.TestCase):
    """Fuzzing tests for load_cell_definition function."""

    def test_malformed_json(self):
        """Malformed JSON syntax is handled safely (exits with error)."""
        # Only test actual JSON syntax errors.
        malformed_jsons = [
            "",
            "not json",
            "{",
            '{"key": }',
            '{"key": undefined}',
        ]
        for content in malformed_jsons:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                f.write(content)
                f.flush()
                try:
                    with self.assertRaises(SystemExit):
                        brig.load_cell_definition(f.name)
                finally:
                    os.unlink(f.name)

    def test_valid_json_non_object(self):
        """Valid JSON that isn't an object is handled.

        Note: JSON like null, true, 123, "string", [1,2,3] is valid JSON
        but not valid cell definitions. The function may accept them
        (returning them as-is) since validation happens separately.
        """
        valid_non_objects = [
            "null",
            "true",
            '"string"',
            "123",
            "[1, 2, 3]",
        ]
        for content in valid_non_objects:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                f.write(content)
                f.flush()
                try:
                    # May return the parsed value or may fail - both OK.
                    result = brig.load_cell_definition(f.name)
                    # If it returns, that's fine - validation is separate.
                except SystemExit:
                    pass  # Also acceptable.
                finally:
                    os.unlink(f.name)

    def test_valid_but_empty_json(self):
        """Valid but empty JSON object is handled."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{}")
            f.flush()
            try:
                cell_def = brig.load_cell_definition(f.name)
                self.assertEqual(cell_def, {})
            finally:
                os.unlink(f.name)

    def test_json_with_extra_fields(self):
        """JSON with extra fields is handled."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "image": "alpine",
                "unknown_field": "value",
                "another_field": [1, 2, 3],
            }, f)
            f.flush()
            try:
                cell_def = brig.load_cell_definition(f.name)
                self.assertEqual(cell_def["image"], "alpine")
            finally:
                os.unlink(f.name)


class TestRateLimitFuzzing(unittest.TestCase):
    """Fuzzing tests for rate limiting."""

    def setUp(self):
        """Create temp directory for rate limit file."""
        self.temp_dir = tempfile.mkdtemp()
        self._original_rate_limit_file = brig.RATE_LIMIT_FILE
        brig.RATE_LIMIT_FILE = Path(self.temp_dir) / "rate_limit.json"

    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir)
        brig.RATE_LIMIT_FILE = self._original_rate_limit_file

    def test_corrupted_timestamps(self):
        """Corrupted timestamp data doesn't crash."""
        corrupted_data = [
            {"timestamps": "not a list"},
            {"timestamps": [None, None]},
            {"timestamps": ["string", "timestamps"]},
            {"timestamps": [float('inf'), float('-inf')]},
            {"timestamps": [1, 2, 3, "mixed", None]},
            {"wrong_key": [1, 2, 3]},
        ]
        for data in corrupted_data:
            with open(brig.RATE_LIMIT_FILE, 'w') as f:
                json.dump(data, f)
            # Should not crash.
            try:
                result = brig.check_rate_limit()
                self.assertIsInstance(result, bool)
            except (TypeError, ValueError):
                pass  # OK to fail on bad data.

    def test_many_rapid_checks(self):
        """Many rapid rate limit checks don't crash."""
        for _ in range(1000):
            result = brig.check_rate_limit()
            self.assertIsInstance(result, bool)


if __name__ == "__main__":
    unittest.main(verbosity=2)
