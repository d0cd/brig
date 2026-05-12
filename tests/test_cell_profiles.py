"""Tests for brig.cell.profiles — trust profiles."""

import json
import tempfile
import unittest
from pathlib import Path

from brig.cell.profiles import BUILTIN_PROFILES, apply_profile, load_profile


class TestBuiltinProfiles(unittest.TestCase):
    """Test security-relevant profile properties."""

    def test_airgapped_no_network(self):
        self.assertEqual(BUILTIN_PROFILES["airgapped"]["network"], "none")

    def test_honeypot_deny_all(self):
        self.assertEqual(BUILTIN_PROFILES["honeypot"]["policy"]["deny"], ["*"])


class TestLoadProfile(unittest.TestCase):
    """Test load_profile() resolution."""

    def test_load_builtin(self):
        profile = load_profile("untrusted")
        self.assertEqual(profile["memory"], "512m")

    def test_load_nonexistent_raises(self):
        with self.assertRaises(ValueError, msg="Unknown profile"):
            load_profile("nonexistent-profile")

    def test_load_user_profile(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profiles_dir = Path(tmpdir)
            profile_file = profiles_dir / "custom.json"
            profile_file.write_text(json.dumps({"memory": "8g", "cpus": "8"}))
            profile = load_profile("custom", profiles_dir=profiles_dir)
            self.assertEqual(profile["memory"], "8g")


class TestApplyProfile(unittest.TestCase):
    """Test apply_profile() merging behavior."""

    def test_profile_fills_missing(self):
        spec = {"name": "test", "image": "alpine"}
        profile = {"memory": "1g", "cpus": "1"}
        merged = apply_profile(spec, profile)
        self.assertEqual(merged["memory"], "1g")
        self.assertEqual(merged["cpus"], "1")

    def test_spec_overrides_profile(self):
        spec = {"name": "test", "image": "alpine", "memory": "4g"}
        profile = {"memory": "1g", "cpus": "1"}
        merged = apply_profile(spec, profile)
        self.assertEqual(merged["memory"], "4g")  # Spec wins.
        self.assertEqual(merged["cpus"], "1")  # Profile fills.

    def test_policy_merge(self):
        spec = {"name": "test"}
        profile = {"policy": {"allow": ["example.com"], "deny": []}}
        merged = apply_profile(spec, profile)
        self.assertEqual(merged["policy"]["allow"], ["example.com"])

    def test_labels_merge(self):
        spec = {"labels": {"custom": "value"}}
        profile = {"labels": {"brig.profile": "test"}}
        merged = apply_profile(spec, profile)
        self.assertEqual(merged["labels"]["brig.profile"], "test")
        self.assertEqual(merged["labels"]["custom"], "value")
