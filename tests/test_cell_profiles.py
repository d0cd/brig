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

    def test_policy_merge_into_flat_lists(self):
        """Profile's nested policy.allow/deny prepends to the spec's
        flat policy_allow / policy_deny lists (the CellSpec shape)."""
        spec = {"name": "test"}
        profile = {"policy": {"allow": ["example.com"], "deny": ["bad.com"]}}
        merged = apply_profile(spec, profile)
        self.assertEqual(merged["policy_allow"], ["example.com"])
        self.assertEqual(merged["policy_deny"], ["bad.com"])

    def test_policy_profile_extends_existing_lists(self):
        """Profile baseline + cell additions both included; profile
        first (so cell adds extend it)."""
        spec = {"policy_allow": ["cell.com"]}
        profile = {"policy": {"allow": ["base.com"]}}
        merged = apply_profile(spec, profile)
        self.assertEqual(merged["policy_allow"], ["base.com", "cell.com"])

    def test_policy_tls_passthrough_propagates_from_profile(self):
        """Profile's policy.tls_passthrough prepends to the spec's flat
        policy_passthrough_tls list, same shape as allow/deny."""
        spec = {"name": "test"}
        profile = {"policy": {
            "allow": ["chatgpt.com"],
            "tls_passthrough": ["chatgpt.com"],
        }}
        merged = apply_profile(spec, profile)
        self.assertEqual(merged["policy_passthrough_tls"], ["chatgpt.com"])

    def test_labels_merge_dict_shape(self):
        spec = {"labels": {"custom": "value"}}
        profile = {"labels": {"brig.profile": "test"}}
        merged = apply_profile(spec, profile)
        self.assertEqual(merged["labels"]["brig.profile"], "test")
        self.assertEqual(merged["labels"]["custom"], "value")

    def test_labels_merge_list_shape_preserves_trust_marker(self):
        # The shape production actually uses: CLI/SDK seed labels as a LIST.
        # brig.profile=untrusted MUST survive — the ingress auth:none replay
        # gate reads it off the container label. (Regression: the dict-only
        # merge dropped it for every real untrusted cell.)
        from brig.cell.profiles import BUILTIN_PROFILES
        merged = apply_profile({"labels": []}, BUILTIN_PROFILES["untrusted"])
        self.assertIn("brig.profile=untrusted", merged["labels"])

    def test_labels_merge_custom_list_form_profile(self):
        merged = apply_profile(
            {"labels": ["x=1"]}, {"labels": {"brig.profile": "untrusted"}})
        self.assertIn("brig.profile=untrusted", merged["labels"])
        self.assertIn("x=1", merged["labels"])


class TestLoadProfileGuards(unittest.TestCase):
    """load_profile's own guards — reached from the CLI/SDK BEFORE
    validate_cell_definition, so they're load-bearing on unvalidated input."""

    def test_user_file_shadowing_builtin_rejected(self):
        # The reservation branch (no name short-circuit for honeypot/airgapped).
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "honeypot.yaml").write_text("memory: 8g\n")
            with self.assertRaises(ValueError) as ctx:
                load_profile("honeypot", profiles_dir=d)
            self.assertIn("shadow", str(ctx.exception).lower())

    def test_untrusted_shadow_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "untrusted.yaml").write_text("labels:\n  brig.profile: relaxed\n")
            with self.assertRaises(ValueError):
                load_profile("untrusted", profiles_dir=d)

    def test_traversal_name_rejected(self):
        for bad in ("../../etc/passwd", "a/b", "..", "x\x00y"):
            with self.assertRaises(ValueError):
                load_profile(bad)
