"""Tests for brig.security.secrets — secret path validation.

Tests invariant 4: macOS state directory is untrusted.
"""

import tempfile
import unittest
from pathlib import Path

from brig.security.secrets import validate_secret_path


class TestValidateSecretPath(unittest.TestCase):
    """Test validate_secret_path() defends against path traversal."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.secrets_dir = Path(self.tmpdir) / "secrets"
        self.secrets_dir.mkdir()

    def test_legit_secret(self):
        secret_file = self.secrets_dir / "api-key"
        secret_file.write_text("secret-value")
        result = validate_secret_path("api-key", self.secrets_dir)
        self.assertEqual(result, secret_file.resolve())

    def test_dotdot_traversal_rejected(self):
        """Path with .. is rejected."""
        # Create a file outside secrets dir.
        outside = Path(self.tmpdir) / "outside"
        outside.write_text("bad")
        with self.assertRaises(ValueError, msg="escapes secrets directory"):
            validate_secret_path("../outside", self.secrets_dir)

    def test_symlink_escaping_rejected(self):
        """Symlink pointing outside secrets dir is rejected."""
        outside = Path(self.tmpdir) / "outside-secret"
        outside.write_text("bad")
        link = self.secrets_dir / "legit-name"
        link.symlink_to(outside)
        with self.assertRaises(ValueError, msg="escapes secrets directory"):
            validate_secret_path("legit-name", self.secrets_dir)

    def test_double_hop_symlink_rejected(self):
        """Chain of symlinks escaping secrets dir is rejected."""
        outside = Path(self.tmpdir) / "outside"
        outside.write_text("bad")
        hop1 = Path(self.tmpdir) / "hop1"
        hop1.symlink_to(outside)
        hop2 = self.secrets_dir / "hop2"
        hop2.symlink_to(hop1)
        with self.assertRaises(ValueError, msg="escapes secrets directory"):
            validate_secret_path("hop2", self.secrets_dir)

    def test_nonexistent_secret(self):
        """Secret that doesn't exist raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError, msg="Secret not found"):
            validate_secret_path("nonexistent", self.secrets_dir)

    def test_nonexistent_dir(self):
        """Nonexistent secrets dir raises FileNotFoundError."""
        bad_dir = Path(self.tmpdir) / "nope"
        with self.assertRaises(FileNotFoundError):
            validate_secret_path("any", bad_dir)

    def test_symlink_within_dir_allowed(self):
        """Symlink staying within secrets dir is allowed."""
        real = self.secrets_dir / "real-secret"
        real.write_text("value")
        link = self.secrets_dir / "alias"
        link.symlink_to(real)
        result = validate_secret_path("alias", self.secrets_dir)
        self.assertEqual(result, real.resolve())
