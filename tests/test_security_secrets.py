"""Tests for brig.security.secrets — secret path validation.

Tests invariant 4: macOS state directory is untrusted.
"""

import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from brig.security.secrets import validate_secret_path


class TestSecretsAddSymlinkGuard(unittest.TestCase):
    """`brig secrets add` must refuse a pre-planted symlink at the target path
    (invariant 4: the secrets dir is untrusted) — else a symlink like
    `name -> ~/.ssh/authorized_keys` would let a write overwrite it. The lstat
    check + O_NOFOLLOW open both defend this."""

    def test_refuses_preplanted_symlink_and_leaves_target(self):
        from brig.commands.secrets_cmd import cmd_secrets_add
        from brig.config import HostPaths
        from brig.errors import BrigError
        HostPaths.SECRETS_DIR.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as td:
            victim = Path(td) / "victim"
            victim.write_text("original")
            link = HostPaths.SECRETS_DIR / "evil"
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(victim)
            # force=True proves the symlink check fires even on an overwrite.
            args = types.SimpleNamespace(
                name="evil", value="pwned", force=True, from_file=None)
            with self.assertRaises(BrigError) as ctx:
                cmd_secrets_add(args)
            self.assertIn("symlink", str(ctx.exception).lower())
            self.assertEqual(victim.read_text(), "original")  # not overwritten
            link.unlink()


class TestSecretsRmValidatesName(unittest.TestCase):
    """`brig secrets rm` must reject traversal/charset like `add` does, so it
    can't unlink a file outside the secrets dir."""

    def _args(self, name):
        return types.SimpleNamespace(name=name, yes=True)

    def test_traversal_name_rejected_before_unlink(self):
        from brig.commands.secrets_cmd import cmd_secrets_rm
        from brig.errors import BrigError
        for bad in ("../../etc/passwd", "a/b", "..", "bad name", "UPPER"):
            with patch("brig.commands.secrets_cmd.HostPaths") as hp:
                # If validation is skipped, unlink would be attempted; make the
                # path's unlink explode so a regression is loud.
                hp.SECRETS_DIR = Path("/nonexistent-secrets-dir")
                with self.assertRaises(BrigError, msg=f"{bad!r} should be rejected"):
                    cmd_secrets_rm(self._args(bad))


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
