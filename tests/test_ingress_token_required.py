"""Cell yaml with ingress + auth: token requires the token to exist
before the cell can register routes. Missing token = BrigError, not
a silent WARN.

Regression for aitelier-feedback #6: silent ingress-broken state
(routes registered, every request 401s) is worse than failing fast.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _ingress_spec():
    return [{"name": "api", "port": 8080,
             "path_prefix": "/api", "auth": "token"}]


class TestIngressTokenRequired(unittest.TestCase):
    def _patch_container_info(self):
        return patch(
            "brig.cell.reconciler._podman_inspect_json",
            return_value={"NetworkSettings": {"Networks": {
                "brig-alice": {"IPAddress": "10.60.1.5"},
            }}},
        )

    def test_no_token_raises_brigerror(self):
        from brig.cell.lifecycle import register_ingress_for
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            secrets_dir = Path(td)  # empty — no token
            with patch("brig.config.HostPaths.SECRETS_DIR", secrets_dir), \
                 self._patch_container_info():
                with self.assertRaises(BrigError) as ctx:
                    register_ingress_for("alice", _ingress_spec())
        msg = str(ctx.exception)
        self.assertIn("token", msg.lower())
        self.assertIn("alice", msg)

    def test_empty_token_raises_brigerror(self):
        from brig.cell.lifecycle import register_ingress_for
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            secrets_dir = Path(td)
            (secrets_dir / "alice-ingress-token").write_text("")
            with patch("brig.config.HostPaths.SECRETS_DIR", secrets_dir), \
                 self._patch_container_info():
                with self.assertRaises(BrigError) as ctx:
                    register_ingress_for("alice", _ingress_spec())
        self.assertIn("empty", str(ctx.exception).lower())

    def test_short_token_rejected(self):
        """A token below the length floor is rejected — a weak token in the
        untrusted routes file is offline-crackable at SHA-256 speed."""
        from brig.cell.lifecycle import register_ingress_for
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            secrets_dir = Path(td)
            (secrets_dir / "alice-ingress-token").write_text("short")
            with patch("brig.config.HostPaths.SECRETS_DIR", secrets_dir), \
                 self._patch_container_info(), \
                 patch("brig.network.ingress.register_ingress") as mock_reg:
                with self.assertRaises(BrigError) as ctx:
                    register_ingress_for("alice", _ingress_spec())
                mock_reg.assert_not_called()
        self.assertIn("alice", str(ctx.exception))

    def test_valid_token_registers_routes(self):
        from brig.cell.lifecycle import register_ingress_for
        with tempfile.TemporaryDirectory() as td:
            secrets_dir = Path(td)
            (secrets_dir / "alice-ingress-token").write_text("a" * 64)
            with patch("brig.config.HostPaths.SECRETS_DIR", secrets_dir), \
                 self._patch_container_info(), \
                 patch("brig.network.ingress.register_ingress") as mock_reg:
                register_ingress_for("alice", _ingress_spec())
                mock_reg.assert_called_once()


if __name__ == "__main__":
    unittest.main()
