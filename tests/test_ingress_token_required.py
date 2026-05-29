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
from unittest.mock import MagicMock, patch


def _spec_with_ingress(name="alice"):
    from brig.cell.spec import CellSpec
    return CellSpec(
        name=name, image="alpine",
        ingress=[{"name": "api", "port": 8080,
                  "path_prefix": "/api", "auth": "token"}],
    )


class TestIngressTokenRequired(unittest.TestCase):
    def _patch_container_info(self):
        return patch(
            "brig.cell.reconciler._podman_inspect_json",
            return_value={"NetworkSettings": {"Networks": {
                "brig-alice": {"IPAddress": "10.60.1.5"},
            }}},
        )

    def test_no_token_raises_brigerror(self):
        from brig.cell.lifecycle import _register_cell_ingress
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            secrets_dir = Path(td)  # empty — no token
            with patch("brig.config.HostPaths.SECRETS_DIR", secrets_dir), \
                 self._patch_container_info():
                with self.assertRaises(BrigError) as ctx:
                    _register_cell_ingress(_spec_with_ingress(), MagicMock())
        msg = str(ctx.exception)
        self.assertIn("token", msg.lower())
        self.assertIn("alice", msg)

    def test_empty_token_raises_brigerror(self):
        from brig.cell.lifecycle import _register_cell_ingress
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            secrets_dir = Path(td)
            (secrets_dir / "alice-ingress-token").write_text("")
            with patch("brig.config.HostPaths.SECRETS_DIR", secrets_dir), \
                 self._patch_container_info():
                with self.assertRaises(BrigError) as ctx:
                    _register_cell_ingress(_spec_with_ingress(), MagicMock())
        self.assertIn("empty", str(ctx.exception).lower())

    def test_short_token_warns_but_proceeds(self):
        """Short tokens are insecure but not silently-broken — keep as warn."""
        from brig.cell.lifecycle import _register_cell_ingress
        with tempfile.TemporaryDirectory() as td:
            secrets_dir = Path(td)
            (secrets_dir / "alice-ingress-token").write_text("short")
            with patch("brig.config.HostPaths.SECRETS_DIR", secrets_dir), \
                 self._patch_container_info(), \
                 patch("brig.network.ingress.register_ingress") as mock_reg:
                _register_cell_ingress(_spec_with_ingress(), MagicMock())
                mock_reg.assert_called_once()

    def test_valid_token_registers_routes(self):
        from brig.cell.lifecycle import _register_cell_ingress
        with tempfile.TemporaryDirectory() as td:
            secrets_dir = Path(td)
            (secrets_dir / "alice-ingress-token").write_text("a" * 64)
            with patch("brig.config.HostPaths.SECRETS_DIR", secrets_dir), \
                 self._patch_container_info(), \
                 patch("brig.network.ingress.register_ingress") as mock_reg:
                _register_cell_ingress(_spec_with_ingress(), MagicMock())
                mock_reg.assert_called_once()


if __name__ == "__main__":
    unittest.main()
