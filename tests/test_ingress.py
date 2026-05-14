"""Tests for ingress — spec validation, route management, and addon security.

Covers:
  - CellSpec ingress field validation
  - Ingress route registration/deregistration
  - Ingress addon route matching
  - Ingress addon token authentication
  - Security: path traversal, auth bypass, SSRF
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from brig.cell.spec import CellSpec, validate_cell_definition


class TestIngressSpecValidation(unittest.TestCase):
    """Test validate_cell_definition() for ingress field."""

    def test_valid_ingress(self):
        cell_def = {
            "name": "test",
            "image": "alpine",
            "ingress": [
                {"name": "api", "port": 8642, "path_prefix": "/api", "auth": "token"},
            ],
        }
        errors = validate_cell_definition(cell_def)
        self.assertEqual(errors, [])

    def test_valid_multiple_ingress(self):
        cell_def = {
            "name": "test",
            "image": "alpine",
            "ingress": [
                {"name": "api", "port": 8642, "path_prefix": "/api", "auth": "token"},
                {"name": "dashboard", "port": 9119, "path_prefix": "/dashboard", "auth": "token"},
            ],
        }
        errors = validate_cell_definition(cell_def)
        self.assertEqual(errors, [])

    def test_ingress_not_list(self):
        errors = validate_cell_definition({"ingress": "bad"})
        self.assertTrue(any("must be a list" in e for e in errors))

    def test_ingress_entry_not_dict(self):
        errors = validate_cell_definition({"ingress": ["bad"]})
        self.assertTrue(any("must be a dict" in e for e in errors))

    def test_ingress_missing_name(self):
        errors = validate_cell_definition({"ingress": [
            {"port": 8080, "path_prefix": "/api", "auth": "token"},
        ]})
        self.assertTrue(any("name" in e and "required" in e for e in errors))

    def test_ingress_invalid_name(self):
        errors = validate_cell_definition({"ingress": [
            {"name": "INVALID!", "port": 8080, "path_prefix": "/api", "auth": "token"},
        ]})
        self.assertTrue(any("name" in e and "lowercase" in e for e in errors))

    def test_ingress_duplicate_name(self):
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "port": 8080, "path_prefix": "/api", "auth": "token"},
            {"name": "api", "port": 9090, "path_prefix": "/other", "auth": "token"},
        ]})
        self.assertTrue(any("Duplicate" in e and "name" in e for e in errors))

    def test_ingress_missing_port(self):
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "path_prefix": "/api", "auth": "token"},
        ]})
        self.assertTrue(any("port" in e and "required" in e for e in errors))

    def test_ingress_port_zero(self):
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "port": 0, "path_prefix": "/api", "auth": "token"},
        ]})
        self.assertTrue(any("port" in e and "1-65535" in e for e in errors))

    def test_ingress_port_too_large(self):
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "port": 70000, "path_prefix": "/api", "auth": "token"},
        ]})
        self.assertTrue(any("port" in e and "1-65535" in e for e in errors))

    def test_ingress_port_not_int(self):
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "port": "8080", "path_prefix": "/api", "auth": "token"},
        ]})
        self.assertTrue(any("port" in e and "integer" in e for e in errors))

    def test_ingress_missing_path_prefix(self):
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "port": 8080, "auth": "token"},
        ]})
        self.assertTrue(any("path_prefix" in e and "required" in e for e in errors))

    def test_ingress_path_prefix_no_leading_slash(self):
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "port": 8080, "path_prefix": "api", "auth": "token"},
        ]})
        self.assertTrue(any("path_prefix" in e and "'/'" in e for e in errors))

    def test_ingress_path_prefix_traversal(self):
        """Security: path traversal in path_prefix must be rejected."""
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "port": 8080, "path_prefix": "/api/../etc", "auth": "token"},
        ]})
        self.assertTrue(any("path_prefix" in e and ".." in e for e in errors))

    def test_ingress_path_prefix_invalid_chars(self):
        """Security: special characters in path_prefix must be rejected."""
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "port": 8080, "path_prefix": "/api?query=1", "auth": "token"},
        ]})
        self.assertTrue(any("path_prefix" in e and "invalid" in e for e in errors))

    def test_ingress_duplicate_path_prefix(self):
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "port": 8080, "path_prefix": "/api", "auth": "token"},
            {"name": "api2", "port": 9090, "path_prefix": "/api", "auth": "token"},
        ]})
        self.assertTrue(any("Duplicate" in e and "path_prefix" in e for e in errors))

    def test_ingress_missing_auth(self):
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "port": 8080, "path_prefix": "/api"},
        ]})
        self.assertTrue(any("auth" in e and "required" in e for e in errors))

    def test_ingress_invalid_auth_method(self):
        errors = validate_cell_definition({"ingress": [
            {"name": "api", "port": 8080, "path_prefix": "/api", "auth": "none"},
        ]})
        self.assertTrue(any("auth" in e and "must be one of" in e for e in errors))

    def test_ingress_too_many_entries(self):
        entries = [
            {"name": f"api{i}", "port": 8080 + i, "path_prefix": f"/api{i}", "auth": "token"}
            for i in range(10)
        ]
        errors = validate_cell_definition({"ingress": entries})
        self.assertTrue(any("Too many" in e for e in errors))

    def test_ingress_with_airgapped_rejected(self):
        """Security: ingress cannot be used with airgapped cells."""
        errors = validate_cell_definition({
            "network": "none",
            "ingress": [
                {"name": "api", "port": 8080, "path_prefix": "/api", "auth": "token"},
            ],
        })
        self.assertTrue(any("airgapped" in e for e in errors))

    def test_no_ingress_is_valid(self):
        """Cells without ingress should work exactly as before."""
        errors = validate_cell_definition({"name": "test", "image": "alpine"})
        self.assertEqual(errors, [])

    def test_empty_ingress_is_valid(self):
        errors = validate_cell_definition({"ingress": []})
        self.assertEqual(errors, [])


class TestCellSpecIngress(unittest.TestCase):
    """Test CellSpec dataclass with ingress field."""

    def test_default_empty_ingress(self):
        spec = CellSpec(name="test", image="alpine")
        self.assertEqual(spec.ingress, [])

    def test_ingress_set(self):
        ingress = [{"name": "api", "port": 8080, "path_prefix": "/api", "auth": "token"}]
        spec = CellSpec(name="test", image="alpine", ingress=ingress)
        self.assertEqual(spec.ingress, ingress)


class TestIngressRouteManagement(unittest.TestCase):
    """Test ingress route registration/deregistration."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.routes_file = Path(self.tmpdir) / "ingress-routes.json"
        self.lock_file = self.routes_file.with_suffix(".lock")

    @patch("brig.network.ingress.HostPaths")
    def test_register_ingress(self, mock_paths):
        mock_paths.INGRESS_ROUTES_FILE = self.routes_file
        mock_paths.SECRETS_DIR = Path(self.tmpdir) / "secrets"

        from brig.network.ingress import register_ingress
        register_ingress(
            "mycell", "10.60.1.2",
            [{"name": "api", "port": 8642, "path_prefix": "/api", "auth": "token"}],
            "test-token-123",
        )

        data = json.loads(self.routes_file.read_text())
        self.assertEqual(len(data["routes"]), 1)
        route = data["routes"][0]
        self.assertEqual(route["cell"], "mycell")
        self.assertEqual(route["cell_ip"], "10.60.1.2")
        self.assertEqual(route["port"], 8642)
        self.assertEqual(route["path_prefix"], "/api")
        # Token should be hashed, not stored raw.
        # Token must be hashed, not stored raw.
        expected_hash = hashlib.sha256(b"test-token-123").hexdigest()
        self.assertEqual(route["auth_secret_hash"], expected_hash)
        # Raw token must not appear anywhere in the file.
        self.assertNotIn("test-token-123", self.routes_file.read_text())

    @patch("brig.network.ingress.HostPaths")
    def test_register_idempotent(self, mock_paths):
        """Registering the same cell twice replaces routes, doesn't duplicate."""
        mock_paths.INGRESS_ROUTES_FILE = self.routes_file

        from brig.network.ingress import register_ingress
        register_ingress(
            "mycell", "10.60.1.2",
            [{"name": "api", "port": 8642, "path_prefix": "/api", "auth": "token"}],
            "token1",
        )
        register_ingress(
            "mycell", "10.60.1.3",
            [{"name": "api", "port": 9999, "path_prefix": "/api", "auth": "token"}],
            "token2",
        )

        data = json.loads(self.routes_file.read_text())
        self.assertEqual(len(data["routes"]), 1)
        self.assertEqual(data["routes"][0]["cell_ip"], "10.60.1.3")

    @patch("brig.network.ingress.HostPaths")
    def test_deregister_ingress(self, mock_paths):
        mock_paths.INGRESS_ROUTES_FILE = self.routes_file

        from brig.network.ingress import deregister_ingress, register_ingress
        register_ingress(
            "mycell", "10.60.1.2",
            [{"name": "api", "port": 8642, "path_prefix": "/api", "auth": "token"}],
            "token",
        )
        deregister_ingress("mycell")

        data = json.loads(self.routes_file.read_text())
        self.assertEqual(len(data["routes"]), 0)

    @patch("brig.network.ingress.HostPaths")
    def test_deregister_nonexistent_is_safe(self, mock_paths):
        """Deregistering a cell that has no routes is a no-op."""
        mock_paths.INGRESS_ROUTES_FILE = self.routes_file
        from brig.network.ingress import deregister_ingress
        deregister_ingress("nonexistent")  # Should not raise.

    @patch("brig.network.ingress.HostPaths")
    def test_deregister_preserves_other_cells(self, mock_paths):
        mock_paths.INGRESS_ROUTES_FILE = self.routes_file

        from brig.network.ingress import deregister_ingress, register_ingress
        register_ingress(
            "cell1", "10.60.1.2",
            [{"name": "api", "port": 8642, "path_prefix": "/api", "auth": "token"}],
            "token1",
        )
        register_ingress(
            "cell2", "10.60.2.2",
            [{"name": "web", "port": 80, "path_prefix": "/web", "auth": "token"}],
            "token2",
        )
        deregister_ingress("cell1")

        data = json.loads(self.routes_file.read_text())
        self.assertEqual(len(data["routes"]), 1)
        self.assertEqual(data["routes"][0]["cell"], "cell2")


class TestIngressAddonRouteMatching(unittest.TestCase):
    """Test the ingress addon route matching logic."""

    def _make_route(self, **kwargs):
        from importlib import import_module
        # Import from addons path — need to handle the path.
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "addons"))
        try:
            from ingress import IngressRoute
        finally:
            sys.path.pop(0)
        defaults = {
            "cell": "test",
            "cell_ip": "10.60.1.2",
            "name": "api",
            "port": 8642,
            "path_prefix": "/api",
            "auth_secret_hash": "abc123",
        }
        defaults.update(kwargs)
        return IngressRoute(defaults)

    def test_exact_prefix_match(self):
        route = self._make_route(path_prefix="/api")
        self.assertTrue(route.matches_path("/api"))
        self.assertTrue(route.matches_path("/api/v1/chat"))
        self.assertTrue(route.matches_path("/api/"))

    def test_prefix_boundary(self):
        """Security: /api must NOT match /apikeys (segment boundary)."""
        route = self._make_route(path_prefix="/api")
        self.assertFalse(route.matches_path("/apikeys"))
        self.assertFalse(route.matches_path("/apiv2"))

    def test_no_match(self):
        route = self._make_route(path_prefix="/api")
        self.assertFalse(route.matches_path("/dashboard"))
        self.assertFalse(route.matches_path("/"))


class TestIngressAddonTokenAuth(unittest.TestCase):
    """Test the ingress addon token authentication."""

    def _get_router_class(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "addons"))
        try:
            from ingress import IngressRouter
        finally:
            sys.path.pop(0)
        return IngressRouter

    def test_valid_token(self):
        """Valid Bearer token should authenticate."""
        Router = self._get_router_class()
        token = "my-secret-token"
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        request = MagicMock()
        request.headers = {"Authorization": f"Bearer {token}"}

        self.assertTrue(Router._validate_token(request, token_hash))

    def test_wrong_token(self):
        """Wrong token should fail."""
        Router = self._get_router_class()
        token_hash = hashlib.sha256(b"correct-token").hexdigest()

        request = MagicMock()
        request.headers = {"Authorization": "Bearer wrong-token"}

        self.assertFalse(Router._validate_token(request, token_hash))

    def test_missing_auth_header(self):
        """Missing Authorization header should fail."""
        Router = self._get_router_class()

        request = MagicMock()
        request.headers = {}

        self.assertFalse(Router._validate_token(request, "somehash"))

    def test_wrong_scheme(self):
        """Non-Bearer scheme should fail."""
        Router = self._get_router_class()

        request = MagicMock()
        request.headers = {"Authorization": "Basic dXNlcjpwYXNz"}

        self.assertFalse(Router._validate_token(request, "somehash"))

    def test_empty_token(self):
        """Empty Bearer token should fail."""
        Router = self._get_router_class()

        request = MagicMock()
        request.headers = {"Authorization": "Bearer "}

        self.assertFalse(Router._validate_token(request, "somehash"))

    def test_constant_time_comparison(self):
        """Token comparison uses hmac.compare_digest (constant-time)."""
        Router = self._get_router_class()
        # This test verifies the implementation uses hmac.compare_digest
        # by checking the source code — timing attacks are hard to test.
        import inspect
        source = inspect.getsource(Router._validate_token)
        self.assertIn("hmac.compare_digest", source)


class TestIngressAddonCellIpValidation(unittest.TestCase):
    """Test that the ingress addon validates cell IPs."""

    def _get_router(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "addons"))
        try:
            from ingress import IngressRouter
        finally:
            sys.path.pop(0)
        return IngressRouter()

    def test_valid_cell_ip_loaded(self):
        """Routes with valid cell IPs in 10.60.x.x range are loaded."""
        router = self._get_router()
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"routes": [{
                "cell": "test",
                "cell_ip": "10.60.1.2",
                "name": "api",
                "port": 8642,
                "path_prefix": "/api",
                "auth_secret_hash": "abc",
            }]}, f)
            f.flush()

            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "addons"))
            try:
                import ingress as ingress_mod
                old_path = ingress_mod.ROUTES_FILE
                ingress_mod.ROUTES_FILE = Path(f.name)
                try:
                    router._reload_routes()
                    self.assertIn("test", router.routes)
                finally:
                    ingress_mod.ROUTES_FILE = old_path
            finally:
                sys.path.pop(0)

    def test_invalid_cell_ip_rejected(self):
        """Security: routes with IPs outside 10.60.x.x are skipped."""
        router = self._get_router()
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"routes": [{
                "cell": "evil",
                "cell_ip": "192.168.1.1",
                "name": "api",
                "port": 8642,
                "path_prefix": "/api",
                "auth_secret_hash": "abc",
            }]}, f)
            f.flush()

            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "addons"))
            try:
                import ingress as ingress_mod
                old_path = ingress_mod.ROUTES_FILE
                ingress_mod.ROUTES_FILE = Path(f.name)
                try:
                    router._reload_routes()
                    self.assertNotIn("evil", router.routes)
                finally:
                    ingress_mod.ROUTES_FILE = old_path
            finally:
                sys.path.pop(0)


class TestIngressWebSocketLogging(unittest.TestCase):
    """Test that WebSocket hooks are present in enforce.py and logger.py."""

    def test_enforce_has_websocket_hook(self):
        """enforce.py must have websocket_message method."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "addons"))
        try:
            from enforce import PolicyEnforcer
        finally:
            sys.path.pop(0)
        self.assertTrue(hasattr(PolicyEnforcer, "websocket_message"))

    def test_logger_has_websocket_hook(self):
        """logger.py must have websocket_message method."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "addons"))
        try:
            from logger import RequestLogger
        finally:
            sys.path.pop(0)
        self.assertTrue(hasattr(RequestLogger, "websocket_message"))
