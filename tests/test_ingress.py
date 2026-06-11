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
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Mock mitmproxy so `from ingress import IngressRouter` works no matter
# what order pytest invokes the test files in. Without this, test_ingress.py
# silently relied on an earlier file (test_addons_ops.py et al.) setting
# the same mock first — running test_ingress.py in isolation crashed.
for _mod in (
    "mitmproxy", "mitmproxy.http", "mitmproxy.ctx", "mitmproxy.connection",
):
    sys.modules.setdefault(_mod, MagicMock())

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

    def test_auth_none_accepted(self):
        cell_def = {
            "name": "test", "image": "alpine",
            "ingress": [
                {"name": "dash", "port": 9119, "path_prefix": "/dash", "auth": "none"},
            ],
        }
        self.assertEqual(validate_cell_definition(cell_def), [])

    def test_auth_none_rejected_on_untrusted_profile(self):
        cell_def = {
            "name": "test", "image": "alpine", "profile": "untrusted",
            "ingress": [
                {"name": "dash", "port": 9119, "path_prefix": "/dash", "auth": "none"},
            ],
        }
        errs = validate_cell_definition(cell_def)
        self.assertTrue(any("auth: none" in e for e in errs), errs)

    def test_auth_token_still_ok_on_untrusted_profile(self):
        # token ingress must remain allowed on untrusted — only `none` is gated.
        cell_def = {
            "name": "test", "image": "alpine", "profile": "untrusted",
            "ingress": [
                {"name": "api", "port": 8642, "path_prefix": "/api", "auth": "token"},
            ],
        }
        errs = validate_cell_definition(cell_def)
        self.assertFalse(any("ingress" in e for e in errs), errs)

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
            {"name": "api", "port": 8080, "path_prefix": "/api", "auth": "basic"},
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
        errors = validate_cell_definition({"name": "x", "ingress": []})
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
        # Token must be salted-hashed, not stored raw.
        self.assertIn("auth_secret_hash", route)
        self.assertIn("auth_salt", route)
        self.assertEqual(len(route["auth_salt"]), 32, "Salt must be 32 hex chars")
        # Verify the stored hash matches salted computation.
        expected_hash = hashlib.sha256(
            (route["auth_salt"] + "test-token-123").encode()
        ).hexdigest()
        self.assertEqual(route["auth_secret_hash"], expected_hash)
        # Raw token must not appear anywhere in the file.
        self.assertNotIn("test-token-123", self.routes_file.read_text())

    @patch("brig.network.ingress.HostPaths")
    def test_register_auth_none_needs_no_token(self, mock_paths):
        mock_paths.INGRESS_ROUTES_FILE = self.routes_file
        from brig.network.ingress import register_ingress
        register_ingress(
            "mycell", "10.60.1.2",
            [{"name": "dash", "port": 9119, "path_prefix": "/dash", "auth": "none"}],
            None,  # transparent — no token
        )
        route = json.loads(self.routes_file.read_text())["routes"][0]
        self.assertEqual(route["auth"], "none")
        self.assertEqual(route["auth_secret_hash"], "")
        self.assertEqual(route["auth_salt"], "")

    @patch("brig.network.ingress.HostPaths")
    def test_register_mixed_auth_only_token_route_gets_hash(self, mock_paths):
        mock_paths.INGRESS_ROUTES_FILE = self.routes_file
        from brig.network.ingress import register_ingress
        register_ingress(
            "mycell", "10.60.1.2",
            [{"name": "api", "port": 8642, "path_prefix": "/api", "auth": "token"},
             {"name": "dash", "port": 9119, "path_prefix": "/dash", "auth": "none"}],
            "test-token-123",
        )
        routes = {r["name"]: r for r in json.loads(self.routes_file.read_text())["routes"]}
        self.assertTrue(routes["api"]["auth_secret_hash"])      # gated
        self.assertEqual(routes["dash"]["auth_secret_hash"], "")  # open

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

    @patch("brig.network.ingress.HostPaths")
    def test_sweep_orphan_routes_drops_unallocated(self, mock_paths):
        """sweep_orphan_routes deletes routes whose cell isn't currently
        allocated a subnet. Defends against subnet reuse handing a new
        cell another cell's auth hash."""
        mock_paths.INGRESS_ROUTES_FILE = self.routes_file
        from brig.network.ingress import register_ingress, sweep_orphan_routes
        register_ingress("alive", "10.60.1.2",
            [{"name": "api", "port": 8000, "path_prefix": "/a", "auth": "token"}],
            "t1")
        register_ingress("ghost", "10.60.2.2",
            [{"name": "api", "port": 8000, "path_prefix": "/g", "auth": "token"}],
            "t2")

        removed = sweep_orphan_routes(live_cells={"alive"})

        self.assertEqual(removed, 1)
        routes = json.loads(self.routes_file.read_text())["routes"]
        self.assertEqual([r["cell"] for r in routes], ["alive"])

    @patch("brig.network.ingress.HostPaths")
    def test_sweep_orphan_routes_noop_when_clean(self, mock_paths):
        mock_paths.INGRESS_ROUTES_FILE = self.routes_file
        from brig.network.ingress import register_ingress, sweep_orphan_routes
        register_ingress("alive", "10.60.1.2",
            [{"name": "api", "port": 8000, "path_prefix": "/a", "auth": "token"}],
            "t1")
        removed = sweep_orphan_routes(live_cells={"alive"})
        self.assertEqual(removed, 0)


class TestRegisterIngressForValidation(unittest.TestCase):
    """register_ingress_for accepts ingress entries from on-disk metadata
    (untrusted per invariant 4) and must re-validate them with the same
    rules `_v_ingress_entry` applies at yaml parse time."""

    def _entry(self, **over):
        e = {"name": "api", "port": 8000, "path_prefix": "/api", "auth": "token"}
        e.update(over)
        return e

    def test_tampered_port_zero_rejected(self):
        from unittest.mock import patch
        from brig.cell.lifecycle import register_ingress_for
        from brig.errors import BrigError
        with patch("brig.cell.reconciler._podman_inspect_json",
                   return_value={"NetworkSettings": {"Networks":
                       {"brig-c": {"IPAddress": "10.60.1.2"}}}}):
            with self.assertRaises(BrigError):
                register_ingress_for("c", [self._entry(port=0)])

    def test_tampered_port_out_of_range_rejected(self):
        from unittest.mock import patch
        from brig.cell.lifecycle import register_ingress_for
        from brig.errors import BrigError
        with patch("brig.cell.reconciler._podman_inspect_json",
                   return_value={"NetworkSettings": {"Networks":
                       {"brig-c": {"IPAddress": "10.60.1.2"}}}}):
            with self.assertRaises(BrigError):
                register_ingress_for("c", [self._entry(port=99999)])

    def test_tampered_path_prefix_rejected(self):
        from unittest.mock import patch
        from brig.cell.lifecycle import register_ingress_for
        from brig.errors import BrigError
        with patch("brig.cell.reconciler._podman_inspect_json",
                   return_value={"NetworkSettings": {"Networks":
                       {"brig-c": {"IPAddress": "10.60.1.2"}}}}):
            for bad in ("not-absolute", "/with/../traversal", "/has spaces"):
                with self.assertRaises(BrigError, msg=f"prefix {bad!r}"):
                    register_ingress_for("c", [self._entry(path_prefix=bad)])

    def test_unknown_auth_method_rejected(self):
        from unittest.mock import patch
        from brig.cell.lifecycle import register_ingress_for
        from brig.errors import BrigError
        with patch("brig.cell.reconciler._podman_inspect_json",
                   return_value={"NetworkSettings": {"Networks":
                       {"brig-c": {"IPAddress": "10.60.1.2"}}}}):
            with self.assertRaises(BrigError):
                register_ingress_for("c", [self._entry(auth="bearer")])

    def test_missing_required_field_rejected(self):
        from unittest.mock import patch
        from brig.cell.lifecycle import register_ingress_for
        from brig.errors import BrigError
        with patch("brig.cell.reconciler._podman_inspect_json",
                   return_value={"NetworkSettings": {"Networks":
                       {"brig-c": {"IPAddress": "10.60.1.2"}}}}):
            with self.assertRaises(BrigError):
                register_ingress_for("c", [{"name": "api", "port": 8000}])


class TestIngressAddonRouteMatching(unittest.TestCase):
    """Test the ingress addon route matching logic."""

    def _make_route(self, **kwargs):
        # Import from addons path — need to handle the path.
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
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
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
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

    def test_salted_token(self):
        """Validation must apply the salt: production uses a real 16-byte
        salt, so the hash is sha256(salt + token), not sha256(token)."""
        Router = self._get_router_class()
        salt = "0123456789abcdef"
        token = "my-secret-token"
        expected = hashlib.sha256((salt + token).encode()).hexdigest()

        request = MagicMock()
        request.headers = {"Authorization": f"Bearer {token}"}

        self.assertTrue(Router._validate_token(request, expected, salt))
        # The UNsalted hash must NOT validate when a salt is in force.
        unsalted = hashlib.sha256(token.encode()).hexdigest()
        self.assertFalse(Router._validate_token(request, unsalted, salt))
        # A different salt must also fail.
        self.assertFalse(Router._validate_token(request, expected, "ffffffffffffffff"))

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


class TestIngressAddonAttribution(unittest.TestCase):
    """Rejected ingress attempts (auth fail, oversize) must attribute to the
    cell so they appear in `brig cell network <cell>`, not unknown.jsonl."""

    def _router_with_route(self, **route_kw):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
        try:
            from ingress import IngressRoute, IngressRouter
        finally:
            sys.path.pop(0)
        defaults = {
            "cell": "sa", "cell_ip": "10.60.1.5", "name": "api",
            "port": 8642, "path_prefix": "/api", "auth_secret_hash": "deadbeef",
            "auth_salt": "s",
        }
        defaults.update(route_kw)
        router = IngressRouter()
        router.routes = {"sa": [IngressRoute(defaults)]}
        router._check_reload = lambda: None  # don't reload over injected routes
        return router

    def _flow(self, path="/sa/api/x", auth=None):
        flow = MagicMock()
        flow.client_conn.sockname = ("0.0.0.0", 8443)  # ingress listener port
        flow.client_conn.peername = ("203.0.113.9", 54321)
        flow.request.path = path
        flow.request.headers = {"Authorization": auth} if auth else {}
        flow.metadata = {}
        flow.response = None
        return flow

    def test_auth_failure_attributes_to_cell(self):
        # mitmproxy.http is a MagicMock here, so assert the fix's observable —
        # the flow is attributed to the cell — and that the rewrite (success
        # path) did NOT run (host left unchanged), confirming the auth-fail path.
        router = self._router_with_route()
        flow = self._flow(auth="Bearer wrong")
        router.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.metadata.get("cell"), "sa")
        self.assertEqual(flow.metadata.get("ingress_route"), "api")
        self.assertNotEqual(flow.request.host, "10.60.1.5")  # not proxied

    def test_route_miss_not_attributed(self):
        router = self._router_with_route()
        flow = self._flow(path="/nope/x")
        router.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertIsNone(flow.metadata.get("cell"))

    def test_success_attributes_and_rewrites(self):
        token, salt = "good-token", "s"
        h = hashlib.sha256((salt + token).encode()).hexdigest()
        router = self._router_with_route(auth_secret_hash=h, auth_salt=salt)
        flow = self._flow(auth=f"Bearer {token}")
        router.request(flow)
        self.assertEqual(flow.metadata.get("ingress_route"), "api")
        self.assertEqual(flow.request.host, "10.60.1.5")  # rewritten to cell

    def test_auth_none_passes_through_without_token(self):
        # No Authorization header, yet the request is proxied (no 401) — the
        # cell's app is the gate.
        router = self._router_with_route(auth="none")
        flow = self._flow()
        router.request(flow)
        self.assertEqual(flow.request.host, "10.60.1.5")  # proxied to cell
        self.assertEqual(flow.metadata.get("ingress_route"), "api")

    def test_auth_none_preserves_authorization_header(self):
        # Transparent: brig must NOT strip the credential the app authenticates with.
        router = self._router_with_route(auth="none")
        flow = self._flow(auth="Bearer app-session-token")
        router.request(flow)
        self.assertEqual(flow.request.headers.get("Authorization"),
                         "Bearer app-session-token")
        self.assertEqual(flow.request.host, "10.60.1.5")


class TestIngressAddonCellIpValidation(unittest.TestCase):
    """Test that the ingress addon validates cell IPs."""

    def _get_router(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
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
            sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
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
            sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
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

    def test_in_range_reserved_host_octets_rejected(self):
        """Reserved host octets WITHIN the cell range must be rejected.

        `192.168.x` is caught by the outside-range branch and never reaches
        the reserved-octet gate; these IPs are in 10.60.0.0/16 so they
        exercise it directly: .0 (network), .1 (warden gateway — forwarding
        here loops back into mitmproxy), and .255 (broadcast).
        """
        for reserved_ip in ("10.60.1.0", "10.60.1.1", "10.60.1.255"):
            router = self._get_router()
            with tempfile.NamedTemporaryFile(suffix=".json", mode="w",
                                             delete=False) as f:
                json.dump({"routes": [{
                    "cell": "evil",
                    "cell_ip": reserved_ip,
                    "name": "api",
                    "port": 8642,
                    "path_prefix": "/api",
                    "auth_secret_hash": "abc",
                }]}, f)
                f.flush()

                import sys
                sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
                try:
                    import ingress as ingress_mod
                    old_path = ingress_mod.ROUTES_FILE
                    ingress_mod.ROUTES_FILE = Path(f.name)
                    try:
                        router._reload_routes()
                        self.assertNotIn(
                            "evil", router.routes,
                            f"{reserved_ip} should be rejected as a reserved octet",
                        )
                    finally:
                        ingress_mod.ROUTES_FILE = old_path
                finally:
                    sys.path.pop(0)


class TestIngressRouteReloadSignature(unittest.TestCase):
    """A same-second route rewrite (identical mtime) must still reload.

    Otherwise a deregister+register that reuses a subnet index within the
    filesystem mtime window keeps the prior cell's auth-token hash / cell_ip.
    """

    def _get_router(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
        try:
            from ingress import IngressRouter
        finally:
            sys.path.pop(0)
        return IngressRouter()

    def test_reload_detects_same_mtime_different_content(self):
        import os
        import sys

        router = self._get_router()
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"routes": [{
                "cell": "alpha", "cell_ip": "10.60.5.2", "name": "api",
                "port": 8642, "path_prefix": "/api", "auth_secret_hash": "aaa",
            }]}, f)
            f.flush()
            path = Path(f.name)

        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
        try:
            import ingress as ingress_mod
            old_path = ingress_mod.ROUTES_FILE
            ingress_mod.ROUTES_FILE = path
            try:
                router._reload_routes()
                self.assertIn("alpha", router.routes)

                st = path.stat()
                # New cell reuses 10.60.5.2 with a different token; pin mtime
                # back so a float comparison would treat the file as unchanged.
                path.write_text(json.dumps({"routes": [{
                    "cell": "bravo", "cell_ip": "10.60.5.2", "name": "api",
                    "port": 8642, "path_prefix": "/api",
                    "auth_secret_hash": "bbbbbbbb",
                }]}))
                os.utime(path, ns=(st.st_mtime_ns, st.st_mtime_ns))

                router._reload_routes()
                self.assertIn("bravo", router.routes)
                self.assertNotIn("alpha", router.routes)
            finally:
                ingress_mod.ROUTES_FILE = old_path
        finally:
            sys.path.pop(0)


class TestIngressWebSocketLogging(unittest.TestCase):
    """Test that WebSocket hooks are present in enforce.py and logger.py."""

    def test_enforce_has_websocket_hook(self):
        """enforce.py must have websocket_message method."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
        try:
            from enforce import PolicyEnforcer
        finally:
            sys.path.pop(0)
        self.assertTrue(hasattr(PolicyEnforcer, "websocket_message"))

    def test_logger_has_websocket_hook(self):
        """logger.py must have websocket_message method."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
        try:
            from logger import RequestLogger
        finally:
            sys.path.pop(0)
        self.assertTrue(hasattr(RequestLogger, "websocket_message"))


class TestIngressSseStreaming(unittest.TestCase):
    """Ingress responseheaders flips flow.response.stream=True for
    text/event-stream so mitmproxy passes SSE bytes through unbuffered.

    Aitelier diagnosed this — SA's ACP bridge emits notifications via
    SSE, and without streaming the client sees nothing until the
    upstream closes the connection. Egress flows are unaffected; only
    ingress flows opt into streaming."""

    def _router(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons"))
        try:
            from ingress import IngressRouter
        finally:
            sys.path.pop(0)
        return IngressRouter()

    def _flow(self, content_type, *, is_ingress=True):
        from unittest.mock import MagicMock
        flow = MagicMock()
        flow.metadata = {"ingress_route": "api"} if is_ingress else {}
        flow.metadata.update({"cell": "alice"} if is_ingress else {})
        flow.response = MagicMock()
        flow.response.headers = {"Content-Type": content_type}
        flow.response.stream = False
        return flow

    def test_sse_response_enables_streaming(self):
        router = self._router()
        flow = self._flow("text/event-stream")
        router.responseheaders(flow)
        self.assertTrue(flow.response.stream)

    def test_sse_response_with_charset_suffix_enables_streaming(self):
        """Some servers send `Content-Type: text/event-stream; charset=utf-8`.
        The semicolon-suffixed form must still be detected."""
        router = self._router()
        flow = self._flow("text/event-stream; charset=utf-8")
        router.responseheaders(flow)
        self.assertTrue(flow.response.stream)

    def test_non_sse_response_keeps_buffering(self):
        router = self._router()
        flow = self._flow("application/json")
        router.responseheaders(flow)
        self.assertFalse(flow.response.stream)

    def test_egress_sse_not_touched_by_ingress_addon(self):
        """Egress flows (no ingress_route metadata) must not be affected;
        the egress path keeps buffering so enforce.py's body-side checks
        still see complete responses."""
        router = self._router()
        flow = self._flow("text/event-stream", is_ingress=False)
        router.responseheaders(flow)
        self.assertFalse(flow.response.stream)

    def test_no_response_safely_returns(self):
        """If a flow reaches responseheaders without a response object
        (early termination, mock test conditions), don't crash."""
        from unittest.mock import MagicMock
        router = self._router()
        flow = MagicMock()
        flow.metadata = {"ingress_route": "api"}
        flow.response = None
        router.responseheaders(flow)  # must not raise

    def test_lowercase_header_name_still_detected(self):
        """Some servers (RFC-compliant) emit `content-type: ...` in all
        lowercase. The detection must be case-insensitive on the header
        NAME, not just the value. Audit found the original code relied
        on mitmproxy's Headers normalization, which was fine in
        production but brittle to test against."""
        router = self._router()
        flow = self._flow("text/event-stream")
        # Override headers to use the lowercase key.
        flow.response.headers = {"content-type": "text/event-stream"}
        router.responseheaders(flow)
        self.assertTrue(flow.response.stream)

    def test_mixed_case_header_value_detected(self):
        """Servers occasionally send `Content-Type: Text/Event-Stream`
        (rare but valid). Production code lowercases the value before
        comparing; this pins that behavior."""
        router = self._router()
        flow = self._flow("text/event-stream")
        flow.response.headers = {"Content-Type": "Text/Event-Stream"}
        router.responseheaders(flow)
        self.assertTrue(flow.response.stream)
