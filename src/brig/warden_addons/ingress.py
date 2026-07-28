"""
Ingress addon for mitmproxy — authenticated reverse proxy for inbound traffic.

Routes external requests to cell-internal ports through Warden.

Design:
    - Cells declare ingress endpoints in their spec (opt-in, not default)
    - Warden reverse-proxies by path: /{cell}/{path_prefix}/... -> cell_ip:port/...
    - Every request requires token authentication (Authorization: Bearer <token>)
    - All inbound traffic is logged (same detail as egress)
    - No east-west: external -> Warden -> cell only (invariant 1 intact)

Routes file format (JSON, written by reconciler):
    {
        "routes": [
            {
                "cell": "mycell",
                "cell_ip": "10.60.5.2",
                "name": "api",
                "port": 8642,
                "path_prefix": "/api",
                "auth": "token",
                "auth_secret_hash": "<sha256 hex>"
            }
        ]
    }

Reverse-proxy by path is the SEMANTICS; the addon is loaded into warden's
single multi-mode mitmproxy (started with `--mode regular@8080 --mode
regular@8443`), and it claims inbound requests by listen port — request()
handles only the ingress port (8443) and ignores egress (8080). It is not
launched as a standalone `--mode reverse` proxy.
"""

import collections
import fcntl
import hashlib
import hmac
import json
import re
import threading
import time
from pathlib import Path

from mitmproxy import ctx, http

from _common import redact_path, stat_signature


# Routes file (written by reconciler, watched by this addon).
ROUTES_FILE = Path("/var/run/cells/ingress-routes.json")
ROUTES_LOCK_FILE = Path("/var/run/cells/ingress-routes.lock")

# Ingress listener port (must match INGRESS_PORT in brig config.py).
INGRESS_PORT = 8443

# Maximum request body size for ingress (16 MB). Prevents memory exhaustion.
MAX_INGRESS_BODY_SIZE = 16 * 1024 * 1024

# Auth failure rate limiting: max failures per IP before returning 429.
AUTH_FAIL_WINDOW = 60  # Seconds.
AUTH_FAIL_MAX = 10  # Max failures per window per IP.
AUTH_FAIL_MAX_IPS = 10000  # Max tracked IPs (LRU eviction beyond this).


class IngressRoute:
    """A parsed ingress route."""

    __slots__ = ("cell", "cell_ip", "name", "port", "path_prefix", "auth",
                 "auth_secret_hash", "auth_salt")

    def __init__(self, route: dict):
        self.cell = route["cell"]
        self.cell_ip = route["cell_ip"]
        self.name = route["name"]
        self.port = route["port"]
        self.path_prefix = route["path_prefix"]
        # Default to "token" (fail-secure): a route missing `auth` is gated,
        # never silently treated as open. NOTE (invariant 4): the routes file
        # lives in the untrusted state dir. The PRIMARY defense against an
        # auth:none route on an untrusted cell is the host-side gate in
        # lifecycle.register_ingress_for (keyed on the TRUSTED container label),
        # which refuses to write such a route. This addon does not independently
        # re-validate a directly-tampered routes file — signed routes are the
        # deferred hardening (docs/ROADMAP.md, "Trusted-source hardening").
        self.auth = route.get("auth", "token")
        self.auth_secret_hash = route.get("auth_secret_hash", "")
        self.auth_salt = route.get("auth_salt", "")

    def matches_path(self, path: str) -> bool:
        """Check if request path matches this route's prefix.

        Requires exact prefix match on path segment boundaries to prevent
        /api matching /apikeys. The prefix must be followed by '/' or end
        of path.
        """
        if path == self.path_prefix:
            return True
        return path.startswith(self.path_prefix + "/")


class IngressRouter:
    """mitmproxy addon for authenticated ingress reverse proxying."""

    def __init__(self):
        self.routes: dict[str, list[IngressRoute]] = {}  # cell_name -> routes
        # (st_mtime_ns, st_size); see _common.stat_signature for why a float
        # mtime would miss a same-second route rewrite.
        self._routes_sig: tuple[int, int] = (0, 0)
        self._reload_lock = threading.Lock()
        self._last_check_time = 0.0
        self._CHECK_INTERVAL = 1.0
        # Per-IP auth failure tracking: ip -> deque of failure timestamps.
        # OrderedDict so eviction at capacity is genuinely LRU (see
        # AUTH_FAIL_MAX_IPS): each access/record moves the IP to the end, so a
        # flood of fresh IPs can't evict an IP that's actively being throttled.
        self._auth_failures: collections.OrderedDict[str, collections.deque] = (
            collections.OrderedDict()
        )
        self._auth_failures_lock = threading.Lock()

    def load(self, loader):
        """Load ingress routes on startup."""
        ctx.log.info("IngressRouter: Loading...")
        self._reload_routes(strict=True)
        ctx.log.info("IngressRouter: Loaded")

    def configure(self, updated):
        """Check for route file changes."""
        self._check_reload()

    def _check_reload(self):
        """Throttled mtime check and reload."""
        now = time.monotonic()
        if now - self._last_check_time < self._CHECK_INTERVAL:
            return
        self._last_check_time = now

        try:
            if ROUTES_FILE.exists():
                if stat_signature(ROUTES_FILE) != self._routes_sig:
                    with self._reload_lock:
                        self._reload_routes()
        except OSError:
            pass

    def _reload_routes(self, strict: bool = False) -> None:
        """Load routes from file.

        strict=True (startup): missing file is OK (no cells yet).
        strict=False (reload): keep last-good routes on error.
        """
        try:
            if not ROUTES_FILE.exists():
                self.routes = {}
                self._routes_sig = (0, 0)
                return

            sig = stat_signature(ROUTES_FILE)
            if sig == self._routes_sig:
                return

            # Acquire shared lock to prevent reading a partially written file.
            lock_fd = None
            try:
                if ROUTES_LOCK_FILE.exists() or ROUTES_FILE.exists():
                    lock_fd = open(ROUTES_LOCK_FILE, "a")
                    fcntl.flock(lock_fd, fcntl.LOCK_SH)
            except OSError:
                pass  # Best-effort locking.

            with open(ROUTES_FILE, "r") as f:
                data = json.load(f)

            if lock_fd:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    lock_fd.close()
                except OSError:
                    pass

            if not isinstance(data, dict) or "routes" not in data:
                raise ValueError("Invalid routes file: missing 'routes' key")

            new_routes: dict[str, list[IngressRoute]] = {}
            for entry in data["routes"]:
                route = IngressRoute(entry)
                # Validate cell_ip is a valid IPv4 in the cell subnet range
                # (10.60.1.0/24 through 10.60.254.0/24). Reject anything else
                # to prevent SSRF via poisoned routes file.
                try:
                    import ipaddress
                    ip = ipaddress.ip_address(route.cell_ip)
                    cell_net = ipaddress.ip_network("10.60.0.0/16", strict=False)
                    if ip not in cell_net:
                        raise ValueError("outside cell range")
                    # Reject .0 (network) and .255 (broadcast) addresses.
                    octets = route.cell_ip.split(".")
                    if int(octets[2]) < 1 or int(octets[2]) > 254:
                        raise ValueError("invalid subnet octet")
                    # Host octets .0 (network), .1 (warden gateway on each cell
                    # network), and .255 (broadcast) are reserved. Forwarding
                    # ingress to .1 would loop back into mitmproxy itself.
                    host_octet = int(octets[3])
                    if host_octet < 2 or host_octet > 254:
                        raise ValueError("invalid host octet (reserved)")
                except (ValueError, TypeError) as e:
                    ctx.log.warn(
                        f"IngressRouter: Skipping route with invalid cell_ip: "
                        f"{route.cell_ip} ({e})"
                    )
                    continue
                # Validate port from the untrusted routes file (invariant 4) —
                # it's used to forward to cell_ip:port, so reject anything that
                # isn't a real TCP port. bool is an int subclass; reject it too.
                if (isinstance(route.port, bool)
                        or not isinstance(route.port, int)
                        or not 1 <= route.port <= 65535):
                    ctx.log.warn(
                        f"IngressRouter: Skipping route '{route.name}' with "
                        f"invalid port: {route.port!r}"
                    )
                    continue
                if route.cell not in new_routes:
                    new_routes[route.cell] = []
                new_routes[route.cell].append(route)

            self.routes = new_routes
            self._routes_sig = sig

            total = sum(len(v) for v in self.routes.values())
            ctx.log.info(
                f"IngressRouter: Loaded {total} routes for "
                f"{len(self.routes)} cells"
            )

        except Exception as e:
            if strict:
                # On startup, missing file is fine (no cells with ingress yet).
                if isinstance(e, FileNotFoundError):
                    return
                raise
            ctx.log.error(f"IngressRouter: Failed to load routes: {e}")

    def _find_route(self, path: str) -> tuple[IngressRoute | None, str]:
        """Find matching route for a request path.

        Path format: /{cell_name}/{path_prefix}/...
        Returns (route, remaining_path) or (None, "").
        """
        # Strip leading slash, split on first segment (cell name).
        stripped = path.lstrip("/")
        if "/" not in stripped:
            return None, ""

        cell_name, rest = stripped.split("/", 1)
        rest = "/" + rest  # Restore leading slash for prefix matching.

        cell_routes = self.routes.get(cell_name)
        if not cell_routes:
            return None, ""

        # Longest-prefix wins. With overlapping prefixes (e.g. "/" and "/api")
        # the list order is arbitrary, so pick the most specific match rather
        # than the first — otherwise a broad "/" route shadows "/api".
        best: IngressRoute | None = None
        for route in cell_routes:
            if route.matches_path(rest) and (
                best is None or len(route.path_prefix) > len(best.path_prefix)
            ):
                best = route
        if best is not None:
            return best, rest

        return None, ""

    def _is_rate_limited(self, client_ip: str) -> bool:
        """Check if an IP has exceeded the auth failure rate limit."""
        now = time.monotonic()
        with self._auth_failures_lock:
            failures = self._auth_failures.get(client_ip)
            if not failures:
                return False
            # Evict old entries outside the window.
            while failures and failures[0] < now - AUTH_FAIL_WINDOW:
                failures.popleft()
            # Touch: this IP is active, so it's the last we want evicted.
            self._auth_failures.move_to_end(client_ip)
            return len(failures) >= AUTH_FAIL_MAX

    def _record_auth_failure(self, client_ip: str) -> None:
        """Record an authentication failure for rate limiting."""
        now = time.monotonic()
        with self._auth_failures_lock:
            if client_ip not in self._auth_failures:
                # Evict least-recently-used IP if at capacity.
                if len(self._auth_failures) >= AUTH_FAIL_MAX_IPS:
                    try:
                        self._auth_failures.popitem(last=False)
                    except KeyError:
                        pass
                self._auth_failures[client_ip] = collections.deque()
            self._auth_failures[client_ip].append(now)
            self._auth_failures.move_to_end(client_ip)
            # Cap deque size to prevent memory growth.
            while len(self._auth_failures[client_ip]) > AUTH_FAIL_MAX * 2:
                self._auth_failures[client_ip].popleft()

    @staticmethod
    def _validate_token(request: http.Request, expected_hash: str, salt: str = "") -> bool:
        """Validate Bearer token against expected salted SHA-256 hash.

        Uses constant-time comparison to prevent timing attacks.
        Returns False if no Authorization header, wrong scheme, or mismatch.
        """
        auth_header = request.headers.get("Authorization", "")
        if not auth_header:
            return False

        # Parse "Bearer <token>".
        parts = auth_header.split(" ", 1)
        if len(parts) != 2 or parts[0] != "Bearer":
            return False

        token = parts[1]
        if not token:
            return False

        # Hash the provided token with salt and compare (constant-time).
        salted = salt + token
        token_hash = hashlib.sha256(salted.encode("utf-8")).hexdigest()
        return hmac.compare_digest(token_hash, expected_hash)

    def request(self, flow: http.HTTPFlow) -> None:
        """Process inbound request: route, authenticate, proxy.

        Only handles requests arriving on the ingress port (8443).
        Egress traffic on port 8080 is ignored (handled by enforce.py).
        """
        # Skip egress traffic — only handle ingress port.
        listen_port = flow.client_conn.sockname[1] if flow.client_conn.sockname else 0
        if listen_port != INGRESS_PORT:
            return

        self._check_reload()

        path = flow.request.path
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"

        # Sanitize for logging: strip control characters AND redact secrets in
        # the path/query (ctx.log is captured as warden container stdout).
        safe_path = redact_path(re.sub(r'[\x00-\x1f\x7f]', '', path))

        # Rate limit check — reject before any processing if IP is abusing auth.
        if self._is_rate_limited(client_ip):
            flow.response = http.Response.make(
                429, "Too many authentication failures",
                {"Content-Type": "text/plain", "Retry-After": str(AUTH_FAIL_WINDOW)},
            )
            ctx.log.warn(f"INGRESS RATE LIMITED: {client_ip}")
            return

        # Find matching route.
        route, remaining_path = self._find_route(path)

        if route is None:
            # Count route misses toward the rate limiter. The 401 path is
            # throttled but a miss returns 404; without this an attacker could
            # probe nonexistent cell/route names unbounded from a single IP.
            self._record_auth_failure(client_ip)
            flow.response = http.Response.make(
                404, f"No ingress route registered for '{safe_path}'\n",
                {"Content-Type": "text/plain"},
            )
            ctx.log.info(f"INGRESS MISS: {client_ip} {safe_path}")
            return

        # Tag the flow with its route now (not just on the proxied path) so
        # rejected attempts — auth failures, oversize bodies — also attribute
        # to the cell and show up in `brig cell network <cell>` rather than
        # vanishing into unknown.jsonl.
        flow.metadata["ingress"] = True
        flow.metadata["cell"] = route.cell
        flow.metadata["ingress_cell"] = route.cell
        flow.metadata["ingress_route"] = route.name
        flow.metadata["ingress_client_ip"] = client_ip

        # Validate authentication — unless the route opts out (auth: none),
        # in which case brig is a transparent proxy and the cell's app is the
        # gate. The untrusted profile can't declare auth: none (parse-time gate).
        if route.auth != "none":
            if not self._validate_token(flow.request, route.auth_secret_hash, route.auth_salt):
                self._record_auth_failure(client_ip)
                flow.response = http.Response.make(
                    401,
                    "Unauthorized",
                    {
                        "Content-Type": "text/plain",
                        "WWW-Authenticate": "Bearer",
                    },
                )
                ctx.log.warn(
                    f"INGRESS AUTH FAIL: {client_ip} -> {route.cell}{safe_path}"
                )
                return

        # Check request body size.
        #
        # LIMITATION: mitmproxy has already buffered the body into memory by
        # the time this check runs, so this gate is post-allocation and
        # only protects the cell-side application (and downstream memory)
        # from large payloads. For auth: token routes the 401 above returns
        # first, so only authenticated clients can make warden buffer a body;
        # an auth: none route has no brig gate (the operator opted out), so its
        # cell app is reachable with bodies up to this cap. For a true
        # wire-level cap, mitmproxy stream mode would have to be configured for
        # the ingress listener; we don't do that today.
        if flow.request.content and len(flow.request.content) > MAX_INGRESS_BODY_SIZE:
            flow.response = http.Response.make(
                413, "Request body too large", {"Content-Type": "text/plain"}
            )
            ctx.log.warn(
                f"INGRESS TOO LARGE: {client_ip} -> {route.cell}{safe_path} "
                f"{len(flow.request.content)}b"
            )
            return

        # Strip the Authorization header before forwarding so the cell never
        # sees brig's ingress token. For auth: none, leave it intact — the
        # request passes through transparently for the app to authenticate.
        if route.auth != "none" and "Authorization" in flow.request.headers:
            del flow.request.headers["Authorization"]

        # Rewrite request to target cell.
        flow.request.host = route.cell_ip
        flow.request.port = route.port
        flow.request.path = remaining_path
        flow.request.scheme = "http"  # Internal traffic is plaintext.

        # Override Host header to prevent host-header confusion/poisoning
        # in the target cell application.
        flow.request.headers["Host"] = f"{route.cell_ip}:{route.port}"

        ctx.log.info(
            f"INGRESS: {client_ip} -> {route.cell}:{route.port}"
            f"{remaining_path} ({route.name})"
        )

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        """Pass SSE / streaming responses through unbuffered.

        mitmproxy buffers response bodies by default so addons can
        inspect them. For Server-Sent-Events (Content-Type:
        text/event-stream) and other long-lived streaming protocols
        (chunked agent message streams, NDJSON), buffering is fatal —
        the proxy holds bytes until the server closes, so the client
        sees "everything at once at session close" instead of a
        stream. Setting `flow.response.stream = True` in this hook
        flips mitmproxy into pass-through mode for the response body.

        Scoped to ingress flows only: egress (cell → outside) still
        buffers so enforce.py's response-side checks (DNS rebinding,
        etc.) keep working on per-request bodies. Ingress responses
        come from cells we already trust on this listener and don't
        need body inspection.

        SSE-style streams (e.g. an agent emitting `agent_message_chunk`
        notifications) need this: without passthrough the client never sees
        chunks before session close.
        """
        if not flow.metadata.get("ingress_route"):
            return
        if flow.response is None:
            return
        # Case-insensitive header lookup. mitmproxy's Headers class
        # normalizes for us, but `flow.response.headers.get(...)` is
        # case-sensitive on plain dicts (tests) and on some mitmproxy
        # versions in edge cases. Iterating keys with `.lower()`
        # comparison keeps the code correct against any header
        # container that supports `.items()`.
        content_type = ""
        try:
            for k, v in flow.response.headers.items():
                if isinstance(k, str) and k.lower() == "content-type":
                    content_type = str(v).lower()
                    break
        except AttributeError:
            return
        # Strip any `; charset=...` suffix before comparing.
        media_type = content_type.split(";", 1)[0].strip()
        if media_type == "text/event-stream":
            flow.response.stream = True
            ctx.log.info(
                f"INGRESS STREAM: passthrough for "
                f"{flow.metadata.get('cell')}:{flow.metadata.get('ingress_route')}"
            )


addons = [IngressRouter()]
