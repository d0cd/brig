"""
Policy enforcement addon for mitmproxy.

Enforces network policy on egress traffic:
    - Per-cell allowlist/denylist with wildcard support
    - Path and method-based filtering
    - Block internal IP ranges (RFC1918, localhost, CGNAT, etc.)
    - Block literal IP addresses
    - Block non-HTTP/HTTPS ports
    - Default-deny on errors and for cells without a policy (fail closed)

Egress is evaluated solely against the requesting cell's own policy file in
/var/run/cells/policies/<cell>.json; a cell with no per-cell policy is blocked.
The global /policy.json is read only for the `policy_trace` settings — it
carries no allow/deny rules.

Per-cell policy file (JSON):
    {
        "allow": [
            "example.com",
            "*.github.com",
            {"domain": "api.example.com", "paths": ["/v1/*"], "methods": ["GET", "POST"]}
        ],
        "deny": ["evil.com"],
        "tls_passthrough": ["example.com"],
        "host_services": [{"name": "db", "port": 5432, "protocol": "tcp"}]
    }

Usage:
    mitmdump -s enforce.py
"""

import collections
import ipaddress
import json
import re
import threading
import time
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http

from _common import BLOCKED_NETWORKS, SubnetResolver, canonical_ip, is_blocked_ip, redact_path, stat_signature  # noqa: F401 (BLOCKED_NETWORKS re-exported for the constant-mirror test)
# Re-exported for tests and any external addons that import policy types
# from `enforce` for historical reasons. Implementation lives in _policy.
from _policy import (  # noqa: F401
    DomainTrie,
    Policy,
    PolicyRule,
    PolicyTraceConfig,
)


# Policy file path (mounted into container).
POLICY_FILE = Path("/policy.json")

# Host service virtual domain suffix. Cells request <name>.host.brig;
# Warden rewrites to the macOS host IP + declared port.
HOST_SERVICE_SUFFIX = ".host.brig"

# Upstream host that warden's TCP host_service reverse listeners dial.
# Mirrors warden.proxy.TCP_UPSTREAM_HOST — a raw-TCP host_service flow's
# server.address[0] is this literal string (not the resolved host IP).
TCP_UPSTREAM_HOST = "host.lima.internal"

# Subnet map for cell identification.
SUBNET_MAP_FILE = Path("/var/run/cells/subnet-map.json")

# Per-cell policy directory.
CELL_POLICY_DIR = Path("/var/run/cells/policies")

# Allowed ports.
ALLOWED_PORTS = {80, 443}

# Maximum number of cell policies to cache (LRU eviction beyond this).
MAX_CACHED_CELL_POLICIES = 1000

# Per-cell policy JSON files are mounted from the brig CLI side. brig
# writes them via atomic_write_json; the writer has no explicit size cap.
# Cap reads here so a malformed / tampered file can't OOM warden by
# loading a multi-gigabyte JSON. 1 MiB is well above any realistic
# policy (1000 rules ≈ ~100 KiB at the verbose end).
MAX_POLICY_FILE_BYTES = 1024 * 1024


class PolicyEnforcer:
    """mitmproxy addon for policy enforcement."""

    def __init__(self):
        self.cell_policies: collections.OrderedDict[str, Policy] = collections.OrderedDict()
        self.subnets = SubnetResolver(SUBNET_MAP_FILE)
        # mtime is tracked as (st_mtime_ns, st_size) so coarse-grained
        # filesystem mtimes (HFS+ has 1-second resolution; some tmpfs
        # variants in CI are similar) can't hide a same-second policy
        # rewrite — a float-equality comparison on st_mtime alone would
        # silently skip reload for edits within the same wall-clock second.
        self.policy_mtime: tuple[int, int] = (0, 0)
        self.cell_policy_mtimes: dict[str, tuple[int, int]] = {}
        self.trace_config = PolicyTraceConfig()
        self._cell_policy_lock = threading.Lock()
        self._reload_lock = threading.RLock()
        self._host_ip: str = ""

    def load(self, loader):
        """Called when addon is loaded.

        Startup uses strict policy load: a missing or malformed /policy.json
        raises so warden refuses to start instead of silently running with an
        empty allow/deny list (which defaults-deny but looks healthy).
        """
        ctx.log.info("PolicyEnforcer: Loading...")
        self._discover_host_ip()
        self._reload_policy(strict=True)
        self.subnets.reload()
        self._reload_cell_policies()
        ctx.log.info("PolicyEnforcer: Loaded")

    def _discover_host_ip(self) -> None:
        """Discover the macOS host IP from inside the Lima VM.

        Tries host.lima.internal first (Lima's built-in host alias),
        then falls back to the default gateway IP.
        """
        import socket
        import subprocess

        # Try Lima's host alias.
        try:
            self._host_ip = socket.gethostbyname("host.lima.internal")
            ctx.log.info(f"PolicyEnforcer: Host IP (Lima): {self._host_ip}")
            return
        except socket.gaierror:
            pass

        # Fallback: default gateway (works on most Linux VMs).
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            for part in result.stdout.split():
                try:
                    ipaddress.ip_address(part)
                    self._host_ip = part
                    ctx.log.info(f"PolicyEnforcer: Host IP (gateway): {self._host_ip}")
                    return
                except ValueError:
                    continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        ctx.log.warn("PolicyEnforcer: Could not discover host IP — host services disabled")

    def configure(self, updated):
        """Called by mitmproxy on configuration changes and periodically.

        Checks file mtimes and reloads when policy or subnet-map changes.
        Replaces the old SIGHUP dispatcher — no signal handling needed.
        """
        self._check_reload()

    _last_check_time: float = 0.0
    _CHECK_INTERVAL: float = 1.0  # Seconds between mtime checks.

    def _check_reload(self):
        """Check file mtimes and reload if anything changed.

        Throttled to at most once per second to avoid stat syscalls on
        every HTTP request. Serialized by _reload_lock.
        """
        now = time.monotonic()
        if now - self._last_check_time < self._CHECK_INTERVAL:
            return
        self._last_check_time = now

        try:
            policy_changed = (
                POLICY_FILE.exists() and
                stat_signature(POLICY_FILE) != self.policy_mtime
            )
            subnet_changed = (
                SUBNET_MAP_FILE.exists() and
                stat_signature(SUBNET_MAP_FILE) != self.subnets._sig
            )
            policy_dir_changed = False
            if CELL_POLICY_DIR.exists():
                # Dir mtime bumps on add / remove / rename of a policy file
                # (in-place edits are caught per-file by mtime+size in
                # _reload_cell_policies); any bump triggers a rescan.
                dir_mtime_ns = CELL_POLICY_DIR.stat().st_mtime_ns
                if not hasattr(self, "_cell_policy_dir_mtime"):
                    self._cell_policy_dir_mtime = 0
                policy_dir_changed = dir_mtime_ns != self._cell_policy_dir_mtime
                if policy_dir_changed:
                    self._cell_policy_dir_mtime = dir_mtime_ns
        except OSError:
            return

        if not policy_changed and not subnet_changed and not policy_dir_changed:
            return

        with self._reload_lock:
            ctx.log.info("PolicyEnforcer: Reloading (file change detected)...")
            if policy_changed:
                self._reload_policy()
            if subnet_changed:
                self.subnets.reload()
            if policy_dir_changed or policy_changed:
                self._reload_cell_policies()

    def _reload_policy(self, strict: bool = False) -> None:
        """Load global policy from file.

        strict=True (startup): missing/malformed policy raises.
        strict=False (SIGHUP reload): keeps the last-good policy on failure
        so a bad edit does not break a running service.
        """
        try:
            if not POLICY_FILE.exists():
                if strict:
                    raise FileNotFoundError(
                        f"Policy file not found: {POLICY_FILE}"
                    )
                ctx.log.warn(f"PolicyEnforcer: Policy file not found: {POLICY_FILE}")
                return

            sig = stat_signature(POLICY_FILE)
            if sig == self.policy_mtime:
                return

            with open(POLICY_FILE, "r") as f:
                data = json.load(f)

            self.trace_config = PolicyTraceConfig(data.get("policy_trace", {}))
            self.policy_mtime = sig

            if self.trace_config.enabled:
                ctx.log.info("PolicyEnforcer: Policy tracing enabled")

        except Exception as e:
            # Broad catch intentional: structural errors (non-dict JSON,
            # wrong-typed rules raising from PolicyRule) must not escape
            # into request()/http_connect() and break the mitmproxy event
            # loop. Strict startup still propagates to fail loud.
            if strict:
                raise
            ctx.log.error(f"PolicyEnforcer: Failed to load policy: {e}")
            # Keep existing policy on error (fail closed for new connections).

    def _reload_cell_policies(self) -> None:
        """Load per-cell policies with LRU eviction to bound memory."""
        try:
            if not CELL_POLICY_DIR.exists():
                return

            present: set[str] = set()
            for policy_file in CELL_POLICY_DIR.glob("*.json"):
                cell_name = policy_file.stem
                present.add(cell_name)
                stat = policy_file.stat()
                sig = (stat.st_mtime_ns, stat.st_size)

                # Size cap — refuse to load files larger than
                # MAX_POLICY_FILE_BYTES. Fail-closed: a too-large file
                # leaves the previous policy (if any) in place; cells
                # without a prior policy hit the existing "no per-cell
                # policy" block at request time. Logged so operators
                # see the rejection.
                if stat.st_size > MAX_POLICY_FILE_BYTES:
                    ctx.log.error(
                        f"PolicyEnforcer: skipping policy '{cell_name}' "
                        f"({stat.st_size} bytes > "
                        f"{MAX_POLICY_FILE_BYTES} byte cap)"
                    )
                    continue

                with self._cell_policy_lock:
                    if self.cell_policy_mtimes.get(cell_name) == sig:
                        continue  # No change.

                    # Evict least recently used policy if at capacity.
                    if cell_name not in self.cell_policies:
                        if len(self.cell_policies) >= MAX_CACHED_CELL_POLICIES:
                            oldest_key, _ = self.cell_policies.popitem(last=False)
                            del self.cell_policy_mtimes[oldest_key]
                            ctx.log.debug(f"PolicyEnforcer: Evicted policy for '{oldest_key}'")

                    # Read and insert while still holding the lock.
                    try:
                        with open(policy_file, "r") as f:
                            data = json.load(f)
                        if not isinstance(data, dict):
                            # Tampered non-dict policy file (invariant 4): fail
                            # closed. The file is never adopted — an unseen cell
                            # hits the "no per-cell policy" default-deny, and a
                            # cell whose good policy is already cached keeps it.
                            # Either way the tampered content grants nothing.
                            ctx.log.error(
                                f"PolicyEnforcer: policy '{cell_name}' is not a "
                                f"JSON object; skipping (fail closed)"
                            )
                            continue
                        self.cell_policies[cell_name] = Policy(
                            allow=data.get("allow", []),
                            deny=data.get("deny", []),
                            host_services=data.get("host_services"),
                            tls_passthrough=data.get("tls_passthrough", []),
                        )
                        self.cell_policy_mtimes[cell_name] = sig
                        ctx.log.info(f"PolicyEnforcer: Loaded policy for cell '{cell_name}'")
                    except Exception as e:
                        # Broad on purpose (mirrors the global _reload_policy):
                        # Policy()/PolicyRule() raise ValueError on a malformed
                        # rule (empty domain, bad IDN). Such a structural error
                        # MUST NOT escape — _reload_cell_policies runs via
                        # _check_reload() at the top of request()/http_connect(),
                        # where an unhandled hook exception fails OPEN (mitmproxy
                        # lets the flow through with no 403). Skip the bad file;
                        # the cell falls to default-deny.
                        ctx.log.error(f"PolicyEnforcer: Failed to load cell policy {cell_name}: {e}")

            # Evict cached policies whose file was deleted (`brig policy rm`).
            # Teardown already default-denies a removed cell via subnet-map,
            # but dropping the cache keeps it from lingering and re-applying if
            # the cell name (and subnet) is later reused.
            with self._cell_policy_lock:
                for stale in [c for c in self.cell_policies if c not in present]:
                    del self.cell_policies[stale]
                    self.cell_policy_mtimes.pop(stale, None)
                    ctx.log.info(f"PolicyEnforcer: Dropped deleted policy for '{stale}'")

        except OSError as e:
            ctx.log.error(f"PolicyEnforcer: Failed to scan cell policies: {e}")

    def _is_internal_ip(self, host: str) -> bool:
        """Check if host is an internal/reserved IP address.

        Delegates to _common.is_blocked_ip so the membership check and the
        bracketed-IPv6 unwrap stay in one place. Returns False for
        non-IP hosts (domain names), matching the prior behavior.
        """
        return is_blocked_ip(host)

    def _is_literal_ip(self, host: str) -> bool:
        """Check if host is a literal IP address (not a domain).

        Delegates to _common.canonical_ip so alternate IPv4 encodings
        (integer/hex/octal/short-dotted) are recognized as literals rather
        than slipping through as domain names.
        """
        return canonical_ip(host) is not None

    @staticmethod
    def _normalize_hostspec(hostspec: str) -> str:
        """Strip brackets and port; lowercase. IPv6-aware.

        Inputs and expected outputs:
          "example.com"        -> "example.com"
          "example.com:443"    -> "example.com"
          "[::1]:443"          -> "::1"
          "[::1]"              -> "::1"
          "fe80::1"            -> "fe80::1"   (bare IPv6, no port)
          "Example.COM"        -> "example.com"

        Bracketed IPv6 is unambiguous. For un-bracketed strings with multiple
        colons we use ipaddress.ip_address to validate as IPv6 — strings like
        "example.com:80:extra" or "1::1::bad" should NOT be treated as bare
        IPv6 (an attacker could otherwise smuggle host comparisons).
        """
        h = (hostspec or "").strip()
        if h.startswith("["):
            end = h.find("]")
            if end == -1:
                return h.lower()
            return h[1:end].lower()
        if h.count(":") > 1:
            try:
                ipaddress.ip_address(h)
                return h.lower()
            except ValueError:
                pass
        return h.split(":", 1)[0].lower()

    @staticmethod
    def _host_header_mismatches(flow: "http.HTTPFlow") -> bool:
        """Return True if the Host header is present and disagrees with the URL host.

        Defends against Host header smuggling: a cell could request an allowlisted
        URL while setting Host to a disallowed domain, hoping the upstream server
        routes on Host. A missing Host header is allowed (HTTP/1.0 clients).
        Port suffixes are stripped IPv6-aware, comparison is case-insensitive,
        and any CR/LF/NUL in the Host value is treated as a smuggle attempt
        (classic request-smuggling injection).
        """
        try:
            header = flow.request.headers.get("Host")
        except Exception:
            return False
        if not header:
            return False
        if any(c in header for c in ("\r", "\n", "\x00")):
            return True
        header_host = PolicyEnforcer._normalize_hostspec(header)
        url_host = PolicyEnforcer._normalize_hostspec(flow.request.host or "")
        if not header_host or not url_host:
            return False
        return header_host != url_host

    def request(self, flow: http.HTTPFlow) -> None:
        """Process each HTTP request.

        Egress traffic (port 8080): full policy enforcement.
        Ingress traffic (port 8443): handled by ingress addon. If the ingress
        addon has already processed the request (set metadata), allow it.
        Otherwise block — fail closed.
        """
        listen_port = flow.client_conn.sockname[1] if flow.client_conn.sockname else 0
        if listen_port == 8443:
            # Ingress addon sets this flag after successful auth + routing.
            if flow.metadata.get("ingress"):
                return
            # Ingress addon did not handle this request — block.
            self._block(flow, "ingress: not handled by ingress addon (fail closed)")
            return

        # Drain any deferred SIGHUP reload. Double-checked under _reload_lock
        # so concurrent requests do not both run the reload body.
        self._check_reload()

        # Extract request details.
        host = flow.request.host
        port = flow.request.port
        path = flow.request.path
        method = flow.request.method
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"

        # Resolve cell name.
        cell_name = self.subnets.get_cell_name(client_ip)

        # Store for logging addon.
        flow.metadata["cell"] = cell_name or "unknown"
        flow.metadata["client_ip"] = client_ip

        # Check 0: Host services — virtual .host.brig domains.
        # Must come before port/IP checks since we rewrite to a private IP.
        if host.endswith(HOST_SERVICE_SUFFIX):
            cell_policy_for_host_svc = self._lookup_cell_policy(cell_name)
            self._handle_host_service(flow, host, cell_name, cell_policy_for_host_svc)
            return

        # Check 1: Port restriction.
        if port not in ALLOWED_PORTS:
            self._block(flow, f"port {port} not allowed (only 80, 443)")
            return

        # Check 2: Internal IP ranges.
        if self._is_internal_ip(host):
            self._block(flow, f"internal IP range blocked: {host}")
            return

        # Check 3: Literal IP addresses.
        if self._is_literal_ip(host):
            self._block(flow, f"literal IP addresses blocked: {host}")
            return

        # Check 3b: Host header smuggling — URL host must match Host header
        # when the Host header is present. Prevents a cell from reaching a
        # disallowed upstream by rewriting Host on an allowlisted URL.
        if self._host_header_mismatches(flow):
            self._block(
                flow,
                f"host header mismatch: URL={host} Host={flow.request.headers.get('Host')}"
            )
            return

        cell_policy = self._lookup_cell_policy(cell_name)
        if cell_policy is None:
            self._block(
                flow,
                f"cell '{cell_name or 'unknown'}' has no per-cell policy",
            )
            return
        allowed, reason, trace = cell_policy.is_allowed(
            host, path, method, self.trace_config,
        )
        if trace and self.trace_config.enabled:
            flow.metadata["policy_trace"] = trace
        if allowed:
            flow.metadata["policy_reason"] = f"cell:{reason}"
            return
        self._block(flow, f"cell policy: {reason}")

    def _lookup_cell_policy(self, cell_name: Optional[str]) -> Optional[Policy]:
        """Look up the cell policy and update LRU position. Returns None if no policy."""
        if not cell_name:
            return None
        with self._cell_policy_lock:
            policy = self.cell_policies.get(cell_name)
            if policy is not None:
                self.cell_policies.move_to_end(cell_name)
            return policy

    def _handle_host_service(
        self,
        flow: http.HTTPFlow,
        host: str,
        cell_name: Optional[str],
        cell_policy: Optional[Policy],
    ) -> None:
        """Route a .host.brig request to the macOS host.

        Looks up the port in the cell's per-cell host_services map.
        Blocks if host IP isn't discovered, the cell has no per-cell
        policy, or the requested name isn't in the cell's map.
        """
        service_name = host[: -len(HOST_SERVICE_SUFFIX)]
        safe_name = re.sub(r'[\x00-\x1f\x7f]', '', service_name)

        if not self._host_ip:
            self._block(flow, f"host service '{safe_name}': host IP not discovered")
            return

        # Per-cell host_services map. Cells without a per-cell policy have
        # no host-service access — host services must be declared in the
        # cell yaml.
        if cell_policy is None or cell_policy.host_services_map is None:
            self._block(
                flow,
                f"host service '{safe_name}': cell '{cell_name or 'unknown'}' "
                f"has no host_services declared",
            )
            return
        service_port = cell_policy.host_services_map.get(service_name)
        if service_port is None:
            tcp_map = cell_policy.tcp_host_services_map or {}
            if service_name in tcp_map:
                # Reached as HTTP but declared TCP. Block with a clearer
                # message; sending HTTP framing to a raw TCP listener
                # would only produce garbage on both ends, but a precise
                # error helps the cell author debug their config.
                self._block(
                    flow,
                    f"host service '{safe_name}': declared as TCP, "
                    f"connect via raw TCP to '{safe_name}.host.brig:"
                    f"{tcp_map[service_name]}' instead",
                )
                return
            self._block(
                flow,
                f"host service '{safe_name}': not declared in cell "
                f"'{cell_name}' yaml",
            )
            return

        # Rewrite request to target the macOS host.
        flow.request.host = self._host_ip
        flow.request.port = service_port
        flow.request.headers["Host"] = f"{service_name}.host.brig"

        flow.metadata["host_service"] = service_name
        flow.metadata["cell"] = cell_name or "unknown"
        flow.metadata["policy_reason"] = f"host_service:{service_name}"

        ctx.log.info(
            f"HOST_SERVICE: {cell_name or 'unknown'} -> "
            f"{service_name} ({self._host_ip}:{service_port})"
        )

    def _block(self, flow: http.HTTPFlow, reason: str) -> None:
        """Block the request with a 403 response."""
        flow.metadata["blocked"] = True
        flow.metadata["block_reason"] = reason

        # Return generic message to cell; log details server-side only.
        flow.response = http.Response.make(
            403,
            "Blocked by network policy",
            {"Content-Type": "text/plain"}
        )
        safe_host = re.sub(r'[\x00-\x1f\x7f]', '', flow.request.host)
        # Redact secrets in the path/query — ctx.log is captured as warden
        # container stdout, the same trust level as the structured sinks.
        safe_path = redact_path(re.sub(r'[\x00-\x1f\x7f]', '', flow.request.path))
        safe_reason = re.sub(r'[\x00-\x1f\x7f]', '', reason)
        ctx.log.info(f"BLOCKED: {safe_host}{safe_path} - {safe_reason}")

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """Enforce port and domain policy on CONNECT tunnels.

        CONNECT is blocked entirely on the ingress port — reverse proxy
        ingress does not support tunneling.
        """
        listen_port = flow.client_conn.sockname[1] if flow.client_conn.sockname else 0
        if listen_port == 8443:
            self._block(flow, "CONNECT not allowed on ingress port")
            return

        self._check_reload()

        host = flow.request.host
        port = flow.request.port

        # Host services — rewrite .host.brig CONNECT tunnels.
        if host.endswith(HOST_SERVICE_SUFFIX):
            client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
            cell_name = self.subnets.get_cell_name(client_ip)
            cell_policy_for_host_svc = self._lookup_cell_policy(cell_name)
            self._handle_host_service(flow, host, cell_name, cell_policy_for_host_svc)
            return

        if port not in ALLOWED_PORTS:
            self._block(flow, f"port {port} not allowed (only 80, 443)")
            return

        # Block internal IP ranges.
        if self._is_internal_ip(host):
            self._block(flow, f"internal IP range blocked: {host}")
            return

        # Block literal IP addresses.
        if self._is_literal_ip(host):
            self._block(flow, f"literal IP addresses blocked: {host}")
            return

        # Host header smuggling — CONNECT requests can also carry a Host
        # header inside the request. Enforce the same match as in request().
        if self._host_header_mismatches(flow):
            self._block(
                flow,
                f"host header mismatch: URL={host} Host={flow.request.headers.get('Host')}"
            )
            return

        # Resolve cell name for per-cell policy.
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
        cell_name = self.subnets.get_cell_name(client_ip)

        cell_policy = self._lookup_cell_policy(cell_name)
        if cell_policy is None:
            self._block(
                flow,
                f"cell '{cell_name or 'unknown'}' has no per-cell policy",
            )
            return
        # CONNECT only sets up the tunnel; path and method are encrypted inside
        # it. Gate on the host alone here — per-request path/method rules are
        # enforced in request() after MITM. Using the full is_allowed() with a
        # placeholder "/"+"CONNECT" would wrongly block HTTPS to any host whose
        # allow rule is path- or method-scoped.
        allowed, reason = cell_policy.is_host_allowed(host)
        if not allowed:
            self._block(flow, f"cell policy: {reason}")

    def tls_clienthello(self, data) -> None:
        """Decide MITM vs passthrough at TLS client-hello time.

        Invariant 11 (docs/INVARIANTS.md): a cell that has declared
        `policy.tls_passthrough: [host]` AND has `host` in
        `policy.allow` opts that host out of MITM. Warden tunnels TCP
        bytes after the CONNECT, routed by SNI; never sees cleartext.

        Two security checks here:

        1. **SNI/CONNECT match.** Reject if the SNI in the client hello
           doesn't equal the host from the preceding CONNECT request.
           Otherwise a malicious cell could CONNECT to allowed-host:443,
           then send SNI=attacker.com to abuse warden as a generic TLS
           tunnel for arbitrary hosts.

        2. **Passthrough requires both lists.** `is_passthrough` is
           defense-in-depth — it only returns True when the SNI matches
           BOTH a passthrough rule AND an allow rule. A tampered policy
           file that lists a host only in `tls_passthrough` cannot
           bypass the allow gate.

        On error we leave passthrough off and let MITM proceed; that
        fails closed (cell sees a TLS error rather than silently
        leaking past inspection).
        """
        try:
            sni = getattr(getattr(data, "client_hello", None), "sni", None)
            if not sni:
                return
            sni = sni.strip().lower()
            client_conn = getattr(data, "context", None)
            client_conn = getattr(client_conn, "client", None)
            # mitmproxy populates context.client.sni from the hello once
            # parsed, but we read directly from the hello to get the
            # raw value before any normalization.
            peer = getattr(client_conn, "peername", None) if client_conn else None
            client_ip = peer[0] if peer else None
            if not client_ip:
                return

            # CONNECT host comes from the http_connect flow; mitmproxy
            # stores it on the client connection's sni/alpn context, but
            # the most reliable cross-version source is the proxy's
            # server-address-resolution metadata. mitmproxy 10+ sets
            # data.context.client.proxy_mode / sni / etc. — use the
            # server-side address pre-resolution, which is the CONNECT
            # target.
            connect_host = None
            server = getattr(getattr(data, "context", None), "server", None)
            address = getattr(server, "address", None) if server else None
            if address and len(address) >= 1 and isinstance(address[0], str):
                connect_host = address[0].strip().lower()

            # FAIL CLOSED: if we couldn't read the CONNECT host, we
            # cannot verify SNI/CONNECT match. Treat as a mismatch —
            # don't flip passthrough. Otherwise a cell could exploit
            # a mitmproxy-API quirk that leaves context.server.address
            # unpopulated to ship arbitrary SNI through the tunnel
            # (would let warden tunnel to attacker.com after CONNECT to
            # allowed.com). The cell-visible failure is identical to
            # the SNI≠CONNECT case: TLS handshake fails because
            # mitmproxy will present its own MITM cert for the host
            # in the CONNECT, which won't match the SNI the cell sent.
            if connect_host is None:
                ctx.log.warn(
                    f"PASSTHROUGH skipped: CONNECT host unreadable, "
                    f"sni={sni}, falling through to MITM"
                )
                return
            if sni != connect_host:
                ctx.log.warn(
                    f"BLOCKED: SNI/CONNECT mismatch sni={sni} connect={connect_host}"
                )
                return

            cell_name = self.subnets.get_cell_name(client_ip)
            cell_policy = self._lookup_cell_policy(cell_name)
            if cell_policy is None:
                return

            if cell_policy.is_passthrough(sni):
                # Connect-time SSRF / DNS-rebinding guard for passthrough.
                # A passthrough tunnel is raw TCP: warden never sees an HTTP
                # response, so the responseheaders IP re-check never fires for
                # it. Resolve the SNI here and REFUSE to flip passthrough if it
                # points into a blocked range — fall through to MITM instead,
                # which fails closed (the cell hits a cert error, or the MITM
                # server_connect / responseheaders guard blocks the internal
                # IP). This is the passthrough counterpart to server_connect.
                if self._resolve_safe(sni) is None:
                    ctx.log.warn(
                        f"PASSTHROUGH refused: cell={cell_name} sni={sni} "
                        f"resolves to an internal/reserved address"
                    )
                    return
                # Engage mitmproxy passthrough: setting ignore_connection on
                # the ClientHelloData makes mitmproxy tunnel the TLS bytes raw
                # after the CONNECT (no MITM), routed to the already-resolved
                # CONNECT target. This is THE passthrough switch the TLS layer
                # reads (`if tls_clienthello.ignore_connection`). Setting an
                # attribute on the client connection does nothing — mitmproxy
                # never reads it.
                #
                # A raw-tunneled (ignored) connection produces no TCPFlow, so
                # tcp_start/tcp_message/tcp_end do NOT fire and there are no
                # per-byte passthrough metrics — that is inherent to true
                # passthrough (warden never decrypts). The connection-level
                # audit is the PASSTHROUGH log line below (cell + SNI); the
                # connection is still gated by the CONNECT allowlist check, the
                # SNI/CONNECT match above, the resolved-IP guard, and
                # server_connect. The client-connection metadata tags below are
                # best-effort context for any hook that does observe the
                # connection.
                data.ignore_connection = True
                if client_conn is not None:
                    metadata = getattr(client_conn, "metadata", None)
                    if isinstance(metadata, dict):
                        metadata["tls_mode"] = "passthrough"
                        metadata["passthrough_sni"] = sni
                        metadata["cell"] = cell_name or "unknown"
                ctx.log.info(
                    f"PASSTHROUGH: cell={cell_name} sni={sni} (no MITM, SNI-routed)"
                )
        except Exception as e:
            # Fail closed by NOT flipping passthrough. The TLS handshake
            # will then proceed in MITM mode; the cell will hit the cert
            # error (existing behavior pre-passthrough) rather than
            # silently leaking through.
            ctx.log.warn(f"tls_clienthello error, defaulting to MITM: {e}")

    def _resolve_safe(self, host: str) -> Optional[str]:
        """Resolve `host` and return an IP only if NO resolved address is in
        a blocked range. Returns None if the host is unresolvable or any
        answer is internal/blocked (fail closed, rebinding-resistant — a
        split-horizon answer set with one internal IP is refused outright).

        A literal-IP host is validated directly. Domain names are resolved
        via getaddrinfo; warden runs in the same VM netns mitmproxy connects
        from, so this resolver sees the same answers.
        """
        if canonical_ip(host) is not None:
            return None if is_blocked_ip(host) else host
        import socket
        try:
            infos = socket.getaddrinfo(host, None)
        except (socket.gaierror, UnicodeError, OSError):
            return None
        candidate: Optional[str] = None
        for info in infos:
            ip = info[4][0]
            if is_blocked_ip(ip):
                return None
            if candidate is None:
                candidate = ip
        return candidate

    def server_connect(self, data) -> None:
        """Connect-time destination-IP guard (SSRF / DNS rebinding).

        The request-time checks (request/http_connect) validate the
        cell-supplied host *name*, not the resolved upstream IP. The
        responseheaders re-check sees the resolved IP but only AFTER the
        request is forwarded. This hook resolves the destination before the
        connection is used and refuses it — via the same `data.server.error`
        mechanism mitmproxy's own proxyserver uses — if it resolves into a
        blocked range, closing the request-before-block gap on the MITM path.
        Passthrough tunnels are guarded separately at tls_clienthello (the
        raw-TCP relay may not reach this hook). Fails closed on any error.

        Warden's own internal routing is exempt: host_service flows are
        rewritten to the macOS host IP, and ingress flows (reverse proxy on
        :8443) connect warden to a managed cell IP. Both are warden's
        decisions, not cell-controlled egress.
        """
        try:
            server = getattr(data, "server", None)
            address = getattr(server, "address", None) if server else None
            if not address:
                return
            host = address[0]

            # host_service rewrite target — a deliberate, policy-gated
            # internal destination.
            if self._host_ip and host == self._host_ip:
                return
            # Ingress (reverse-proxy) flows arrive on the :8443 listener;
            # warden→cell connections there are expected.
            client = getattr(data, "client", None)
            sockname = getattr(client, "sockname", None) if client else None
            if sockname and len(sockname) >= 2 and sockname[1] == 8443:
                return

            # TCP host_service flows: warden's `reverse:tcp` listener dials
            # TCP_UPSTREAM_HOST (host.lima.internal), which resolves to the
            # internal Lima host IP. Exempt these, but ONLY for a port the
            # REQUESTING cell actually declared as a TCP host_service — mirrors
            # tcp_start's per-cell ACL, so a cell can't reach the host by
            # allowlisting the hostname directly.
            port = address[1] if len(address) >= 2 else None
            if host == TCP_UPSTREAM_HOST and isinstance(port, int):
                peer = getattr(client, "peername", None) if client else None
                client_ip = peer[0] if peer else None
                cell_name = self.subnets.get_cell_name(client_ip) if client_ip else None
                cell_policy = self._lookup_cell_policy(cell_name)
                tcp_map = (getattr(cell_policy, "tcp_host_services_map", None) or {}) if cell_policy else {}
                if port in set(tcp_map.values()):
                    return

            # Defense-in-depth: re-check the upstream port against the egress
            # allowlist. Every flow normally passes the request-time port check
            # first; this makes the connect-time guard self-sufficient if a
            # future flow type ever reaches it without that earlier check. The
            # legitimate non-80/443 destinations (host_service rewrites, ingress,
            # declared TCP host_services) are already exempted above.
            if isinstance(port, int) and port not in ALLOWED_PORTS:
                server.error = f"blocked: port {port} not allowed for egress"
                ctx.log.warn(f"BLOCKED connect: {host}:{port} (port not in egress allowlist)")
                return

            if self._resolve_safe(host) is None:
                server.error = (
                    f"blocked: {host} resolves to a disallowed "
                    f"(internal/reserved) address"
                )
                ctx.log.warn(f"BLOCKED connect: {host} (internal/reserved resolution)")
        except Exception as e:
            ctx.log.warn(f"server_connect guard error, failing closed: {e}")
            try:
                data.server.error = "blocked: connect-time validation error"
            except Exception:
                pass

    # Resolved-IP guards by flow type: tls_clienthello refuses passthrough to
    # an internal-resolving SNI; server_connect (above) blocks MITM flows at
    # connect time; responseheaders keeps a post-connect re-check for MITM as
    # defence in depth.

    def tcp_start(self, flow) -> None:
        """Per-cell access control for TCP host_service flows.

        Warden listens on `--mode reverse:tcp://host.lima.internal:<port>@<port>`
        for every TCP host_service port that ANY cell has declared.
        That makes the listener reachable from every cell network —
        but per-cell access must come from the cell's own policy:
        only cells that declared the service in their cell yaml should
        be able to use the listener.

        Decision (defense in depth, matches the HTTP host_service
        check in http_connect/_handle_host_service):
          1. Resolve cell from peer IP (existing subnet-map lookup).
          2. Load cell's per-cell policy.
          3. If the listening port isn't in cell.tcp_host_services_map,
             kill the flow.
          4. Otherwise tag metadata so otel_export's tcp_* hooks can
             emit per-cell + per-service counters and the audit log
             distinguishes TCP-host-service from TLS-passthrough flows.

        Cells that wouldn't have policy (system flows, unknown peer)
        are killed fail-closed. TLS-passthrough flows engage via
        tls_clienthello's `data.ignore_connection`, which makes mitmproxy
        build an ignored TCPLayer (no flow) — so tcp_start does NOT fire for
        them. The passthrough-metadata early-return below is therefore
        defensive only (it would matter for a future flow-bearing relay);
        this hook in practice handles TCP host_service flows.
        """
        try:
            client = getattr(flow, "client_conn", None)
            # Skip if this is a TLS-passthrough flow — different
            # mechanism (invariant 11), gated by SNI not host_service.
            meta = getattr(client, "metadata", None) or {}
            if meta.get("tls_mode") == "passthrough":
                return
            peer = getattr(client, "peername", None)
            client_ip = peer[0] if peer else None
            if not client_ip:
                self._kill_tcp(flow, "no peer IP")
                return
            server = getattr(flow, "server_conn", None)
            address = getattr(server, "address", None) if server else None
            listen_port = address[1] if address and len(address) >= 2 else None
            if not isinstance(listen_port, int):
                self._kill_tcp(flow, "no listen port")
                return
            cell_name = self.subnets.get_cell_name(client_ip)
            cell_policy = self._lookup_cell_policy(cell_name)
            if cell_policy is None:
                self._kill_tcp(
                    flow,
                    f"cell '{cell_name or 'unknown'}' has no per-cell policy",
                )
                return
            tcp_map = getattr(cell_policy, "tcp_host_services_map", None) or {}
            allowed_ports = set(tcp_map.values())
            if listen_port not in allowed_ports:
                self._kill_tcp(
                    flow,
                    f"cell '{cell_name}' did not declare TCP "
                    f"host_service on port {listen_port}",
                )
                return
            # Identify which service this is (first name with the
            # matching port — operators usually have one service per
            # port; ties get the lexically-first name).
            svc_name = next(
                (n for n, p in sorted(tcp_map.items()) if p == listen_port),
                "unknown",
            )
            flow.metadata["cell"] = cell_name
            flow.metadata["host_service"] = svc_name
            flow.metadata["host_service_protocol"] = "tcp"
            flow.metadata["host_service_port"] = listen_port
            ctx.log.info(
                f"TCP HOST_SERVICE: {cell_name} -> {svc_name}:{listen_port}"
            )
        except Exception as e:
            # Fail closed on any unexpected mitmproxy API shape change.
            ctx.log.warn(f"tcp_start error, killing flow: {e}")
            self._kill_tcp(flow, "tcp_start internal error")

    def _kill_tcp(self, flow, reason: str) -> None:
        """Kill a TCP flow with an audit log entry. mitmproxy's flow.kill()
        terminates both ends; we tag metadata first so the logger addon
        records the denial in the same shape as HTTP blocks."""
        safe_reason = re.sub(r'[\x00-\x1f\x7f]', '', reason)
        ctx.log.warn(f"BLOCKED tcp: {safe_reason}")
        flow.metadata["blocked"] = True
        flow.metadata["block_reason"] = safe_reason
        try:
            flow.kill()
        except Exception:
            pass

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Log WebSocket messages on established connections.

        The initial HTTP upgrade is already checked by request()/http_connect()
        against the domain allowlist. This hook only logs frame metadata for
        observability — it does not re-check policy (the connection is already
        allowed).
        """
        message = flow.websocket.messages[-1] if flow.websocket and flow.websocket.messages else None
        if message is None:
            return
        cell_name = flow.metadata.get("cell", "unknown")
        direction = "client" if message.from_client else "server"
        safe_host = re.sub(r'[\x00-\x1f\x7f]', '', flow.request.host)
        ctx.log.debug(
            f"WS: {cell_name} {direction} {safe_host} "
            f"{'text' if message.is_text else 'binary'} {len(message.content)}b"
        )

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        """Block responses from connections that resolved to internal IPs.

        Fails closed: if IP validation raises an exception, block the flow.
        Skips check only for flows we explicitly rewrote to a host service.
        """
        if not flow.server_conn or not flow.server_conn.peername:
            return
        # Skip blocked-IP check for flows warden's own addon chain
        # routed: host_service rewrites (this addon) and ingress flows
        # (ingress.py routed to cell IP). Both are warden's choices.
        if (flow.metadata.get("host_service")
                or flow.metadata.get("ingress_route")):
            return
        try:
            ip_str = flow.server_conn.peername[0]
        except (IndexError, AttributeError):
            self._block(flow, "IP validation failed in responseheaders")
            return
        if is_blocked_ip(ip_str):
            self._block(flow, f"DNS rebinding: resolved to {ip_str}")
            return
        # is_blocked_ip returns False for unparseable input; treat
        # unparseable peer IPs as fail-closed since we cannot prove the
        # server isn't internal.
        try:
            ipaddress.ip_address(
                ip_str[1:-1] if ip_str.startswith("[") and ip_str.endswith("]") else ip_str
            )
        except ValueError:
            self._block(flow, "IP validation failed in responseheaders")


addons = [PolicyEnforcer()]
