"""
Policy enforcement addon for mitmproxy.

Enforces network policy on egress traffic:
    - Allowlist/denylist with wildcard support
    - Per-cell policies override global policy
    - Path and method-based filtering
    - Block internal IP ranges (RFC1918, localhost, CGNAT, etc.)
    - Block literal IP addresses
    - Block non-HTTP/HTTPS ports
    - Default-deny on errors (fail closed)

Policy format (JSON):
    {
        "allow": [
            "example.com",
            "*.github.com",
            {"domain": "api.example.com", "paths": ["/v1/*"], "methods": ["GET", "POST"]}
        ],
        "deny": ["evil.com"],
        "cells": {
            "my-cell": {
                "allow": ["extra.com"],
                "deny": ["blocked.com"]
            }
        }
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

from _common import BLOCKED_NETWORKS, SubnetResolver
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

# Subnet map for cell identification.
SUBNET_MAP_FILE = Path("/var/run/cells/subnet-map.json")

# Per-cell policy directory.
CELL_POLICY_DIR = Path("/var/run/cells/policies")

# Allowed ports.
ALLOWED_PORTS = {80, 443}

# Maximum number of cell policies to cache (LRU eviction beyond this).
MAX_CACHED_CELL_POLICIES = 1000


class PolicyEnforcer:
    """mitmproxy addon for policy enforcement."""

    def __init__(self):
        self.cell_policies: collections.OrderedDict[str, Policy] = collections.OrderedDict()
        self.subnets = SubnetResolver(SUBNET_MAP_FILE)
        self.policy_mtime = 0.0
        self.cell_policy_mtimes: dict[str, float] = {}
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
                POLICY_FILE.stat().st_mtime != self.policy_mtime
            )
            subnet_changed = (
                SUBNET_MAP_FILE.exists() and
                SUBNET_MAP_FILE.stat().st_mtime != self.subnets._mtime
            )
            policy_dir_changed = False
            if CELL_POLICY_DIR.exists():
                # Detect adds / removes / edits to per-cell policies via dir mtime.
                dir_mtime = CELL_POLICY_DIR.stat().st_mtime
                if not hasattr(self, "_cell_policy_dir_mtime"):
                    self._cell_policy_dir_mtime = 0.0
                policy_dir_changed = dir_mtime != self._cell_policy_dir_mtime
                if policy_dir_changed:
                    self._cell_policy_dir_mtime = dir_mtime
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

            mtime = POLICY_FILE.stat().st_mtime
            if mtime == self.policy_mtime:
                return

            with open(POLICY_FILE, "r") as f:
                data = json.load(f)

            self.trace_config = PolicyTraceConfig(data.get("policy_trace", {}))
            self.policy_mtime = mtime

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

            for policy_file in CELL_POLICY_DIR.glob("*.json"):
                cell_name = policy_file.stem
                mtime = policy_file.stat().st_mtime

                with self._cell_policy_lock:
                    if self.cell_policy_mtimes.get(cell_name) == mtime:
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
                        self.cell_policies[cell_name] = Policy(
                            allow=data.get("allow", []),
                            deny=data.get("deny", []),
                            host_services=data.get("host_services"),
                            tls_passthrough=data.get("tls_passthrough", []),
                        )
                        self.cell_policy_mtimes[cell_name] = mtime
                        ctx.log.info(f"PolicyEnforcer: Loaded policy for cell '{cell_name}'")
                    except (json.JSONDecodeError, IOError) as e:
                        ctx.log.error(f"PolicyEnforcer: Failed to load cell policy {cell_name}: {e}")

        except OSError as e:
            ctx.log.error(f"PolicyEnforcer: Failed to scan cell policies: {e}")

    def _is_internal_ip(self, host: str) -> bool:
        """Check if host is an internal/reserved IP address."""
        try:
            addr = host[1:-1] if host.startswith("[") and host.endswith("]") else host
            ip = ipaddress.ip_address(addr)
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    return True
        except ValueError:
            # Not an IP address (domain name).
            pass
        return False

    def _is_literal_ip(self, host: str) -> bool:
        """Check if host is a literal IP address (not a domain)."""
        try:
            addr = host[1:-1] if host.startswith("[") and host.endswith("]") else host
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False

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
        safe_path = re.sub(r'[\x00-\x1f\x7f]', '', flow.request.path)
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
        allowed, reason, _ = cell_policy.is_allowed(host, "/", "CONNECT")
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

            if connect_host and sni != connect_host:
                ctx.log.warn(
                    f"BLOCKED: SNI/CONNECT mismatch sni={sni} connect={connect_host}"
                )
                # Don't close — mitmproxy will fail the handshake when we
                # don't tag passthrough and the cert mismatches. Logging
                # surfaces the attempt; the existing host-allow check in
                # http_connect already blocked the CONNECT if the host
                # wasn't permitted.
                return

            cell_name = self.subnets.get_cell_name(client_ip)
            cell_policy = self._lookup_cell_policy(cell_name)
            if cell_policy is None:
                return

            if cell_policy.is_passthrough(sni):
                # Flip mitmproxy's passthrough switch — connection is
                # tunneled raw after this point. Tag context so audit
                # log lines (server_connected, response*) can mark
                # tls_mode=passthrough.
                if client_conn is not None:
                    setattr(client_conn, "tls_passthrough", True)
                # Persist for later hooks. Use a dict on data.context if
                # mitmproxy exposes one; otherwise set an attribute on
                # the client connection.
                if client_conn is not None:
                    metadata = getattr(client_conn, "metadata", None)
                    if isinstance(metadata, dict):
                        metadata["tls_mode"] = "passthrough"
                        metadata["passthrough_sni"] = sni
                ctx.log.info(
                    f"PASSTHROUGH: cell={cell_name} sni={sni} (no MITM, SNI-routed)"
                )
        except Exception as e:
            # Fail closed by NOT flipping passthrough. The TLS handshake
            # will then proceed in MITM mode; the cell will hit the cert
            # error (existing behavior pre-passthrough) rather than
            # silently leaking through.
            ctx.log.warn(f"tls_clienthello error, defaulting to MITM: {e}")

    def server_connected(self, data):
        """Check resolved IP against blocked ranges after DNS resolution.

        Fails closed: if IP validation raises an exception, kill the connection.
        Skips check for connections we explicitly rewrote to a host service
        (gated by flow.metadata, not just by the (ip, port) tuple — a tuple
        match alone would let a DNS-rebinding allowlisted domain reach a
        host service that resolves to the same private (ip, port) pair).
        """
        try:
            # Skip ONLY if this server connection was created for a flow that
            # we rewrote in _handle_host_service. The flow attribute is
            # populated for HTTP flows in mitmproxy >= 10.
            flow = getattr(data, "flow", None)
            # Skip the rebinding check for flows warden's own addon chain
            # routed: host_service rewrites (handled here in enforce.py)
            # and ingress flows (ingress.py picked the cell IP itself).
            # Both are warden's choices, not poisoned DNS responses.
            if flow is not None and (
                flow.metadata.get("host_service")
                or flow.metadata.get("ingress_route")
            ):
                return

            peername = data.server.peername
            if peername:
                ip_str = peername[0]
                ip = ipaddress.ip_address(ip_str)
                for net in BLOCKED_NETWORKS:
                    if ip in net:
                        ctx.log.warn(f"BLOCKED: DNS rebinding detected - resolved to {ip_str}")
                        data.server.close()
                        return
        except Exception:
            # Fail closed: kill the connection on any parse/validation error.
            ctx.log.warn("BLOCKED: server_connected failed to validate IP, closing connection")
            try:
                data.server.close()
            except OSError:
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
            ip = ipaddress.ip_address(ip_str)
            for net in BLOCKED_NETWORKS:
                if ip in net:
                    reason = f"DNS rebinding: resolved to {ip_str}"
                    self._block(flow, reason)
                    return
        except (ValueError, IndexError):
            # Fail closed: block on any parse/validation error.
            self._block(flow, "IP validation failed in responseheaders")


addons = [PolicyEnforcer()]
