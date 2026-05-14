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
import fnmatch
import ipaddress
import json
import re
import threading
import time
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http


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

# Blocked IP ranges.
BLOCKED_NETWORKS = [
    # RFC1918 private ranges.
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Localhost.
    ipaddress.ip_network("127.0.0.0/8"),
    # Link-local.
    ipaddress.ip_network("169.254.0.0/16"),
    # CGNAT.
    ipaddress.ip_network("100.64.0.0/10"),
    # Benchmarking.
    ipaddress.ip_network("198.18.0.0/15"),
    # Reserved.
    ipaddress.ip_network("240.0.0.0/4"),
    # "This network" (used in SSRF attacks).
    ipaddress.ip_network("0.0.0.0/8"),
    # Multicast.
    ipaddress.ip_network("224.0.0.0/4"),
    # IPv6 equivalents.
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    # IPv4-mapped IPv6 (bypass for all IPv4 blocked ranges).
    ipaddress.ip_network("::ffff:0:0/96"),
    # Documentation prefix (should never appear in production).
    ipaddress.ip_network("2001:db8::/32"),
    # IPv6 multicast.
    ipaddress.ip_network("ff00::/8"),
]


class PolicyRule:
    """A parsed policy rule supporting domain, path, and method matching.

    Path patterns are precompiled to regex for faster matching.
    """

    def __init__(self, rule):
        """Parse a rule from string or dict format."""
        if isinstance(rule, str):
            self.domain = rule.rstrip(".")
            self.paths = None
            self.methods = None
        elif isinstance(rule, dict):
            self.domain = rule.get("domain", "").rstrip(".")
            if not self.domain:
                raise ValueError("PolicyRule: domain must not be empty")
            self.paths = rule.get("paths")
            self.methods = rule.get("methods")
            if self.methods:
                self.methods = [m.upper() for m in self.methods]
        else:
            raise ValueError(f"Invalid rule format: {rule}")

        # Pre-compile domain pattern (normalize IDN to punycode).
        self.is_wildcard = self.domain.startswith("*.")
        if self.is_wildcard:
            base = self.domain[2:]
            # Fast path: skip IDN encode for ASCII domains.
            if not base.isascii():
                try:
                    base = base.encode("idna").decode("ascii")
                except (UnicodeError, UnicodeDecodeError):
                    pass
            self.suffix = ("." + base).lower()  # Keep the dot for suffix matching.
            self.domain_exact = base.lower()  # For exact match of base domain.
        else:
            # Fast path: skip IDN encode for ASCII domains.
            if self.domain.isascii():
                normalized = self.domain
            else:
                try:
                    normalized = self.domain.encode("idna").decode("ascii")
                except (UnicodeError, UnicodeDecodeError):
                    normalized = self.domain
            self.suffix = None
            self.domain_exact = normalized.lower()

        # Pre-compile path patterns to regex for faster matching.
        self._path_patterns = None
        if self.paths:
            self._path_patterns = []
            for p in self.paths:
                # Convert fnmatch pattern to regex.
                regex_pattern = fnmatch.translate(p)
                self._path_patterns.append(re.compile(regex_pattern))

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Normalize domain to ASCII/punycode for consistent matching."""
        domain = domain.rstrip(".")
        # Fast path: skip IDN encode for ASCII domains.
        if domain.isascii():
            return domain.lower()
        try:
            return domain.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            return domain.lower()

    def matches_domain(self, host: str) -> bool:
        """Check if host matches this rule's domain pattern.

        Wildcard patterns match subdomains only:
            *.example.com matches foo.example.com, NOT example.com itself.
        """
        host = self._normalize_domain(host)

        if self.is_wildcard:
            # Wildcard: *.example.com matches sub.example.com only.
            # Does NOT match the bare domain (example.com).
            # Dot-boundary check prevents "notexample.com" matching ".example.com".
            return host.endswith(self.suffix) and len(host) > len(self.suffix)
        else:
            # Exact match.
            return host == self.domain_exact

    def matches_path(self, path: str) -> bool:
        """Check if path matches this rule's path patterns."""
        if self._path_patterns is None:
            return True  # No path restriction.

        for pattern in self._path_patterns:
            if pattern.match(path):
                return True
        return False

    def matches_method(self, method: str) -> bool:
        """Check if method matches this rule's method restrictions."""
        if self.methods is None:
            return True  # No method restriction.
        return method.upper() in self.methods

    def matches(self, host: str, path: str, method: str) -> bool:
        """Check if request matches this rule completely."""
        return (
            self.matches_domain(host) and
            self.matches_path(path) and
            self.matches_method(method)
        )


class DomainTrie:
    """Reverse-label trie for fast domain matching.

    Stores rules indexed by reversed domain labels.
    e.g., "api.github.com" is stored as ["com", "github", "api"]
    Wildcard "*.github.com" is stored as ["com", "github"] with a wildcard marker.
    """

    __slots__ = ("children", "exact_rules", "wildcard_rules")

    def __init__(self):
        self.children: dict[str, "DomainTrie"] = {}
        self.exact_rules: list[PolicyRule] = []
        self.wildcard_rules: list[PolicyRule] = []

    def insert(self, rule: PolicyRule) -> None:
        """Insert a PolicyRule into the trie."""
        if rule.is_wildcard:
            # Wildcard "*.example.com" — store at ["com", "example"] with wildcard marker.
            labels = rule.domain_exact.split(".")
        else:
            # Exact "api.example.com" — store at ["com", "example", "api"].
            labels = rule.domain_exact.split(".")

        labels.reverse()
        node = self
        for label in labels:
            if label not in node.children:
                node.children[label] = DomainTrie()
            node = node.children[label]

        if rule.is_wildcard:
            node.wildcard_rules.append(rule)
        else:
            node.exact_rules.append(rule)

    def lookup(self, host: str) -> list[PolicyRule]:
        """Return all matching PolicyRules for a given host.

        Walks the trie from root, collecting wildcard matches at each level,
        and exact matches at the leaf.
        """
        host = PolicyRule._normalize_domain(host)
        labels = host.split(".")
        labels.reverse()

        node = self
        matches = []

        for i, label in enumerate(labels):
            if label not in node.children:
                # No deeper match possible.
                return matches
            node = node.children[label]

            # Wildcard rules at this node match any deeper domain.
            # Only match if there are more labels remaining (wildcard requires subdomain).
            if node.wildcard_rules and i < len(labels) - 1:
                matches.extend(node.wildcard_rules)

        # Exact rules match only if we consumed all labels.
        if node.exact_rules:
            matches.extend(node.exact_rules)

        return matches


class PolicyTraceConfig:
    """Configuration for policy evaluation tracing."""

    def __init__(self, config: dict = None):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.include_rule_details = config.get("include_rule_details", True)
        self.include_timing = config.get("include_timing", False)


class Policy:
    """Parsed policy with allow/deny rules."""

    def __init__(self, allow: list = None, deny: list = None):
        self.allow_rules = [PolicyRule(r) for r in (allow or [])]
        self.deny_rules = [PolicyRule(r) for r in (deny or [])]
        # Build reverse-label tries for O(k) domain lookup.
        self._allow_trie = DomainTrie()
        for rule in self.allow_rules:
            self._allow_trie.insert(rule)
        self._deny_trie = DomainTrie()
        for rule in self.deny_rules:
            self._deny_trie.insert(rule)
        # Pre-build rule -> index map for O(1) trace lookups.
        self._rule_index = {id(r): i for i, r in enumerate(self.deny_rules)}
        self._rule_index.update({id(r): i for i, r in enumerate(self.allow_rules)})

    def is_allowed(self, host: str, path: str, method: str, trace_config: PolicyTraceConfig = None) -> tuple[bool, str, dict]:
        """Check if request is allowed.

        Returns (allowed, reason, trace) tuple.
        Trace contains evaluation details when tracing is enabled.
        Uses reverse-label trie for O(k) domain lookup where k = label count.
        """
        trace = {}
        decision_path = []

        if trace_config and trace_config.enabled:
            if trace_config.include_timing:
                import time
                start_time = time.time()

        # Check denylist first (deny takes precedence).
        decision_path.append("check_deny")
        deny_matches = self._deny_trie.lookup(host)
        for rule in deny_matches:
            if rule.matches_path(path) and rule.matches_method(method):
                decision_path.append("denied")
                if trace_config and trace_config.enabled:
                    trace["deny_rules_checked"] = len(deny_matches)
                    trace["allow_rules_checked"] = 0
                    trace["matched_rule"] = rule.domain
                    trace["matched_index"] = self._rule_index.get(id(rule), -1)
                    trace["decision_path"] = decision_path
                    if trace_config.include_timing:
                        trace["evaluation_ms"] = round((time.time() - start_time) * 1000, 3)
                return False, f"denied by rule: {rule.domain}", trace

        # Check allowlist.
        decision_path.append("check_allow")
        allow_matches = self._allow_trie.lookup(host)
        for rule in allow_matches:
            if rule.matches_path(path) and rule.matches_method(method):
                decision_path.append("allowed")
                if trace_config and trace_config.enabled:
                    trace["deny_rules_checked"] = len(deny_matches)
                    trace["allow_rules_checked"] = len(allow_matches)
                    trace["matched_rule"] = rule.domain
                    trace["matched_index"] = self._rule_index.get(id(rule), -1)
                    trace["decision_path"] = decision_path
                    if trace_config.include_timing:
                        trace["evaluation_ms"] = round((time.time() - start_time) * 1000, 3)
                return True, f"allowed by rule: {rule.domain}", trace

        # Default deny.
        decision_path.append("default_deny")
        if trace_config and trace_config.enabled:
            trace["deny_rules_checked"] = len(deny_matches)
            trace["allow_rules_checked"] = len(allow_matches)
            trace["matched_rule"] = None
            trace["matched_index"] = -1
            trace["decision_path"] = decision_path
            if trace_config.include_timing:
                trace["evaluation_ms"] = round((time.time() - start_time) * 1000, 3)
        return False, "not in allowlist", trace


class PolicyEnforcer:
    """mitmproxy addon for policy enforcement."""

    def __init__(self):
        self.global_policy = Policy()
        self.cell_policies: collections.OrderedDict[str, Policy] = collections.OrderedDict()
        self.subnet_map: dict[str, str] = {}
        self._subnet_index: dict[int, str] = {}  # Third-octet index for O(1) /24 lookup.
        self.policy_mtime = 0.0
        self.subnet_map_mtime = 0.0
        self.cell_policy_mtimes: dict[str, float] = {}
        self.trace_config = PolicyTraceConfig()
        self._cell_policy_lock = threading.Lock()
        self._reload_lock = threading.RLock()
        # Host services: name → port mapping for cell → host forwarding.
        self.host_services: dict[str, int] = {}
        self._host_ip: str = ""
        # Set of (host_ip, port) tuples for host-service-rewritten connections.
        # server_connected/responseheaders check this to skip blocked-IP checks.
        self._host_service_targets: set[tuple[str, int]] = set()

    def load(self, loader):
        """Called when addon is loaded.

        Startup uses strict policy load: a missing or malformed /policy.json
        raises so warden refuses to start instead of silently running with an
        empty allow/deny list (which defaults-deny but looks healthy).
        """
        ctx.log.info("PolicyEnforcer: Loading...")
        self._discover_host_ip()
        self._reload_policy(strict=True)
        self._reload_subnet_map()
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
                SUBNET_MAP_FILE.stat().st_mtime != self.subnet_map_mtime
            )
        except OSError:
            return

        if not policy_changed and not subnet_changed:
            return

        with self._reload_lock:
            ctx.log.info("PolicyEnforcer: Reloading (file change detected)...")
            if policy_changed:
                self._reload_policy()
            if subnet_changed:
                self._reload_subnet_map()
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
                self.global_policy = Policy()
                return

            mtime = POLICY_FILE.stat().st_mtime
            if mtime == self.policy_mtime:
                return  # No change.

            with open(POLICY_FILE, "r") as f:
                data = json.load(f)

            self.global_policy = Policy(
                allow=data.get("allow", []),
                deny=data.get("deny", [])
            )

            # Load policy trace configuration.
            trace_config = data.get("policy_trace", {})
            self.trace_config = PolicyTraceConfig(trace_config)

            # Load host services with strict validation.
            new_host_services: dict[str, int] = {}
            for svc in data.get("host_services", []):
                if not isinstance(svc, dict):
                    continue
                svc_name = svc.get("name")
                svc_port = svc.get("port")
                if not isinstance(svc_name, str) or not isinstance(svc_port, int):
                    continue
                # Validate name: lowercase alphanumeric + hyphens, max 31 chars.
                if not re.match(r'^[a-z0-9][a-z0-9-]{0,30}$', svc_name):
                    ctx.log.warn(
                        f"PolicyEnforcer: Skipping host service with invalid name: "
                        f"{svc_name!r}"
                    )
                    continue
                # Validate port: 1-65535.
                if svc_port < 1 or svc_port > 65535:
                    ctx.log.warn(
                        f"PolicyEnforcer: Skipping host service '{svc_name}' with "
                        f"invalid port: {svc_port}"
                    )
                    continue
                new_host_services[svc_name] = svc_port
            self.host_services = new_host_services
            # Rebuild host service targets set.
            if self._host_ip:
                self._host_service_targets = {
                    (self._host_ip, port) for port in new_host_services.values()
                }

            self.policy_mtime = mtime

            ctx.log.info(
                f"PolicyEnforcer: Loaded policy - "
                f"{len(self.global_policy.allow_rules)} allow, "
                f"{len(self.global_policy.deny_rules)} deny rules"
            )
            if self.host_services:
                ctx.log.info(
                    f"PolicyEnforcer: {len(self.host_services)} host services: "
                    f"{', '.join(sorted(self.host_services))}"
                )
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

    def _reload_subnet_map(self) -> None:
        """Load subnet-to-cell mapping."""
        try:
            if not SUBNET_MAP_FILE.exists():
                return

            mtime = SUBNET_MAP_FILE.stat().st_mtime
            if mtime == self.subnet_map_mtime:
                return  # No change.

            with open(SUBNET_MAP_FILE, "r") as f:
                self.subnet_map = json.load(f)
            self.subnet_map_mtime = mtime
            self._build_subnet_index()

            ctx.log.info(f"PolicyEnforcer: Loaded subnet map - {len(self.subnet_map)} cells")

        except (json.JSONDecodeError, IOError, OSError) as e:
            ctx.log.error(f"PolicyEnforcer: Failed to load subnet map: {e}")

    def _build_subnet_index(self) -> None:
        """Build O(1) lookup index for /24 subnets keyed by top 24 bits.

        Uses the network prefix (top 24 bits) as key to avoid collisions
        between subnets in different /16 ranges.
        """
        index = {}
        for subnet_str, cell_name in self.subnet_map.items():
            try:
                net = ipaddress.ip_network(subnet_str, strict=False)
                if net.version == 4 and net.prefixlen == 24:
                    prefix = int(net.network_address) >> 8
                    index[prefix] = cell_name
            except ValueError:
                continue
        self._subnet_index = index

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
                            deny=data.get("deny", [])
                        )
                        self.cell_policy_mtimes[cell_name] = mtime
                        ctx.log.info(f"PolicyEnforcer: Loaded policy for cell '{cell_name}'")
                    except (json.JSONDecodeError, IOError) as e:
                        ctx.log.error(f"PolicyEnforcer: Failed to load cell policy {cell_name}: {e}")

        except OSError as e:
            ctx.log.error(f"PolicyEnforcer: Failed to scan cell policies: {e}")

    def _get_cell_name(self, client_ip: str) -> Optional[str]:
        """Resolve client IP to cell name via subnet map.

        Fast path: O(1) dict lookup by third octet for /24 IPv4 subnets.
        Slow path: linear scan for non-/24 or IPv6 subnets.
        """
        try:
            ip = ipaddress.ip_address(client_ip)
            # Fast path: IPv4 with /24 index.
            if isinstance(ip, ipaddress.IPv4Address) and self._subnet_index:
                prefix = int(ip) >> 8
                result = self._subnet_index.get(prefix)
                if result is not None:
                    return result
            # Slow path: linear scan for non-indexed subnets.
            for subnet_str, cell_name in self.subnet_map.items():
                try:
                    subnet = ipaddress.ip_network(subnet_str, strict=False)
                    if ip in subnet:
                        return cell_name
                except ValueError:
                    continue
        except ValueError:
            pass
        return None

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
        """
        h = (hostspec or "").strip()
        if h.startswith("["):
            end = h.find("]")
            if end == -1:
                return h.lower()
            return h[1:end].lower()
        # Bare IPv6 has >= 2 colons and no brackets: don't strip "port".
        if h.count(":") > 1:
            return h.lower()
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
        cell_name = self._get_cell_name(client_ip)

        # Store for logging addon.
        flow.metadata["cell"] = cell_name or "unknown"
        flow.metadata["client_ip"] = client_ip

        # Check 0: Host services — virtual .host.brig domains.
        # Must come before port/IP checks since we rewrite to a private IP.
        if host.endswith(HOST_SERVICE_SUFFIX):
            self._handle_host_service(flow, host, cell_name)
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

        # Check 4: Per-cell policy (if exists).
        cell_policy = None
        if cell_name:
            with self._cell_policy_lock:
                if cell_name in self.cell_policies:
                    cell_policy = self.cell_policies[cell_name]
                    self.cell_policies.move_to_end(cell_name)  # LRU tracking.
        if cell_policy:
            allowed, reason, trace = cell_policy.is_allowed(host, path, method, self.trace_config)
            if trace and self.trace_config.enabled:
                flow.metadata["policy_trace"] = trace
            if allowed:
                flow.metadata["policy_reason"] = f"cell:{reason}"
                return
            # Cell policy exists but didn't allow — block without falling through.
            self._block(flow, f"cell policy: {reason}")
            return

        # Check 5: Global policy.
        allowed, reason, trace = self.global_policy.is_allowed(host, path, method, self.trace_config)
        if trace and self.trace_config.enabled:
            flow.metadata["policy_trace"] = trace
        if allowed:
            flow.metadata["policy_reason"] = f"global:{reason}"
            return

        # Default: Block.
        self._block(flow, f"global policy: {reason}")

    def _handle_host_service(self, flow: http.HTTPFlow, host: str, cell_name: str | None) -> None:
        """Route a .host.brig request to the macOS host.

        Validates the service name, rewrites host/port, tags metadata.
        Blocks if service is unknown or host IP is not discovered.
        """
        service_name = host[: -len(HOST_SERVICE_SUFFIX)]
        safe_name = re.sub(r'[\x00-\x1f\x7f]', '', service_name)

        if not self._host_ip:
            self._block(flow, f"host service '{safe_name}': host IP not discovered")
            return

        service_port = self.host_services.get(service_name)
        if service_port is None:
            self._block(flow, f"unknown host service: {safe_name}")
            return

        # Rewrite request to target the macOS host.
        flow.request.host = self._host_ip
        flow.request.port = service_port
        flow.request.headers["Host"] = f"{service_name}.host.brig"

        # Register target so server_connected/responseheaders skip the
        # blocked-IP check for this connection (the host IP is private).
        self._host_service_targets.add((self._host_ip, service_port))

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
            cell_name = self._get_cell_name(client_ip)
            self._handle_host_service(flow, host, cell_name)
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
        cell_name = self._get_cell_name(client_ip)

        # Check per-cell policy.
        cell_policy = None
        if cell_name:
            with self._cell_policy_lock:
                if cell_name in self.cell_policies:
                    cell_policy = self.cell_policies[cell_name]
                    self.cell_policies.move_to_end(cell_name)
        if cell_policy:
            allowed, reason, _ = cell_policy.is_allowed(host, "/", "CONNECT")
            if not allowed:
                self._block(flow, f"cell policy: {reason}")
            return

        # Check global policy.
        allowed, reason, _ = self.global_policy.is_allowed(host, "/", "CONNECT")
        if not allowed:
            self._block(flow, f"global policy: {reason}")

    def server_connected(self, data):
        """Check resolved IP against blocked ranges after DNS resolution.

        Fails closed: if IP validation raises an exception, kill the connection.
        Skips check for host-service-rewritten connections (the target IP
        is private by design).
        """
        try:
            peername = data.server.peername
            if peername:
                ip_str = peername[0]
                port = peername[1] if len(peername) > 1 else 0

                # Skip blocked-IP check for host service targets.
                if (ip_str, port) in self._host_service_targets:
                    return

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
        """
        if not flow.server_conn or not flow.server_conn.peername:
            return
        try:
            ip_str = flow.server_conn.peername[0]
            port = flow.server_conn.peername[1] if len(flow.server_conn.peername) > 1 else 0

            # Skip blocked-IP check for host service targets.
            if (ip_str, port) in self._host_service_targets:
                return

            ip = ipaddress.ip_address(ip_str)
            for net in BLOCKED_NETWORKS:
                if ip in net:
                    reason = f"DNS rebinding: resolved to {ip_str}"
                    self._block(flow, reason)
                    return
        except Exception:
            # Fail closed: block on any parse/validation error.
            self._block(flow, "IP validation failed in responseheaders")


addons = [PolicyEnforcer()]
