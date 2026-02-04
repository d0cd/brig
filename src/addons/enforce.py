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

import ipaddress
import json
import fnmatch
import os
import re
import signal
import threading
import time
from pathlib import Path
from typing import Optional

from mitmproxy import http, ctx

# Policy file path (mounted into container).
POLICY_FILE = Path("/policy.json")

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
    # IPv6 equivalents.
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class PolicyRule:
    """A parsed policy rule supporting domain, path, and method matching.

    Path patterns are precompiled to regex for faster matching.
    """

    def __init__(self, rule):
        """Parse a rule from string or dict format."""
        if isinstance(rule, str):
            self.domain = rule
            self.paths = None
            self.methods = None
        elif isinstance(rule, dict):
            self.domain = rule.get("domain", "")
            self.paths = rule.get("paths")
            self.methods = rule.get("methods")
            if self.methods:
                self.methods = [m.upper() for m in self.methods]
        else:
            raise ValueError(f"Invalid rule format: {rule}")

        # Pre-compile domain pattern.
        self.is_wildcard = self.domain.startswith("*.")
        if self.is_wildcard:
            self.suffix = self.domain[1:].lower()  # Keep the dot for suffix matching.
            self.domain_exact = self.domain[2:].lower()  # For exact match of base domain.
        else:
            self.suffix = None
            self.domain_exact = self.domain.lower()

        # Pre-compile path patterns to regex for faster matching.
        self._path_patterns = None
        if self.paths:
            self._path_patterns = []
            for p in self.paths:
                # Convert fnmatch pattern to regex.
                regex_pattern = fnmatch.translate(p)
                self._path_patterns.append(re.compile(regex_pattern))

    def matches_domain(self, host: str) -> bool:
        """Check if host matches this rule's domain pattern."""
        host = host.lower()

        if self.is_wildcard:
            # Wildcard: *.example.com matches sub.example.com and example.com.
            return host.endswith(self.suffix) or host == self.domain_exact
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

    def is_allowed(self, host: str, path: str, method: str, trace_config: PolicyTraceConfig = None) -> tuple[bool, str, dict]:
        """Check if request is allowed.

        Returns (allowed, reason, trace) tuple.
        Trace contains evaluation details when tracing is enabled.
        """
        trace = {}
        decision_path = []

        if trace_config and trace_config.enabled:
            if trace_config.include_timing:
                import time
                start_time = time.time()

        # Check denylist first (deny takes precedence).
        decision_path.append("check_deny")
        deny_rules_checked = 0
        for i, rule in enumerate(self.deny_rules):
            deny_rules_checked += 1
            if rule.matches(host, path, method):
                decision_path.append("denied")
                if trace_config and trace_config.enabled:
                    trace["deny_rules_checked"] = deny_rules_checked
                    trace["allow_rules_checked"] = 0
                    trace["matched_rule"] = rule.domain
                    trace["matched_index"] = i
                    trace["decision_path"] = decision_path
                    if trace_config.include_timing:
                        trace["evaluation_ms"] = round((time.time() - start_time) * 1000, 3)
                return False, f"denied by rule: {rule.domain}", trace

        # Check allowlist.
        decision_path.append("check_allow")
        allow_rules_checked = 0
        for i, rule in enumerate(self.allow_rules):
            allow_rules_checked += 1
            if rule.matches(host, path, method):
                decision_path.append("allowed")
                if trace_config and trace_config.enabled:
                    trace["deny_rules_checked"] = deny_rules_checked
                    trace["allow_rules_checked"] = allow_rules_checked
                    trace["matched_rule"] = rule.domain
                    trace["matched_index"] = i
                    trace["decision_path"] = decision_path
                    if trace_config.include_timing:
                        trace["evaluation_ms"] = round((time.time() - start_time) * 1000, 3)
                return True, f"allowed by rule: {rule.domain}", trace

        # Default deny.
        decision_path.append("default_deny")
        if trace_config and trace_config.enabled:
            trace["deny_rules_checked"] = deny_rules_checked
            trace["allow_rules_checked"] = allow_rules_checked
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
        self.cell_policies: dict[str, Policy] = {}
        self.subnet_map: dict[str, str] = {}
        self.policy_mtime = 0.0
        self.subnet_map_mtime = 0.0
        self.cell_policy_mtimes: dict[str, float] = {}
        self.cell_policy_last_access: dict[str, float] = {}  # LRU tracking.
        self.trace_config = PolicyTraceConfig()
        self._cell_policy_lock = threading.Lock()  # Protects cell_policies access.

    def load(self, loader):
        """Called when addon is loaded."""
        ctx.log.info("PolicyEnforcer: Loading...")
        self._reload_policy()
        self._reload_subnet_map()
        self._reload_cell_policies()
        # Register SIGHUP handler for signal-based reload.
        signal.signal(signal.SIGHUP, self._handle_sighup)
        ctx.log.info("PolicyEnforcer: SIGHUP reload handler registered")

    def _handle_sighup(self, signum, frame):
        """Handle SIGHUP signal for policy reload."""
        ctx.log.info("PolicyEnforcer: Received SIGHUP, reloading policies...")
        # Force reload by resetting mtimes and clearing caches.
        self.policy_mtime = 0.0
        self.subnet_map_mtime = 0.0
        with self._cell_policy_lock:
            self.cell_policy_mtimes.clear()
            self.cell_policy_last_access.clear()
        self._reload_policy()
        self._reload_subnet_map()
        self._reload_cell_policies()

    def _reload_policy(self) -> None:
        """Load global policy from file."""
        try:
            if not POLICY_FILE.exists():
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

            self.policy_mtime = mtime

            ctx.log.info(
                f"PolicyEnforcer: Loaded policy - "
                f"{len(self.global_policy.allow_rules)} allow, "
                f"{len(self.global_policy.deny_rules)} deny rules"
            )
            if self.trace_config.enabled:
                ctx.log.info("PolicyEnforcer: Policy tracing enabled")

        except (json.JSONDecodeError, IOError, OSError) as e:
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

            ctx.log.info(f"PolicyEnforcer: Loaded subnet map - {len(self.subnet_map)} cells")

        except (json.JSONDecodeError, IOError, OSError) as e:
            ctx.log.error(f"PolicyEnforcer: Failed to load subnet map: {e}")

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

                    # Evict oldest policy if at capacity.
                    if cell_name not in self.cell_policies:
                        if len(self.cell_policies) >= MAX_CACHED_CELL_POLICIES:
                            oldest = min(
                                self.cell_policy_last_access.keys(),
                                key=lambda k: self.cell_policy_last_access[k]
                            )
                            del self.cell_policies[oldest]
                            del self.cell_policy_mtimes[oldest]
                            del self.cell_policy_last_access[oldest]
                            ctx.log.debug(f"PolicyEnforcer: Evicted policy for '{oldest}'")

                try:
                    with open(policy_file, "r") as f:
                        data = json.load(f)
                    with self._cell_policy_lock:
                        self.cell_policies[cell_name] = Policy(
                            allow=data.get("allow", []),
                            deny=data.get("deny", [])
                        )
                        self.cell_policy_mtimes[cell_name] = mtime
                        self.cell_policy_last_access[cell_name] = time.time()
                    ctx.log.info(f"PolicyEnforcer: Loaded policy for cell '{cell_name}'")
                except (json.JSONDecodeError, IOError) as e:
                    ctx.log.error(f"PolicyEnforcer: Failed to load cell policy {cell_name}: {e}")

        except OSError as e:
            ctx.log.error(f"PolicyEnforcer: Failed to scan cell policies: {e}")

    def _get_cell_name(self, client_ip: str) -> Optional[str]:
        """Resolve client IP to cell name via subnet map."""
        try:
            ip = ipaddress.ip_address(client_ip)
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
            ip = ipaddress.ip_address(host)
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
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def request(self, flow: http.HTTPFlow) -> None:
        """Process each HTTP request."""
        # Policy reload now handled via SIGHUP signal (see _handle_sighup).
        # No per-request stat() calls for better performance.

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

        # Check 4: Per-cell policy (if exists).
        cell_policy = None
        if cell_name:
            with self._cell_policy_lock:
                if cell_name in self.cell_policies:
                    cell_policy = self.cell_policies[cell_name]
                    self.cell_policy_last_access[cell_name] = time.time()  # LRU tracking.
        if cell_policy:
            allowed, reason, trace = cell_policy.is_allowed(host, path, method, self.trace_config)
            if trace and self.trace_config.enabled:
                flow.metadata["policy_trace"] = trace
            if allowed:
                flow.metadata["policy_reason"] = f"cell:{reason}"
                return
            # Fall through to global policy check if not explicitly denied.
            if "denied by rule" in reason:
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

    def _block(self, flow: http.HTTPFlow, reason: str) -> None:
        """Block the request with a 403 response."""
        flow.metadata["blocked"] = True
        flow.metadata["block_reason"] = reason

        flow.response = http.Response.make(
            403,
            f"Blocked by Warden: {reason}",
            {"Content-Type": "text/plain"}
        )
        ctx.log.info(f"BLOCKED: {flow.request.host}{flow.request.path} - {reason}")


addons = [PolicyEnforcer()]
