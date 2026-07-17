"""
Policy data structures for the warden enforce addon.

This module is intentionally a sibling of enforce.py rather than nested
under it: addons run in the warden container with their script directory
on sys.path[0] and import each other by bare name. Keeping the matching
logic here lets enforce.py focus on the mitmproxy lifecycle hooks.

Contains:
  - PolicyRule: parsed allow/deny rule with optional path / method filters.
  - DomainTrie: reverse-label trie for O(label-count) domain lookup.
  - PolicyTraceConfig: knobs for evaluation tracing.
  - Policy: an allow/deny rule set + optional host-services ACL, with the
    is_allowed() decision function.
"""

from __future__ import annotations

import fnmatch
import re
import time
from typing import Optional

# Ports warden binds for itself: 8080 (HTTP egress proxy) and 8443 (ingress).
# A host_service must never rewrite to one of these. Mirrors
# warden.proxy.WARDEN_RESERVED_PORTS — addons can't import brig.*/warden.*,
# so the constant is duplicated here. Keep in sync.
WARDEN_RESERVED_PORTS = frozenset({8080, 8443})


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
        # If IDN encode fails, raise — better to reject the rule at load time
        # than to silently leave the unencoded form in domain_exact, which
        # can never match the encoded SNI/Host header on egress.
        self.is_wildcard = self.domain.startswith("*.")
        base = self.domain[2:] if self.is_wildcard else self.domain
        encoded = self._encode_idn(base)
        if self.is_wildcard:
            self.suffix = ("." + encoded).lower()  # Keep the dot for suffix matching.
            self.domain_exact = encoded.lower()
        else:
            self.suffix = None
            self.domain_exact = encoded.lower()

        # Pre-compile path patterns to regex for faster matching.
        self._path_patterns = None
        if self.paths:
            self._path_patterns = []
            for p in self.paths:
                regex_pattern = fnmatch.translate(p)
                self._path_patterns.append(re.compile(regex_pattern))

    @staticmethod
    def _encode_idn(domain: str) -> str:
        """Encode a non-ASCII domain to punycode. ASCII domains pass through.

        Raises ValueError on failure so callers can reject the rule rather
        than silently storing an unencodable form.
        """
        if domain.isascii():
            return domain
        try:
            return domain.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError) as e:
            raise ValueError(f"PolicyRule: cannot encode IDN domain {domain!r}: {e}")

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Normalize a *queried* host to ASCII/punycode for consistent matching.

        Lookup-time fallback: if a host can't be encoded (malformed input
        from a client), lowercase it and let the trie miss — fail-closed.
        """
        domain = domain.rstrip(".")
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
        return host == self.domain_exact

    def matches_path(self, path: str) -> bool:
        """Check if path matches this rule's path patterns.

        Matched against the path WITHOUT its query string — a path filter scopes
        endpoints, not query values, so `/v1/x` allows `/v1/x?foo=bar`. Patterns
        are globs over the whole path (a `*` spans `/`), so `/v1/*` also matches
        `/v1/a/b`; write a narrower pattern if you need a single segment.
        """
        if self._path_patterns is None:
            return True  # No path restriction.
        base = path.split("?", 1)[0]
        for pattern in self._path_patterns:
            if pattern.match(base):
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
            self.matches_domain(host)
            and self.matches_path(path)
            and self.matches_method(method)
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
        # An empty label (leading/trailing/double dot, e.g. ".example.com")
        # is a malformed host and must match nothing — otherwise the wildcard
        # walk below would fire `*.example.com` for `.example.com`, disagreeing
        # with PolicyRule.matches_domain / domain_matches_rule (they return
        # False), which are documented to agree with this matcher.
        if "" in labels:
            return []
        labels.reverse()

        node = self
        matches = []

        for i, label in enumerate(labels):
            if label not in node.children:
                return matches  # No deeper match possible.
            node = node.children[label]

            # Wildcard rules at this node match any deeper domain.
            # Only match if there are more labels remaining (wildcard requires subdomain).
            if node.wildcard_rules and i < len(labels) - 1:
                matches.extend(node.wildcard_rules)

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
    """Parsed policy with allow/deny rules and optional host-service map.

    host_services entries are dicts {"name": str, "port": int}; the
    dict shape is the only supported form. Populates
    host_services_map: dict[name, port].

    tls_passthrough is a list of host patterns (same wildcard semantics
    as allow/deny). When a passthrough host's SNI is seen at TLS
    client-hello time, Warden tunnels TCP without decrypting (no MITM).
    See is_passthrough() for the defense-in-depth allow-list check.
    """

    def __init__(self, allow: list = None, deny: list = None,
                 host_services: list = None,
                 tls_passthrough: list = None):
        self.allow_rules = [PolicyRule(r) for r in (allow or [])]
        self.deny_rules = [PolicyRule(r) for r in (deny or [])]
        self.passthrough_rules = [PolicyRule(r) for r in (tls_passthrough or [])]
        # HTTP host_services: name -> port. Used by enforce.py to rewrite
        # `<name>.host.brig` requests at L7.
        self.host_services_map: Optional[dict] = None
        # TCP host_services: name -> port. Same shape, separate dict so
        # enforce.py can quickly distinguish: HTTP entries get the L7
        # rewrite, TCP entries are forwarded by warden's `--mode tcp@PORT`
        # listener with a tcp_start hook checking this map.
        self.tcp_host_services_map: Optional[dict] = None
        if host_services is not None:
            self.host_services_map = {}
            self.tcp_host_services_map = {}
            for item in host_services:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                port = item.get("port")
                protocol = item.get("protocol", "http")
                if isinstance(name, str) and isinstance(port, int):
                    # The on-disk policy is untrusted (invariant 4). Validate
                    # the port here too — enforce.py rewrites a .host.brig
                    # request straight to this port on the macOS host, so an
                    # out-of-range or reserved port would turn warden into a
                    # gateway to an arbitrary host service (invariant 2).
                    if (port < 1 or port > 65535
                            or port in WARDEN_RESERVED_PORTS):
                        try:
                            import logging
                            logging.getLogger("brig.warden").warning(
                                "Policy: dropping host_service '%s' with "
                                "invalid/reserved port %r", name, port,
                            )
                        except Exception:
                            pass
                        continue
                    if protocol == "tcp":
                        self.tcp_host_services_map[name] = port
                    elif protocol == "http":
                        self.host_services_map[name] = port
                    else:
                        # Unknown protocol on a tampered on-disk policy
                        # (invariant 4: state dir untrusted). Fail-safe:
                        # drop the entry entirely rather than degrade to
                        # HTTP. Log so the operator sees it during
                        # warden-log inspection.
                        try:
                            import logging
                            logging.getLogger("brig.warden").warning(
                                "Policy: dropping host_service '%s' with "
                                "unknown protocol %r — only http/tcp "
                                "are valid",
                                name, protocol,
                            )
                        except Exception:
                            pass
        # Build reverse-label tries for O(k) domain lookup.
        self._allow_trie = DomainTrie()
        for rule in self.allow_rules:
            self._allow_trie.insert(rule)
        self._deny_trie = DomainTrie()
        for rule in self.deny_rules:
            self._deny_trie.insert(rule)
        self._passthrough_trie = DomainTrie()
        for rule in self.passthrough_rules:
            self._passthrough_trie.insert(rule)
        # Pre-build rule -> index map for O(1) trace lookups.
        self._rule_index = {id(r): i for i, r in enumerate(self.deny_rules)}
        self._rule_index.update({id(r): i for i, r in enumerate(self.allow_rules)})

    def is_passthrough(self, host: str) -> bool:
        """True iff host matches a passthrough rule AND an allow rule.

        Defense in depth: the brig CLI's schema validator already enforces
        that passthrough hosts appear in allow at parse time. Re-checking
        here means a tampered on-disk policy file cannot opt a host out
        of MITM without also having allow coverage. Without this, an
        attacker who can write a per-cell policy file (invariant 4: macOS
        state dir is untrusted) could bypass policy by adding ONLY a
        passthrough entry. Fail closed if either check misses.
        """
        if not self.passthrough_rules:
            return False
        pt_matches = self._passthrough_trie.lookup(host)
        if not any(r.matches_domain(host) for r in pt_matches):
            return False
        allow_matches = self._allow_trie.lookup(host)
        return any(r.matches_domain(host) for r in allow_matches)

    def is_host_allowed(self, host: str) -> tuple[bool, str]:
        """Host-level allow decision for a CONNECT (HTTPS tunnel setup).

        At CONNECT time the path and method live inside the not-yet-established
        TLS tunnel, so they can't be matched — decide on host alone. An
        UNSCOPED deny rule (no path/method filter) blocks the tunnel; any allow
        rule for the host permits it. Path/method-scoped rules are enforced
        per-request in is_allowed()/request() after MITM decryption. Gating the
        CONNECT on a path-scoped allow like `{domain: x, paths: [/api]}` would
        wrongly break ALL HTTPS to that host (the path isn't known yet).
        """
        for rule in self._deny_trie.lookup(host):
            # An unscoped deny (no path/method filter) blocks the tunnel. Treat
            # an EMPTY paths/methods list the same as None — is_allowed's
            # matches_path/matches_method also treat empty as "no restriction"
            # (matches everything), so a `paths: []` deny blocks all HTTP and
            # must block the CONNECT too, not be mistaken for a scoped rule.
            if not rule.paths and not rule.methods and rule.matches_domain(host):
                return False, f"denied by rule: {rule.domain}"
        for rule in self._allow_trie.lookup(host):
            if rule.matches_domain(host):
                return True, f"allowed by rule: {rule.domain}"
        return False, "not in allowlist"

    def is_allowed(self, host: str, path: str, method: str,
                   trace_config: PolicyTraceConfig = None) -> tuple[bool, str, dict]:
        """Check if request is allowed.

        Returns (allowed, reason, trace) tuple.
        Trace contains evaluation details when tracing is enabled.
        Uses reverse-label trie for O(k) domain lookup where k = label count.
        """
        trace: dict = {}
        decision_path: list = []

        start_time = 0.0
        if trace_config and trace_config.enabled and trace_config.include_timing:
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
