"""
CLI handlers for policy commands.

Supports both per-cell and global policy editing. Also exposes
register_parser() so cli.py doesn't have to know the policy subcommand layout.
"""

from __future__ import annotations

import json
from typing import Any

from brig.config import HostPaths
from brig.errors import BrigError
from brig.ops.atomic import atomic_write_json
from brig.ops.history import log_policy_change
from brig.ops.logging import info, output
from brig.policy.policy import delete_cell_policy, load_cell_policy, save_cell_policy


def register_parser(sub) -> None:
    """Register the `brig policy` subcommand tree."""
    p = sub.add_parser("policy", help="Manage cell policies")
    s = p.add_subparsers(dest="policy_command", required=True)

    p_show = s.add_parser("show", help="Show cell or global policy")
    p_show.add_argument("name", nargs="?", default="global",
                        help="Cell name or 'global'")
    p_show.add_argument("--effective", action="store_true",
                        help="Show merged global + per-cell policy")

    p_test = s.add_parser("test", help="Test whether a domain is allowed")
    p_test.add_argument("domain", help="Domain to test")
    p_test.add_argument("--path", default="/", help="Path to test")
    p_test.add_argument("--method", default="GET", help="HTTP method")

    p_set = s.add_parser("set", help="Update cell or global policy")
    p_set.add_argument("name", help="Cell name or 'global'")
    p_set.add_argument("--allow", action="append", help="Add allowed domain")
    p_set.add_argument("--deny", action="append", help="Add denied domain")
    p_set.add_argument("--remove-allow", action="append", help="Remove allowed domain")
    p_set.add_argument("--remove-deny", action="append", help="Remove denied domain")
    p_set.add_argument("--host-service", action="append",
                       help="Add host service (name:port, e.g. aitelier:7777)")
    p_set.add_argument("--remove-host-service", action="append",
                       help="Remove host service by name")

    p_rm = s.add_parser("rm", help="Delete a cell's per-cell policy (falls back to global)")
    p_rm.add_argument("name", help="Cell name")


def _load_global_policy() -> dict:
    """Load global network policy from host."""
    path = HostPaths.NETWORK_POLICY
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"allow": [], "deny": []}
    except json.JSONDecodeError as e:
        raise BrigError(f"Invalid global policy: {e}")


def _save_global_policy(policy: dict) -> None:
    """Save global network policy to host."""
    atomic_write_json(HostPaths.NETWORK_POLICY, policy)


def cmd_policy_show(args: Any) -> int:
    """Handle `brig policy show`.

    With --effective: shows merged global + per-cell policy.
    """
    effective = getattr(args, "effective", False)
    name = getattr(args, "name", None)

    if name == "global" or (not name and not effective):
        output(json.dumps(_load_global_policy(), indent=2))
        return 0

    cell_policy = load_cell_policy(name) if name else None

    if effective and name:
        global_pol = _load_global_policy()
        if cell_policy:
            merged = {
                "allow": global_pol.get("allow", []) + cell_policy.get("allow", []),
                "deny": global_pol.get("deny", []) + cell_policy.get("deny", []),
            }
            output(f"# Effective policy for '{name}' (global + per-cell override)")
            output(json.dumps(merged, indent=2))
        else:
            output(f"# Effective policy for '{name}' (global only, no override)")
            output(json.dumps(global_pol, indent=2))
    elif cell_policy is None:
        output(f"No custom policy for cell '{name}' (using global policy)")
    else:
        output(json.dumps(cell_policy, indent=2))
    return 0


def cmd_policy_test(args: Any) -> int:
    """Handle `brig policy test <domain>` — check if a domain is allowed.

    Walks the same global policy that warden enforces and reports the
    decision. Useful for debugging "why was this blocked?" before sending
    real traffic through warden.
    """
    from pathlib import Path
    from brig.policy.policy import load_policy_file

    domain = args.domain
    # path/method aren't used yet — global policy at the brig CLI level
    # only stores domain-level rules. Path/method matching happens in
    # the warden enforce addon's PolicyRule.

    try:
        policy = load_policy_file(HostPaths.NETWORK_POLICY)
    except (ValueError, FileNotFoundError) as e:
        raise BrigError(f"Failed to load global policy: {e}")

    def _matches(rule: str | dict, host: str) -> bool:
        rule_str = rule if isinstance(rule, str) else rule.get("domain", "")
        rule_str = rule_str.lower().rstrip(".")
        host = host.lower().rstrip(".")
        if rule_str.startswith("*."):
            suffix = rule_str[1:]
            return host.endswith(suffix) and len(host) > len(suffix)
        return host == rule_str

    for rule in policy.get("deny", []):
        if _matches(rule, domain):
            rule_str = rule if isinstance(rule, str) else rule.get("domain", "")
            output(f"BLOCKED: denied by rule: {rule_str}")
            return 1
    for rule in policy.get("allow", []):
        if _matches(rule, domain):
            rule_str = rule if isinstance(rule, str) else rule.get("domain", "")
            output(f"ALLOWED: matched rule: {rule_str}")
            return 0
    output("BLOCKED: not in allowlist (default deny)")
    return 1


def cmd_policy_set(args: Any) -> int:
    """Handle `brig policy set`.

    If name is 'global', edits the global policy.
    """
    name = args.name

    if name == "global":
        return _edit_global_policy(args)

    policy = load_cell_policy(name) or {"allow": [], "deny": []}
    old_policy = dict(policy)
    changes = _apply_policy_changes(args, policy)

    save_cell_policy(name, policy)
    log_policy_change(name, "update", changes, old_policy, policy)
    info(f"Updated policy for cell '{name}'")
    return 0


def _edit_global_policy(args: Any) -> int:
    """Edit the global network policy."""
    policy = _load_global_policy()
    old_policy = dict(policy)
    changes = _apply_policy_changes(args, policy, is_global=True)

    _save_global_policy(policy)
    log_policy_change("global", "update", changes, old_policy, policy)
    info("Updated global policy")

    # Nudge warden to reload.
    try:
        from warden.proxy import reload_policy
        reload_policy()
        info("Warden policy reloaded")
    except Exception:
        info("Note: run 'warden reload' to apply changes")

    return 0


def _validate_domains(domains: list[str]) -> None:
    """Validate domain patterns. Raises BrigError on suspicious/invalid domains."""
    import re
    from brig.config import DOMAIN_PATTERN
    from brig.network.validation import is_suspicious_domain

    for domain in domains:
        if not re.match(DOMAIN_PATTERN, domain):
            raise BrigError(f"Invalid domain pattern: {domain}")
        suspicious = is_suspicious_domain(domain)
        if suspicious:
            raise BrigError(f"Rejected: {suspicious}")


def _apply_policy_changes(args: Any, policy: dict, *, is_global: bool = False) -> dict:
    """Apply --allow/--deny/--remove-allow/--remove-deny/--host-service to a policy dict.

    is_global selects the host-service schema (name:port dicts for global,
    bare name strings for per-cell ACL).
    """
    changes: dict[str, list[str]] = {}

    if getattr(args, "allow", None):
        _validate_domains(args.allow)
        policy.setdefault("allow", []).extend(args.allow)
        changes["add_allow"] = args.allow

    if getattr(args, "deny", None):
        _validate_domains(args.deny)
        policy.setdefault("deny", []).extend(args.deny)
        changes["add_deny"] = args.deny

    if getattr(args, "remove_allow", None):
        allow_list = policy.get("allow", [])
        for domain in args.remove_allow:
            if domain in allow_list:
                allow_list.remove(domain)
        changes["remove_allow"] = args.remove_allow

    if getattr(args, "remove_deny", None):
        deny_list = policy.get("deny", [])
        for domain in args.remove_deny:
            if domain in deny_list:
                deny_list.remove(domain)
        changes["remove_deny"] = args.remove_deny

    # Host services.
    if getattr(args, "host_service", None):
        _apply_host_service_additions(args.host_service, policy, is_global=is_global)
        changes["add_host_services"] = args.host_service

    if getattr(args, "remove_host_service", None):
        _apply_host_service_removals(args.remove_host_service, policy)
        changes["remove_host_services"] = args.remove_host_service

    return changes


def _apply_host_service_additions(
    services: list[str], policy: dict, *, is_global: bool,
) -> None:
    """Add host service entries.

    For the **global** policy: each entry must be `name:port` (warden uses
    this to know how to forward `<name>.host.brig`). Stored as a list of
    `{name, port}` dicts.

    For a **per-cell** policy: each entry is just `name` (an ACL grant
    referencing a name declared in the global policy). Stored as a list of
    string names. This is what the H1 enforcement in `enforce.py` reads
    via `cell_policy.host_services_allowed`.
    """
    from brig.config import HOST_SERVICE_NAME_PATTERN, MAX_HOST_SERVICES

    if is_global:
        host_services = policy.setdefault("host_services", [])
        for spec in services:
            if ":" not in spec:
                raise BrigError(
                    f"Global host service requires name:port format: {spec}",
                    suggestion="e.g. brig policy set global --host-service aitelier:7777",
                )
            name, port_str = spec.rsplit(":", 1)
            if not HOST_SERVICE_NAME_PATTERN.match(name):
                raise BrigError(
                    f"Invalid host service name: {name}",
                    suggestion="Use lowercase alphanumeric with hyphens, max 31 chars",
                )
            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    raise ValueError
            except ValueError:
                raise BrigError(f"Invalid port for host service '{name}': {port_str}")

            # Remove existing entry with same name (idempotent update).
            host_services[:] = [s for s in host_services if s.get("name") != name]
            if len(host_services) >= MAX_HOST_SERVICES:
                raise BrigError(f"Too many host services (max {MAX_HOST_SERVICES})")
            host_services.append({"name": name, "port": port})
    else:
        # Per-cell ACL: list of names referencing global declarations.
        host_services = policy.setdefault("host_services", [])
        for spec in services:
            if ":" in spec:
                raise BrigError(
                    f"Per-cell host service must be a name only (no port): {spec}",
                    suggestion=(
                        "Per-cell entries grant access to a service already declared "
                        "in the global policy. e.g. brig policy set <cell> --host-service aitelier"
                    ),
                )
            if not HOST_SERVICE_NAME_PATTERN.match(spec):
                raise BrigError(
                    f"Invalid host service name: {spec}",
                    suggestion="Use lowercase alphanumeric with hyphens, max 31 chars",
                )
            if spec not in host_services:
                if len(host_services) >= MAX_HOST_SERVICES:
                    raise BrigError(f"Too many host services (max {MAX_HOST_SERVICES})")
                host_services.append(spec)


def _apply_host_service_removals(names: list[str], policy: dict) -> None:
    """Remove host services by name. Handles both schemas (global dicts and
    per-cell strings) so the same flag works for either policy scope."""
    host_services = policy.get("host_services", [])
    policy["host_services"] = [
        s for s in host_services
        if (s.get("name") if isinstance(s, dict) else s) not in names
    ]


def cmd_policy_rm(args: Any) -> int:
    """Handle `brig policy rm <cell>` — drop the per-cell policy override.

    The cell falls back to the global policy on the next request. (Or, if
    you want to keep the override but disable it, use `brig policy set
    <cell> --remove-allow <pattern>`.)
    """
    if args.name == "global":
        raise BrigError("Refusing to delete the global policy",
                        suggestion="Edit it instead: brig policy set global --remove-allow ...")
    if delete_cell_policy(args.name):
        log_policy_change(args.name, "delete", changes={})
        info(f"Deleted per-cell policy for '{args.name}'")
        try:
            from warden.proxy import reload_policy
            reload_policy()
        except Exception:
            info("Note: run 'warden reload' to apply changes")
        return 0
    raise BrigError(f"No per-cell policy for '{args.name}'")


DISPATCH = {
    "show": cmd_policy_show,
    "set": cmd_policy_set,
    "test": cmd_policy_test,
    "rm": cmd_policy_rm,
}
