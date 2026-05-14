"""
CLI handlers for policy commands.

Supports both per-cell and global policy editing.
"""

from __future__ import annotations

import json
from typing import Any

from brig.config import HostPaths
from brig.errors import BrigError
from brig.ops.history import log_policy_change
from brig.ops.logging import info, output
from brig.policy.policy import delete_cell_policy, load_cell_policy, save_cell_policy


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
    path = HostPaths.NETWORK_POLICY
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(policy, f, indent=2)


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
    changes = _apply_policy_changes(args, policy)

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


def _apply_policy_changes(args: Any, policy: dict) -> dict:
    """Apply --allow/--deny/--remove-allow/--remove-deny/--host-service to a policy dict."""
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
        _apply_host_service_additions(args.host_service, policy)
        changes["add_host_services"] = args.host_service

    if getattr(args, "remove_host_service", None):
        _apply_host_service_removals(args.remove_host_service, policy)
        changes["remove_host_services"] = args.remove_host_service

    return changes


def _apply_host_service_additions(services: list[str], policy: dict) -> None:
    """Parse and add host service entries (name:port format)."""
    import re
    from brig.config import HOST_SERVICE_NAME_PATTERN, MAX_HOST_SERVICES

    host_services = policy.setdefault("host_services", [])

    for spec in services:
        if ":" not in spec:
            raise BrigError(
                f"Invalid host service format: {spec}",
                suggestion="Use name:port format, e.g. aitelier:7777",
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
            raise BrigError(
                f"Too many host services (max {MAX_HOST_SERVICES})",
            )

        host_services.append({"name": name, "port": port})


def _apply_host_service_removals(names: list[str], policy: dict) -> None:
    """Remove host services by name."""
    host_services = policy.get("host_services", [])
    policy["host_services"] = [
        s for s in host_services if s.get("name") not in names
    ]
