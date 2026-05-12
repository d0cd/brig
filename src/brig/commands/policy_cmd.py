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


def _apply_policy_changes(args: Any, policy: dict) -> dict:
    """Apply --allow/--deny/--remove-allow/--remove-deny to a policy dict."""
    changes: dict[str, list[str]] = {}

    if getattr(args, "allow", None):
        policy.setdefault("allow", []).extend(args.allow)
        changes["add_allow"] = args.allow

    if getattr(args, "deny", None):
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

    return changes
