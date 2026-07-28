"""
CLI handlers for per-cell policy editing.

Policy lives entirely per-cell. Cells without a policy block all
egress (fail closed). For shared defaults across many cells, use a
trust profile in the cell yaml.
"""

from __future__ import annotations

import argparse
import json

from brig.config import CELL_NAME_PATTERN
from brig.errors import BrigError
from brig.ops.history import log_policy_change
from brig.ops.logging import info, output
from brig.policy.policy import delete_cell_policy, load_cell_policy, mutate_cell_policy


def _require_valid_cell_name(name: str) -> None:
    # args.name is a plain CLI positional that flows into per-cell policy file
    # paths (load/mutate/delete_cell_policy). Validate against CELL_NAME_PATTERN
    # (which forbids '/' and can't express '..') so a crafted name can't
    # traverse into or out of the policy dir.
    if not isinstance(name, str) or not CELL_NAME_PATTERN.match(name):
        raise BrigError(
            f"Invalid cell name '{name}': must start with a lowercase letter or "
            f"digit, then up to 62 of [a-z0-9._-] — no uppercase, no '/'."
        )


def register_parser(sub) -> None:
    p = sub.add_parser("policy", help="Manage per-cell policies")
    s = p.add_subparsers(dest="policy_command", required=True)

    p_show = s.add_parser("show", help="Show a cell's policy")
    p_show.add_argument("name", help="Cell name")

    p_test = s.add_parser("test", help="Test whether a cell would allow a request")
    p_test.add_argument("name", help="Cell name")
    p_test.add_argument("domain", help="Domain to test")
    p_test.add_argument("--path", default="/", help="Path to test")
    p_test.add_argument("--method", default="GET", help="HTTP method")

    p_set = s.add_parser("set", help="Update a cell's policy")
    p_set.add_argument("name", help="Cell name")
    p_set.add_argument("--allow", action="append", help="Add allowed domain")
    p_set.add_argument("--deny", action="append", help="Add denied domain")
    p_set.add_argument("--remove-allow", action="append", help="Remove allowed domain")
    p_set.add_argument("--remove-deny", action="append", help="Remove denied domain")

    p_rm = s.add_parser("rm", help="Delete a cell's policy (cell will block all egress)")
    p_rm.add_argument("name", help="Cell name")


def cmd_policy_show(args: argparse.Namespace) -> int:
    _require_valid_cell_name(args.name)
    policy = load_cell_policy(args.name)
    if policy is None:
        # No per-cell policy file = default deny. Don't error — show
        # the effective contents (empty) with a note so the operator
        # understands the cell is reachable-by-nothing.
        output(json.dumps({"allow": [], "deny": [], "host_services": []},
                          indent=2))
        output(f"# (no policy file for '{args.name}' — cell blocks all egress)")
        return 0
    output(json.dumps(policy, indent=2))
    return 0


def cmd_policy_test(args: argparse.Namespace) -> int:
    """Simulate a request against a cell's policy."""
    _require_valid_cell_name(args.name)
    policy = load_cell_policy(args.name)
    if policy is None:
        output(f"BLOCKED: cell '{args.name}' has no policy (default deny)")
        return 1

    domain = args.domain
    path = args.path or "/"
    method = (args.method or "GET").upper()

    from brig.policy.policy import domain_matches_rule

    def _matches(rule, host, path, method) -> bool:
        if isinstance(rule, str):
            return domain_matches_rule(rule, host)
        if not domain_matches_rule(rule.get("domain", ""), host):
            return False
        paths = rule.get("paths")
        if paths:
            import fnmatch
            if not any(fnmatch.fnmatch(path, p) for p in paths):
                return False
        methods = rule.get("methods")
        if methods and method not in {m.upper() for m in methods}:
            return False
        return True

    def _name(rule):
        return rule if isinstance(rule, str) else rule.get("domain", "")

    for rule in policy.get("deny", []):
        if _matches(rule, domain, path, method):
            output(f"BLOCKED: denied by rule: {_name(rule)}")
            return 1
    for rule in policy.get("allow", []):
        if _matches(rule, domain, path, method):
            output(f"ALLOWED: matched rule: {_name(rule)} ({method} {path})")
            return 0
    output("BLOCKED: not in allowlist (default deny)")
    return 1


def cmd_policy_set(args: argparse.Namespace) -> int:
    _require_valid_cell_name(args.name)
    # Read-modify-write under one exclusive lock so a concurrent `brig run`
    # re-sync or parallel `brig policy set` can't drop this update.
    captured: dict = {}

    def _mutate(policy: dict | None) -> dict:
        import copy
        policy = policy or {"allow": [], "deny": []}
        # Deep copy: _apply_policy_changes mutates the inner allow/deny lists
        # in place, so a shallow dict() copy would make the "old" snapshot
        # alias the post-mutation lists and log old == new.
        captured["old"] = copy.deepcopy(policy)
        captured["changes"] = _apply_policy_changes(args, policy)
        return policy

    new_policy = mutate_cell_policy(args.name, _mutate)
    log_policy_change(args.name, "update", captured["changes"], captured["old"], new_policy)
    from brig.cell.metadata import refresh_metadata_if_present
    refresh_metadata_if_present(args.name)
    info(f"Updated policy for cell '{args.name}'")
    return 0


def _validate_domains(domains: list[str]) -> None:
    import re
    from brig.config import DOMAIN_PATTERN
    from brig.network.validation import is_suspicious_domain

    for domain in domains:
        if not re.match(DOMAIN_PATTERN, domain):
            raise BrigError(f"Invalid domain pattern: {domain}")
        suspicious = is_suspicious_domain(domain)
        if suspicious:
            raise BrigError(f"Rejected: {suspicious}")


def _apply_policy_changes(args: argparse.Namespace, policy: dict) -> dict:
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
        removed = [d for d in args.remove_allow if d in allow_list]
        for domain in removed:
            allow_list.remove(domain)
        # Record only what was actually removed, so the audit summary doesn't
        # claim a removal that never happened for an absent domain.
        changes["remove_allow"] = removed

    if getattr(args, "remove_deny", None):
        deny_list = policy.get("deny", [])
        removed = [d for d in args.remove_deny if d in deny_list]
        for domain in removed:
            deny_list.remove(domain)
        changes["remove_deny"] = removed

    return changes


def cmd_policy_rm(args: argparse.Namespace) -> int:
    _require_valid_cell_name(args.name)
    if delete_cell_policy(args.name):
        log_policy_change(args.name, "delete", changes={})
        from brig.cell.metadata import refresh_metadata_if_present
        refresh_metadata_if_present(args.name)
        # Warden auto-reloads per-cell policies on file-change (mtime poll),
        # same as `brig policy set` — no explicit reload needed.
        info(f"Deleted policy for '{args.name}' (cell will block all egress)")
        return 0
    raise BrigError(f"No policy for '{args.name}'")


DISPATCH = {
    "show": cmd_policy_show,
    "set": cmd_policy_set,
    "test": cmd_policy_test,
    "rm": cmd_policy_rm,
}
