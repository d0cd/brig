"""Policy commands: policy show, set, validate, test."""

import json
import re

from pathlib import Path

from brig.commands._helpers import (
    DOMAIN_PATTERN,
    cell_exists,
    debug,
    error,
    error_cell_not_found,
    error_invalid_json,
    is_suspicious_domain,
    load_cell_policy,
    log_policy_change,
    output,
    run,
    save_cell_policy,
    validate_cell_name,
    validate_policy_conflicts,
    warn,
)


def cmd_policy_show(args) -> int:
    """Show a cell's effective network policy."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    # Load per-cell policy.
    cell_policy = load_cell_policy(cell_name)

    # Load global policy for comparison.
    global_policy_path = Path("/cells/network-policy.json")
    global_policy = {"allow": [], "deny": []}
    if global_policy_path.exists():
        try:
            with open(global_policy_path, "r") as f:
                global_policy = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            debug(f"Failed to load global policy: {e}")

    print(f"Policy for cell: {cell_name}")
    print("=" * 40)

    print("\nGlobal Allowlist:")
    for domain in global_policy.get("allow", []):
        print(f"  + {domain}")

    print("\nGlobal Denylist:")
    for domain in global_policy.get("deny", []):
        print(f"  - {domain}")

    if cell_policy.get("allow") or cell_policy.get("deny"):
        print("\nPer-Cell Allowlist:")
        for domain in cell_policy.get("allow", []):
            print(f"  + {domain}")

        print("\nPer-Cell Denylist:")
        for domain in cell_policy.get("deny", []):
            print(f"  - {domain}")
    else:
        print("\nNo per-cell policy configured (using global only)")

    return 0


def cmd_policy_set(args) -> int:
    """Update a cell's network policy."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    # Load existing policy and keep a copy for audit.
    old_policy = load_cell_policy(cell_name)
    policy = {
        "allow": list(old_policy.get("allow", [])),
        "deny": list(old_policy.get("deny", [])),
    }

    # Track changes for audit trail.
    changes = {
        "added_allow": [],
        "added_deny": [],
        "removed_allow": [],
        "removed_deny": [],
    }

    # Validate domain patterns before applying changes.
    for domain_list in [args.allow, args.deny]:
        if domain_list:
            for domain in domain_list:
                if not re.match(DOMAIN_PATTERN, domain):
                    error(
                        f"Invalid domain pattern: {domain}",
                        "Use lowercase domain names like 'example.com' or wildcards like '*.example.com'"
                    )
                    return 1

    # Apply changes.
    if args.allow:
        for domain in args.allow:
            if domain in policy["allow"]:
                warn(f"'{domain}' is already in the allowlist")
            elif domain in policy["deny"]:
                warn(f"'{domain}' is in the denylist (deny takes precedence)")
                policy["allow"].append(domain)
                changes["added_allow"].append(domain)
                output(f"Added to allowlist: {domain}")
            else:
                policy["allow"].append(domain)
                changes["added_allow"].append(domain)
                output(f"Added to allowlist: {domain}")

    if args.deny:
        for domain in args.deny:
            if domain in policy["deny"]:
                warn(f"'{domain}' is already in the denylist")
            elif domain in policy["allow"]:
                warn(f"'{domain}' is also in the allowlist (deny takes precedence)")
                policy["deny"].append(domain)
                changes["added_deny"].append(domain)
                output(f"Added to denylist: {domain}")
            else:
                policy["deny"].append(domain)
                changes["added_deny"].append(domain)
                output(f"Added to denylist: {domain}")

    if args.remove_allow:
        for domain in args.remove_allow:
            if domain in policy["allow"]:
                policy["allow"].remove(domain)
                changes["removed_allow"].append(domain)
                output(f"Removed from allowlist: {domain}")

    if args.remove_deny:
        for domain in args.remove_deny:
            if domain in policy["deny"]:
                policy["deny"].remove(domain)
                changes["removed_deny"].append(domain)
                output(f"Removed from denylist: {domain}")

    # Check for conflicts before saving.
    conflicts = validate_policy_conflicts(policy)
    for warning in conflicts:
        warn(warning)

    # Save updated policy.
    if not save_cell_policy(cell_name, policy):
        error(
            f"Failed to save policy for {cell_name}",
            "Check file permissions and disk space"
        )

    # Log policy change to audit trail.
    # Only include non-empty change lists.
    audit_changes = {k: v for k, v in changes.items() if v}
    if audit_changes:
        log_policy_change(
            cell_name=cell_name,
            action="update",
            changes=audit_changes,
            old_policy=old_policy,
            new_policy=policy
        )

    output(f"\nPolicy updated for {cell_name}")

    # Signal proxy to reload.
    result = run(["warden", "reload"], check=False, capture=True)
    if result.returncode == 0:
        output("Proxy reloaded")
    else:
        warn("Could not reload proxy. Changes take effect on next proxy restart.")

    return 0


def _validate_policy_rule(rule, context: str) -> list[str]:
    """Validate a single policy rule. Returns list of errors."""
    errors = []

    if isinstance(rule, str):
        # Simple domain pattern.
        if not rule:
            errors.append(f"{context}: empty domain")
        elif rule.startswith("*."):
            # Wildcard pattern.
            if len(rule) < 3:
                errors.append(f"{context}: invalid wildcard pattern '{rule}'")
        # Check for suspicious patterns.
        suspicious = is_suspicious_domain(rule)
        if suspicious:
            errors.append(f"{context}: {suspicious}")
    elif isinstance(rule, dict):
        # Complex rule with path/method.
        domain = rule.get("domain", "")
        if not domain:
            errors.append(f"{context}: missing 'domain' field")

        paths = rule.get("paths")
        if paths is not None and not isinstance(paths, list):
            errors.append(f"{context}: 'paths' must be a list")

        methods = rule.get("methods")
        if methods is not None:
            if not isinstance(methods, list):
                errors.append(f"{context}: 'methods' must be a list")
            else:
                valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
                for method in methods:
                    if method.upper() not in valid_methods:
                        errors.append(f"{context}: invalid method '{method}'")
    else:
        errors.append(f"{context}: invalid rule type (must be string or object)")

    return errors


def cmd_policy_validate(args) -> int:
    """Validate a policy file syntax."""
    policy_path = Path(args.file) if args.file else Path("/cells/network-policy.json")

    if not policy_path.exists():
        error(
            f"Policy file not found: {policy_path}",
            "Create a policy with: brig policy set CELL --allow DOMAIN"
        )

    try:
        with open(policy_path, "r") as f:
            policy = json.load(f)
    except json.JSONDecodeError as e:
        error_invalid_json(str(policy_path), str(e))

    errors = []
    warnings = []

    # Validate allow rules.
    allow_rules = policy.get("allow", [])
    if not isinstance(allow_rules, list):
        errors.append("'allow' must be a list")
    else:
        for i, rule in enumerate(allow_rules):
            rule_errors = _validate_policy_rule(rule, f"allow[{i}]")
            errors.extend(rule_errors)

    # Validate deny rules.
    deny_rules = policy.get("deny", [])
    if not isinstance(deny_rules, list):
        errors.append("'deny' must be a list")
    else:
        for i, rule in enumerate(deny_rules):
            rule_errors = _validate_policy_rule(rule, f"deny[{i}]")
            errors.extend(rule_errors)

    # Validate rate limits.
    rate_limits = policy.get("rate_limits", {})
    if rate_limits:
        default = rate_limits.get("default", {})
        if default:
            if "rate" in default and not isinstance(default["rate"], (int, float)):
                errors.append("rate_limits.default.rate must be a number")
            if "burst" in default and not isinstance(default["burst"], int):
                errors.append("rate_limits.default.burst must be an integer")

    # Validate log filter.
    log_filter = policy.get("log_filter", {})
    if log_filter:
        sample_rate = log_filter.get("sample_rate", 1.0)
        if not (0 <= sample_rate <= 1):
            errors.append("log_filter.sample_rate must be between 0 and 1")

    # Check for overlapping rules.
    all_domains = []
    for rule in allow_rules:
        if isinstance(rule, str):
            all_domains.append(rule)
        elif isinstance(rule, dict):
            all_domains.append(rule.get("domain", ""))

    for domain in set(all_domains):
        count = all_domains.count(domain)
        if count > 1:
            warnings.append(f"Domain '{domain}' appears {count} times in allow rules")

    # Report results.
    if errors:
        print("Validation FAILED:")
        for err in errors:
            print(f"  ERROR: {err}")
        for warning in warnings:
            print(f"  WARNING: {warning}")
        return 1
    else:
        print(f"Validation OK: {len(allow_rules)} allow rules, {len(deny_rules)} deny rules")
        for warning in warnings:
            print(f"  WARNING: {warning}")
        return 0


def _matches_domain(pattern: str, domain: str) -> bool:
    """Check if domain matches pattern.

    Wildcard patterns match subdomains only:
        *.example.com matches foo.example.com, NOT example.com itself.
    This matches enforce.py's PolicyRule.matches_domain() behavior.
    """
    pattern = pattern.lower()
    domain = domain.lower()

    if pattern.startswith("*."):
        suffix = pattern[1:]  # Keep the dot.
        return domain.endswith(suffix)
    else:
        return domain == pattern


def _matches_rule(rule, domain: str, path: str, method: str) -> bool:
    """Check if request matches a rule."""
    import fnmatch

    if isinstance(rule, str):
        return _matches_domain(rule, domain)
    elif isinstance(rule, dict):
        if not _matches_domain(rule.get("domain", ""), domain):
            return False

        paths = rule.get("paths")
        if paths is not None:
            if not any(fnmatch.fnmatch(path, p) for p in paths):
                return False

        methods = rule.get("methods")
        if methods is not None:
            if method.upper() not in [m.upper() for m in methods]:
                return False

        return True
    return False


def cmd_policy_test(args) -> int:
    """Test if a domain would be allowed by policy for a specific cell."""
    cell_name = args.name
    validate_cell_name(cell_name)
    domain = args.domain
    path = args.path
    method = args.method

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    # Load per-cell policy.
    cell_policy = load_cell_policy(cell_name)

    # Load global policy.
    global_policy_path = Path("/cells/network-policy.json")
    global_policy = {"allow": [], "deny": []}
    if global_policy_path.exists():
        try:
            with open(global_policy_path, "r") as f:
                global_policy = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            debug(f"Failed to load global policy: {e}")

    verbose = args.verbose

    # Check cell deny rules first.
    if verbose:
        print(f"Testing: {method} {domain}{path} for cell '{cell_name}'")
        print("-" * 50)

    for i, rule in enumerate(cell_policy.get("deny", [])):
        if _matches_rule(rule, domain, path, method):
            print(f"BLOCKED: Cell deny rule [{i}]: {rule}")
            return 1

    # Check global deny rules.
    for i, rule in enumerate(global_policy.get("deny", [])):
        if _matches_rule(rule, domain, path, method):
            print(f"BLOCKED: Global deny rule [{i}]: {rule}")
            return 1

    # Check cell allow rules.
    for i, rule in enumerate(cell_policy.get("allow", [])):
        if _matches_rule(rule, domain, path, method):
            print(f"ALLOWED: Cell allow rule [{i}]: {rule}")
            return 0

    # Check global allow rules.
    for i, rule in enumerate(global_policy.get("allow", [])):
        if _matches_rule(rule, domain, path, method):
            print(f"ALLOWED: Global allow rule [{i}]: {rule}")
            return 0

    # Default deny.
    print("BLOCKED: Not in any allowlist")
    if verbose:
        print(f"\nCell policy: {len(cell_policy.get('allow', []))} allow, {len(cell_policy.get('deny', []))} deny rules")
        print(f"Global policy: {len(global_policy.get('allow', []))} allow, {len(global_policy.get('deny', []))} deny rules")
    return 1
