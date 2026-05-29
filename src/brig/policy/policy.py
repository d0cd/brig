"""
Cell policy management — load, save, delete, validate.

Supports both JSON and YAML policy files.
"""

from __future__ import annotations

import fcntl
import json
import re
from pathlib import Path
from typing import Any

from brig.config import DOMAIN_PATTERN, POLICY_DIR
from brig.network.validation import is_suspicious_domain
from brig.ops.atomic import atomic_write_json
from brig.ops.logging import debug

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


def _policy_lock_path(policy_dir: Path) -> Path:
    """Path of the policy-directory write lock.

    Single lockfile per policy_dir — `brig run` invocations on different
    cells contend on this same lock so the load-modify-write sequence
    around per-cell policies is serialized; without it, concurrent
    writers can lose each other's updates.
    """
    return policy_dir / ".lock"


def _encode_idn(domain: str) -> str:
    """Return the punycode form of `domain` or fall back to lowercase.

    Mirrors src/addons/_policy.py:PolicyRule._normalize_domain so the
    host-side `policy.test` and the warden-side runtime match decisions
    agree on unicode/IDN inputs — without punycode encoding here, a
    unicode rule pair can pass cross-field validation on the host (UTF-8
    compare) but diverge in the addon (punycode compare).
    """
    if domain.isascii():
        return domain.lower()
    try:
        return domain.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return domain.lower()


def domain_matches_rule(rule: str, host: str) -> bool:
    """Brig-CLI-side wildcard suffix match for "is host allowed by this rule".

    Mirrors src/addons/_policy.py:PolicyRule.matches_domain. The host-side
    `brig policy test` path and the in-warden `enforce.py` evaluator
    must agree on IDN encoding — see _encode_idn.

    Wildcard `*.example.com` matches `sub.example.com` but NOT
    `example.com` itself (dot-boundary check).
    """
    rule = _encode_idn(rule.rstrip("."))
    host = _encode_idn(host.rstrip("."))
    if rule.startswith("*."):
        suffix = rule[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == rule


def get_cell_policy_path(cell_name: str, policy_dir: Path = POLICY_DIR) -> Path:
    """Get the path for a cell's policy file."""
    return policy_dir / f"{cell_name}.json"


def load_cell_policy(
    cell_name: str,
    policy_dir: Path = POLICY_DIR,
) -> dict[str, Any] | None:
    """Load a cell's policy from disk. Returns None if no policy exists.

    Acquires a shared lock on the policy directory so the load can't tear
    against an in-flight `save_cell_policy`. Atomic-rename writes mean
    readers without the lock already see a consistent file, but the lock
    also serializes against the read-modify-write callers in
    lifecycle_cmd._sync_cell_policy.
    """
    path = get_cell_policy_path(cell_name, policy_dir)
    if not path.exists():
        return None
    try:
        with _locked_policy_dir(policy_dir, exclusive=False):
            with open(path) as f:
                return json.load(f)  # type: ignore[no-any-return]
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, IOError) as e:
        debug(f"Failed to load policy for {cell_name}: {e}")
        return None


def save_cell_policy(
    cell_name: str,
    policy: dict[str, Any],
    policy_dir: Path = POLICY_DIR,
) -> None:
    """Save a cell's policy to disk under an exclusive directory lock.

    Atomic-write alone protects against torn reads, but concurrent
    read-modify-write sequences (two `brig run` invocations on the same
    cell, or `brig policy add` in parallel with `brig run`) can each
    load the previous state, merge, and write — silently dropping the
    other's update. The lock mirrors the subnet allocator's pattern
    (src/brig/network/subnet.py).
    """
    with _locked_policy_dir(policy_dir, exclusive=True):
        atomic_write_json(get_cell_policy_path(cell_name, policy_dir), policy)


def delete_cell_policy(
    cell_name: str,
    policy_dir: Path = POLICY_DIR,
) -> bool:
    """Delete a cell's policy file. Returns True if deleted."""
    with _locked_policy_dir(policy_dir, exclusive=True):
        path = get_cell_policy_path(cell_name, policy_dir)
        try:
            path.unlink()
            return True
        except FileNotFoundError:
            return False


class _locked_policy_dir:
    """Context manager: fcntl.flock on the policy-directory lock file.

    Creates policy_dir (and the lockfile) if missing. Use shared lock for
    reads and exclusive lock for writes. Operates as a no-op silently if
    the platform lacks fcntl (Windows isn't supported, but tests may run
    in stripped environments).
    """

    def __init__(self, policy_dir: Path, exclusive: bool):
        self.policy_dir = policy_dir
        self.exclusive = exclusive
        self._lock_fh: Any = None

    def __enter__(self) -> "_locked_policy_dir":
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        lock_path = _policy_lock_path(self.policy_dir)
        # Open with O_CREAT semantics via "a" — read mode would fail if
        # the lockfile didn't exist yet, write mode would truncate
        # contents we don't care about anyway. "a" is the simplest no-op.
        self._lock_fh = open(lock_path, "a")
        try:
            fcntl.flock(
                self._lock_fh,
                fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH,
            )
        except OSError:
            self._lock_fh.close()
            self._lock_fh = None
            raise
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._lock_fh is not None:
            try:
                fcntl.flock(self._lock_fh, fcntl.LOCK_UN)
            finally:
                self._lock_fh.close()
                self._lock_fh = None


def load_policy_file(path: Path) -> dict[str, Any]:
    """Load a policy from a JSON or YAML file.

    Detects format by extension. Raises ValueError on parse errors.
    """
    content = path.read_text()
    suffix = path.suffix.lower()

    if suffix in (".yaml", ".yml"):
        if not YAML_AVAILABLE:
            raise ValueError("YAML support requires pyyaml: pip install pyyaml")
        try:
            result = yaml.safe_load(content)
            if not isinstance(result, dict):
                raise ValueError("Policy file must contain a YAML mapping")
            return result
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse YAML: {e}")
    else:
        try:
            result = json.loads(content)
            if not isinstance(result, dict):
                raise ValueError("Policy file must contain a JSON object")
            return result
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON: {e}")


def validate_policy(policy: dict[str, Any]) -> list[str]:
    """Validate a policy dict and return list of errors."""
    errors: list[str] = []

    if not isinstance(policy, dict):
        return ["Policy must be a dict"]

    for key in ("allow", "deny"):
        if key in policy:
            rules = policy[key]
            if not isinstance(rules, list):
                errors.append(f"'{key}' must be a list")
                continue
            for domain in rules:
                if isinstance(domain, str):
                    if not re.match(DOMAIN_PATTERN, domain):
                        errors.append(f"Invalid domain '{domain}' in {key}")
                    elif key == "allow":
                        suspicious = is_suspicious_domain(domain)
                        if suspicious:
                            errors.append(f"Security: {suspicious}")
                elif isinstance(domain, dict):
                    if "domain" not in domain:
                        errors.append(f"Rule in '{key}' missing 'domain' field")
                else:
                    errors.append(f"'{key}' items must be strings or dicts")

    return errors
