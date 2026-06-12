"""
Cell policy management — load, save, delete.

Per-cell policies are stored as JSON, one file per cell.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

from brig.config import POLICY_DIR
from brig.ops.atomic import atomic_write_json
from brig.ops.locking import locked_file
from brig.ops.logging import debug


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

    Mirrors src/brig/warden_addons/_policy.py:PolicyRule._normalize_domain so the
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

    Mirrors src/brig/warden_addons/_policy.py:PolicyRule.matches_domain. The host-side
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
    brig.cell.lifecycle.sync_cell_policy.
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
    cell, or `brig policy set` in parallel with `brig run`) can each
    load the previous state, merge, and write — silently dropping the
    other's update. The lock mirrors the subnet allocator's pattern
    (src/brig/network/subnet.py).
    """
    with _locked_policy_dir(policy_dir, exclusive=True):
        atomic_write_json(get_cell_policy_path(cell_name, policy_dir), policy)


def mutate_cell_policy(
    cell_name: str,
    mutator: Callable[[dict[str, Any] | None], dict[str, Any] | None],
    policy_dir: Path = POLICY_DIR,
) -> dict[str, Any] | None:
    """Atomically read-modify-write a cell's policy under one exclusive lock.

    `mutator` receives the current policy dict (or None if no policy file
    exists yet) and returns the policy dict to persist — or None to signal
    "no change", in which case nothing is written (avoids churning mtime and
    triggering a needless warden reload). Holding a single exclusive lock
    across the load and the store closes the race where two concurrent
    writers each load the same baseline and last-write-wins, silently
    dropping one update. Returns the persisted (or unchanged current) policy.
    """
    path = get_cell_policy_path(cell_name, policy_dir)
    with _locked_policy_dir(policy_dir, exclusive=True):
        current: dict[str, Any] | None = None
        if path.exists():
            try:
                with open(path) as f:
                    current = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                debug(f"Failed to load policy for {cell_name}: {e}")
                current = None
        result = mutator(current)
        if result is None:
            return current
        atomic_write_json(path, result)
        return result


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


@contextmanager
def _locked_policy_dir(policy_dir: Path, exclusive: bool) -> Iterator[None]:
    """Advisory lock on the policy-directory lock file — shared for reads,
    exclusive for writes — so the per-cell load-modify-write sequence is
    serialized. Creates policy_dir if missing.
    """
    policy_dir.mkdir(parents=True, exist_ok=True)
    with locked_file(_policy_lock_path(policy_dir), exclusive=exclusive):
        yield
