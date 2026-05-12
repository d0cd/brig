"""
Trust profiles for cells.

A profile is a partial cell spec that sets defaults for resource limits,
network mode, and policy. CLI flags always override profile values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from brig.config import BRIG_HOME
from brig.ops.logging import debug

PROFILES_DIR = BRIG_HOME / "profiles"

# Built-in profiles. Each is a partial cell definition (no name/image/command).
BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "untrusted": {
        "runtime": "runsc",
        "memory": "512m",
        "cpus": "1",
        "pids_limit": 256,
        "network": "default",
        "policy": {"allow": [], "deny": []},
        "labels": {"brig.profile": "untrusted"},
    },
    "supervised": {
        "runtime": "runsc",
        "memory": "2g",
        "cpus": "2",
        "pids_limit": 512,
        "network": "default",
        "labels": {"brig.profile": "supervised"},
    },
    "dev": {
        "runtime": "runsc",
        "memory": "4g",
        "cpus": "4",
        "pids_limit": 2048,
        "network": "default",
        "labels": {"brig.profile": "dev"},
    },
    "airgapped": {
        "runtime": "runsc",
        "memory": "2g",
        "cpus": "2",
        "pids_limit": 512,
        "network": "none",
        "labels": {"brig.profile": "airgapped"},
    },
    "honeypot": {
        "runtime": "runsc",
        "memory": "1g",
        "cpus": "1",
        "pids_limit": 256,
        "network": "default",
        "policy": {"allow": [], "deny": ["*"]},
        "labels": {"brig.profile": "honeypot"},
    },
}


def load_profile(name: str, profiles_dir: Path = PROFILES_DIR) -> dict[str, Any]:
    """Load a trust profile by name.

    Checks user profiles directory first, then built-in profiles.
    Raises ValueError if not found.
    """
    # User-defined profiles.
    for ext in (".yaml", ".yml", ".json"):
        user_profile = profiles_dir / f"{name}{ext}"
        if user_profile.exists():
            debug(f"Loading user profile: {user_profile}")
            from brig.cell.spec import load_cell_definition
            return load_cell_definition(str(user_profile))

    # Built-in profiles.
    if name in BUILTIN_PROFILES:
        debug(f"Loading built-in profile: {name}")
        return BUILTIN_PROFILES[name].copy()

    available = list(BUILTIN_PROFILES.keys())
    if profiles_dir.exists():
        for f in profiles_dir.iterdir():
            if f.suffix in (".yaml", ".yml", ".json"):
                available.append(f.stem)

    raise ValueError(
        f"Unknown profile: {name}. "
        f"Available profiles: {', '.join(sorted(set(available)))}"
    )


def apply_profile(spec: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """Apply profile defaults to a cell spec dict.

    Profile values only fill in fields not already set. Returns merged dict.
    """
    merged = dict(spec)

    # Simple fields: set if not present.
    for key in ("memory", "cpus", "pids_limit", "network"):
        if key in profile and key not in merged:
            merged[key] = profile[key]

    # Policy: merge allow/deny lists.
    if "policy" in profile:
        if "policy" not in merged:
            merged["policy"] = {}
        prof_policy = profile["policy"]
        for key in ("allow", "deny"):
            if key in prof_policy and key not in merged["policy"]:
                merged["policy"][key] = prof_policy[key]

    # Labels: prepend profile labels.
    if "labels" in profile:
        profile_labels = profile["labels"]
        if isinstance(profile_labels, dict):
            existing = merged.get("labels", {})
            if isinstance(existing, dict):
                merged["labels"] = {**profile_labels, **existing}

    return merged
