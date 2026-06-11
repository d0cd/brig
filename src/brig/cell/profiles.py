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
#
# `runtime` is intentionally omitted: invariant 5 requires gVisor (`runsc`)
# and the reconciler hardcodes `--runtime runsc`, so a profile-level runtime
# would imply a configurability that does not exist.
BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "untrusted": {
        "memory": "512m",
        "cpus": "1",
        "pids_limit": 256,
        "network": "default",
        "policy": {"allow": [], "deny": []},
        "labels": {"brig.profile": "untrusted"},
    },
    "supervised": {
        "memory": "2g",
        "cpus": "2",
        "pids_limit": 512,
        "network": "default",
        "labels": {"brig.profile": "supervised"},
    },
    "dev": {
        "memory": "4g",
        "cpus": "4",
        "pids_limit": 2048,
        "network": "default",
        "labels": {"brig.profile": "dev"},
    },
    "airgapped": {
        "memory": "2g",
        "cpus": "2",
        "pids_limit": 512,
        "network": "none",
        "labels": {"brig.profile": "airgapped"},
    },
    "honeypot": {
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

    Built-in profile names are reserved — a user profile file with the
    same name is refused outright so it can't silently shadow the
    builtin. This is load-bearing for `untrusted`, where the untrusted
    cell's adversarial-code guarantees come from the profile NAME being
    `untrusted`; if a user-defined file at ~/.brig/profiles/untrusted.yaml
    were loaded instead, the operator could remove the host_sockets /
    host_services / tls_passthrough rejections by editing one file.

    Raises ValueError if not found or if a user file shadows a builtin.
    """
    for ext in (".yaml", ".yml", ".json"):
        user_profile = profiles_dir / f"{name}{ext}"
        if user_profile.exists():
            if name in BUILTIN_PROFILES:
                raise ValueError(
                    f"User profile {user_profile} shadows the built-in "
                    f"'{name}' profile, which is not allowed. Rename "
                    f"the file to a different profile name."
                )
            debug(f"Loading user profile: {user_profile}")
            from brig.cell.spec import load_cell_definition
            return load_cell_definition(str(user_profile))

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

    Profile values only fill in fields the spec hasn't already set.
    Policy and host_services from the profile prepend to the spec's
    own entries (profile = baseline, yaml = additions). Returns
    merged dict.
    """
    merged = dict(spec)

    for key in ("memory", "cpus", "pids_limit", "network"):
        if key in profile and key not in merged:
            merged[key] = profile[key]

    # Profile's policy.allow / policy.deny prepend to the spec's flat
    # policy_allow / policy_deny lists (cell yaml additions extend the
    # profile baseline).
    if "policy" in profile:
        prof_policy = profile["policy"]
        if isinstance(prof_policy, dict):
            for src_key, dst_key in (("allow", "policy_allow"),
                                      ("deny", "policy_deny"),
                                      ("tls_passthrough", "policy_passthrough_tls")):
                src = prof_policy.get(src_key) or []
                if src:
                    merged[dst_key] = list(src) + list(merged.get(dst_key) or [])

    # Profile-declared host_services prepend to the cell's list.
    if "host_services" in profile and isinstance(profile["host_services"], list):
        merged["host_services"] = (
            list(profile["host_services"]) + list(merged.get("host_services") or [])
        )

    if "labels" in profile:
        profile_labels = profile["labels"]
        if isinstance(profile_labels, dict):
            existing = merged.get("labels", {})
            if isinstance(existing, dict):
                merged["labels"] = {**profile_labels, **existing}

    return merged
