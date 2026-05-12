"""
Cell specification — dataclass, validation, and loading.

A CellSpec describes the desired state of a cell. It is the input to the
reconciler, which computes the actions needed to make reality match.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from brig.config import CELL_NAME_PATTERN, DOMAIN_PATTERN, MEMORY_PATTERN
from brig.network.validation import is_suspicious_domain

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Size units for parse_size.
_SIZE_UNITS = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_size(size_str: str) -> int:
    """Parse a human-readable size string to bytes (e.g. '500m', '2g')."""
    size_str = size_str.strip().lower()
    if not size_str:
        raise ValueError("Empty size string")
    if size_str[-1] in _SIZE_UNITS:
        try:
            return int(float(size_str[:-1]) * _SIZE_UNITS[size_str[-1]])
        except ValueError:
            raise ValueError(f"Invalid size: {size_str}")
    try:
        return int(size_str)
    except ValueError:
        raise ValueError(f"Invalid size: {size_str}")


def parse_duration(duration_str: str) -> int | None:
    """Parse a duration string into seconds (e.g. '30s', '5m', '2h', '1d').

    Returns None if format is invalid.
    """
    duration_str = duration_str.strip()
    if duration_str.isdigit():
        return int(duration_str)
    match = re.match(r"^(\d+)([smhd])$", duration_str)
    if not match:
        return None
    value = int(match.group(1))
    unit = match.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


@dataclass
class CellSpec:
    """Desired state of a cell."""
    name: str
    image: str
    command: list[str] = field(default_factory=list)
    env: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    memory: str = "2g"
    cpus: str = "2"
    pids_limit: int = 512
    network: str = "default"  # "default" (per-cell isolated) or "none" (airgapped)
    policy_allow: list[str] = field(default_factory=list)
    policy_deny: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    timeout: str | None = None
    workspace_quota: str | None = None
    detach: bool = False
    rm: bool = False
    tor: bool = False
    seccomp_profile: str | None = None
    workdir: str | None = None
    image_digest: str | None = None
    profile: str | None = None

    def __post_init__(self) -> None:
        """Validate inputs at construction time — the system boundary."""
        if not CELL_NAME_PATTERN.match(self.name):
            raise ValueError(
                f"Invalid cell name '{self.name}': must match {CELL_NAME_PATTERN.pattern}"
            )

    @property
    def is_airgapped(self) -> bool:
        """True if cell has no network access."""
        return self.network == "none"


def validate_cell_definition(cell_def: dict[str, Any], file_path: str = "") -> list[str]:
    """Validate a cell definition dict and return list of errors.

    Enforces security invariants:
      - Invariant 1/6: Rejects network=proxy-external
      - Invariant 8: Rejects network=[list]
    """
    errors: list[str] = []
    context = f" in {file_path}" if file_path else ""

    # Name format.
    if "name" in cell_def:
        name = cell_def["name"]
        if not isinstance(name, str):
            errors.append(f"'name' must be a string{context}")
        elif not CELL_NAME_PATTERN.match(name):
            errors.append(f"'name' must match pattern {CELL_NAME_PATTERN.pattern}{context}")

    # Image.
    if "image" in cell_def:
        if not isinstance(cell_def["image"], str) or not cell_def["image"]:
            errors.append(f"'image' must be a non-empty string{context}")

    # Command.
    if "command" in cell_def:
        cmd = cell_def["command"]
        if not isinstance(cmd, (str, list)):
            errors.append(f"'command' must be a string or list{context}")
        elif isinstance(cmd, list) and not all(isinstance(c, str) for c in cmd):
            errors.append(f"'command' list items must be strings{context}")

    # Env.
    if "env" in cell_def:
        env = cell_def["env"]
        if isinstance(env, dict):
            for k, v in env.items():
                if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
                    errors.append(f"'env' keys must be strings, values must be primitives{context}")
        elif isinstance(env, list):
            for item in env:
                if not isinstance(item, str) or "=" not in item:
                    errors.append(f"'env' list items must be 'KEY=value' strings{context}")
        else:
            errors.append(f"'env' must be a dict or list{context}")

    # Secrets.
    if "secrets" in cell_def:
        secrets = cell_def["secrets"]
        if not isinstance(secrets, list):
            errors.append(f"'secrets' must be a list{context}")
        else:
            for secret in secrets:
                if not isinstance(secret, str):
                    errors.append(f"'secrets' items must be strings{context}")
                elif ".." in secret or "/" in secret:
                    errors.append(f"Invalid secret name '{secret}': path traversal not allowed{context}")

    # Memory.
    if "memory" in cell_def:
        mem = str(cell_def["memory"])
        if not re.match(MEMORY_PATTERN, mem):
            errors.append(f"Invalid 'memory' format '{mem}': use format like '512m', '2g'{context}")

    # CPUs.
    if "cpus" in cell_def:
        cpus = cell_def["cpus"]
        if not isinstance(cpus, (int, float, str)):
            errors.append(f"'cpus' must be a number or string{context}")
        else:
            try:
                float(cpus)
            except ValueError:
                errors.append(f"'cpus' must be a valid number{context}")

    # PID limit.
    if "pids_limit" in cell_def:
        pids = cell_def["pids_limit"]
        if not isinstance(pids, int) or pids < 1:
            errors.append(f"'pids_limit' must be a positive integer{context}")

    # Policy.
    if "policy" in cell_def:
        policy = cell_def["policy"]
        if not isinstance(policy, dict):
            errors.append(f"'policy' must be a dict{context}")
        else:
            for key in ["allow", "deny"]:
                if key in policy:
                    if not isinstance(policy[key], list):
                        errors.append(f"'policy.{key}' must be a list{context}")
                    else:
                        for domain in policy[key]:
                            if not isinstance(domain, str):
                                errors.append(f"'policy.{key}' items must be strings{context}")
                            elif not re.match(DOMAIN_PATTERN, domain):
                                errors.append(f"Invalid domain '{domain}' in policy.{key}{context}")
                            elif key == "allow":
                                suspicious = is_suspicious_domain(domain)
                                if suspicious:
                                    errors.append(f"Security: {suspicious}{context}")

    # Tor.
    if "tor" in cell_def:
        if not isinstance(cell_def["tor"], bool):
            errors.append(f"'tor' must be a boolean{context}")

    # Network — SECURITY INVARIANTS 1, 6, 8.
    # Only "default" (per-cell isolated) and "none" (airgapped) are valid.
    # "proxy-external" is rejected (invariant 6: only warden may attach).
    # List values are rejected (invariant 8: cells must be single-homed).
    if "network" in cell_def:
        net = cell_def["network"]
        if not isinstance(net, str):
            errors.append(
                f"'network' must be a string ('default' or 'none'){context}"
            )
        elif net not in ("default", "none"):
            errors.append(
                f"Invalid 'network' value '{net}': must be 'default' or 'none'"
                f" (attaching cells to other networks violates single-homing){context}"
            )

    # Workspace quota.
    if "workspace_quota" in cell_def:
        if not isinstance(cell_def["workspace_quota"], str):
            errors.append(f"'workspace_quota' must be a string like '500m' or '2g'{context}")
        else:
            try:
                parse_size(cell_def["workspace_quota"])
            except ValueError:
                errors.append(f"Invalid workspace_quota value: {cell_def['workspace_quota']}{context}")

    # Detach.
    if "detach" in cell_def:
        if not isinstance(cell_def["detach"], bool):
            errors.append(f"'detach' must be a boolean{context}")

    return errors


def load_cell_definition(path: str) -> dict[str, Any]:
    """Load a cell definition from a JSON or YAML file.

    Raises BrigError on failure.
    """
    from brig.errors import BrigError

    p = Path(path)
    if not p.exists():
        raise BrigError(f"Cell definition file not found: {path}")

    content = p.read_text()
    suffix = p.suffix.lower()

    if suffix in (".yaml", ".yml"):
        if not YAML_AVAILABLE:
            raise BrigError(
                "YAML support requires pyyaml",
                suggestion="Install with: pip install pyyaml",
            )
        try:
            result = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise BrigError(
                f"Failed to parse YAML: {e}",
                suggestion="Check the YAML syntax and try again",
            )
    else:
        try:
            result = json.loads(content)
        except json.JSONDecodeError as e:
            raise BrigError(
                f"Failed to parse JSON: {e}",
                suggestion="Check the JSON syntax. Validate with: python -m json.tool FILE",
            )

    if not isinstance(result, dict):
        raise BrigError(f"Cell definition must be a mapping, got {type(result).__name__}")
    return result
