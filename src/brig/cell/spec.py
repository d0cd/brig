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

from brig.config import (
    CELL_NAME_PATTERN,
    DOMAIN_PATTERN,
    INGRESS_AUTH_METHODS,
    INGRESS_NAME_PATTERN,
    INGRESS_PATH_PREFIX_PATTERN,
    MAX_INGRESS_PER_CELL,
    MEMORY_PATTERN,
)
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
    seccomp_profile: str | None = None
    workdir: str | None = None
    image_digest: str | None = None
    profile: str | None = None
    ingress: list[dict[str, Any]] = field(default_factory=list)

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


# --- Per-field validators ---------------------------------------------------
#
# Each `_v_<field>` function returns a list of error strings (possibly empty).
# `validate_cell_definition` dispatches to these by key. Splitting them keeps
# the dispatch loop short and lets each validator be tested in isolation.


def _v_name(value: Any, context: str) -> list[str]:
    if not isinstance(value, str):
        return [f"'name' must be a string{context}"]
    if not CELL_NAME_PATTERN.match(value):
        return [f"'name' must match pattern {CELL_NAME_PATTERN.pattern}{context}"]
    return []


def _v_image(value: Any, context: str) -> list[str]:
    if not isinstance(value, str) or not value:
        return [f"'image' must be a non-empty string{context}"]
    return []


def _v_command(value: Any, context: str) -> list[str]:
    if not isinstance(value, (str, list)):
        return [f"'command' must be a string or list{context}"]
    if isinstance(value, list) and not all(isinstance(c, str) for c in value):
        return [f"'command' list items must be strings{context}"]
    return []


def _v_env(value: Any, context: str) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
                errors.append(f"'env' keys must be strings, values must be primitives{context}")
                break
    elif isinstance(value, list):
        for item in value:
            if not isinstance(item, str) or "=" not in item:
                errors.append(f"'env' list items must be 'KEY=value' strings{context}")
                break
    else:
        errors.append(f"'env' must be a dict or list{context}")
    return errors


def _v_secrets(value: Any, context: str) -> list[str]:
    if not isinstance(value, list):
        return [f"'secrets' must be a list{context}"]
    errors: list[str] = []
    for secret in value:
        if not isinstance(secret, str):
            errors.append(f"'secrets' items must be strings{context}")
        elif ".." in secret or "/" in secret:
            errors.append(f"Invalid secret name '{secret}': path traversal not allowed{context}")
    return errors


def _v_memory(value: Any, context: str) -> list[str]:
    mem = str(value)
    if not re.match(MEMORY_PATTERN, mem):
        return [f"Invalid 'memory' format '{mem}': use format like '512m', '2g'{context}"]
    return []


def _v_cpus(value: Any, context: str) -> list[str]:
    if not isinstance(value, (int, float, str)):
        return [f"'cpus' must be a number or string{context}"]
    try:
        float(value)
    except ValueError:
        return [f"'cpus' must be a valid number{context}"]
    return []


def _v_pids_limit(value: Any, context: str) -> list[str]:
    if not isinstance(value, int) or value < 1:
        return [f"'pids_limit' must be a positive integer{context}"]
    return []


def _v_policy(value: Any, context: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"'policy' must be a dict{context}"]
    errors: list[str] = []
    for key in ("allow", "deny"):
        if key not in value:
            continue
        if not isinstance(value[key], list):
            errors.append(f"'policy.{key}' must be a list{context}")
            continue
        for domain in value[key]:
            if not isinstance(domain, str):
                errors.append(f"'policy.{key}' items must be strings{context}")
            elif not re.match(DOMAIN_PATTERN, domain):
                errors.append(f"Invalid domain '{domain}' in policy.{key}{context}")
            elif key == "allow":
                suspicious = is_suspicious_domain(domain)
                if suspicious:
                    errors.append(f"Security: {suspicious}{context}")
    return errors


def _v_network(value: Any, context: str) -> list[str]:
    """Network — SECURITY INVARIANTS 1, 6, 8.

    Only "default" (per-cell isolated) and "none" (airgapped) are valid.
    "proxy-external" is rejected (invariant 6: only warden may attach).
    List values are rejected (invariant 8: cells must be single-homed).
    """
    if not isinstance(value, str):
        return [f"'network' must be a string ('default' or 'none'){context}"]
    if value not in ("default", "none"):
        return [
            f"Invalid 'network' value '{value}': must be 'default' or 'none'"
            f" (attaching cells to other networks violates single-homing){context}"
        ]
    return []


def _v_workspace_quota(value: Any, context: str) -> list[str]:
    if not isinstance(value, str):
        return [f"'workspace_quota' must be a string like '500m' or '2g'{context}"]
    try:
        parse_size(value)
    except ValueError:
        return [f"Invalid workspace_quota value: {value}{context}"]
    return []


def _v_detach(value: Any, context: str) -> list[str]:
    if not isinstance(value, bool):
        return [f"'detach' must be a boolean{context}"]
    return []


def _v_ingress_entry(i: int, entry: Any, seen_names: set, seen_prefixes: set,
                     context: str) -> list[str]:
    """Validate one ingress entry. Mutates seen_* sets to track duplicates."""
    if not isinstance(entry, dict):
        return [f"'ingress[{i}]' must be a dict{context}"]

    errors: list[str] = []

    name = entry.get("name")
    if not name or not isinstance(name, str):
        errors.append(f"'ingress[{i}].name' is required and must be a string{context}")
    elif not INGRESS_NAME_PATTERN.match(name):
        errors.append(
            f"'ingress[{i}].name' must be lowercase alphanumeric "
            f"with hyphens, max 31 chars{context}"
        )
    elif name in seen_names:
        errors.append(f"Duplicate ingress name '{name}'{context}")
    else:
        seen_names.add(name)

    port = entry.get("port")
    if port is None:
        errors.append(f"'ingress[{i}].port' is required{context}")
    elif not isinstance(port, int) or port < 1 or port > 65535:
        errors.append(f"'ingress[{i}].port' must be an integer 1-65535{context}")

    path_prefix = entry.get("path_prefix")
    if not path_prefix or not isinstance(path_prefix, str):
        errors.append(f"'ingress[{i}].path_prefix' is required and must be a string{context}")
    elif not path_prefix.startswith("/"):
        errors.append(f"'ingress[{i}].path_prefix' must start with '/'{context}")
    elif ".." in path_prefix:
        errors.append(f"'ingress[{i}].path_prefix' must not contain '..'{context}")
    elif not INGRESS_PATH_PREFIX_PATTERN.match(path_prefix):
        errors.append(
            f"'ingress[{i}].path_prefix' contains invalid characters "
            f"(only alphanumeric, /, -, _ allowed){context}"
        )
    elif path_prefix in seen_prefixes:
        errors.append(f"Duplicate ingress path_prefix '{path_prefix}'{context}")
    else:
        seen_prefixes.add(path_prefix)

    auth = entry.get("auth")
    if not auth or not isinstance(auth, str):
        errors.append(f"'ingress[{i}].auth' is required and must be a string{context}")
    elif auth not in INGRESS_AUTH_METHODS:
        errors.append(
            f"'ingress[{i}].auth' must be one of: "
            f"{', '.join(sorted(INGRESS_AUTH_METHODS))}{context}"
        )

    return errors


def _v_ingress(value: Any, cell_def: dict, context: str) -> list[str]:
    if not isinstance(value, list):
        return [f"'ingress' must be a list{context}"]

    errors: list[str] = []
    if len(value) > MAX_INGRESS_PER_CELL:
        errors.append(
            f"Too many ingress entries ({len(value)}), "
            f"max {MAX_INGRESS_PER_CELL}{context}"
        )

    seen_names: set = set()
    seen_prefixes: set = set()
    for i, entry in enumerate(value):
        errors.extend(_v_ingress_entry(i, entry, seen_names, seen_prefixes, context))

    # Ingress requires network=default (not airgapped).
    net = cell_def.get("network", "default")
    if isinstance(net, str) and net == "none" and value:
        errors.append(f"'ingress' cannot be used with network='none' (airgapped){context}")
    return errors


# Map field name -> validator that takes (value, context). Validators that
# need other fields (like ingress checking network) are handled below.
_SIMPLE_VALIDATORS = {
    "name": _v_name,
    "image": _v_image,
    "command": _v_command,
    "env": _v_env,
    "secrets": _v_secrets,
    "memory": _v_memory,
    "cpus": _v_cpus,
    "pids_limit": _v_pids_limit,
    "policy": _v_policy,
    "network": _v_network,
    "workspace_quota": _v_workspace_quota,
    "detach": _v_detach,
}


def validate_cell_definition(cell_def: dict[str, Any], file_path: str = "") -> list[str]:
    """Validate a cell definition dict and return list of errors.

    Enforces security invariants:
      - Invariant 1/6: Rejects network=proxy-external
      - Invariant 8: Rejects network=[list]
    """
    errors: list[str] = []
    context = f" in {file_path}" if file_path else ""

    for field_name, validator in _SIMPLE_VALIDATORS.items():
        if field_name in cell_def:
            errors.extend(validator(cell_def[field_name], context))

    if "ingress" in cell_def:
        errors.extend(_v_ingress(cell_def["ingress"], cell_def, context))

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
