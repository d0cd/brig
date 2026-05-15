"""
Cell policy management — load, save, delete, validate.

Supports both JSON and YAML policy files.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from brig.config import DOMAIN_PATTERN, POLICY_DIR
from brig.network.validation import is_suspicious_domain
from brig.ops.logging import debug

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


def get_cell_policy_path(cell_name: str, policy_dir: Path = POLICY_DIR) -> Path:
    """Get the path for a cell's policy file."""
    return policy_dir / f"{cell_name}.json"


def load_cell_policy(
    cell_name: str,
    policy_dir: Path = POLICY_DIR,
) -> dict[str, Any] | None:
    """Load a cell's policy from disk. Returns None if no policy exists."""
    path = get_cell_policy_path(cell_name, policy_dir)
    try:
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
    """Save a cell's policy to disk. Atomic write (temp + rename)."""
    policy_dir.mkdir(parents=True, exist_ok=True)
    path = get_cell_policy_path(cell_name, policy_dir)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(policy, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    tmp.rename(path)


def delete_cell_policy(
    cell_name: str,
    policy_dir: Path = POLICY_DIR,
) -> bool:
    """Delete a cell's policy file. Returns True if deleted."""
    path = get_cell_policy_path(cell_name, policy_dir)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


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
