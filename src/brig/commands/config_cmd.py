"""
CLI handlers for config commands.
"""

from __future__ import annotations

import json
from typing import Any

from brig.config import CONFIG_FILE
from brig.errors import BrigError
from brig.ops.logging import info, output


def cmd_config_show(args: Any) -> int:
    """Handle `brig config show`."""
    try:
        with open(CONFIG_FILE) as f:
            config = json.load(f)
    except FileNotFoundError:
        output("No configuration file (using defaults)")
        return 0
    except json.JSONDecodeError as e:
        raise BrigError(f"Invalid config file: {e}")

    key = getattr(args, "key", None)
    if key:
        # Dot-path lookup (e.g. "operation_logging.level").
        parts = key.split(".")
        val = config
        for part in parts:
            if isinstance(val, dict) and part in val:
                val = val[part]
            else:
                raise BrigError(f"Config key not found: {key}")
        output(json.dumps(val, indent=2) if isinstance(val, (dict, list)) else str(val))
    else:
        output(json.dumps(config, indent=2))
    return 0


def cmd_config_set(args: Any) -> int:
    """Handle `brig config set`."""
    try:
        with open(CONFIG_FILE) as f:
            config = json.load(f)
    except FileNotFoundError:
        config = {}
    except json.JSONDecodeError as e:
        raise BrigError(f"Invalid config file: {e}")

    # Parse value as JSON if possible, else treat as string.
    try:
        value = json.loads(args.value)
    except json.JSONDecodeError:
        value = args.value

    # Dot-path set (e.g. "operation_logging.level").
    parts = args.key.split(".")
    target = config
    for part in parts[:-1]:
        if part not in target:
            target[part] = {}
        target = target[part]
    target[parts[-1]] = value

    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

    info(f"Set {args.key} = {args.value}")
    return 0


def cmd_config_reset(args: Any) -> int:
    """Handle `brig config reset`."""
    default = {
        "operation_logging": {
            "enabled": True,
            "level": "all",
            "redact_secrets": True,
            "redact_env_values": True,
        }
    }
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(default, f, indent=2)
    info("Configuration reset to defaults")
    return 0
