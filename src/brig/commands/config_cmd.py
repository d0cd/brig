"""
CLI handlers for config commands.
"""

from __future__ import annotations

import json
import argparse

from brig.config import CONFIG_FILE
from brig.errors import BrigError
from brig.ops.atomic import atomic_write_json
from brig.ops.logging import info, output


def register_parser(sub) -> None:
    """Register the `brig config` subcommand tree."""
    p = sub.add_parser("config", help="Manage configuration")
    s = p.add_subparsers(dest="config_command", required=True)
    p_show = s.add_parser("show", help="Show configuration")
    p_show.add_argument("key", nargs="?", help="Config key")
    p_set = s.add_parser("set", help="Set configuration value")
    p_set.add_argument("key", help="Config key")
    p_set.add_argument("value", help="Value")
    s.add_parser("reset", help="Reset to defaults")


def cmd_config_show(args: argparse.Namespace) -> int:
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


def cmd_config_set(args: argparse.Namespace) -> int:
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
    for i, part in enumerate(parts[:-1]):
        if part not in target:
            target[part] = {}
        elif not isinstance(target[part], dict):
            # A prior scalar set at this key blocks descending into it; raise a
            # clear error instead of a TypeError on item assignment below.
            conflict = ".".join(parts[: i + 1])
            raise BrigError(
                f"Cannot set '{args.key}': '{conflict}' is already a value, "
                f"not a section",
                suggestion=f"brig config set {conflict} <new-value>  # overwrite it, OR "
                           f"pick a different key",
            )
        target = target[part]
    target[parts[-1]] = value

    # mount_roots feeds lima.yaml + grants cells host access — vet it now so the
    # operator gets immediate feedback instead of a later cell/VM failure.
    if args.key == "mount_roots":
        from brig.config import validate_mount_roots
        # Mirror config.mount_roots()'s coercion: a list, or a comma-separated
        # string. Any other JSON type is a usage error, not a list of paths.
        if isinstance(value, list):
            raw = value
        elif isinstance(value, str):
            raw = value.split(",")
        else:
            raise BrigError(
                "mount_roots must be a list or a comma-separated string of "
                "absolute paths"
            )
        roots = [p.strip() for p in raw if isinstance(p, str) and p.strip()]
        errs = validate_mount_roots(roots)
        if errs:
            raise BrigError("Invalid mount_roots:\n  - " + "\n  - ".join(errs))

    atomic_write_json(CONFIG_FILE, config)

    info(f"Set {args.key} = {args.value}")
    return 0


def cmd_config_reset(args: argparse.Namespace) -> int:
    """Handle `brig config reset`."""
    default = {
        "operation_logging": {
            "enabled": True,
            "level": "all",
            "redact_secrets": True,
            "redact_env_values": True,
        }
    }
    atomic_write_json(CONFIG_FILE, default)
    info("Configuration reset to defaults")
    return 0


DISPATCH = {
    "show": cmd_config_show,
    "set": cmd_config_set,
    "reset": cmd_config_reset,
}
