"""Configuration commands: config show, config set, config reset."""

import json
import os

import brig.commands._helpers as _helpers
from brig.commands._helpers import (
    _load_operation_config,
    debug,
    error,
    output,
)


def cmd_config_show(args) -> int:
    """Show current configuration."""
    # Define available configuration keys with types and defaults.
    from typing import Any
    config_schema: dict[str, dict[str, Any]] = {
        "operation_logging.enabled": {
            "type": "bool",
            "default": True,
            "description": "Enable operation logging to JSONL file",
        },
        "operation_logging.level": {
            "type": "str",
            "default": "all",
            "values": ["all", "mutations", "none"],
            "description": "Which operations to log",
        },
        "operation_logging.redact_secrets": {
            "type": "bool",
            "default": True,
            "description": "Redact secret values in logs",
        },
        "operation_logging.redact_env_values": {
            "type": "bool",
            "default": True,
            "description": "Redact environment variable values containing sensitive patterns",
        },
    }

    if getattr(args, "keys", False):
        # List available keys.
        print("Available configuration keys:\n")
        for key, schema_info in config_schema.items():
            type_str = schema_info["type"]
            if "values" in schema_info:
                type_str = f"{type_str} ({', '.join(schema_info['values'])})"
            print(f"  {key}")
            print(f"    Type:    {type_str}")
            print(f"    Default: {schema_info['default']}")
            print(f"    {schema_info['description']}")
            print()
        return 0

    config = _load_operation_config()

    if args.key:
        # Show specific key.
        keys = args.key.split(".")
        value = config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                error(
                    f"Config key not found: {args.key}",
                    "List available keys with: brig config show"
                )
        if isinstance(value, dict):
            print(json.dumps(value, indent=2))
        else:
            print(value)
    else:
        # Show all config.
        print(json.dumps(config, indent=2))

    return 0


def cmd_config_set(args) -> int:
    """Set a configuration value."""
    key = args.key
    value = args.value

    # Parse value as JSON if possible, otherwise use as string.
    try:
        parsed_value = json.loads(value)
    except json.JSONDecodeError:
        # Check for boolean strings.
        if value.lower() == "true":
            parsed_value = True
        elif value.lower() == "false":
            parsed_value = False
        else:
            parsed_value = value

    # Load existing config.
    if _helpers.CONFIG_FILE.exists():
        try:
            with open(_helpers.CONFIG_FILE, "r") as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            debug(f"Failed to load config file: {e}")
            config = {}
    else:
        config = {}

    # Set nested key.
    keys = key.split(".")
    current = config
    for k in keys[:-1]:
        if k not in current:
            current[k] = {}
        current = current[k]
    current[keys[-1]] = parsed_value

    # Write config atomically.
    _helpers.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp_file = _helpers.CONFIG_FILE.with_suffix(".tmp")
    try:
        with open(tmp_file, "w") as f:
            json.dump(config, f, indent=2)
        tmp_file.rename(_helpers.CONFIG_FILE)
    except (IOError, OSError) as e:
        error(
            f"Failed to write config: {e}",
            "Check file permissions and disk space"
        )

    output(f"Set {key} = {parsed_value}")
    return 0


def cmd_config_reset(args) -> int:
    """Reset configuration to defaults."""
    if _helpers.CONFIG_FILE.exists():
        try:
            _helpers.CONFIG_FILE.unlink()
            output("Configuration reset to defaults")
        except OSError as e:
            error(
                f"Failed to reset config: {e}",
                "Check file permissions"
            )
    else:
        output("Configuration already at defaults")
    return 0
