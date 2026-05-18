"""
Operation and lifecycle logging.

All log entries are JSONL (one JSON object per line) with file locking.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from brig.config import (
    CONFIG_FILE,
    HISTORY_FILE,
    LIFECYCLE_FILE,
    MUTATION_COMMANDS,
    OPERATIONS_FILE,
    POLICY_AUDIT_FILE,
    SENSITIVE_PATTERNS,
)
from brig.ops.logging import debug


MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB per log file.


def _append_jsonl(path: Path, entry: dict[str, Any]) -> None:
    """Append a JSON line to a log file under an exclusive lock.

    The lock is held across both the rotation check and the append, so two
    concurrent brig invocations can't race on the size check (both seeing
    >MAX_LOG_SIZE and both renaming the file). Sidecar `.lock` file lets
    the data file be renamed without affecting the lock.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _maybe_rotate(path)
        with open(path, "a") as f:
            f.write(json.dumps(entry) + "\n")


def _maybe_rotate(path: Path) -> None:
    """Rotate log file if it exceeds MAX_LOG_SIZE.

    Caller must hold the sidecar lock (`<path>.lock` via fcntl.LOCK_EX).
    """
    try:
        if not path.exists() or path.stat().st_size < MAX_LOG_SIZE:
            return
    except OSError:
        return

    # Rotate: .2 → delete, .1 → .2, current → .1.
    for i in range(2, 0, -1):
        src = path.with_suffix(f"{path.suffix}.{i}")
        dst = path.with_suffix(f"{path.suffix}.{i + 1}")
        if i == 2 and src.exists():
            src.unlink()
        elif src.exists():
            src.rename(dst)
    path.rename(path.with_suffix(f"{path.suffix}.1"))


def log_operation(
    operation: str,
    cell_name: str | None = None,
    details: dict[str, Any] | None = None,
    history_file: Path = HISTORY_FILE,
) -> None:
    """Log an operation to the history file."""
    try:
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operation": operation,
        }
        if cell_name:
            entry["cell"] = cell_name
        if details:
            entry["details"] = details
        _append_jsonl(history_file, entry)
    except (IOError, OSError) as e:
        debug(f"Failed to log operation: {e}")


def log_lifecycle(
    event: str,
    cell_name: str,
    details: dict[str, Any] | None = None,
    lifecycle_file: Path = LIFECYCLE_FILE,
) -> None:
    """Log a cell lifecycle event (start, stop, kill, rm)."""
    try:
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "cell": cell_name,
        }
        if details:
            entry.update(details)
        _append_jsonl(lifecycle_file, entry)
    except (IOError, OSError) as e:
        debug(f"Failed to log lifecycle event: {e}")


def log_policy_change(
    cell_name: str,
    action: str,
    changes: dict[str, Any],
    old_policy: dict[str, Any] | None = None,
    new_policy: dict[str, Any] | None = None,
    audit_file: Path = POLICY_AUDIT_FILE,
) -> None:
    """Log a policy change for audit trail."""
    try:
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cell": cell_name,
            "action": action,
            "changes": changes,
        }
        if old_policy is not None:
            entry["old_policy"] = old_policy
        if new_policy is not None:
            entry["new_policy"] = new_policy
        _append_jsonl(audit_file, entry)
    except (IOError, OSError) as e:
        debug(f"Failed to log policy change: {e}")


# --- Comprehensive operation logging (start/end with timing and redaction) ---

# Operation config cache.
_operation_config: dict[str, Any] | None = None
_operation_config_mtime: float = 0.0


def _load_operation_config(config_file: Path = CONFIG_FILE) -> dict[str, Any]:
    """Load operation logging configuration from config file."""
    global _operation_config, _operation_config_mtime

    default_config: dict[str, Any] = {
        "operation_logging": {
            "enabled": True,
            "level": "all",
            "redact_secrets": True,
            "redact_env_values": True,
        }
    }

    try:
        mtime = config_file.stat().st_mtime
        if _operation_config is not None and mtime == _operation_config_mtime:
            return _operation_config

        with open(config_file) as f:
            config = json.load(f)

        _operation_config = {**default_config, **config}
        _operation_config_mtime = mtime
        return _operation_config

    except (json.JSONDecodeError, IOError, OSError) as e:
        debug(f"Failed to load operation config: {e}")
        return default_config


def _redact_sensitive_value(key: str, value: str, config: dict[str, Any]) -> str:
    """Redact sensitive values based on key patterns."""
    if not config.get("operation_logging", {}).get("redact_env_values", True):
        return value
    key_lower = key.lower()
    for pattern in SENSITIVE_PATTERNS:
        if pattern in key_lower:
            return "[REDACTED]"
    return value


def _redact_args(args: Any, config: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive information from command arguments."""
    redacted: dict[str, Any] = {}
    redact_secrets = config.get("operation_logging", {}).get("redact_secrets", True)
    redact_env = config.get("operation_logging", {}).get("redact_env_values", True)

    for key, value in vars(args).items():
        if key.startswith("_"):
            continue

        # Secrets: log names only, never values.
        if key == "secret" and value and redact_secrets:
            redacted[key] = value
            continue

        # Environment variables: redact values.
        if key == "env" and value and redact_env:
            redacted_env = []
            for env_str in value:
                if "=" in env_str:
                    env_key, env_val = env_str.split("=", 1)
                    redacted_val = _redact_sensitive_value(env_key, env_val, config)
                    redacted_env.append(f"{env_key}={redacted_val}")
                else:
                    redacted_env.append(env_str)
            redacted[key] = redacted_env
            continue

        # Other potentially sensitive arguments.
        if isinstance(value, str):
            key_lower = key.lower()
            is_sensitive = any(p in key_lower for p in SENSITIVE_PATTERNS)
            if is_sensitive and redact_env:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = value
        elif isinstance(value, (list, tuple)):
            redacted[key] = list(value)
        elif isinstance(value, (int, float, bool, type(None))):
            redacted[key] = value

    return redacted


def _extract_cell_name(args: Any) -> str | None:
    """Extract cell name from args if present."""
    for attr in ["name", "cell_name", "cell"]:
        if hasattr(args, attr):
            val = getattr(args, attr)
            if val:
                return val  # type: ignore[no-any-return]
    return None


def log_operation_start(
    command: str,
    args: Any,
    config_file: Path = CONFIG_FILE,
) -> dict[str, Any]:
    """Log the start of an operation. Returns context for log_operation_end."""
    config = _load_operation_config(config_file)
    op_config = config.get("operation_logging", {})

    if not op_config.get("enabled", True):
        return {"enabled": False}

    level = op_config.get("level", "all")
    if level == "none":
        return {"enabled": False}
    if level == "mutations" and command not in MUTATION_COMMANDS:
        return {"enabled": False}

    return {
        "enabled": True,
        "start_time": time.time(),
        "command": command,
        "args": args,
        "config": config,
    }


def log_operation_end(
    context: dict[str, Any],
    exit_code: int = 0,
    error: str | None = None,
    operations_file: Path = OPERATIONS_FILE,
) -> None:
    """Log the end of an operation with timing and result."""
    if not context.get("enabled", False):
        return

    config = context.get("config", {})
    start_time = context.get("start_time", time.time())
    duration_ms = int((time.time() - start_time) * 1000)

    try:
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "command": context.get("command"),
            "duration_ms": duration_ms,
            "exit_code": exit_code,
        }

        cell_name = _extract_cell_name(context.get("args"))
        if cell_name:
            entry["cell"] = cell_name

        args = context.get("args")
        if args:
            entry["args"] = _redact_args(args, config)

        if error:
            entry["error"] = re.sub(r'(/[^\s:]+)', '<path>', error)

        _append_jsonl(operations_file, entry)

    except (IOError, OSError) as e:
        debug(f"Failed to log operation: {e}")
