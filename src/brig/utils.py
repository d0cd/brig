"""
Utility functions for the Brig SDK package.

Note: src/brig.py (the CLI monolith) has its own copies of several functions
defined here (colorize, log, debug, etc.). The brig.py versions include QUIET
mode, fsync durability, and timeout parameters that the SDK versions do not.
Shared constants live in brig.config to avoid duplication.
"""

import fcntl
import json
import subprocess
import sys
import time
from typing import Any

from .config import CACHE_TTL, HISTORY_FILE, RATE_LIMIT_FILE, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW


class BrigError(Exception):
    """Base error for brig operations.

    Raised instead of sys.exit() so SDK consumers get a catchable exception.
    CLI entry points catch this and exit with the appropriate code.
    """
    def __init__(self, message: str, returncode: int = 1, stderr: str = "",
                 suggestion: str | None = None):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr
        self.suggestion = suggestion

# Debug mode (set via --debug flag).
DEBUG = False

# Log levels.
LOG_LEVEL_DEBUG = 0
LOG_LEVEL_INFO = 1
LOG_LEVEL_WARN = 2
LOG_LEVEL_ERROR = 3

# Current log level.
LOG_LEVEL = LOG_LEVEL_INFO

# Color output enabled.
COLOR_ENABLED = sys.stdout.isatty()

# ANSI color codes.
COLORS = {
    "reset": "\033[0m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "gray": "\033[90m",
}

# Simple TTL cache.
_cache: dict[str, tuple[float, Any]] = {}


def colorize(text: str, color: str) -> str:
    """Apply ANSI color to text if colors are enabled."""
    if COLOR_ENABLED and color in COLORS:
        return f"{COLORS[color]}{text}{COLORS['reset']}"
    return text


def status_color(status: str) -> str:
    """Get colorized status string."""
    status_lower = status.lower()
    if status_lower == "running":
        return colorize(status, "green")
    elif status_lower == "paused":
        return colorize(status, "yellow")
    elif status_lower in ("exited", "stopped", "dead"):
        return colorize(status, "red")
    elif status_lower == "created":
        return colorize(status, "blue")
    else:
        return status


def log(level: int, msg: str, level_name: str | None = None) -> None:
    """Log a message at the specified level."""
    if level < LOG_LEVEL:
        return
    level_names = {
        LOG_LEVEL_DEBUG: "DEBUG",
        LOG_LEVEL_INFO: "INFO",
        LOG_LEVEL_WARN: "WARN",
        LOG_LEVEL_ERROR: "ERROR",
    }
    level_colors = {
        LOG_LEVEL_DEBUG: "gray",
        LOG_LEVEL_INFO: "blue",
        LOG_LEVEL_WARN: "yellow",
        LOG_LEVEL_ERROR: "red",
    }
    name = level_name or level_names.get(level, "INFO")
    color = level_colors.get(level, None)
    if COLOR_ENABLED and color:
        prefix = colorize(f"[{name}]", color)
    else:
        prefix = f"[{name}]"
    print(f"{prefix} {msg}", file=sys.stderr)


def debug(msg: str) -> None:
    """Print debug message if debug mode is enabled."""
    log(LOG_LEVEL_DEBUG, msg)


def info(msg: str) -> None:
    """Print info message."""
    log(LOG_LEVEL_INFO, msg)


def warn(msg: str) -> None:
    """Print warning message."""
    log(LOG_LEVEL_WARN, msg)


def error(msg: str, suggestion: str | None = None) -> None:
    """Raise BrigError with message and optional suggestion.

    SDK consumers catch BrigError; CLI entry points print and sys.exit().
    """
    raise BrigError(msg, suggestion=suggestion)


def error_cell_not_found(cell_name: str) -> None:
    """Error helper for cell not found."""
    error(
        f"Cell '{cell_name}' does not exist",
        "Use 'brig list' to see available cells, or 'brig run' to create one"
    )


def error_cell_not_running(cell_name: str) -> None:
    """Error helper for cell not running."""
    error(
        f"Cell '{cell_name}' is not running",
        f"Use 'brig start {cell_name}' to start it"
    )


def error_proxy_not_running() -> None:
    """Error helper for proxy not running."""
    error(
        "Warden proxy is not running",
        "Start the proxy with: warden start"
    )


def log_operation(operation: str, cell_name: str | None = None, details: dict | None = None) -> None:
    """Log an operation to the history file.

    Uses file locking to prevent corruption from concurrent processes.
    """
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        entry: dict[str, object] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operation": operation,
        }
        if cell_name:
            entry["cell"] = cell_name
        if details:
            entry["details"] = details
        with open(HISTORY_FILE, "a") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(json.dumps(entry) + "\n")
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except (IOError, OSError) as e:
        debug(f"Failed to log operation: {e}")


def check_rate_limit() -> bool:
    """Check if cell creation is rate limited. Returns True if allowed.

    Uses file locking to prevent races between concurrent brig processes.
    """
    try:
        RATE_LIMIT_FILE.parent.mkdir(parents=True, exist_ok=True)

        now = time.time()

        # Use a lock file to serialize rate limit read-modify-write.
        lock_path = RATE_LIMIT_FILE.with_suffix(".lock")
        with open(lock_path, "w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                timestamps = []
                if RATE_LIMIT_FILE.exists():
                    try:
                        with open(RATE_LIMIT_FILE, "r") as f:
                            data = json.load(f)
                            timestamps = data.get("timestamps", [])
                    except (json.JSONDecodeError, IOError):
                        timestamps = []

                cutoff = now - RATE_LIMIT_WINDOW
                timestamps = [ts for ts in timestamps if ts > cutoff]

                if len(timestamps) >= RATE_LIMIT_MAX:
                    return False

                timestamps.append(now)
                with open(RATE_LIMIT_FILE, "w") as f:
                    json.dump({"timestamps": timestamps}, f)

                return True
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except (IOError, OSError) as e:
        debug(f"Rate limit check failed: {e}")
        # Fail closed: deny operation when rate limit state is unreadable.
        return False


def _cached(key: str, ttl: float = CACHE_TTL) -> tuple[bool, Any]:
    """Check if a cached value is still valid."""
    if key in _cache:
        ts, value = _cache[key]
        if time.time() - ts < ttl:
            return True, value
    return False, None


def _set_cache(key: str, value: Any) -> None:
    """Store a value in the cache."""
    _cache[key] = (time.time(), value)


def invalidate_cell_cache(cell_name: str) -> None:
    """Invalidate cache for a specific cell after state changes."""
    _cache.pop(f"cell_exists:{cell_name}", None)
    _cache.pop(f"cell_running:{cell_name}", None)


def _redact_cmd(cmd: list[str]) -> str:
    """Redact sensitive arguments from command for debug logging."""
    redacted = []
    skip_next = False
    sensitive_flags = {"--secret", "--password", "--token", "--key"}
    for i, arg in enumerate(cmd):
        if skip_next:
            redacted.append("***")
            skip_next = False
        elif arg in sensitive_flags:
            redacted.append(arg)
            skip_next = True
        elif "=" in arg and arg.split("=", 1)[0] in sensitive_flags:
            redacted.append(f"{arg.split('=', 1)[0]}=***")
        else:
            redacted.append(arg)
    return " ".join(redacted)


def run(cmd: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a command."""
    debug(f"Executing: {_redact_cmd(cmd)}")
    result = subprocess.run(cmd, check=check, capture_output=capture, text=True)
    if capture and result.returncode != 0:
        debug(f"Command failed with code {result.returncode}")
    return result
