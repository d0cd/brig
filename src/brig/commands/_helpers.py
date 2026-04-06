"""
Shared helpers, constants, and mutable globals for brig commands.

All command modules import from here. brig.py re-exports via wildcard
so that tests using importlib still find every name on the module.
"""

import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

# Shared constants from canonical source.
from brig.config import (
    CACHE_TTL,
    CELL_NAME_PATTERN,
    CONTAINER_PREFIX,
    DOMAIN_PATTERN,
    HISTORY_FILE,
    MEMORY_PATTERN,
    POLICY_DIR,
    PROXY_NAME,
    RATE_LIMIT_FILE,
    RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW,
    RUNTIME,
    STATE_DIR,
    SUSPICIOUS_DOMAIN_PATTERNS,
)

# Version information.
VERSION = "0.2.0"

try:
    import yaml  # type: ignore[import-untyped]
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Brig home directory (macOS side, for init command).
BRIG_HOME = Path.home() / ".brig"

# Operations log file (comprehensive command logging).
OPERATIONS_FILE = STATE_DIR / "system" / "operations.jsonl"

# Brig config file.
CONFIG_FILE = Path("/cells/config.json")

# Lifecycle log file.
LIFECYCLE_FILE = STATE_DIR / "system" / "lifecycle.jsonl"

# Policy audit log file.
POLICY_AUDIT_FILE = STATE_DIR / "system" / "policy_audit.jsonl"

# Mutation commands (for operation logging level filtering).
MUTATION_COMMANDS = {"run", "stop", "kill", "rm", "start", "pause", "unpause", "cp", "policy"}

# Sensitive argument patterns for redaction.
SENSITIVE_PATTERNS = {"password", "secret", "key", "token", "credential", "auth"}

# Resolve brig-subnet binary to absolute path to prevent PATH injection.
# Falls back to sibling of brig.py if not found in PATH.
BRIG_SUBNET_BIN = shutil.which("brig-subnet") or str(
    Path(__file__).parent.parent.parent / "brig_subnet_cli.py"
)

# Debug mode (set via --debug flag).
DEBUG = False

# Quiet mode (set via --quiet flag).
QUIET = False

# ANSI color codes.
COLORS = {
    "reset": "\033[0m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "gray": "\033[90m",
}

# Color output enabled (disable if not a TTY).
COLOR_ENABLED = sys.stdout.isatty()


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

class Spinner:
    """Context manager for showing a spinner during long operations."""

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str):
        self.message = message
        self.running = False
        self.thread = None

    def _spin(self):
        idx = 0
        while self.running:
            if sys.stderr.isatty():
                frame = self.FRAMES[idx % len(self.FRAMES)]
                sys.stderr.write(f"\r{frame} {self.message}")
                sys.stderr.flush()
                idx += 1
            time.sleep(0.1)  # 10 fps — smooth animation without busy-waiting.

    def __enter__(self):
        if sys.stderr.isatty() and not DEBUG and not QUIET:
            self.running = True
            self.thread = threading.Thread(target=self._spin, daemon=True)
            self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty() and not DEBUG and not QUIET:
            # Clear the spinner line.
            sys.stderr.write("\r" + " " * (len(self.message) + 3) + "\r")
            sys.stderr.flush()
        return False

    def success(self, message: str = None):
        """Show success message and stop spinner."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty() and not QUIET:
            msg = message or self.message
            sys.stderr.write(f"\r{colorize('✓', 'green')} {msg}\n")
            sys.stderr.flush()

    def fail(self, message: str = None):
        """Show failure message and stop spinner."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty():
            # Always show failures, even in quiet mode.
            msg = message or self.message
            sys.stderr.write(f"\r{colorize('✗', 'red')} {msg}\n")
            sys.stderr.flush()


# Simple TTL cache for expensive operations.
_cache: dict[str, tuple[float, Any]] = {}


# Log levels.
LOG_LEVEL_DEBUG = 0
LOG_LEVEL_INFO = 1
LOG_LEVEL_WARN = 2
LOG_LEVEL_ERROR = 3

# Current log level (set based on --debug flag).
LOG_LEVEL = LOG_LEVEL_INFO


def log(level: int, msg: str, level_name: str = None) -> None:
    """Log a message at the specified level."""
    if level < LOG_LEVEL:
        return
    # In quiet mode, suppress DEBUG and INFO messages.
    if QUIET and level < LOG_LEVEL_WARN:
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


def output(msg: str) -> None:
    """Print output message (respects quiet mode)."""
    if not QUIET:
        print(msg)


def warn(msg: str) -> None:
    """Print warning message."""
    log(LOG_LEVEL_WARN, msg)


def _append_jsonl(path: Path, entry: dict) -> None:
    """Append a JSON line to a log file with file locking and fsync.

    Holds an exclusive lock for the write to prevent interleaved lines
    from concurrent brig invocations.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())


def log_operation(operation: str, cell_name: str = None, details: dict = None) -> None:
    """Log an operation to the history file."""
    try:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operation": operation,
        }
        if cell_name:
            entry["cell"] = cell_name
        if details:
            entry["details"] = details
        _append_jsonl(HISTORY_FILE, entry)
    except (IOError, OSError) as e:
        debug(f"Failed to log operation: {e}")


def log_lifecycle(event: str, cell_name: str, details: dict = None) -> None:
    """Log a cell lifecycle event.

    Events: start, stop, kill, rm
    Details can include: image, command, exit_code, runtime_seconds, purged_workspace
    """
    try:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "cell": cell_name,
        }
        if details:
            entry.update(details)
        _append_jsonl(LIFECYCLE_FILE, entry)
    except (IOError, OSError) as e:
        debug(f"Failed to log lifecycle event: {e}")


def log_policy_change(
    cell_name: str,
    action: str,
    changes: dict,
    old_policy: dict = None,
    new_policy: dict = None
) -> None:
    """Log a policy change for audit trail.

    Args:
        cell_name: Name of the cell whose policy changed.
        action: Type of change (add_allow, add_deny, remove_allow, remove_deny, create, delete).
        changes: Dict describing what changed (e.g., {"domains": ["example.com"]}).
        old_policy: Policy before change (optional).
        new_policy: Policy after change (optional).

    """
    try:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cell": cell_name,
            "action": action,
            "changes": changes,
        }
        if old_policy is not None:
            entry["old_policy"] = old_policy
        if new_policy is not None:
            entry["new_policy"] = new_policy
        _append_jsonl(POLICY_AUDIT_FILE, entry)
    except (IOError, OSError) as e:
        debug(f"Failed to log policy change: {e}")


# Operation logging configuration cache.
_operation_config: dict = None
_operation_config_mtime: float = 0.0


def _load_operation_config() -> dict:
    """Load operation logging configuration from config file."""
    global _operation_config, _operation_config_mtime

    default_config = {
        "operation_logging": {
            "enabled": True,
            "level": "all",  # "all", "mutations", "none"
            "redact_secrets": True,
            "redact_env_values": True,
        }
    }

    try:
        if not CONFIG_FILE.exists():
            return default_config

        mtime = CONFIG_FILE.stat().st_mtime
        if _operation_config is not None and mtime == _operation_config_mtime:
            return _operation_config

        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)

        _operation_config = {**default_config, **config}
        _operation_config_mtime = mtime
        return _operation_config

    except (json.JSONDecodeError, IOError, OSError) as e:
        debug(f"Failed to load operation config: {e}")
        return default_config


def _redact_sensitive_value(key: str, value: str, config: dict) -> str:
    """Redact sensitive values based on key patterns."""
    if not config.get("operation_logging", {}).get("redact_env_values", True):
        return value

    key_lower = key.lower()
    for pattern in SENSITIVE_PATTERNS:
        if pattern in key_lower:
            return "[REDACTED]"
    return value


def _redact_args(args, config: dict) -> dict:
    """Redact sensitive information from command arguments."""
    redacted = {}
    redact_secrets = config.get("operation_logging", {}).get("redact_secrets", True)
    redact_env = config.get("operation_logging", {}).get("redact_env_values", True)

    for key, value in vars(args).items():
        # Skip internal/private attributes.
        if key.startswith("_"):
            continue

        # Handle secrets - log names only, never values.
        if key == "secret" and value and redact_secrets:
            redacted[key] = value  # Just the names, which is safe.
            continue

        # Handle environment variables - redact values.
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

        # Handle other potentially sensitive arguments.
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
        # Skip complex objects.

    return redacted


def _extract_cell_name(args) -> str:
    """Extract cell name from args if present."""
    # Try common attribute names for cell name.
    for attr in ["name", "cell_name", "cell"]:
        if hasattr(args, attr):
            val = getattr(args, attr)
            if val:
                return val
    return None


def log_operation_start(command: str, args) -> dict:
    """Log the start of an operation. Returns context for log_operation_end."""
    config = _load_operation_config()
    op_config = config.get("operation_logging", {})

    # Check if logging is enabled.
    if not op_config.get("enabled", True):
        return {"enabled": False}

    # Check logging level.
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


def log_operation_end(context: dict, exit_code: int = 0, error: str = None) -> None:
    """Log the end of an operation with timing and result."""
    if not context.get("enabled", False):
        return

    config = context.get("config", {})
    start_time = context.get("start_time", time.time())
    duration_ms = int((time.time() - start_time) * 1000)

    try:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "command": context.get("command"),
            "duration_ms": duration_ms,
            "exit_code": exit_code,
        }

        # Add cell name if present.
        cell_name = _extract_cell_name(context.get("args"))
        if cell_name:
            entry["cell"] = cell_name

        # Add redacted args.
        args = context.get("args")
        if args:
            entry["args"] = _redact_args(args, config)

        # Add error if present, with path redaction.
        if error:
            entry["error"] = re.sub(r'(/[^\s:]+)', '<path>', error)

        _append_jsonl(OPERATIONS_FILE, entry)

    except (IOError, OSError) as e:
        debug(f"Failed to log operation: {e}")


def check_rate_limit() -> bool:
    """Check if cell creation is rate limited. Returns True if allowed.

    Uses file locking to prevent TOCTOU races between concurrent brig
    invocations.
    """
    try:
        RATE_LIMIT_FILE.parent.mkdir(parents=True, exist_ok=True)

        now = time.time()

        # Use separate lock file so the data file can be atomically replaced.
        lock_path = RATE_LIMIT_FILE.with_suffix(".lock")
        with open(lock_path, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)

            # Read current data.
            timestamps = []
            if RATE_LIMIT_FILE.exists():
                try:
                    with open(RATE_LIMIT_FILE, "r") as f:
                        data = json.loads(f.read())
                        timestamps = data.get("timestamps", [])
                except (json.JSONDecodeError, IOError):
                    timestamps = []

            # Filter to only timestamps within the window.
            cutoff = now - RATE_LIMIT_WINDOW
            timestamps = [ts for ts in timestamps if ts > cutoff]

            # Check if limit exceeded.
            if len(timestamps) >= RATE_LIMIT_MAX:
                return False

            # Add current timestamp and save atomically.
            timestamps.append(now)
            tmp_path = RATE_LIMIT_FILE.with_suffix(".tmp")
            with open(tmp_path, "w") as tmp:
                json.dump({"timestamps": timestamps}, tmp)
                tmp.flush()
                os.fsync(tmp.fileno())
            tmp_path.rename(RATE_LIMIT_FILE)

        return True
    except (IOError, OSError) as e:
        debug(f"Rate limit check failed: {e}")
        return False  # Fail closed on error.


def verify_image_signature(
    image: str,
    key: str = None,
    keyless: bool = False,
    certificate_identity: str = None,
    certificate_oidc_issuer: str = None,
) -> tuple[bool, str, dict]:
    """Verify image signature using cosign or podman trust.

    Returns (success, message, details) tuple. Details dict contains parsed
    verification metadata when available.
    """
    # Try cosign first (preferred for sigstore signatures).
    result = run(
        ["which", "cosign"],
        check=False, capture=True
    )
    if result.returncode != 0:
        # Fall back to podman image trust.
        debug(f"Verifying image with podman trust: {image}")
        result = run(
            ["podman", "image", "trust", "show"],
            check=False, capture=True
        )
        if result.returncode == 0:
            # Check if image registry is in trusted list.
            if "accept" in result.stdout.lower():
                return True, "Image from trusted registry", {}

        return (
            False,
            "cosign is not installed. Install from https://docs.sigstore.dev/cosign/",
            {},
        )

    # Build cosign verify command.
    cmd = ["cosign", "verify"]
    if key:
        cmd.extend(["--key", key])
    elif keyless:
        if certificate_identity:
            cmd.extend(["--certificate-identity", certificate_identity])
        if certificate_oidc_issuer:
            cmd.extend(["--certificate-oidc-issuer", certificate_oidc_issuer])
    cmd.append(image)

    debug(f"Verifying image with cosign: {image}")
    result = run(cmd, check=False, capture=True)

    if result.returncode == 0:
        # Parse cosign JSON output for verification details.
        details = _parse_cosign_output(result.stdout)
        return True, "Signature verified with cosign", details

    # Check if it's unsigned vs invalid signature.
    stderr = result.stderr or ""
    if "no matching signatures" in stderr.lower():
        return False, "Image has no signature", {}
    return False, f"Signature verification failed: {stderr.strip()}", {}


def _parse_cosign_output(stdout: str) -> dict:
    """Parse cosign verification JSON output into a details dict."""
    details = {}
    if not stdout:
        return details
    try:
        data = json.loads(stdout)
        if isinstance(data, list):
            details["signatures"] = len(data)
            # Extract certificate info from the first entry if present.
            if data:
                first = data[0]
                optional = first.get("optional", {})
                bundle = first.get("bundle", {})
                if optional.get("Subject"):
                    details["certificate_identity"] = optional["Subject"]
                if optional.get("Issuer"):
                    details["issuer"] = optional["Issuer"]
                if bundle:
                    details["bundle"] = True
        elif isinstance(data, dict):
            details["signatures"] = 1
    except (json.JSONDecodeError, TypeError, KeyError):
        # Cosign output may not always be JSON (e.g., --output text).
        pass
    return details


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


def _redact_cmd(cmd: list[str]) -> list[str]:
    """Redact sensitive values from command arguments for debug logging."""
    redacted = []
    sensitive_flags = {"--secret", "--env", "-e", "--password", "--token"}
    redact_next = False
    for arg in cmd:
        if redact_next:
            # Redact the value following a sensitive flag.
            if "=" in arg:
                key, _ = arg.split("=", 1)
                redacted.append(f"{key}=***")
            else:
                redacted.append("***")
            redact_next = False
        elif arg in sensitive_flags:
            redacted.append(arg)
            redact_next = True
        elif any(arg.startswith(f"{f}=") for f in sensitive_flags):
            flag, _ = arg.split("=", 1)
            redacted.append(f"{flag}=***")
        else:
            redacted.append(arg)
    return redacted


def run(cmd: list[str], check: bool = True, capture: bool = False,
        timeout: int = None) -> subprocess.CompletedProcess:
    """Run a command with optional timeout in seconds."""
    debug(f"Executing: {' '.join(_redact_cmd(cmd))}")
    result = subprocess.run(cmd, check=check, capture_output=capture, text=True,
                            timeout=timeout)
    if capture and result.returncode != 0:
        debug(f"Command failed with code {result.returncode}")
    return result


def parse_duration(duration_str: str) -> int:
    """Parse a duration string into seconds.

    Supports: 30s, 5m, 2h, 1d, or plain integer (seconds).
    Returns None if format is invalid.
    """
    duration_str = duration_str.strip()

    # Plain integer means seconds.
    if duration_str.isdigit():
        return int(duration_str)

    match = re.match(r"^(\d+)([smhd])$", duration_str)
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


def print_error(msg: str, suggestion: str = None) -> None:
    """Print error with optional suggestion (does not exit)."""
    print(f"ERROR: {msg}", file=sys.stderr)
    if suggestion:
        print(f"  Suggestion: {suggestion}", file=sys.stderr)


def error(msg: str, suggestion: str = None) -> None:
    """Print error with optional suggestion and exit."""
    print_error(msg, suggestion)
    sys.exit(1)


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


VM_NAME = "brig"


def error_lima_not_installed() -> None:
    """Error helper for Lima not installed."""
    error(
        "Lima is not installed",
        "Install with: brew install lima"
    )


def error_vm_not_running() -> None:
    """Error helper for VM not running."""
    error(
        f"VM '{VM_NAME}' is not running",
        "Start with: brig vm start"
    )


def error_vm_not_created() -> None:
    """Error helper for VM not created."""
    error(
        f"VM '{VM_NAME}' does not exist",
        "Create with: brig vm create"
    )


def error_lima_config_not_found() -> None:
    """Error helper for Lima config not found."""
    error(
        f"Lima configuration not found at {BRIG_HOME / 'lima.yaml'}",
        "Run 'brig init' first to create the configuration"
    )


def error_unknown_command(command: str) -> None:
    """Error helper for unknown command."""
    error(
        f"Unknown command: {command}",
        "Use 'brig --help' to see available commands"
    )


def error_unknown_vm_command(command: str) -> None:
    """Error helper for unknown VM command."""
    error(
        f"Unknown vm command: {command}",
        "Use 'brig vm --help' to see available VM commands"
    )


def error_invalid_json(path: str, details: str) -> None:
    """Error helper for invalid JSON file."""
    error(
        f"Invalid JSON in {path}: {details}",
        "Check the file syntax and try again"
    )


def error_cell_already_exists(cell_name: str) -> None:
    """Error helper for cell already exists."""
    error(
        f"Cell '{cell_name}' already exists",
        f"Remove it first with: brig rm {cell_name}"
    )


def error_cell_running(cell_name: str) -> None:
    """Error helper for cell is running when it shouldn't be."""
    error(
        f"Cell '{cell_name}' is running",
        f"Stop it first with: brig stop {cell_name}"
    )


def validate_workspace_path(workspace: Path, user_path: str) -> Path:
    """Validate and resolve a path within a workspace directory.

    Prevents path traversal attacks by resolving the full path and
    verifying it stays within the workspace boundary.
    Returns the resolved absolute path, or calls error() on violation.
    """
    # Reject obvious traversal patterns before resolution.
    if ".." in user_path.split("/"):
        error(
            "Path traversal not allowed",
            "Use a relative path within the workspace (no '..' components)"
        )

    # Build and resolve the full path.
    full_path = (workspace / user_path.lstrip("/")).resolve()
    workspace_resolved = workspace.resolve()

    # Verify the resolved path is within the workspace.
    try:
        full_path.relative_to(workspace_resolved)
    except ValueError:
        error(
            "Path traversal not allowed: path escapes workspace",
            "Use a relative path within the workspace (no '..' components)"
        )

    return full_path


def validate_cell_name(name: str) -> None:
    """Validate a cell name for DNS safety and injection prevention.

    Cell names must be 1-63 characters, start with alphanumeric,
    and contain only alphanumeric, dash, or underscore.
    """
    if not name:
        error(
            "Cell name is required",
            "Provide a cell name as argument (e.g., brig stop mycell)"
        )
    if not CELL_NAME_PATTERN.match(name):
        error(
            f"Invalid cell name: {name}",
            "Cell names must start with lowercase alphanumeric, contain only [a-z0-9._-], and be max 63 characters"
        )


def container_name(cell_name: str) -> str:
    """Get container name from cell name."""
    return f"{CONTAINER_PREFIX}{cell_name}"


def network_name(cell_name: str) -> str:
    """Get network name from cell name."""
    return f"{CONTAINER_PREFIX}{cell_name}"


def proxy_running() -> bool:
    """Check if proxy is running (cached for performance)."""
    hit, value = _cached("proxy_running")
    if hit:
        return value

    result = run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={PROXY_NAME}"],
        check=False, capture=True
    )
    is_running = PROXY_NAME in result.stdout.strip().split("\n")
    _set_cache("proxy_running", is_running)
    return is_running


def get_proxy_ip(network: str) -> str:
    """Get proxy IP on a specific network."""
    # Validate network name to prevent Go template injection.
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', network):
        debug(f"Invalid network name: {network}")
        return ""
    result = run(
        ["podman", "inspect", PROXY_NAME, "--format",
         "{{range $k, $v := .NetworkSettings.Networks}}{{if eq $k \"" + network + "\"}}{{$v.IPAddress}}{{end}}{{end}}"],
        check=False, capture=True
    )
    return result.stdout.strip()


def invalidate_cell_cache(cell_name: str) -> None:
    """Invalidate cache for a specific cell after state changes."""
    _cache.pop(f"cell_exists:{cell_name}", None)
    _cache.pop(f"cell_running:{cell_name}", None)


def cell_exists(cell_name: str) -> bool:
    """Check if cell container exists (cached for performance)."""
    cache_key = f"cell_exists:{cell_name}"
    hit, value = _cached(cache_key)
    if hit:
        return value

    result = run(
        ["podman", "ps", "-a", "--format", "{{.Names}}", "--filter", f"name={container_name(cell_name)}"],
        check=False, capture=True
    )
    exists = container_name(cell_name) in result.stdout.strip().split("\n")
    _set_cache(cache_key, exists)
    return exists


def cell_running(cell_name: str) -> bool:
    """Check if cell container is running (cached for performance)."""
    cache_key = f"cell_running:{cell_name}"
    hit, value = _cached(cache_key)
    if hit:
        return value

    result = run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={container_name(cell_name)}"],
        check=False, capture=True
    )
    is_running = container_name(cell_name) in result.stdout.strip().split("\n")
    _set_cache(cache_key, is_running)
    return is_running


def get_cell_policy_path(cell_name: str) -> Path:
    """Get the policy file path for a cell."""
    return POLICY_DIR / f"{cell_name}.json"


def load_cell_policy(cell_name: str) -> dict:
    """Load a cell's policy file, or return empty policy if none exists."""
    policy_path = get_cell_policy_path(cell_name)
    if policy_path.exists():
        try:
            with open(policy_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            debug(f"Failed to load policy for {cell_name}: {e}")
    return {"allow": [], "deny": []}


def save_cell_policy(cell_name: str, policy: dict) -> bool:
    """Save a cell's policy file. Returns True on success, False on failure."""
    try:
        POLICY_DIR.mkdir(parents=True, exist_ok=True)
        policy_path = get_cell_policy_path(cell_name)
        # Atomic write.
        tmp_path = policy_path.with_suffix(".tmp")
        with open(tmp_path, "w") as f:
            json.dump(policy, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        tmp_path.rename(policy_path)
        # Verify the write succeeded by reading back.
        with open(policy_path, "r") as f:
            saved = json.load(f)
        return saved == policy
    except (IOError, OSError, json.JSONDecodeError) as e:
        debug(f"Failed to save policy: {e}")
        return False


def validate_policy_conflicts(policy: dict) -> list[str]:
    """Check for conflicts and issues in a policy. Returns list of warnings."""
    warnings = []

    allow_set = set(policy.get("allow", []))
    deny_set = set(policy.get("deny", []))

    # Check for exact duplicates between allow and deny.
    conflicts = allow_set & deny_set
    for domain in conflicts:
        warnings.append(f"'{domain}' is in both allow and deny lists (deny takes precedence)")

    # Check for wildcard conflicts (e.g., *.example.com in allow, example.com in deny).
    for allow_domain in allow_set:
        if allow_domain.startswith("*."):
            base = allow_domain[2:]
            if base in deny_set:
                warnings.append(f"'{allow_domain}' allows subdomains but '{base}' is denied")
            for deny_domain in deny_set:
                if deny_domain.startswith("*.") and deny_domain[2:] == base:
                    warnings.append(f"'{allow_domain}' and '{deny_domain}' conflict")

    # Check for overly permissive patterns.
    for domain in allow_set:
        permissive_warning = is_overly_permissive_domain(domain)
        if permissive_warning:
            warnings.append(permissive_warning)

    return warnings


def delete_cell_policy(cell_name: str) -> None:
    """Delete a cell's policy file if it exists."""
    policy_path = get_cell_policy_path(cell_name)
    if policy_path.exists():
        policy_path.unlink()


def load_cell_definition(file_path: str) -> dict:
    """Load a cell definition from a YAML or JSON file."""
    path = Path(file_path)
    if not path.exists():
        error(
            f"Cell definition file not found: {file_path}",
            "Check the path and try again"
        )

    with open(path, "r") as f:
        content = f.read()

    if path.suffix in (".yaml", ".yml"):
        if not YAML_AVAILABLE:
            # Fall back to JSON-style parsing for simple YAML.
            # This handles basic key: value format.
            try:
                result = {}
                for line in content.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip()
                        value = value.strip()
                        # Handle lists.
                        if value.startswith("[") and value.endswith("]"):
                            value = json.loads(value)
                        elif value.startswith('"') and value.endswith('"'):
                            value = value[1:-1]
                        elif value.isdigit():
                            value = int(value)
                        elif value == "true":
                            value = True
                        elif value == "false":
                            value = False
                        result[key] = value
                return result
            except Exception as e:
                error(
                    f"Failed to parse YAML (pyyaml not installed): {e}",
                    "Install with: pip install pyyaml"
                )
        else:
            try:
                return yaml.safe_load(content)
            except yaml.YAMLError as e:
                error(
                    f"Failed to parse YAML: {e}",
                    "Check the YAML syntax and try again"
                )
    else:
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            error(
                f"Failed to parse JSON: {e}",
                "Check the JSON syntax. Validate with: python -m json.tool FILE"
            )


# Overly permissive TLD patterns that effectively allow most of the internet.
# These generate warnings but are not blocked.
OVERLY_PERMISSIVE_PATTERNS = [
    "*.com",       # Millions of domains.
    "*.net",       # Many hosting providers.
    "*.org",       # Many organizations.
    "*.io",        # Popular for tech startups.
    "*.co",        # Country code TLD, widely used.
    "*.dev",       # Developer sites.
    "*.app",       # App domains.
    "*.me",        # Personal sites.
    "*.us",        # US country code.
    "*.uk",        # UK country code.
    "*.de",        # Germany.
    "*.cn",        # China.
    "*.ru",        # Russia.
    "*.xyz",       # Generic TLD.
    "*.info",      # Generic TLD.
    "*.biz",       # Business TLD.
]


def is_suspicious_domain(domain: str) -> str:
    """Check if domain pattern is suspicious for DNS rebinding. Returns reason or empty."""
    domain_lower = domain.lower()

    # Check against known suspicious patterns.
    for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
        if domain_lower == pattern:
            return f"'{domain}' is too broad and could allow DNS rebinding"

    # Wildcard on bare TLD (e.g. "*.com") — one dot means no subdomain.
    if domain_lower.startswith("*.") and domain_lower.count(".") == 1:
        return f"'{domain}' wildcard on TLD is too broad"

    # Pure wildcard.
    if domain_lower == "*":
        return "Wildcard '*' matches everything"

    return ""


def is_overly_permissive_domain(domain: str) -> str:
    """Check if domain pattern is overly permissive. Returns warning or empty.

    Unlike suspicious patterns, these are allowed but generate warnings.
    """
    domain_lower = domain.lower()

    # Check against known overly permissive patterns.
    for pattern in OVERLY_PERMISSIVE_PATTERNS:
        if domain_lower == pattern:
            tld = pattern[2:]  # Remove '*.'
            return f"'{domain}' matches all .{tld} domains - consider using more specific patterns"

    # Wildcard directly under popular TLD (e.g., *.google.com is OK, *.com is not).
    # One dot means the wildcard sits directly on the TLD.
    if domain_lower.startswith("*.") and domain_lower.count(".") == 1:
        tld = domain_lower[2:]
        # 4 chars covers common TLDs: com, net, org, io, dev, app, etc.
        if len(tld) <= 4:
            return f"'{domain}' wildcard on .{tld} TLD allows many domains"

    return ""


def validate_cell_definition(cell_def: dict, file_path: str = "") -> list[str]:
    """Validate a cell definition and return list of errors."""
    errors = []
    context = f" in {file_path}" if file_path else ""

    # Check name format.
    if "name" in cell_def:
        name = cell_def["name"]
        if not isinstance(name, str):
            errors.append(f"'name' must be a string{context}")
        elif not CELL_NAME_PATTERN.match(name):
            errors.append(f"'name' must match pattern {CELL_NAME_PATTERN.pattern}{context}")

    # Check image is present.
    if "image" in cell_def:
        if not isinstance(cell_def["image"], str) or not cell_def["image"]:
            errors.append(f"'image' must be a non-empty string{context}")

    # Check command format.
    if "command" in cell_def:
        cmd = cell_def["command"]
        if not isinstance(cmd, (str, list)):
            errors.append(f"'command' must be a string or list{context}")
        elif isinstance(cmd, list) and not all(isinstance(c, str) for c in cmd):
            errors.append(f"'command' list items must be strings{context}")

    # Check env format.
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

    # Check secrets format.
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

    # Check memory format.
    if "memory" in cell_def:
        mem = str(cell_def["memory"])
        if not re.match(MEMORY_PATTERN, mem):
            errors.append(f"Invalid 'memory' format '{mem}': use format like '512m', '2g'{context}")

    # Check cpus format.
    if "cpus" in cell_def:
        cpus = cell_def["cpus"]
        if not isinstance(cpus, (int, float, str)):
            errors.append(f"'cpus' must be a number or string{context}")
        else:
            try:
                float(cpus)
            except ValueError:
                errors.append(f"'cpus' must be a valid number{context}")

    # Check pids_limit format.
    if "pids_limit" in cell_def:
        pids = cell_def["pids_limit"]
        if not isinstance(pids, int) or pids < 1:
            errors.append(f"'pids_limit' must be a positive integer{context}")

    # Check policy format.
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
                            else:
                                # Check for DNS rebinding risk (only for allow list).
                                if key == "allow":
                                    suspicious = is_suspicious_domain(domain)
                                    if suspicious:
                                        errors.append(f"Security: {suspicious}{context}")

    # Check tor format.
    if "tor" in cell_def:
        if not isinstance(cell_def["tor"], bool):
            errors.append(f"'tor' must be a boolean{context}")

    # Check workspace_quota format.
    if "workspace_quota" in cell_def:
        if not isinstance(cell_def["workspace_quota"], str):
            errors.append(f"'workspace_quota' must be a string like '500m' or '2g'{context}")
        else:
            try:
                parse_size(cell_def["workspace_quota"])
            except ValueError:
                errors.append(f"Invalid workspace_quota value: {cell_def['workspace_quota']}{context}")

    # Check detach format.
    if "detach" in cell_def:
        if not isinstance(cell_def["detach"], bool):
            errors.append(f"'detach' must be a boolean{context}")

    return errors


# ──────────────────────────────────────────────────────────────────
# Trust Profiles
# ──────────────────────────────────────────────────────────────────

# Profile directory (macOS side).
PROFILES_DIR = BRIG_HOME / "profiles"

# Built-in profiles. Each is a partial cell definition (no name/image/command).
#
# Resource rationale:
#   untrusted  — minimal: enough for a single CLI tool or script.
#   supervised — moderate: typical web scraper or build tool.
#   dev        — generous: IDE, compiler, test suite.
#   airgapped  — same as supervised but no network egress.
#   honeypot   — minimal with deny-all: observe but block everything.
#
# PID limits prevent fork bombs. Values are powers of 2 aligned with cgroup defaults.
# Memory follows podman convention: 512m / 1g / 2g / 4g.
BUILTIN_PROFILES = {
    "untrusted": {
        "runtime": "runsc",
        "memory": "512m",       # Minimal — single process workload.
        "cpus": "1",
        "pids_limit": 256,      # Enough for one main + helpers.
        "network": "default",
        "policy": {"allow": [], "deny": []},
        "labels": {"brig.profile": "untrusted"},
    },
    "supervised": {
        "runtime": "runsc",
        "memory": "2g",         # Moderate — build tools, scrapers.
        "cpus": "2",
        "pids_limit": 512,
        "network": "default",
        "labels": {"brig.profile": "supervised"},
    },
    "dev": {
        "runtime": "runsc",
        "memory": "4g",         # Generous — IDE, compiler, tests.
        "cpus": "4",
        "pids_limit": 2048,     # Test suites spawn many processes.
        "network": "default",
        "labels": {"brig.profile": "dev"},
    },
    "airgapped": {
        "runtime": "runsc",
        "memory": "2g",
        "cpus": "2",
        "pids_limit": 512,
        "network": "none",      # No egress at all.
        "labels": {"brig.profile": "airgapped"},
    },
    "honeypot": {
        "runtime": "runsc",
        "memory": "1g",
        "cpus": "1",
        "pids_limit": 256,
        "network": "default",
        "policy": {"allow": [], "deny": ["*"]},  # Observe but block all.
        "labels": {"brig.profile": "honeypot"},
    },
}


def load_profile(name: str) -> dict:
    """Load a trust profile by name.

    Checks user profiles directory first, then built-in profiles.
    Returns the profile dict or calls error() if not found.
    """
    # Check user-defined profiles.
    for ext in (".yaml", ".yml", ".json"):
        user_profile = PROFILES_DIR / f"{name}{ext}"
        if user_profile.exists():
            debug(f"Loading user profile: {user_profile}")
            return load_cell_definition(str(user_profile))

    # Check built-in profiles.
    if name in BUILTIN_PROFILES:
        debug(f"Loading built-in profile: {name}")
        return BUILTIN_PROFILES[name].copy()

    available = list(BUILTIN_PROFILES.keys())
    # Also list user profiles.
    if PROFILES_DIR.exists():
        for f in PROFILES_DIR.iterdir():
            if f.suffix in (".yaml", ".yml", ".json"):
                available.append(f.stem)
    error(
        f"Unknown profile: {name}",
        f"Available profiles: {', '.join(sorted(set(available)))}"
    )


def _apply_profile(args) -> None:
    """Apply a trust profile to args, setting defaults for unset fields.

    Merge order: profile defaults → cell definition file → CLI flags.
    Profile sets defaults; explicit CLI flags always win.
    Uses None sentinel to detect which flags the user explicitly provided.
    """
    profile = load_profile(args.profile)

    # Apply profile defaults only for fields not explicitly set by the user.
    # Fields default to None in argparse; non-None means user provided a value.
    if "memory" in profile and args.memory is None:
        args.memory = profile["memory"]
    if "cpus" in profile and args.cpus is None:
        args.cpus = str(profile["cpus"])
    if "pids_limit" in profile and args.pids_limit is None:
        args.pids_limit = profile["pids_limit"]
    if "network" in profile and getattr(args, "network", None) is None:
        args.network = profile["network"]
    if "policy" in profile:
        pol = profile["policy"]
        if "allow" in pol and not args.policy_allow:
            args.policy_allow = pol["allow"]
        if "deny" in pol and not args.policy_deny:
            args.policy_deny = pol["deny"]
    if "labels" in profile:
        profile_labels = [f"{k}={v}" for k, v in profile["labels"].items()]
        args.label = profile_labels + (args.label or [])

    # Apply hardcoded defaults for still-None fields.
    # These match the "supervised" profile — a reasonable middle ground.
    if args.memory is None:
        args.memory = "2g"
    if args.cpus is None:
        args.cpus = "2"
    if args.pids_limit is None:
        args.pids_limit = 512
    if getattr(args, "network", None) is None:
        args.network = "default"


# Default network policy for new installations.
DEFAULT_NETWORK_POLICY = {
    "allow": [
        "pypi.org",
        "*.pythonhosted.org",
        "files.pythonhosted.org",
        "github.com",
        "api.github.com",
        "*.githubusercontent.com",
        "registry.npmjs.org",
    ],
    "deny": [],
    "rate_limits": {
        "default": {
            "rate": 100,   # Requests per second — prevents runaway loops.
            "burst": 500   # Burst capacity — allows short spikes (5x rate).
        }
    },
    "log_filter": {
        "exclude_hosts": [],
        "exclude_paths": ["/health", "/ping"],
        "sample_rate": 1.0  # 1.0 = log 100% of requests (no sampling).
    },
    "policy_trace": {
        "enabled": True,
        "include_rule_details": True,
        "include_timing": False
    }
}


# Default Lima VM configuration.
DEFAULT_LIMA_YAML = """# Brig Lima VM Configuration
# See: https://lima-vm.io/docs/reference/

# VM name
# lima create --name=brig ~/.brig/lima.yaml

# Base image - Ubuntu 22.04 LTS
images:
  - location: "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img"
    arch: "x86_64"
  - location: "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-arm64.img"
    arch: "aarch64"

# CPU and memory — sized for running multiple cells concurrently.
# 4 CPUs: enough for 2-3 active cells with overhead for Warden + system.
# 8 GiB RAM: headroom for podman, gVisor, and cell working sets.
# 50 GiB disk: container images (5-10 GiB typical) + logs + workspaces.
cpus: 4
memory: "8GiB"
disk: "50GiB"

# Mount brig directories into the VM
mounts:
  - location: "~/.brig/cells"
    mountPoint: "/cells"
    writable: false
  - location: "~/.brig/secrets"
    mountPoint: "/secrets"
    writable: false
  - location: "~/.brig/state"
    mountPoint: "/state"
    writable: true

# Provision script - installs Podman, gVisor, creates directories
provision:
  - mode: system
    script: |
      #!/bin/bash
      set -eux

      # Install Podman
      apt-get update
      apt-get install -y podman uidmap slirp4netns fuse-overlayfs

      # Install gVisor (runsc)
      ARCH=$(uname -m)
      if [ "$ARCH" = "x86_64" ]; then
        GVISOR_ARCH="amd64"
      else
        GVISOR_ARCH="arm64"
      fi
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/${GVISOR_ARCH}/runsc -o /usr/local/bin/runsc
      chmod +x /usr/local/bin/runsc

      # Configure Podman to use gVisor
      mkdir -p /etc/containers
      cat > /etc/containers/containers.conf << 'EOF'
      [engine]
      runtime = "runsc"

      [engine.runtimes]
      runsc = ["/usr/local/bin/runsc"]
      crun = ["/usr/bin/crun"]
      EOF

      # Create required directories
      mkdir -p /var/log/brig/network
      mkdir -p /var/run/brig/policies
      mkdir -p /state/system

      # Create proxy-external network
      podman network create --internal=false proxy-external || true

      # Install logrotate config for brig network logs.
      cat > /etc/logrotate.d/brig << 'LOGROTATE'
      /var/log/brig/network/*.jsonl {
          daily
          rotate 7    # Keep 7 days of rotated logs (~1 week of history).
          compress
          delaycompress
          missingok
          notifempty
          create 0644 root root
          dateext
          dateformat -%Y%m%d
          sharedscripts
          postrotate
              podman kill -s HUP warden 2>/dev/null || true
          endscript
      }
      LOGROTATE

      # Install systemd service for Warden watchdog auto-start.
      cat > /etc/systemd/system/warden-watchdog.service << 'SYSTEMD'
      [Unit]
      Description=Brig Warden Proxy Watchdog
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=simple
      # Check every 30s — fast enough to detect crashes, light on resources.
      # Give up after 5 consecutive failures to avoid restart loops.
      ExecStart=/usr/bin/warden watchdog --interval 30 --max-restarts 5
      Restart=on-failure
      RestartSec=10   # Wait 10s before systemd restarts the watchdog itself.

      [Install]
      WantedBy=multi-user.target
      SYSTEMD

      systemctl daemon-reload
      systemctl enable warden-watchdog.service

      echo "Brig VM provisioning complete"

# Networking
networks:
  - lima: shared

# Port forwarding (optional - for debugging)
# portForwards:
#   - guestPort: 8080
#     hostPort: 8080

# Message shown after VM starts
message: |
  Brig VM is ready.

  Warden watchdog is enabled and will auto-start the proxy on boot.
  To check status: limactl shell brig warden status

  To run a cell:
    brig run --name test --image alpine -- echo "Hello from cell"
"""


# Current schema version. Bump when state file formats change.
SCHEMA_VERSION = "1.0.0"

# Version file lives on macOS side so it survives VM recreation.
VERSION_FILE = BRIG_HOME / "state" / "version"


# ---------------------------------------------------------------------------
# Workspace quota helpers
# ---------------------------------------------------------------------------

_SIZE_UNITS = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_size(size_str: str) -> int:
    """Parse a human-readable size string to bytes.

    Accepts: '500m', '2g', '512k', '1t', or plain bytes like '1048576'.
    """
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


def format_size(size_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f}{unit}" if size_bytes != int(size_bytes) else f"{int(size_bytes)}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}PB"


def get_workspace_size(cell_name: str) -> int:
    """Get workspace directory size in bytes."""
    workspace = STATE_DIR / cell_name / "workspace"
    if not workspace.exists():
        return 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(workspace):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total += os.path.getsize(fp)
            except OSError:
                pass
    return total


def _quota_file(cell_name: str) -> Path:
    """Path to a cell's quota metadata file."""
    return STATE_DIR / cell_name / "quota.json"


def save_workspace_quota(cell_name: str, max_bytes: int) -> None:
    """Save workspace quota for a cell."""
    qf = _quota_file(cell_name)
    qf.parent.mkdir(parents=True, exist_ok=True)
    tmp = qf.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump({"max_bytes": max_bytes}, f)
    tmp.rename(qf)


def get_workspace_quota(cell_name: str) -> int | None:
    """Get workspace quota for a cell. Returns max_bytes or None if unset."""
    qf = _quota_file(cell_name)
    if not qf.exists():
        return None
    try:
        with open(qf) as f:
            return json.load(f).get("max_bytes")
    except (json.JSONDecodeError, IOError):
        return None


def check_workspace_quota(cell_name: str) -> tuple[bool, int, int | None]:
    """Check workspace against quota.

    Returns (within_quota, current_bytes, max_bytes).
    max_bytes is None if no quota is set.
    """
    current = get_workspace_size(cell_name)
    max_bytes = get_workspace_quota(cell_name)
    if max_bytes is None:
        return True, current, None
    return current <= max_bytes, current, max_bytes
