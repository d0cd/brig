#!/usr/bin/env python3
"""
Brig - Secure workload harness for running untrusted code.

Each cell runs in an isolated network with gVisor sandboxing.
All egress traffic goes through the Warden policy-enforcing proxy.

Usage:
    brig [--debug] <command> [options]

Commands:
    brig run [options] <image> [command...]   Run a new cell
    brig stop <name>                          Gracefully stop a cell
    brig kill <name>                          Immediately kill a cell
    brig rm [-f] <name>                       Remove a cell
    brig start <name>                         Start a stopped cell
    brig pause <name>                         Pause a running cell
    brig unpause <name>                       Unpause a paused cell
    brig list [--format=table|json]           List all cells
    brig logs [-f] [--tail N] <name>          View cell logs
    brig exec <name> [command...]             Execute command in cell
    brig attach <name>                        Attach to cell console
    brig inspect <name>                       Show cell details
    brig export <name>                        Export cell as YAML
    brig stats [name]                         Show resource usage
    brig top <name>                           Show processes in cell
    brig diff <name>                          Show filesystem changes
    brig files <name> [path]                  List workspace contents
    brig cat <name> <path>                    View file in workspace
    brig cp <src> <dst>                       Copy files to/from workspace
    brig network <name>                       View network activity
    brig diagnose <name>                      Run diagnostic checks
    brig health [--format=table|json]         Check system health
    brig metrics                              Output Prometheus metrics
    brig verify                               Verify security invariants
    brig history [--tail N] [--cell <name>]   Show operation history
    brig policy show <name>                   Show cell's policy
    brig policy set <name> [--allow/--deny]   Update cell's policy

Security:
    - Cells run with gVisor (runsc) for syscall isolation.
    - Each cell gets an isolated internal network.
    - Warden proxy enforces domain allowlist on egress.
    - Secrets mounted as files, never in env vars.
"""

import argparse
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Container naming prefix for cells.
CONTAINER_PREFIX = "brig-"

# Default runtime (gVisor).
RUNTIME = "runsc"

# Warden proxy container name.
PROXY_NAME = "warden"

# State directory (inside VM).
STATE_DIR = Path("/state")

# Per-cell policy directory (inside VM).
POLICY_DIR = Path("/var/run/brig/policies")

# Brig home directory (macOS side, for init command).
BRIG_HOME = Path.home() / ".brig"

# History log file.
HISTORY_FILE = STATE_DIR / "system" / "history.jsonl"

# Operations log file (comprehensive command logging).
OPERATIONS_FILE = STATE_DIR / "system" / "operations.jsonl"

# Brig config file.
CONFIG_FILE = Path("/cells/config.json")

# Rate limiting configuration.
RATE_LIMIT_FILE = STATE_DIR / "system" / "rate_limit.json"
RATE_LIMIT_MAX = 10  # Max cells created per window.
RATE_LIMIT_WINDOW = 60  # Window in seconds.

# Mutation commands (for operation logging level filtering).
MUTATION_COMMANDS = {"run", "stop", "kill", "rm", "start", "pause", "unpause", "cp", "policy"}

# Sensitive argument patterns for redaction.
SENSITIVE_PATTERNS = {"password", "secret", "key", "token", "credential", "auth"}

# Cache TTL in seconds.
CACHE_TTL = 2.0

# Debug mode (set via --debug flag).
DEBUG = False

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
            time.sleep(0.1)

    def __enter__(self):
        if sys.stderr.isatty() and not DEBUG:
            self.running = True
            self.thread = threading.Thread(target=self._spin, daemon=True)
            self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty() and not DEBUG:
            # Clear the spinner line.
            sys.stderr.write("\r" + " " * (len(self.message) + 3) + "\r")
            sys.stderr.flush()
        return False

    def success(self, message: str = None):
        """Show success message and stop spinner."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty():
            msg = message or self.message
            sys.stderr.write(f"\r{colorize('✓', 'green')} {msg}\n")
            sys.stderr.flush()

    def fail(self, message: str = None):
        """Show failure message and stop spinner."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty():
            msg = message or self.message
            sys.stderr.write(f"\r{colorize('✗', 'red')} {msg}\n")
            sys.stderr.flush()


# Simple TTL cache for expensive operations.
_cache: dict[str, tuple[float, any]] = {}


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


def log_operation(operation: str, cell_name: str = None, details: dict = None) -> None:
    """Log an operation to the history file."""
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operation": operation,
        }
        if cell_name:
            entry["cell"] = cell_name
        if details:
            entry["details"] = details
        with open(HISTORY_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except (IOError, OSError) as e:
        debug(f"Failed to log operation: {e}")


# Lifecycle log file.
LIFECYCLE_FILE = STATE_DIR / "system" / "lifecycle.jsonl"


def log_lifecycle(event: str, cell_name: str, details: dict = None) -> None:
    """Log a cell lifecycle event.

    Events: start, stop, kill, rm
    Details can include: image, command, exit_code, runtime_seconds, purged_workspace
    """
    try:
        LIFECYCLE_FILE.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "cell": cell_name,
        }
        if details:
            entry.update(details)
        with open(LIFECYCLE_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except (IOError, OSError) as e:
        debug(f"Failed to log lifecycle event: {e}")


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

    except (json.JSONDecodeError, IOError, OSError):
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
        OPERATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)

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

        # Add error if present.
        if error:
            entry["error"] = error

        with open(OPERATIONS_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

    except (IOError, OSError) as e:
        debug(f"Failed to log operation: {e}")


def check_rate_limit() -> bool:
    """Check if cell creation is rate limited. Returns True if allowed."""
    try:
        RATE_LIMIT_FILE.parent.mkdir(parents=True, exist_ok=True)

        now = time.time()
        timestamps = []

        # Load existing timestamps.
        if RATE_LIMIT_FILE.exists():
            try:
                with open(RATE_LIMIT_FILE, "r") as f:
                    data = json.load(f)
                    timestamps = data.get("timestamps", [])
            except (json.JSONDecodeError, IOError):
                timestamps = []

        # Filter to only timestamps within the window.
        cutoff = now - RATE_LIMIT_WINDOW
        timestamps = [ts for ts in timestamps if ts > cutoff]

        # Check if limit exceeded.
        if len(timestamps) >= RATE_LIMIT_MAX:
            return False

        # Add current timestamp and save.
        timestamps.append(now)
        with open(RATE_LIMIT_FILE, "w") as f:
            json.dump({"timestamps": timestamps}, f)

        return True
    except (IOError, OSError) as e:
        debug(f"Rate limit check failed: {e}")
        return True  # Allow on error to avoid blocking.


def verify_image_signature(image: str) -> tuple[bool, str]:
    """Verify image signature using cosign or podman trust.

    Returns (success, message) tuple.
    """
    # Try cosign first (preferred for sigstore signatures).
    result = run(
        ["which", "cosign"],
        check=False, capture=True
    )
    if result.returncode == 0:
        debug(f"Verifying image with cosign: {image}")
        result = run(
            ["cosign", "verify", "--output", "text", image],
            check=False, capture=True
        )
        if result.returncode == 0:
            return True, "Signature verified with cosign"
        else:
            # Check if it's unsigned vs invalid signature.
            if "no matching signatures" in result.stderr.lower():
                return False, "Image has no signature"
            return False, f"Signature verification failed: {result.stderr.strip()}"

    # Fall back to podman image trust.
    debug(f"Verifying image with podman trust: {image}")
    result = run(
        ["podman", "image", "trust", "show"],
        check=False, capture=True
    )
    if result.returncode == 0:
        # Check if image registry is in trusted list.
        # This is a simplified check - real implementation would parse output.
        if "accept" in result.stdout.lower():
            return True, "Image from trusted registry"

    return False, "No signature verification tool available (install cosign for full support)"


def _cached(key: str, ttl: float = CACHE_TTL) -> tuple[bool, any]:
    """Check if a cached value is still valid."""
    if key in _cache:
        ts, value = _cache[key]
        if time.time() - ts < ttl:
            return True, value
    return False, None


def _set_cache(key: str, value: any) -> None:
    """Store a value in the cache."""
    _cache[key] = (time.time(), value)


def run(cmd: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a command."""
    debug(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=check, capture_output=capture, text=True)
    if capture and result.returncode != 0:
        debug(f"Command failed with code {result.returncode}")
    return result


def error(msg: str, suggestion: str = None) -> None:
    """Print error with optional suggestion and exit."""
    print(f"ERROR: {msg}", file=sys.stderr)
    if suggestion:
        print(f"  Suggestion: {suggestion}", file=sys.stderr)
    sys.exit(1)


def error_cell_not_found(cell_name: str) -> None:
    """Error helper for cell not found."""
    error(
        f"Cell '{cell_name}' does not exist",
        f"Use 'brig list' to see available cells, or 'brig run' to create one"
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
    is_running = PROXY_NAME in result.stdout
    _set_cache("proxy_running", is_running)
    return is_running


def get_proxy_ip(network: str) -> str:
    """Get proxy IP on a specific network."""
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
    exists = container_name(cell_name) in result.stdout
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
    is_running = container_name(cell_name) in result.stdout
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
        except (json.JSONDecodeError, IOError):
            pass
    return {"allow": [], "deny": []}


def save_cell_policy(cell_name: str, policy: dict) -> None:
    """Save a cell's policy file."""
    POLICY_DIR.mkdir(parents=True, exist_ok=True)
    policy_path = get_cell_policy_path(cell_name)
    # Atomic write.
    tmp_path = policy_path.with_suffix(".tmp")
    with open(tmp_path, "w") as f:
        json.dump(policy, f, indent=2)
    tmp_path.rename(policy_path)


def delete_cell_policy(cell_name: str) -> None:
    """Delete a cell's policy file if it exists."""
    policy_path = get_cell_policy_path(cell_name)
    if policy_path.exists():
        policy_path.unlink()


def load_cell_definition(file_path: str) -> dict:
    """Load a cell definition from a YAML or JSON file."""
    path = Path(file_path)
    if not path.exists():
        error(f"Cell definition file not found: {file_path}")

    with open(path, "r") as f:
        content = f.read()

    if path.suffix in (".yaml", ".yml"):
        if not YAML_AVAILABLE:
            # Fall back to JSON-style parsing for simple YAML.
            # This handles basic key: value format.
            try:
                import re
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
                error(f"Failed to parse YAML (pyyaml not installed): {e}")
        else:
            try:
                return yaml.safe_load(content)
            except yaml.YAMLError as e:
                error(f"Failed to parse YAML: {e}")
    else:
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            error(f"Failed to parse JSON: {e}")


# Valid memory suffixes.
MEMORY_PATTERN = r"^\d+[kmgKMG]?[bB]?$"

# Valid domain pattern for policy.
DOMAIN_PATTERN = r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"

# Suspicious domain patterns that could enable DNS rebinding attacks.
# These patterns allow too-broad access that could resolve to internal IPs.
SUSPICIOUS_DOMAIN_PATTERNS = [
    "*",           # Matches everything.
    "*.*",         # Matches all domains.
    "*.local",     # Local network.
    "*.internal",  # Internal domains.
    "*.localhost", # Localhost variants.
    "*.home",      # Home networks.
    "*.lan",       # LAN domains.
    "*.corp",      # Corporate internal.
    "*.private",   # Private domains.
]


def is_suspicious_domain(domain: str) -> str:
    """Check if domain pattern is suspicious for DNS rebinding. Returns reason or empty."""
    domain_lower = domain.lower()

    # Check against known suspicious patterns.
    for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
        if domain_lower == pattern:
            return f"'{domain}' is too broad and could allow DNS rebinding"

    # Wildcard on TLD is suspicious.
    if domain_lower.startswith("*.") and domain_lower.count(".") == 1:
        return f"'{domain}' wildcard on TLD is too broad"

    # Pure wildcard.
    if domain_lower == "*":
        return "Wildcard '*' matches everything"

    return ""


def validate_cell_definition(cell_def: dict, file_path: str = "") -> list[str]:
    """Validate a cell definition and return list of errors."""
    import re
    errors = []
    context = f" in {file_path}" if file_path else ""

    # Check name format.
    if "name" in cell_def:
        name = cell_def["name"]
        if not isinstance(name, str):
            errors.append(f"'name' must be a string{context}")
        elif not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$", name):
            errors.append(f"'name' must start with alphanumeric and contain only alphanumeric, dash, underscore{context}")
        elif len(name) > 63:
            errors.append(f"'name' must be 63 characters or less{context}")

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

    # Check detach format.
    if "detach" in cell_def:
        if not isinstance(cell_def["detach"], bool):
            errors.append(f"'detach' must be a boolean{context}")

    return errors


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
            "rate": 100,
            "burst": 500
        }
    },
    "log_filter": {
        "exclude_hosts": [],
        "exclude_paths": ["/health", "/ping"],
        "sample_rate": 1.0
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

# CPU and memory
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

  To start the warden proxy:
    limactl shell brig warden start

  To run a cell:
    brig run --name test --image alpine -- echo "Hello from cell"
"""


def cmd_init(args) -> int:
    """Initialize the brig directory structure."""
    import platform

    # Check we're on macOS.
    if platform.system() != "Darwin":
        print("WARNING: Brig is designed for macOS. Some features may not work.", file=sys.stderr)

    force = getattr(args, "force", False)
    quiet = getattr(args, "quiet", False)

    def log_msg(msg: str) -> None:
        if not quiet:
            print(msg)

    # Check if already initialized.
    if BRIG_HOME.exists() and not force:
        if (BRIG_HOME / "lima.yaml").exists():
            print(f"Brig is already initialized at {BRIG_HOME}")
            print("Use --force to reinitialize (preserves existing files)")
            return 0

    log_msg(f"Initializing brig at {BRIG_HOME}...")

    # Create directory structure.
    directories = [
        BRIG_HOME,
        BRIG_HOME / "cells",
        BRIG_HOME / "secrets",
        BRIG_HOME / "state",
        BRIG_HOME / "state" / "system",
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
        log_msg(f"  Created {directory}")

    # Set restrictive permissions on secrets directory.
    secrets_dir = BRIG_HOME / "secrets"
    secrets_dir.chmod(0o700)
    log_msg(f"  Set permissions 700 on {secrets_dir}")

    # Create default network policy if not exists.
    policy_file = BRIG_HOME / "cells" / "network-policy.json"
    if not policy_file.exists() or force:
        with open(policy_file, "w") as f:
            json.dump(DEFAULT_NETWORK_POLICY, f, indent=2)
        log_msg(f"  Created {policy_file}")
    else:
        log_msg(f"  Skipped {policy_file} (already exists)")

    # Create Lima config if not exists.
    lima_file = BRIG_HOME / "lima.yaml"
    if not lima_file.exists() or force:
        with open(lima_file, "w") as f:
            f.write(DEFAULT_LIMA_YAML)
        log_msg(f"  Created {lima_file}")
    else:
        log_msg(f"  Skipped {lima_file} (already exists)")

    # Create example cell definition.
    example_cell = BRIG_HOME / "cells" / "example.yaml"
    if not example_cell.exists():
        example_content = """# Example cell definition
# Run with: brig run -f ~/.brig/cells/example.yaml

name: example
image: python:3.11-slim

# Environment variables (non-sensitive)
env:
  PYTHONUNBUFFERED: "1"

# Secrets to mount (create files in ~/.brig/secrets/)
# secrets:
#   - my-api-key

# Resource limits
memory: 2g
cpus: 2
pids_limit: 512

# Run in background
detach: true

# Command to run
command: ["python", "-c", "print('Hello from brig cell!')"]
"""
        with open(example_cell, "w") as f:
            f.write(example_content)
        log_msg(f"  Created {example_cell}")

    # Create brig config file.
    config_file = BRIG_HOME / "cells" / "config.json"
    if not config_file.exists():
        default_config = {
            "operation_logging": {
                "enabled": True,
                "level": "all",
                "redact_secrets": True,
                "redact_env_values": True
            }
        }
        with open(config_file, "w") as f:
            json.dump(default_config, f, indent=2)
        log_msg(f"  Created {config_file}")

    log_msg("")
    log_msg("Brig initialized successfully!")
    log_msg("")
    log_msg("Next steps:")
    log_msg("  1. Install Lima if not already installed:")
    log_msg("       brew install lima")
    log_msg("")
    log_msg("  2. Create the brig VM:")
    log_msg(f"       limactl create --name=brig {lima_file}")
    log_msg("")
    log_msg("  3. Start the VM:")
    log_msg("       limactl start brig")
    log_msg("")
    log_msg("  4. Start the warden proxy:")
    log_msg("       limactl shell brig -- warden start")
    log_msg("")
    log_msg("  5. Run your first cell:")
    log_msg("       brig run --name test --image alpine -- echo 'Hello!'")
    log_msg("")
    log_msg(f"Edit {policy_file} to configure allowed domains.")

    return 0


# -----------------------------------------------------------------------------
# VM Management Commands
# -----------------------------------------------------------------------------

VM_NAME = "brig"


def _lima_installed() -> bool:
    """Check if lima is installed."""
    result = subprocess.run(["which", "limactl"], capture_output=True)
    return result.returncode == 0


def _vm_status() -> dict:
    """Get VM status. Returns dict with 'status' and 'ssh' keys."""
    if not _lima_installed():
        return {"status": "lima_not_installed", "ssh": None}

    result = subprocess.run(
        ["limactl", "list", "--format", "json"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        return {"status": "error", "ssh": None}

    try:
        # Lima outputs JSON Lines (one JSON object per line).
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            vm = json.loads(line)
            if vm.get("name") == VM_NAME:
                return {
                    "status": vm.get("status", "unknown"),
                    "ssh": vm.get("sshLocalPort"),
                    "cpus": vm.get("cpus"),
                    "memory": vm.get("memory"),
                    "disk": vm.get("disk"),
                }
        return {"status": "not_created", "ssh": None}
    except json.JSONDecodeError:
        return {"status": "error", "ssh": None}


def cmd_vm_create(args) -> int:
    """Create the brig VM."""
    if not _lima_installed():
        print("ERROR: Lima is not installed.", file=sys.stderr)
        print("Install with: brew install lima", file=sys.stderr)
        return 1

    status = _vm_status()
    if status["status"] not in ("not_created", "lima_not_installed"):
        print(f"VM '{VM_NAME}' already exists (status: {status['status']})")
        print("Use 'brig vm delete' to remove it first, or 'brig vm start' to start it.")
        return 0

    lima_yaml = BRIG_HOME / "lima.yaml"
    if not lima_yaml.exists():
        print(f"ERROR: Lima configuration not found at {lima_yaml}", file=sys.stderr)
        print("Run 'brig init' first to create the configuration.", file=sys.stderr)
        return 1

    print(f"Creating VM '{VM_NAME}' from {lima_yaml}...")
    cmd = ["limactl", "create", "--name", VM_NAME, str(lima_yaml)]

    if getattr(args, "tty", True) and sys.stdin.isatty():
        # Interactive mode - let user see progress.
        result = subprocess.run(cmd)
    else:
        # Non-interactive.
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)

    if result.returncode == 0:
        print(f"VM '{VM_NAME}' created successfully.")
        print("Start it with: brig vm start")
    return result.returncode


def cmd_vm_start(args) -> int:
    """Start the brig VM."""
    if not _lima_installed():
        print("ERROR: Lima is not installed.", file=sys.stderr)
        print("Install with: brew install lima", file=sys.stderr)
        return 1

    status = _vm_status()
    if status["status"] == "not_created":
        print(f"VM '{VM_NAME}' does not exist.", file=sys.stderr)
        print("Create it with: brig vm create", file=sys.stderr)
        return 1

    if status["status"] == "Running":
        print(f"VM '{VM_NAME}' is already running.")
        return 0

    print(f"Starting VM '{VM_NAME}'...")
    cmd = ["limactl", "start", VM_NAME]

    if getattr(args, "tty", True) and sys.stdin.isatty():
        result = subprocess.run(cmd)
    else:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)

    if result.returncode == 0:
        print(f"VM '{VM_NAME}' started successfully.")
        print("Start warden with: brig vm shell -- warden start")
    return result.returncode


def cmd_vm_stop(args) -> int:
    """Stop the brig VM."""
    if not _lima_installed():
        print("ERROR: Lima is not installed.", file=sys.stderr)
        return 1

    status = _vm_status()
    if status["status"] == "not_created":
        print(f"VM '{VM_NAME}' does not exist.", file=sys.stderr)
        return 1

    if status["status"] != "Running":
        print(f"VM '{VM_NAME}' is not running (status: {status['status']})")
        return 0

    force = getattr(args, "force", False)
    print(f"Stopping VM '{VM_NAME}'...")

    cmd = ["limactl", "stop", VM_NAME]
    if force:
        cmd.append("--force")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"VM '{VM_NAME}' stopped.")
    else:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def cmd_vm_status(args) -> int:
    """Show VM status."""
    if not _lima_installed():
        print("Lima is not installed.")
        print("Install with: brew install lima")
        return 1

    status = _vm_status()

    if getattr(args, "json", False):
        print(json.dumps(status, indent=2))
        return 0

    if status["status"] == "not_created":
        print(f"VM '{VM_NAME}' is not created.")
        print("Create it with: brig vm create")
        return 0

    # Colorize status.
    status_str = status["status"]
    if status_str == "Running":
        status_str = colorize(status_str, "green")
    elif status_str == "Stopped":
        status_str = colorize(status_str, "yellow")
    else:
        status_str = colorize(status_str, "red")

    print(f"VM:     {VM_NAME}")
    print(f"Status: {status_str}")
    if status.get("cpus"):
        print(f"CPUs:   {status['cpus']}")
    if status.get("memory"):
        mem_gb = status["memory"] / (1024 ** 3)
        print(f"Memory: {mem_gb:.1f} GB")
    if status.get("disk"):
        disk_gb = status["disk"] / (1024 ** 3)
        print(f"Disk:   {disk_gb:.1f} GB")
    if status.get("ssh"):
        print(f"SSH:    localhost:{status['ssh']}")

    return 0


def cmd_vm_shell(args) -> int:
    """Open a shell in the VM or run a command."""
    if not _lima_installed():
        print("ERROR: Lima is not installed.", file=sys.stderr)
        return 1

    status = _vm_status()
    if status["status"] != "Running":
        print(f"ERROR: VM '{VM_NAME}' is not running (status: {status['status']})", file=sys.stderr)
        print("Start it with: brig vm start", file=sys.stderr)
        return 1

    cmd = ["limactl", "shell", VM_NAME]

    # If command provided, run it.
    shell_cmd = getattr(args, "shell_cmd", None)
    if shell_cmd:
        cmd.append("--")
        cmd.extend(shell_cmd)

    # Run interactively.
    result = subprocess.run(cmd)
    return result.returncode


def cmd_vm_delete(args) -> int:
    """Delete the brig VM."""
    if not _lima_installed():
        print("ERROR: Lima is not installed.", file=sys.stderr)
        return 1

    status = _vm_status()
    if status["status"] == "not_created":
        print(f"VM '{VM_NAME}' does not exist.")
        return 0

    force = getattr(args, "force", False)

    # Require confirmation unless force.
    if not force:
        print(f"WARNING: This will delete VM '{VM_NAME}' and all data inside it.")
        try:
            response = input("Are you sure? [y/N] ")
            if response.lower() not in ("y", "yes"):
                print("Aborted.")
                return 1
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return 1

    # Stop if running.
    if status["status"] == "Running":
        print("Stopping VM...")
        subprocess.run(["limactl", "stop", VM_NAME], capture_output=True)

    print(f"Deleting VM '{VM_NAME}'...")
    result = subprocess.run(["limactl", "delete", VM_NAME], capture_output=True, text=True)

    if result.returncode == 0:
        print(f"VM '{VM_NAME}' deleted.")
    else:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def cmd_vm(args) -> int:
    """VM management dispatcher."""
    vm_commands = {
        "create": cmd_vm_create,
        "start": cmd_vm_start,
        "stop": cmd_vm_stop,
        "status": cmd_vm_status,
        "shell": cmd_vm_shell,
        "delete": cmd_vm_delete,
    }

    vm_cmd = getattr(args, "vm_command", None)
    if not vm_cmd or vm_cmd not in vm_commands:
        print("ERROR: Unknown vm command", file=sys.stderr)
        return 1

    return vm_commands[vm_cmd](args)


def cmd_run(args) -> int:
    """Run a new cell."""
    # Load cell definition from file if provided.
    if args.file:
        cell_def = load_cell_definition(args.file)
        # Validate cell definition.
        validation_errors = validate_cell_definition(cell_def, args.file)
        if validation_errors:
            print(f"ERROR: Invalid cell definition '{args.file}':", file=sys.stderr)
            for err in validation_errors:
                print(f"  - {err}", file=sys.stderr)
            return 1
        # Override args with cell definition values.
        if "name" in cell_def and not args.name:
            args.name = cell_def["name"]
        if "image" in cell_def and not args.image:
            args.image = cell_def["image"]
        if "command" in cell_def and not args.container_cmd:
            cmd_val = cell_def["command"]
            args.container_cmd = cmd_val if isinstance(cmd_val, list) else [cmd_val]
        if "env" in cell_def:
            env_list = cell_def["env"]
            if isinstance(env_list, dict):
                env_list = [f"{k}={v}" for k, v in env_list.items()]
            args.env = (args.env or []) + env_list
        if "secrets" in cell_def:
            args.secret = (args.secret or []) + cell_def["secrets"]
        if "memory" in cell_def:
            args.memory = cell_def["memory"]
        if "cpus" in cell_def:
            args.cpus = str(cell_def["cpus"])
        if "pids_limit" in cell_def:
            args.pids_limit = cell_def["pids_limit"]
        if "policy" in cell_def:
            policy = cell_def["policy"]
            if "allow" in policy:
                args.policy_allow = (args.policy_allow or []) + policy["allow"]
            if "deny" in policy:
                args.policy_deny = (args.policy_deny or []) + policy["deny"]
        if "detach" in cell_def:
            args.detach = cell_def["detach"]

    cell_name = args.name
    if not cell_name:
        error("Cell name is required (use --name or specify in definition file)")
    if not args.image:
        error("Image is required (provide as argument or in definition file)")

    # Optional image signature verification.
    if getattr(args, "verify_image", False):
        with Spinner(f"Verifying image signature for {args.image}") as spinner:
            verified, message = verify_image_signature(args.image)
            if verified:
                spinner.success(message)
            else:
                spinner.fail(message)
                error(
                    f"Image signature verification failed for {args.image}",
                    "Use a signed image or remove --verify-image to skip verification"
                )

    # Fail-fast: Check proxy is running.
    if not proxy_running():
        error("Proxy is not running. Start it with: warden start")

    # Rate limit check.
    if not check_rate_limit():
        error(
            f"Rate limit exceeded ({RATE_LIMIT_MAX} cells per {RATE_LIMIT_WINDOW}s)",
            "Wait a moment before creating more cells"
        )

    # Check cell doesn't already exist.
    if cell_exists(cell_name):
        error(f"Cell '{cell_name}' already exists. Remove it first with: brig rm {cell_name}")

    # Create per-cell policy if custom policy specified.
    if args.policy_allow or args.policy_deny:
        policy = {
            "allow": args.policy_allow or [],
            "deny": args.policy_deny or [],
        }
        save_cell_policy(cell_name, policy)

    # Allocate subnet.
    print(f"Allocating network for {cell_name}...")
    result = run(["brig-subnet", "allocate", cell_name], check=False, capture=True)
    if result.returncode != 0:
        error(f"Failed to allocate subnet: {result.stderr}")
    subnet = result.stdout.strip()

    # Create internal network.
    result = run(["brig-subnet", "create-network", cell_name], check=False, capture=True)
    if result.returncode != 0:
        # Clean up subnet allocation.
        run(["brig-subnet", "free", cell_name], check=False)
        error(f"Failed to create network: {result.stderr}")

    net_name = network_name(cell_name)

    # Connect proxy to cell network.
    result = run(["podman", "network", "connect", net_name, PROXY_NAME], check=False, capture=True)
    if result.returncode != 0 and "already" not in result.stderr.lower():
        # Clean up.
        run(["brig-subnet", "remove-network", cell_name], check=False)
        error(f"Failed to connect proxy to network: {result.stderr}")

    # Get proxy IP on cell network.
    proxy_ip = get_proxy_ip(net_name)
    if not proxy_ip:
        # Proxy might need a moment.
        time.sleep(1)
        proxy_ip = get_proxy_ip(net_name)

    if not proxy_ip:
        error("Could not determine proxy IP on cell network")

    # Build container command.
    cmd = [
        "podman", "run",
        "--name", container_name(cell_name),
        "--runtime", RUNTIME,
        "--network", net_name,

        # Proxy environment variables.
        "-e", f"http_proxy=http://{proxy_ip}:8080",
        "-e", f"https_proxy=http://{proxy_ip}:8080",
        "-e", f"HTTP_PROXY=http://{proxy_ip}:8080",
        "-e", f"HTTPS_PROXY=http://{proxy_ip}:8080",
        "-e", "no_proxy=localhost,127.0.0.1",

        # Resource limits.
        "--memory", args.memory,
        "--cpus", args.cpus,
        "--pids-limit", str(args.pids_limit),
    ]

    # Seccomp profile (defense-in-depth on top of gVisor).
    if getattr(args, "seccomp_profile", None):
        profile_path = Path(args.seccomp_profile)
        if not profile_path.exists():
            error(f"Seccomp profile not found: {args.seccomp_profile}")
        # Validate it's valid JSON.
        try:
            with open(profile_path, "r") as f:
                json.load(f)
        except json.JSONDecodeError as e:
            error(f"Invalid seccomp profile JSON: {e}")
        cmd.extend(["--security-opt", f"seccomp={profile_path.absolute()}"])
        debug(f"Applying seccomp profile: {profile_path}")

    # Detach mode.
    if args.detach:
        cmd.append("-d")

    # Auto-remove.
    if args.rm:
        cmd.append("--rm")

    # Additional environment variables.
    if args.env:
        for env in args.env:
            cmd.extend(["-e", env])

    # Workspace mount.
    workspace_dir = STATE_DIR / cell_name / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    cmd.extend(["-v", f"{workspace_dir}:/work:rw"])
    cmd.extend(["-w", "/work"])

    # Secrets mounting.
    if args.secret:
        secrets_dir = Path("/secrets")
        for secret_name in args.secret:
            # Validate secret name (no path traversal).
            if ".." in secret_name or "/" in secret_name:
                error(f"Invalid secret name: {secret_name}")

            secret_path = secrets_dir / secret_name
            # Check secret exists.
            if not secret_path.exists():
                error(f"Secret not found: {secret_name}")

            # Mount secret read-only at /run/secrets/{name}.
            cmd.extend(["-v", f"{secret_path}:/run/secrets/{secret_name}:ro"])

            # Set env var pointing to secret path (not value).
            # Convert filename to env var name: test-api-key.txt -> TEST_API_KEY_FILE
            env_name = secret_name.rsplit(".", 1)[0]  # Remove extension.
            env_name = env_name.upper().replace("-", "_") + "_FILE"
            cmd.extend(["-e", f"{env_name}=/run/secrets/{secret_name}"])

    # Image and command.
    cmd.append(args.image)
    if args.container_cmd:
        cmd.extend(args.container_cmd)

    # Dry-run mode: show what would be done.
    if getattr(args, "dry_run", False):
        print("=== Dry Run - No changes will be made ===\n")
        print(f"Cell name:    {cell_name}")
        print(f"Image:        {args.image}")
        print(f"Command:      {' '.join(args.container_cmd) if args.container_cmd else '(default)'}")
        print(f"Network:      {net_name}")
        print(f"Runtime:      {RUNTIME}")
        print(f"Memory:       {args.memory}")
        print(f"CPUs:         {args.cpus}")
        print(f"PIDs limit:   {args.pids_limit}")
        print(f"Detach:       {args.detach}")
        print(f"Auto-remove:  {args.rm}")
        if args.env:
            print(f"Environment:  {', '.join(args.env)}")
        if args.secret:
            print(f"Secrets:      {', '.join(args.secret)}")
        if args.policy_allow or args.policy_deny:
            print(f"Policy allow: {', '.join(args.policy_allow or [])}")
            print(f"Policy deny:  {', '.join(args.policy_deny or [])}")
        print(f"\nPodman command:")
        print(f"  {' '.join(cmd)}")
        return 0

    # Run container.
    with Spinner(f"Starting cell {cell_name}") as spinner:
        result = run(cmd, check=False, capture=True)
        if result.returncode != 0:
            spinner.fail(f"Failed to start cell {cell_name}")
            # Clean up on failure.
            run(["podman", "network", "disconnect", net_name, PROXY_NAME], check=False)
            run(["brig-subnet", "remove-network", cell_name], check=False)
            print(f"ERROR: {result.stderr}", file=sys.stderr)
            return 1
        spinner.success(f"Cell {cell_name} started")

    # Invalidate cache after state change.
    invalidate_cell_cache(cell_name)

    # Log operation and lifecycle event.
    log_operation("run", cell_name, {"image": args.image, "detach": args.detach})
    log_lifecycle("start", cell_name, {
        "image": args.image,
        "command": args.container_cmd if args.container_cmd else None,
        "detach": args.detach,
    })

    return 0


def cmd_stop(args) -> int:
    """Gracefully stop a cell."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    if not cell_running(cell_name):
        print(f"Cell {cell_name} is not running")
        return 0

    with Spinner(f"Stopping cell {cell_name}") as spinner:
        result = run(
            ["podman", "stop", "-t", "10", container_name(cell_name)],
            check=False, capture=True
        )

        if result.returncode != 0:
            spinner.fail(f"Failed to stop cell {cell_name}")
            print(f"ERROR: {result.stderr}", file=sys.stderr)
            return 1

        # Invalidate cache after state change.
        invalidate_cell_cache(cell_name)
        spinner.success(f"Cell {cell_name} stopped")

    # Log operation and lifecycle event.
    log_operation("stop", cell_name)
    log_lifecycle("stop", cell_name)
    return 0


def cmd_kill(args) -> int:
    """Immediately kill a cell."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    print(f"Killing cell {cell_name}...")
    result = run(
        ["podman", "kill", container_name(cell_name)],
        check=False, capture=True
    )

    if result.returncode != 0 and "not running" not in result.stderr.lower():
        error(f"Failed to kill cell: {result.stderr}")

    # Invalidate cache after state change.
    invalidate_cell_cache(cell_name)

    # Log lifecycle event.
    log_lifecycle("kill", cell_name)

    print(f"Cell {cell_name} killed")
    return 0


def cmd_rm(args) -> int:
    """Remove a cell and clean up resources."""
    cell_name = args.name

    # Stop container if running.
    if cell_running(cell_name):
        if args.force:
            run(["podman", "kill", container_name(cell_name)], check=False)
        else:
            error(f"Cell '{cell_name}' is running. Stop it first or use -f to force")

    with Spinner(f"Removing cell {cell_name}") as spinner:
        # Remove container.
        if cell_exists(cell_name):
            result = run(
                ["podman", "rm", "-f", container_name(cell_name)],
                check=False, capture=True
            )
            if result.returncode != 0:
                debug(f"Warning: Failed to remove container: {result.stderr}")

        # Disconnect proxy from network.
        net_name = network_name(cell_name)
        run(["podman", "network", "disconnect", net_name, PROXY_NAME], check=False)

        # Remove network and free subnet.
        run(["brig-subnet", "remove-network", cell_name], check=False)

        # Remove per-cell policy if exists.
        delete_cell_policy(cell_name)

        # Invalidate cache after state change.
        invalidate_cell_cache(cell_name)

        # Optionally remove workspace.
        if args.purge:
            workspace_dir = STATE_DIR / cell_name
            if workspace_dir.exists():
                import shutil
                shutil.rmtree(workspace_dir)
                spinner.success(f"Cell {cell_name} removed (workspace purged)")
                log_operation("rm", cell_name, {"purge": True})
                log_lifecycle("rm", cell_name, {"purged_workspace": True})
                return 0

        spinner.success(f"Cell {cell_name} removed")

    # Log operation and lifecycle event.
    log_operation("rm", cell_name, {"purge": args.purge})
    log_lifecycle("rm", cell_name, {"purged_workspace": args.purge})
    return 0


def cmd_start(args) -> int:
    """Start a stopped cell."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    if cell_running(cell_name):
        print(f"Cell {cell_name} is already running")
        return 0

    # Fail-fast: Check proxy is running.
    if not proxy_running():
        error("Proxy is not running. Start it with: warden start")

    # Ensure proxy is connected to cell network.
    net_name = network_name(cell_name)
    run(["podman", "network", "connect", net_name, PROXY_NAME], check=False)

    print(f"Starting cell {cell_name}...")
    result = run(
        ["podman", "start", container_name(cell_name)],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(f"Failed to start cell: {result.stderr}")

    # Invalidate cache after state change.
    invalidate_cell_cache(cell_name)

    print(f"Cell {cell_name} started")
    return 0


def cmd_list(args) -> int:
    """List all cells."""
    # Get all containers with brig- prefix.
    result = run(
        ["podman", "ps", "-a", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(f"Failed to list cells: {result.stderr}")

    containers = []
    if result.stdout.strip():
        try:
            containers = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass

    if args.format == "json":
        cells = []
        for c in containers:
            name = c.get("Names", [""])[0]
            if name.startswith(CONTAINER_PREFIX):
                cell_name = name[len(CONTAINER_PREFIX):]
                cells.append({
                    "name": cell_name,
                    "status": c.get("State", "unknown"),
                    "image": c.get("Image", "unknown"),
                })
        print(json.dumps(cells, indent=2))
    else:
        # Table format.
        print(f"{'NAME':<20} {'STATUS':<15} {'IMAGE':<30}")
        print("-" * 65)
        for c in containers:
            name = c.get("Names", [""])[0]
            if name.startswith(CONTAINER_PREFIX):
                cell_name = name[len(CONTAINER_PREFIX):]
                status = c.get("State", "unknown")
                image = c.get("Image", "unknown")
                # Truncate long image names.
                if len(image) > 28:
                    image = image[:25] + "..."
                # Colorize status while maintaining column width.
                # Pad the raw status first, then apply color.
                padded_status = f"{status:<15}"
                if COLOR_ENABLED:
                    colored_status = status_color(status) + " " * (15 - len(status))
                else:
                    colored_status = padded_status
                print(f"{cell_name:<20} {colored_status} {image:<30}")

    return 0


def cmd_logs(args) -> int:
    """View cell logs."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    cmd = ["podman", "logs"]

    if args.follow:
        cmd.append("-f")

    if args.tail:
        cmd.extend(["--tail", str(args.tail)])

    cmd.append(container_name(cell_name))

    try:
        run(cmd, check=False)
    except KeyboardInterrupt:
        pass

    return 0


def cmd_exec(args) -> int:
    """Execute command in a running cell."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    if not cell_running(cell_name):
        error_cell_not_running(cell_name)

    cmd = ["podman", "exec"]

    if args.interactive:
        cmd.append("-i")

    if args.tty:
        cmd.append("-t")

    cmd.append(container_name(cell_name))

    if args.exec_cmd:
        cmd.extend(args.exec_cmd)
    else:
        cmd.append("/bin/sh")

    result = run(cmd, check=False)
    return result.returncode


def cmd_attach(args) -> int:
    """Attach to a cell's console."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    if not cell_running(cell_name):
        error(f"Cell '{cell_name}' is not running")

    # Attach to container.
    cmd = ["podman", "attach", container_name(cell_name)]

    try:
        result = run(cmd, check=False)
        return result.returncode
    except KeyboardInterrupt:
        return 0


def cmd_top(args) -> int:
    """Show processes running inside a cell."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    if not cell_running(cell_name):
        error(f"Cell '{cell_name}' is not running")

    cmd = ["podman", "top", container_name(cell_name)]
    result = run(cmd, check=False)
    return result.returncode


def cmd_diff(args) -> int:
    """Show filesystem changes from base image."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    cmd = ["podman", "diff"]
    if args.format == "json":
        cmd.append("--format=json")
    cmd.append(container_name(cell_name))

    result = run(cmd, check=False, capture=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return result.returncode

    if args.format == "json":
        print(result.stdout)
    else:
        # Pretty-print the diff output.
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            if line.startswith("A "):
                print(f"+ {line[2:]}")
            elif line.startswith("D "):
                print(f"- {line[2:]}")
            elif line.startswith("C "):
                print(f"~ {line[2:]}")
            else:
                print(line)

    return 0


def cmd_stats(args) -> int:
    """Show cell resource usage statistics."""
    cmd = ["podman", "stats", "--format",
           "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.PIDs}}"]

    if args.no_stream:
        cmd.append("--no-stream")

    if args.name:
        if not cell_exists(args.name):
            error(f"Cell '{args.name}' does not exist")
        cmd.append(container_name(args.name))
    else:
        # Filter to only cell containers.
        cmd.extend(["--filter", f"name={CONTAINER_PREFIX}"])

    try:
        result = run(cmd, check=False)
        return result.returncode
    except KeyboardInterrupt:
        return 0


def cmd_pause(args) -> int:
    """Pause a running cell."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    if not cell_running(cell_name):
        error(f"Cell '{cell_name}' is not running")

    result = run(
        ["podman", "pause", container_name(cell_name)],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(f"Failed to pause cell: {result.stderr}")

    print(f"Cell {cell_name} paused")
    return 0


def cmd_unpause(args) -> int:
    """Unpause a paused cell."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    result = run(
        ["podman", "unpause", container_name(cell_name)],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(f"Failed to unpause cell: {result.stderr}")

    # Invalidate cache after state change.
    invalidate_cell_cache(cell_name)

    print(f"Cell {cell_name} unpaused")
    return 0


def cmd_files(args) -> int:
    """List contents of a cell's workspace."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    workspace_dir = STATE_DIR / cell_name / "workspace"
    if not workspace_dir.exists():
        print(f"No workspace for {cell_name}")
        return 0

    # Build path within workspace.
    target_path = workspace_dir
    if args.path:
        # Validate path (no traversal).
        if ".." in args.path.split("/"):
            error("Path traversal not allowed")
        target_path = workspace_dir / args.path

    if not target_path.exists():
        error(f"Path does not exist: {args.path}")

    if target_path.is_file():
        # Show single file info.
        stat = target_path.stat()
        print(f"{target_path.name}  {stat.st_size} bytes")
    else:
        # List directory.
        cmd = ["ls", "-la", str(target_path)]
        run(cmd, check=False)

    return 0


def cmd_cat(args) -> int:
    """View contents of a file in cell's workspace."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    workspace_dir = STATE_DIR / cell_name / "workspace"
    if not workspace_dir.exists():
        error(f"No workspace for cell '{cell_name}'")

    # Validate path (no traversal).
    if ".." in args.path.split("/"):
        error("Path traversal not allowed")

    file_path = workspace_dir / args.path

    if not file_path.exists():
        error(f"File not found: {args.path}")

    if file_path.is_dir():
        error(f"Cannot cat directory: {args.path}")

    # Check file size limit (default 1MB).
    max_size = args.max_size * 1024 * 1024  # Convert MB to bytes.
    stat = file_path.stat()
    if stat.st_size > max_size:
        error(f"File too large ({stat.st_size} bytes). Use --max-size to increase limit.")

    # Check for binary content.
    try:
        with open(file_path, "rb") as f:
            sample = f.read(8192)
        if b"\x00" in sample:
            if not args.force:
                error("File appears to be binary. Use --force to display anyway.")
    except IOError as e:
        error(f"Cannot read file: {e}")

    # Display file contents.
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            if args.lines:
                # Show only first N lines.
                for i, line in enumerate(f):
                    if i >= args.lines:
                        print(f"... (truncated at {args.lines} lines)")
                        break
                    print(line, end="")
            else:
                print(f.read())
    except IOError as e:
        error(f"Cannot read file: {e}")

    return 0


# Unsafe file extensions for --sanitize mode.
UNSAFE_EXTENSIONS = {
    ".app", ".command", ".scpt", ".dmg", ".pkg", ".webloc",
    ".jar", ".exe", ".bat", ".cmd", ".msi", ".vbs", ".ps1",
}

SCRIPT_EXTENSIONS = {
    ".sh", ".py", ".js", ".rb", ".pl", ".php",
}


def apply_quarantine(path: Path, source_cell: str = None) -> bool:
    """Apply macOS quarantine attribute to a file or directory.

    This marks files as coming from an untrusted source, triggering
    Gatekeeper warnings if the user tries to execute them.

    Returns True if quarantine was applied successfully.
    """
    import platform
    if platform.system() != "Darwin":
        return False  # Only applies to macOS.

    try:
        # Quarantine attribute format: flags;timestamp;agent;uuid
        # 0x0082 = downloaded from internet, user confirmed
        import uuid
        ts = int(time.time())
        agent = f"brig:{source_cell}" if source_cell else "brig"
        qattr = f"0082;{ts:x};{agent};{uuid.uuid4()}"

        if path.is_dir():
            # Apply to all files in directory.
            for f in path.rglob("*"):
                if f.is_file():
                    run(["xattr", "-w", "com.apple.quarantine", qattr, str(f)],
                        check=False, capture=True)
        else:
            run(["xattr", "-w", "com.apple.quarantine", qattr, str(path)],
                check=False, capture=True)

        debug(f"Applied quarantine to {path}")
        return True
    except Exception as e:
        debug(f"Failed to apply quarantine: {e}")
        return False


def cmd_cp(args) -> int:
    """Copy files to/from a cell's workspace."""
    src = args.src
    dst = args.dst

    # Parse cell:path format.
    src_cell = None
    dst_cell = None

    if ":" in src and not src.startswith("/"):
        parts = src.split(":", 1)
        src_cell = parts[0]
        src_path = parts[1]
    else:
        src_path = src

    if ":" in dst and not dst.startswith("/"):
        parts = dst.split(":", 1)
        dst_cell = parts[0]
        dst_path = parts[1]
    else:
        dst_path = dst

    # Validate: exactly one side must be a cell.
    if src_cell and dst_cell:
        error("Cannot copy between cells directly. Copy to local first.")
    if not src_cell and not dst_cell:
        error("At least one path must be a cell (cell:path format)")

    # Get workspace paths.
    if src_cell:
        if not cell_exists(src_cell):
            error(f"Cell '{src_cell}' does not exist")
        workspace = STATE_DIR / src_cell / "workspace"
        if ".." in src_path.split("/"):
            error("Path traversal not allowed")
        src_full = workspace / src_path.lstrip("/")
        dst_full = Path(dst_path)
    else:
        if not cell_exists(dst_cell):
            error(f"Cell '{dst_cell}' does not exist")
        workspace = STATE_DIR / dst_cell / "workspace"
        if ".." in dst_path.split("/"):
            error("Path traversal not allowed")
        src_full = Path(src_path)
        dst_full = workspace / dst_path.lstrip("/")

    # Check source exists.
    if not src_full.exists():
        error(f"Source not found: {src_full}")

    # Sanitize mode checks.
    if args.sanitize and src_full.is_file():
        ext = src_full.suffix.lower()
        if ext in UNSAFE_EXTENSIONS:
            error(f"Blocked unsafe file type: {ext}")
        if ext in SCRIPT_EXTENSIONS:
            print(f"Warning: Script file {src_full.name} - use --allow-scripts to permit")
            error(f"Blocked script file: {ext}")

    # Perform copy.
    import shutil
    try:
        if src_full.is_dir():
            shutil.copytree(src_full, dst_full)
        else:
            dst_full.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_full, dst_full)

        # Apply quarantine when copying FROM a cell (to local filesystem).
        if src_cell:
            if apply_quarantine(dst_full, src_cell):
                print(f"Copied {src} -> {dst} (quarantined)")
            else:
                print(f"Copied {src} -> {dst}")
        else:
            print(f"Copied {src} -> {dst}")

        return 0
    except Exception as e:
        error(f"Copy failed: {e}")


def cmd_inspect(args) -> int:
    """Show cell details."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    # Get container details.
    result = run(
        ["podman", "inspect", container_name(cell_name), "--format", "json"],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(f"Failed to inspect cell: {result.stderr}")

    try:
        data = json.loads(result.stdout)
        if not data:
            error("No container data returned")
        container = data[0]
    except (json.JSONDecodeError, IndexError) as e:
        error(f"Failed to parse container data: {e}")

    if args.format == "json":
        print(json.dumps(container, indent=2))
    else:
        # Table format.
        name = container.get("Name", "").lstrip("/")
        state = container.get("State", {})
        config = container.get("Config", {})
        host_config = container.get("HostConfig", {})
        networks = container.get("NetworkSettings", {}).get("Networks", {})

        print(f"Name:    {name}")
        print(f"Status:  {state.get('Status', 'unknown')}")
        print(f"Runtime: {host_config.get('Runtime', 'unknown')}")
        print(f"Image:   {config.get('Image', 'unknown')}")
        print(f"Network: {', '.join(networks.keys())}")
        print(f"Pid:     {state.get('Pid', 'N/A')}")

        # Show mounts.
        mounts = container.get("Mounts", [])
        if mounts:
            print("Mounts:")
            for m in mounts:
                src = m.get("Source", "")
                dst = m.get("Destination", "")
                rw = "rw" if m.get("RW", True) else "ro"
                print(f"  {src} -> {dst} ({rw})")

    return 0


def cmd_export(args) -> int:
    """Export cell definition as YAML."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    # Get container details.
    result = run(
        ["podman", "inspect", container_name(cell_name), "--format", "json"],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(f"Failed to inspect cell: {result.stderr}")

    try:
        data = json.loads(result.stdout)
        if not data:
            error("No container data returned")
        container = data[0]
    except (json.JSONDecodeError, IndexError) as e:
        error(f"Failed to parse container data: {e}")

    config = container.get("Config", {})
    host_config = container.get("HostConfig", {})

    # Build cell definition.
    cell_def = {
        "name": cell_name,
        "image": config.get("Image", ""),
    }

    # Add command if present.
    cmd = config.get("Cmd", [])
    if cmd:
        cell_def["command"] = cmd

    # Extract environment variables (excluding proxy vars).
    env_vars = {}
    proxy_vars = {"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy"}
    for env in config.get("Env", []):
        if "=" in env:
            key, value = env.split("=", 1)
            if key not in proxy_vars and not key.endswith("_FILE"):
                env_vars[key] = value
    if env_vars:
        cell_def["env"] = env_vars

    # Extract secrets from mounts.
    secrets = []
    for mount in container.get("Mounts", []):
        dst = mount.get("Destination", "")
        if dst.startswith("/run/secrets/"):
            secret_name = dst.split("/")[-1]
            secrets.append(secret_name)
    if secrets:
        cell_def["secrets"] = secrets

    # Add resource limits.
    memory = host_config.get("Memory", 0)
    if memory > 0:
        # Convert to human readable.
        if memory >= 1024 * 1024 * 1024:
            cell_def["memory"] = f"{memory // (1024 * 1024 * 1024)}g"
        elif memory >= 1024 * 1024:
            cell_def["memory"] = f"{memory // (1024 * 1024)}m"
        else:
            cell_def["memory"] = str(memory)

    cpus = host_config.get("NanoCpus", 0)
    if cpus > 0:
        cell_def["cpus"] = cpus / 1_000_000_000

    pids = host_config.get("PidsLimit", 0)
    if pids > 0:
        cell_def["pids_limit"] = pids

    # Add per-cell policy if exists.
    policy = load_cell_policy(cell_name)
    if policy.get("allow") or policy.get("deny"):
        cell_def["policy"] = policy

    # Output as YAML or JSON.
    if args.format == "json":
        print(json.dumps(cell_def, indent=2))
    else:
        # YAML output.
        if YAML_AVAILABLE:
            print(yaml.dump(cell_def, default_flow_style=False, sort_keys=False))
        else:
            # Simple YAML-like output without pyyaml.
            for key, value in cell_def.items():
                if isinstance(value, dict):
                    print(f"{key}:")
                    for k, v in value.items():
                        print(f"  {k}: {v}")
                elif isinstance(value, list):
                    print(f"{key}:")
                    for item in value:
                        print(f"  - {item}")
                else:
                    print(f"{key}: {value}")

    return 0


def cmd_network(args) -> int:
    """View cell network activity logs."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    # Network logs are stored at /var/log/brig/network/{cell}.jsonl.
    log_file = Path(f"/var/log/brig/network/{cell_name}.jsonl")

    if not log_file.exists():
        print(f"No network activity logged for {cell_name}")
        return 0

    if args.follow:
        # Follow mode - use tail -f.
        cmd = ["tail", "-f", str(log_file)]
        try:
            run(cmd, check=False)
        except KeyboardInterrupt:
            pass
    else:
        # Read last N lines.
        cmd = ["tail", "-n", str(args.tail), str(log_file)]
        result = run(cmd, check=False, capture=True)

        if args.json:
            # Raw JSONL output.
            print(result.stdout)
        else:
            # Formatted output.
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    ts = entry.get("ts", "")[:19]  # Truncate to seconds.
                    method = entry.get("method", "")
                    host = entry.get("host", "")
                    path = entry.get("path", "/")[:50]
                    status = entry.get("status", "")
                    blocked = " [BLOCKED]" if entry.get("blocked") else ""
                    print(f"{ts} {method:6} {host}{path} -> {status}{blocked}")
                except json.JSONDecodeError:
                    print(line)

    return 0


def cmd_diagnose(args) -> int:
    """Run diagnostic checks on a cell."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    print(f"Diagnosing cell: {cell_name}")
    print("-" * 40)
    issues = []

    # Check 1: Container status.
    if cell_running(cell_name):
        print("[OK] Container is running")
    else:
        print("[WARN] Container is not running")
        issues.append("Container stopped - use 'brig start' to restart")

    # Check 2: Proxy running.
    if proxy_running():
        print("[OK] Proxy is running")
    else:
        print("[FAIL] Proxy is not running")
        issues.append("Start proxy with: warden start")

    # Check 3: Network exists.
    net_name = network_name(cell_name)
    result = run(
        ["podman", "network", "exists", net_name],
        check=False, capture=True
    )
    if result.returncode == 0:
        print(f"[OK] Network {net_name} exists")
    else:
        print(f"[FAIL] Network {net_name} missing")
        issues.append("Cell network missing - recreate cell")

    # Check 4: Proxy connected to cell network.
    if proxy_running():
        result = run(
            ["podman", "inspect", PROXY_NAME, "--format",
             "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}"],
            check=False, capture=True
        )
        if net_name in result.stdout:
            print(f"[OK] Proxy connected to {net_name}")
        else:
            print(f"[WARN] Proxy not connected to {net_name}")
            issues.append(f"Connect proxy: podman network connect {net_name} {PROXY_NAME}")

    # Check 5: gVisor runtime.
    if cell_running(cell_name):
        result = run(
            ["podman", "exec", container_name(cell_name), "dmesg"],
            check=False, capture=True
        )
        if "gVisor" in result.stdout:
            print("[OK] gVisor runtime active")
        else:
            print("[WARN] gVisor may not be active")
            issues.append("Container may not be using gVisor runtime")

    # Check 6: Recent blocked requests.
    log_file = Path(f"/var/log/brig/network/{cell_name}.jsonl")
    if log_file.exists():
        result = run(
            ["tail", "-n", "100", str(log_file)],
            check=False, capture=True
        )
        blocked_count = result.stdout.count('"blocked": true') + result.stdout.count('"blocked":true')
        if blocked_count > 0:
            print(f"[INFO] {blocked_count} requests blocked in recent logs")
        else:
            print("[OK] No recent blocked requests")
    else:
        print("[INFO] No network log file yet")

    # Summary.
    print("-" * 40)
    if issues:
        print(f"\nFound {len(issues)} issue(s):")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
        return 1
    else:
        print("\nAll checks passed")
        return 0


def cmd_health(args) -> int:
    """Check system health for monitoring."""
    checks = {
        "proxy": False,
        "network": False,
        "runtime": False,
    }
    details = {}

    # Check 1: Proxy running.
    if proxy_running():
        checks["proxy"] = True
        details["proxy"] = "running"
    else:
        details["proxy"] = "not running"

    # Check 2: Network (proxy-external exists).
    result = run(
        ["podman", "network", "exists", "proxy-external"],
        check=False, capture=True
    )
    if result.returncode == 0:
        checks["network"] = True
        details["network"] = "proxy-external exists"
    else:
        details["network"] = "proxy-external missing"

    # Check 3: Runtime (gVisor available).
    result = run(
        ["podman", "info", "--format", "{{.Host.OCIRuntime.Name}}"],
        check=False, capture=True
    )
    runtime = result.stdout.strip()
    if "runsc" in runtime or result.returncode == 0:
        checks["runtime"] = True
        details["runtime"] = runtime or "available"
    else:
        details["runtime"] = "unknown"

    # Count running cells.
    result = run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={CONTAINER_PREFIX}"],
        check=False, capture=True
    )
    cell_count = len([n for n in result.stdout.strip().split("\n") if n and n != PROXY_NAME])
    details["cells_running"] = cell_count

    all_healthy = all(checks.values())

    if args.format == "json":
        output = {
            "healthy": all_healthy,
            "checks": checks,
            "details": details,
        }
        print(json.dumps(output, indent=2))
    else:
        status = colorize("HEALTHY", "green") if all_healthy else colorize("UNHEALTHY", "red")
        print(f"Status: {status}")
        print()
        for check, passed in checks.items():
            icon = colorize("✓", "green") if passed else colorize("✗", "red")
            detail = details.get(check, "")
            print(f"  {icon} {check}: {detail}")
        print(f"\nCells running: {cell_count}")

    return 0 if all_healthy else 1


def _fetch_warden_metrics() -> dict:
    """Fetch metrics from warden via Unix socket."""
    import socket
    metrics_socket = Path("/var/run/cells/metrics.sock")
    if not metrics_socket.exists():
        return {}

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(metrics_socket))
        sock.settimeout(5.0)
        sock.send(b"all")
        response = sock.recv(65536).decode("utf-8")
        sock.close()
        return json.loads(response)
    except Exception:
        return {}


def _generate_metrics() -> list:
    """Generate all Prometheus metrics."""
    lines = []
    seen_help = set()

    def add_metric(name: str, value: float, help_text: str, metric_type: str = "gauge",
                   labels: dict = None):
        # Only add HELP and TYPE once per metric name.
        if name not in seen_help:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {metric_type}")
            seen_help.add(name)
        if labels:
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")

    # Proxy status.
    proxy_up = 1 if proxy_running() else 0
    add_metric("brig_proxy_up", proxy_up, "Whether the warden proxy is running")

    # Cell counts by state.
    result = run(
        ["podman", "ps", "-a", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
        check=False, capture=True
    )

    state_counts = {"running": 0, "paused": 0, "exited": 0, "created": 0}
    total_cells = 0

    if result.stdout.strip():
        try:
            containers = json.loads(result.stdout)
            for c in containers:
                name = c.get("Names", [""])[0]
                if name == PROXY_NAME:
                    continue
                if name.startswith(CONTAINER_PREFIX):
                    total_cells += 1
                    state = c.get("State", "unknown").lower()
                    if state in state_counts:
                        state_counts[state] += 1
        except json.JSONDecodeError:
            pass

    add_metric("brig_cells_total", total_cells, "Total number of cells")

    for state, count in state_counts.items():
        add_metric("brig_cells_by_state", count, "Number of cells by state",
                   labels={"state": state})

    # Network count.
    result = run(
        ["podman", "network", "ls", "--format", "{{.Name}}"],
        check=False, capture=True
    )
    cell_networks = len([
        n for n in result.stdout.strip().split("\n")
        if n.startswith(CONTAINER_PREFIX)
    ])
    add_metric("brig_networks_total", cell_networks, "Number of cell networks")

    # Warden metrics (per-cell request stats).
    warden_metrics = _fetch_warden_metrics()
    cells_data = warden_metrics.get("cells", {})

    total_requests = 0
    total_blocked = 0
    total_rate_limited = 0
    total_errors = 0
    total_bytes_sent = 0
    total_bytes_received = 0

    for cell_name, cell_metrics in cells_data.items():
        labels = {"cell": cell_name}

        # Request counters.
        requests = cell_metrics.get("total_requests", 0)
        total_requests += requests
        add_metric("brig_cell_requests_total", requests,
                   "Total requests from cell", "counter", labels)

        blocked = cell_metrics.get("blocked_requests", 0)
        total_blocked += blocked
        add_metric("brig_cell_requests_blocked_total", blocked,
                   "Blocked requests from cell", "counter", labels)

        rate_limited = cell_metrics.get("rate_limited_requests", 0)
        total_rate_limited += rate_limited
        add_metric("brig_cell_requests_rate_limited_total", rate_limited,
                   "Rate-limited requests from cell", "counter", labels)

        errors = cell_metrics.get("error_requests", 0)
        total_errors += errors
        add_metric("brig_cell_requests_errors_total", errors,
                   "Error requests from cell", "counter", labels)

        # Bytes counters.
        bytes_sent = cell_metrics.get("bytes_sent", 0)
        total_bytes_sent += bytes_sent
        add_metric("brig_cell_bytes_sent_total", bytes_sent,
                   "Bytes sent by cell", "counter", labels)

        bytes_recv = cell_metrics.get("bytes_received", 0)
        total_bytes_received += bytes_recv
        add_metric("brig_cell_bytes_received_total", bytes_recv,
                   "Bytes received by cell", "counter", labels)

        # Latency gauges.
        p50 = cell_metrics.get("latency_p50_ms", 0)
        add_metric("brig_cell_latency_p50_ms", p50,
                   "50th percentile request latency", "gauge", labels)

        p95 = cell_metrics.get("latency_p95_ms", 0)
        add_metric("brig_cell_latency_p95_ms", p95,
                   "95th percentile request latency", "gauge", labels)

        p99 = cell_metrics.get("latency_p99_ms", 0)
        add_metric("brig_cell_latency_p99_ms", p99,
                   "99th percentile request latency", "gauge", labels)

    # Aggregate totals.
    add_metric("brig_requests_total", total_requests,
               "Total requests across all cells", "counter")
    add_metric("brig_requests_blocked_total", total_blocked,
               "Total blocked requests", "counter")
    add_metric("brig_requests_rate_limited_total", total_rate_limited,
               "Total rate-limited requests", "counter")
    add_metric("brig_requests_errors_total", total_errors,
               "Total error requests", "counter")
    add_metric("brig_bytes_sent_total", total_bytes_sent,
               "Total bytes sent", "counter")
    add_metric("brig_bytes_received_total", total_bytes_received,
               "Total bytes received", "counter")

    # History operations (last hour).
    ops_last_hour = 0
    if HISTORY_FILE.exists():
        try:
            one_hour_ago = time.time() - 3600
            with open(HISTORY_FILE, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        ts_str = entry.get("timestamp", "")
                        if ts_str:
                            import datetime
                            ts = datetime.datetime.strptime(
                                ts_str, "%Y-%m-%dT%H:%M:%SZ"
                            ).timestamp()
                            if ts > one_hour_ago:
                                ops_last_hour += 1
                    except (json.JSONDecodeError, ValueError):
                        continue
        except IOError:
            pass

    add_metric("brig_operations_last_hour", ops_last_hour,
               "Number of operations in the last hour")

    return lines


def cmd_metrics(args) -> int:
    """Output metrics in Prometheus format."""
    import http.server
    import socketserver

    # If --serve specified, start HTTP server.
    if getattr(args, "serve", False):
        port = getattr(args, "port", 9090)

        class MetricsHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                if self.path == "/metrics" or self.path == "/":
                    metrics_lines = _generate_metrics()
                    content = "\n".join(metrics_lines) + "\n"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(content.encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()

        print(f"Serving metrics on http://0.0.0.0:{port}/metrics")
        print("Press Ctrl+C to stop")
        try:
            with socketserver.TCPServer(("0.0.0.0", port), MetricsHandler) as server:
                server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped")
        return 0

    # Otherwise, output metrics once.
    metrics_lines = _generate_metrics()
    for line in metrics_lines:
        print(line)

    return 0


def cmd_verify(args) -> int:
    """Verify security invariants across all cells."""
    print("Verifying security invariants...")
    print("=" * 50)
    issues = []

    # Check 1: Proxy is running.
    print("\n[Check 1] Proxy status")
    if proxy_running():
        print("  [OK] Proxy is running")
    else:
        print("  [FAIL] Proxy is not running")
        issues.append("Proxy must be running")

    # Check 2: Proxy on proxy-external network.
    print("\n[Check 2] Proxy network attachment")
    result = run(
        ["podman", "inspect", PROXY_NAME, "--format",
         "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}"],
        check=False, capture=True
    )
    if "proxy-external" in result.stdout:
        print("  [OK] Proxy attached to proxy-external")
    else:
        print("  [FAIL] Proxy not on proxy-external network")
        issues.append("Proxy must be on proxy-external network")

    # Check 3: All cells use gVisor runtime.
    print("\n[Check 3] gVisor runtime")
    result = run(
        ["podman", "ps", "-a", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
        check=False, capture=True
    )
    if result.stdout.strip():
        try:
            containers = json.loads(result.stdout)
            for c in containers:
                name = c.get("Names", [""])[0]
                if name == PROXY_NAME:
                    continue
                # Check if running and verify gVisor.
                if c.get("State") == "running":
                    cell = name[len(CONTAINER_PREFIX):] if name.startswith(CONTAINER_PREFIX) else name
                    dmesg = run(
                        ["podman", "exec", name, "dmesg"],
                        check=False, capture=True
                    )
                    if "gVisor" in dmesg.stdout:
                        print(f"  [OK] {cell} using gVisor")
                    else:
                        print(f"  [WARN] {cell} may not use gVisor")
        except json.JSONDecodeError:
            pass
    else:
        print("  [INFO] No cells running")

    # Check 4: Cell networks are internal.
    print("\n[Check 4] Network isolation")
    result = run(
        ["podman", "network", "ls", "--format", "{{.Name}}"],
        check=False, capture=True
    )
    cell_networks = [
        net for net in result.stdout.strip().split("\n")
        if net.startswith(CONTAINER_PREFIX) and net != "proxy-external"
    ]
    if cell_networks:
        # Batch inspect all cell networks at once.
        inspect = run(
            ["podman", "network", "inspect"] + cell_networks,
            check=False, capture=True
        )
        try:
            networks_info = json.loads(inspect.stdout)
            for net_info in networks_info:
                net_name = net_info.get("name", "")
                is_internal = net_info.get("internal", False)
                if is_internal:
                    print(f"  [OK] {net_name} is internal")
                else:
                    print(f"  [WARN] {net_name} may not be internal")
                    issues.append(f"Network {net_name} should be internal")
        except json.JSONDecodeError:
            print("  [WARN] Could not parse network info")

    # Check 5: Cells are single-homed.
    print("\n[Check 5] Single-homed cells")
    result = run(
        ["podman", "ps", "-a", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
        check=False, capture=True
    )
    if result.stdout.strip():
        try:
            containers = json.loads(result.stdout)
            # Collect cell container names (exclude proxy).
            cell_names = [
                c.get("Names", [""])[0] for c in containers
                if c.get("Names", [""])[0] != PROXY_NAME
            ]
            if cell_names:
                # Batch inspect all containers at once.
                inspect = run(
                    ["podman", "inspect", "--format", "json"] + cell_names,
                    check=False, capture=True
                )
                container_infos = json.loads(inspect.stdout)
                for c_info in container_infos:
                    name = c_info.get("Name", "").lstrip("/")
                    networks = list(c_info.get("NetworkSettings", {}).get("Networks", {}).keys())
                    if len(networks) == 1:
                        print(f"  [OK] {name} has 1 network")
                    else:
                        print(f"  [WARN] {name} has {len(networks)} networks")
                        issues.append(f"{name} should be single-homed")
        except json.JSONDecodeError:
            pass

    # Summary.
    print("\n" + "=" * 50)
    if issues:
        print(f"FAILED: {len(issues)} issue(s) found")
        for issue in issues:
            print(f"  - {issue}")
        return 1
    else:
        print("PASSED: All security invariants verified")
        return 0


def cmd_history(args) -> int:
    """Show operation history."""
    if not HISTORY_FILE.exists():
        print("No history recorded yet")
        return 0

    entries = []
    try:
        with open(HISTORY_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except IOError as e:
        error(f"Failed to read history: {e}")

    # Filter by cell if specified.
    if args.cell:
        entries = [e for e in entries if e.get("cell") == args.cell]

    # Limit to last N entries.
    if args.tail:
        entries = entries[-args.tail:]

    if args.format == "json":
        print(json.dumps(entries, indent=2))
    else:
        # Table format.
        print(f"{'TIMESTAMP':<22} {'OPERATION':<12} {'CELL':<15} {'DETAILS':<30}")
        print("-" * 80)
        for entry in entries:
            ts = entry.get("timestamp", "")[:19]  # Truncate timezone.
            op = entry.get("operation", "")
            cell = entry.get("cell", "-")
            details = entry.get("details", {})
            detail_str = ", ".join(f"{k}={v}" for k, v in details.items()) if details else ""
            if len(detail_str) > 28:
                detail_str = detail_str[:25] + "..."
            print(f"{ts:<22} {op:<12} {cell:<15} {detail_str:<30}")

    return 0


def cmd_policy_show(args) -> int:
    """Show a cell's effective network policy."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    # Load per-cell policy.
    cell_policy = load_cell_policy(cell_name)

    # Load global policy for comparison.
    global_policy_path = Path("/cells/network-policy.json")
    global_policy = {"allow": [], "deny": []}
    if global_policy_path.exists():
        try:
            with open(global_policy_path, "r") as f:
                global_policy = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

    print(f"Policy for cell: {cell_name}")
    print("=" * 40)

    print("\nGlobal Allowlist:")
    for domain in global_policy.get("allow", []):
        print(f"  + {domain}")

    print("\nGlobal Denylist:")
    for domain in global_policy.get("deny", []):
        print(f"  - {domain}")

    if cell_policy.get("allow") or cell_policy.get("deny"):
        print("\nPer-Cell Allowlist:")
        for domain in cell_policy.get("allow", []):
            print(f"  + {domain}")

        print("\nPer-Cell Denylist:")
        for domain in cell_policy.get("deny", []):
            print(f"  - {domain}")
    else:
        print("\nNo per-cell policy configured (using global only)")

    return 0


def cmd_policy_set(args) -> int:
    """Update a cell's network policy."""
    cell_name = args.name

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    # Load existing policy.
    policy = load_cell_policy(cell_name)

    # Apply changes.
    if args.allow:
        for domain in args.allow:
            if domain not in policy["allow"]:
                policy["allow"].append(domain)
                print(f"Added to allowlist: {domain}")

    if args.deny:
        for domain in args.deny:
            if domain not in policy["deny"]:
                policy["deny"].append(domain)
                print(f"Added to denylist: {domain}")

    if args.remove_allow:
        for domain in args.remove_allow:
            if domain in policy["allow"]:
                policy["allow"].remove(domain)
                print(f"Removed from allowlist: {domain}")

    if args.remove_deny:
        for domain in args.remove_deny:
            if domain in policy["deny"]:
                policy["deny"].remove(domain)
                print(f"Removed from denylist: {domain}")

    # Save updated policy.
    save_cell_policy(cell_name, policy)
    print(f"\nPolicy updated for {cell_name}")

    # Signal proxy to reload.
    result = run(["warden", "reload"], check=False, capture=True)
    if result.returncode == 0:
        print("Proxy reloaded")
    else:
        print("Warning: Could not reload proxy. Changes take effect on next proxy restart.")

    return 0


def _validate_policy_rule(rule, context: str) -> list[str]:
    """Validate a single policy rule. Returns list of errors."""
    import fnmatch
    errors = []

    if isinstance(rule, str):
        # Simple domain pattern.
        if not rule:
            errors.append(f"{context}: empty domain")
        elif rule.startswith("*."):
            # Wildcard pattern.
            if len(rule) < 3:
                errors.append(f"{context}: invalid wildcard pattern '{rule}'")
        # Check for suspicious patterns.
        suspicious = is_suspicious_domain(rule)
        if suspicious:
            errors.append(f"{context}: {suspicious}")
    elif isinstance(rule, dict):
        # Complex rule with path/method.
        domain = rule.get("domain", "")
        if not domain:
            errors.append(f"{context}: missing 'domain' field")

        paths = rule.get("paths")
        if paths is not None and not isinstance(paths, list):
            errors.append(f"{context}: 'paths' must be a list")

        methods = rule.get("methods")
        if methods is not None:
            if not isinstance(methods, list):
                errors.append(f"{context}: 'methods' must be a list")
            else:
                valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
                for method in methods:
                    if method.upper() not in valid_methods:
                        errors.append(f"{context}: invalid method '{method}'")
    else:
        errors.append(f"{context}: invalid rule type (must be string or object)")

    return errors


def cmd_policy_validate(args) -> int:
    """Validate a policy file syntax."""
    import fnmatch

    policy_path = Path(args.file) if args.file else Path("/cells/network-policy.json")

    if not policy_path.exists():
        error(f"Policy file not found: {policy_path}")

    try:
        with open(policy_path, "r") as f:
            policy = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}", file=sys.stderr)
        return 1

    errors = []
    warnings = []

    # Validate allow rules.
    allow_rules = policy.get("allow", [])
    if not isinstance(allow_rules, list):
        errors.append("'allow' must be a list")
    else:
        for i, rule in enumerate(allow_rules):
            rule_errors = _validate_policy_rule(rule, f"allow[{i}]")
            errors.extend(rule_errors)

    # Validate deny rules.
    deny_rules = policy.get("deny", [])
    if not isinstance(deny_rules, list):
        errors.append("'deny' must be a list")
    else:
        for i, rule in enumerate(deny_rules):
            rule_errors = _validate_policy_rule(rule, f"deny[{i}]")
            errors.extend(rule_errors)

    # Validate rate limits.
    rate_limits = policy.get("rate_limits", {})
    if rate_limits:
        default = rate_limits.get("default", {})
        if default:
            if "rate" in default and not isinstance(default["rate"], (int, float)):
                errors.append("rate_limits.default.rate must be a number")
            if "burst" in default and not isinstance(default["burst"], int):
                errors.append("rate_limits.default.burst must be an integer")

    # Validate log filter.
    log_filter = policy.get("log_filter", {})
    if log_filter:
        sample_rate = log_filter.get("sample_rate", 1.0)
        if not (0 <= sample_rate <= 1):
            errors.append("log_filter.sample_rate must be between 0 and 1")

    # Check for overlapping rules.
    all_domains = []
    for rule in allow_rules:
        if isinstance(rule, str):
            all_domains.append(rule)
        elif isinstance(rule, dict):
            all_domains.append(rule.get("domain", ""))

    for domain in set(all_domains):
        count = all_domains.count(domain)
        if count > 1:
            warnings.append(f"Domain '{domain}' appears {count} times in allow rules")

    # Report results.
    if errors:
        print("Validation FAILED:")
        for err in errors:
            print(f"  ERROR: {err}")
        for warning in warnings:
            print(f"  WARNING: {warning}")
        return 1
    else:
        print(f"Validation OK: {len(allow_rules)} allow rules, {len(deny_rules)} deny rules")
        for warning in warnings:
            print(f"  WARNING: {warning}")
        return 0


def _matches_domain(pattern: str, domain: str) -> bool:
    """Check if domain matches pattern."""
    pattern = pattern.lower()
    domain = domain.lower()

    if pattern.startswith("*."):
        suffix = pattern[1:]  # Keep the dot.
        return domain.endswith(suffix) or domain == pattern[2:]
    else:
        return domain == pattern


def _matches_rule(rule, domain: str, path: str, method: str) -> bool:
    """Check if request matches a rule."""
    import fnmatch

    if isinstance(rule, str):
        return _matches_domain(rule, domain)
    elif isinstance(rule, dict):
        if not _matches_domain(rule.get("domain", ""), domain):
            return False

        paths = rule.get("paths")
        if paths is not None:
            if not any(fnmatch.fnmatch(path, p) for p in paths):
                return False

        methods = rule.get("methods")
        if methods is not None:
            if method.upper() not in [m.upper() for m in methods]:
                return False

        return True
    return False


def cmd_policy_test(args) -> int:
    """Test if a domain would be allowed by policy for a specific cell."""
    cell_name = args.name
    domain = args.domain
    path = args.path
    method = args.method

    if not cell_exists(cell_name):
        error(f"Cell '{cell_name}' does not exist")

    # Load per-cell policy.
    cell_policy = load_cell_policy(cell_name)

    # Load global policy.
    global_policy_path = Path("/cells/network-policy.json")
    global_policy = {"allow": [], "deny": []}
    if global_policy_path.exists():
        try:
            with open(global_policy_path, "r") as f:
                global_policy = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

    verbose = args.verbose

    # Check cell deny rules first.
    if verbose:
        print(f"Testing: {method} {domain}{path} for cell '{cell_name}'")
        print("-" * 50)

    for i, rule in enumerate(cell_policy.get("deny", [])):
        if _matches_rule(rule, domain, path, method):
            print(f"BLOCKED: Cell deny rule [{i}]: {rule}")
            return 1

    # Check global deny rules.
    for i, rule in enumerate(global_policy.get("deny", [])):
        if _matches_rule(rule, domain, path, method):
            print(f"BLOCKED: Global deny rule [{i}]: {rule}")
            return 1

    # Check cell allow rules.
    for i, rule in enumerate(cell_policy.get("allow", [])):
        if _matches_rule(rule, domain, path, method):
            print(f"ALLOWED: Cell allow rule [{i}]: {rule}")
            return 0

    # Check global allow rules.
    for i, rule in enumerate(global_policy.get("allow", [])):
        if _matches_rule(rule, domain, path, method):
            print(f"ALLOWED: Global allow rule [{i}]: {rule}")
            return 0

    # Default deny.
    print("BLOCKED: Not in any allowlist")
    if verbose:
        print(f"\nCell policy: {len(cell_policy.get('allow', []))} allow, {len(cell_policy.get('deny', []))} deny rules")
        print(f"Global policy: {len(global_policy.get('allow', []))} allow, {len(global_policy.get('deny', []))} deny rules")
    return 1


def main():
    parser = argparse.ArgumentParser(
        description="Brig - Secure workload harness for cells",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Initialize brig directory structure")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing config files")
    p_init.add_argument("--quiet", "-q", action="store_true", help="Suppress output")

    # vm
    p_vm = subparsers.add_parser("vm", help="Manage the brig Lima VM")
    vm_sub = p_vm.add_subparsers(dest="vm_command", required=True)

    vm_sub.add_parser("create", help="Create the brig VM")

    vm_sub.add_parser("start", help="Start the brig VM")

    p_vm_stop = vm_sub.add_parser("stop", help="Stop the brig VM")
    p_vm_stop.add_argument("-f", "--force", action="store_true", help="Force stop")

    p_vm_status = vm_sub.add_parser("status", help="Show VM status")
    p_vm_status.add_argument("--json", action="store_true", help="Output as JSON")

    p_vm_shell = vm_sub.add_parser("shell", help="Open shell in VM or run command")
    p_vm_shell.add_argument("shell_cmd", nargs="*", help="Command to run (omit for interactive shell)")

    p_vm_delete = vm_sub.add_parser("delete", help="Delete the brig VM")
    p_vm_delete.add_argument("-f", "--force", action="store_true", help="Skip confirmation")

    # run
    p_run = subparsers.add_parser("run", help="Run a new cell")
    p_run.add_argument("--name", "-n", help="Cell name (required unless in definition file)")
    p_run.add_argument("-f", "--file", help="Cell definition file (YAML or JSON)")
    p_run.add_argument("-d", "--detach", action="store_true", help="Run in background")
    p_run.add_argument("--rm", action="store_true", help="Remove container when it exits")
    p_run.add_argument("--dry-run", action="store_true", help="Show what would be done without executing")
    p_run.add_argument("-e", "--env", action="append", help="Set environment variable")
    p_run.add_argument("--secret", action="append", help="Mount secret file at /run/secrets/")
    p_run.add_argument("--memory", default="2g", help="Memory limit (default: 2g)")
    p_run.add_argument("--cpus", default="2", help="CPU limit (default: 2)")
    p_run.add_argument("--pids-limit", type=int, default=512, help="PID limit (default: 512)")
    p_run.add_argument("--policy-allow", action="append", help="Allow domain (adds to global policy)")
    p_run.add_argument("--policy-deny", action="append", help="Deny domain (overrides global policy)")
    p_run.add_argument("--verify-image", action="store_true", help="Verify image signature before running")
    p_run.add_argument("--seccomp-profile", help="Apply seccomp profile (path to JSON file)")
    p_run.add_argument("image", nargs="?", help="Container image")
    p_run.add_argument("container_cmd", nargs="*", help="Command to run")

    # stop
    p_stop = subparsers.add_parser("stop", help="Gracefully stop a cell")
    p_stop.add_argument("name", help="Cell name")

    # kill
    p_kill = subparsers.add_parser("kill", help="Immediately kill a cell")
    p_kill.add_argument("name", help="Cell name")

    # rm
    p_rm = subparsers.add_parser("rm", help="Remove a cell")
    p_rm.add_argument("-f", "--force", action="store_true", help="Force remove running cell")
    p_rm.add_argument("--purge", action="store_true", help="Also remove workspace")
    p_rm.add_argument("name", help="Cell name")

    # start
    p_start = subparsers.add_parser("start", help="Start a stopped cell")
    p_start.add_argument("name", help="Cell name")

    # list
    p_list = subparsers.add_parser("list", help="List all cells")
    p_list.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # logs
    p_logs = subparsers.add_parser("logs", help="View cell logs")
    p_logs.add_argument("-f", "--follow", action="store_true", help="Follow log output")
    p_logs.add_argument("--tail", type=int, help="Number of lines to show")
    p_logs.add_argument("name", help="Cell name")

    # exec
    p_exec = subparsers.add_parser("exec", help="Execute command in cell")
    p_exec.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    p_exec.add_argument("-t", "--tty", action="store_true", help="Allocate pseudo-TTY")
    p_exec.add_argument("name", help="Cell name")
    p_exec.add_argument("exec_cmd", nargs="*", help="Command to execute")

    # attach
    p_attach = subparsers.add_parser("attach", help="Attach to cell's console")
    p_attach.add_argument("name", help="Cell name")

    # top
    p_top = subparsers.add_parser("top", help="Show processes in cell")
    p_top.add_argument("name", help="Cell name")

    # diff
    p_diff = subparsers.add_parser("diff", help="Show filesystem changes from base image")
    p_diff.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    p_diff.add_argument("name", help="Cell name")

    # stats
    p_stats = subparsers.add_parser("stats", help="Show cell resource usage")
    p_stats.add_argument("--no-stream", action="store_true", help="Disable live updates")
    p_stats.add_argument("name", nargs="?", help="Cell name (all cells if omitted)")

    # pause
    p_pause = subparsers.add_parser("pause", help="Pause a running cell")
    p_pause.add_argument("name", help="Cell name")

    # unpause
    p_unpause = subparsers.add_parser("unpause", help="Unpause a paused cell")
    p_unpause.add_argument("name", help="Cell name")

    # files
    p_files = subparsers.add_parser("files", help="List workspace contents")
    p_files.add_argument("name", help="Cell name")
    p_files.add_argument("path", nargs="?", default="", help="Path within workspace")

    # cat
    p_cat = subparsers.add_parser("cat", help="View file in workspace")
    p_cat.add_argument("--lines", "-n", type=int, help="Show only first N lines")
    p_cat.add_argument("--max-size", type=int, default=1, help="Max file size in MB (default: 1)")
    p_cat.add_argument("--force", action="store_true", help="Show binary files")
    p_cat.add_argument("name", help="Cell name")
    p_cat.add_argument("path", help="Path to file within workspace")

    # cp
    p_cp = subparsers.add_parser("cp", help="Copy files to/from workspace")
    p_cp.add_argument("--sanitize", action="store_true", help="Block unsafe file types")
    p_cp.add_argument("src", help="Source path (cell:path or local path)")
    p_cp.add_argument("dst", help="Destination path (cell:path or local path)")

    # inspect
    p_inspect = subparsers.add_parser("inspect", help="Show cell details")
    p_inspect.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    p_inspect.add_argument("name", help="Cell name")

    # export
    p_export = subparsers.add_parser("export", help="Export cell as YAML definition")
    p_export.add_argument("--format", choices=["yaml", "json"], default="yaml", help="Output format")
    p_export.add_argument("name", help="Cell name")

    # network
    p_network = subparsers.add_parser("network", help="View cell network activity")
    p_network.add_argument("-f", "--follow", action="store_true", help="Follow log output")
    p_network.add_argument("--json", action="store_true", help="Output raw JSONL")
    p_network.add_argument("--tail", type=int, default=20, help="Number of lines to show")
    p_network.add_argument("name", help="Cell name")

    # diagnose
    p_diagnose = subparsers.add_parser("diagnose", help="Run diagnostic checks on cell")
    p_diagnose.add_argument("name", help="Cell name")

    # health
    p_health = subparsers.add_parser("health", help="Check system health")
    p_health.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # metrics
    p_metrics = subparsers.add_parser("metrics", help="Output Prometheus metrics")
    p_metrics.add_argument("--serve", action="store_true", help="Serve metrics via HTTP (for Prometheus scraping)")
    p_metrics.add_argument("--port", type=int, default=9090, help="Port for HTTP server (default: 9090)")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify security invariants")

    # history
    p_history = subparsers.add_parser("history", help="Show operation history")
    p_history.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    p_history.add_argument("--tail", "-n", type=int, default=20, help="Show last N entries")
    p_history.add_argument("--cell", help="Filter by cell name")

    # policy
    p_policy = subparsers.add_parser("policy", help="Manage cell network policies")
    policy_sub = p_policy.add_subparsers(dest="policy_command", required=True)

    p_policy_show = policy_sub.add_parser("show", help="Show cell's effective policy")
    p_policy_show.add_argument("name", help="Cell name")

    p_policy_set = policy_sub.add_parser("set", help="Update cell's policy")
    p_policy_set.add_argument("name", help="Cell name")
    p_policy_set.add_argument("--allow", action="append", help="Add allowed domain")
    p_policy_set.add_argument("--deny", action="append", help="Add denied domain")
    p_policy_set.add_argument("--remove-allow", action="append", help="Remove allowed domain")
    p_policy_set.add_argument("--remove-deny", action="append", help="Remove denied domain")

    p_policy_validate = policy_sub.add_parser("validate", help="Validate policy file syntax")
    p_policy_validate.add_argument("file", nargs="?", help="Policy file (default: /cells/network-policy.json)")

    p_policy_test = policy_sub.add_parser("test", help="Test if domain is allowed for cell")
    p_policy_test.add_argument("name", help="Cell name")
    p_policy_test.add_argument("domain", help="Domain to test")
    p_policy_test.add_argument("--path", default="/", help="Path to test (default: /)")
    p_policy_test.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    p_policy_test.add_argument("-v", "--verbose", action="store_true", help="Show detailed evaluation")

    args = parser.parse_args()

    # Set debug mode and log level.
    global DEBUG, LOG_LEVEL
    DEBUG = args.debug
    if args.debug:
        LOG_LEVEL = LOG_LEVEL_DEBUG

    # Set color mode.
    global COLOR_ENABLED
    if args.no_color:
        COLOR_ENABLED = False

    # Command dispatch table.
    commands = {
        "init": cmd_init,
        "vm": cmd_vm,
        "run": cmd_run,
        "stop": cmd_stop,
        "kill": cmd_kill,
        "rm": cmd_rm,
        "start": cmd_start,
        "list": cmd_list,
        "logs": cmd_logs,
        "exec": cmd_exec,
        "attach": cmd_attach,
        "top": cmd_top,
        "diff": cmd_diff,
        "stats": cmd_stats,
        "pause": cmd_pause,
        "unpause": cmd_unpause,
        "files": cmd_files,
        "cat": cmd_cat,
        "cp": cmd_cp,
        "inspect": cmd_inspect,
        "export": cmd_export,
        "network": cmd_network,
        "diagnose": cmd_diagnose,
        "health": cmd_health,
        "metrics": cmd_metrics,
        "verify": cmd_verify,
        "history": cmd_history,
    }

    # Policy subcommands.
    policy_commands = {
        "show": cmd_policy_show,
        "set": cmd_policy_set,
        "validate": cmd_policy_validate,
        "test": cmd_policy_test,
    }

    # Determine command name for logging.
    if args.command == "policy":
        cmd_name = f"policy.{args.policy_command}"
        cmd_func = policy_commands.get(args.policy_command)
    elif args.command == "vm":
        cmd_name = f"vm.{args.vm_command}"
        cmd_func = commands.get("vm")
    else:
        cmd_name = args.command
        cmd_func = commands.get(args.command)

    if not cmd_func:
        print(f"ERROR: Unknown command: {args.command}", file=sys.stderr)
        sys.exit(1)

    # Execute command with operation logging.
    op_context = log_operation_start(cmd_name, args)
    exit_code = 0
    error_msg = None

    try:
        exit_code = cmd_func(args)
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else 1
        raise
    except Exception as e:
        error_msg = str(e)
        exit_code = 1
        raise
    finally:
        log_operation_end(op_context, exit_code, error_msg)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
