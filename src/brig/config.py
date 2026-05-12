"""
Configuration constants for Brig.

Paths are split into two namespaces:
  - Host paths: macOS side, used by the CLI directly.
  - VM paths: inside the Lima VM, used when shelling into the VM.

The CLI runs on macOS. Podman runs inside the VM. All podman commands
are routed through `limactl shell brig --` by brig.vm.shell.
"""

import re
from pathlib import Path

# Version.
VERSION = "0.2.0"

# Lima VM name.
VM_NAME = "brig"

# Canonical cell name pattern: lowercase alphanumeric start, max 63 chars.
CELL_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9._-]{0,62}$')

# Container naming prefix for cells.
CONTAINER_PREFIX = "brig-"

# Default runtime (gVisor).
RUNTIME = "runsc"

# Warden proxy container name.
PROXY_NAME = "warden"

# External network for proxy egress.
PROXY_EXTERNAL_NETWORK = "proxy-external"

# Cache TTL in seconds.
CACHE_TTL = 2.0

# Rate limiting.
RATE_LIMIT_MAX = 10
RATE_LIMIT_WINDOW = 60

# Mutation commands (for operation logging level filtering).
MUTATION_COMMANDS = {"run", "stop", "kill", "rm", "start", "pause", "unpause", "cp", "policy"}

# Sensitive argument patterns for redaction.
SENSITIVE_PATTERNS = {"password", "secret", "key", "token", "credential", "auth"}

# Valid memory suffixes.
MEMORY_PATTERN = r"^\d+[kmgKMG]?[bB]?$"

# Valid domain pattern for policy.
DOMAIN_PATTERN = r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"

# Suspicious domain patterns that could enable DNS rebinding attacks.
SUSPICIOUS_DOMAIN_PATTERNS = [
    "*", "*.*", "*.local", "*.internal", "*.localhost",
    "*.home", "*.lan", "*.corp", "*.private",
]

# Unsafe file extensions for --sanitize mode.
UNSAFE_EXTENSIONS = {
    ".app", ".command", ".scpt", ".dmg", ".pkg", ".webloc",
    ".jar", ".exe", ".bat", ".cmd", ".msi", ".vbs", ".ps1",
}

# Script file extensions.
SCRIPT_EXTENSIONS = {
    ".sh", ".py", ".js", ".rb", ".pl", ".php",
}


# --- Host paths (macOS side) ---

class HostPaths:
    """Paths on the macOS host, used directly by the CLI."""
    BRIG_HOME = Path.home() / ".brig"
    CELLS_DIR = BRIG_HOME / "cells"
    ADDONS_DIR = CELLS_DIR / "addons"
    SECRETS_DIR = BRIG_HOME / "secrets"
    PROFILES_DIR = BRIG_HOME / "profiles"
    STATE_DIR = BRIG_HOME / "state"
    LIMA_YAML = BRIG_HOME / "lima.yaml"
    NETWORK_POLICY = CELLS_DIR / "network-policy.json"
    CONFIG_FILE = CELLS_DIR / "config.json"

    # Rate limit state (host-side, used before entering VM).
    RATE_LIMIT_FILE = STATE_DIR / "system" / "rate_limit.json"

    # Operation logs (host-side, written by CLI).
    OPERATIONS_FILE = STATE_DIR / "system" / "operations.jsonl"
    HISTORY_FILE = STATE_DIR / "system" / "history.jsonl"
    LIFECYCLE_FILE = STATE_DIR / "system" / "lifecycle.jsonl"
    POLICY_AUDIT_FILE = STATE_DIR / "system" / "policy_audit.jsonl"


# --- VM paths (inside Lima VM) ---

class VMPaths:
    """Paths inside the Lima VM, used in podman commands."""
    STATE_DIR = Path("/state")
    CELLS_DIR = Path("/cells")
    SECRETS_DIR = Path("/secrets")
    ADDONS_DIR = CELLS_DIR / "addons"
    NETWORK_POLICY = CELLS_DIR / "network-policy.json"
    CONFIG_FILE = CELLS_DIR / "config.json"

    # Subnet allocator state.
    SUBNET_STATE_FILE = STATE_DIR / "system" / "subnets.json"
    SUBNET_MAP_FILE = Path("/var/run/brig/subnet-map.json")
    ALLOCATOR_LOCK_FILE = Path("/var/run/brig/allocator.lock")

    # Per-cell policy directory (inside VM).
    POLICY_DIR = Path("/var/run/brig/policies")

    # Logs (inside VM).
    LOG_DIR = Path("/var/log/brig/network")


# Backward-compatible aliases used by modules that haven't been updated.
BRIG_HOME = HostPaths.BRIG_HOME
STATE_DIR = HostPaths.STATE_DIR
CONFIG_FILE = HostPaths.CONFIG_FILE
HISTORY_FILE = HostPaths.HISTORY_FILE
OPERATIONS_FILE = HostPaths.OPERATIONS_FILE
LIFECYCLE_FILE = HostPaths.LIFECYCLE_FILE
POLICY_AUDIT_FILE = HostPaths.POLICY_AUDIT_FILE
RATE_LIMIT_FILE = HostPaths.RATE_LIMIT_FILE
# Subnet allocator runs on the host — use host paths.
SUBNET_STATE_FILE = HostPaths.STATE_DIR / "system" / "subnets.json"
SUBNET_MAP_FILE = HostPaths.STATE_DIR / "system" / "subnet-map.json"
ALLOCATOR_LOCK_FILE = HostPaths.STATE_DIR / "system" / "allocator.lock"
POLICY_DIR = VMPaths.POLICY_DIR
