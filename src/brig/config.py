"""
Configuration constants for Brig.

Paths are split into two namespaces:
  - Host paths: macOS side, used by the CLI directly.
  - VM paths: inside the Lima VM, used when shelling into the VM.

The CLI runs on macOS. Podman runs inside the VM. All podman commands
are routed through `limactl shell brig --` by brig.vm.shell.
"""

import re
import os
from pathlib import Path

# Version.
VERSION = "0.3.0"

# Lima VM name.
VM_NAME = "brig"

# Canonical cell name pattern: lowercase alphanumeric start, max 63 chars.
CELL_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9._-]{0,62}$')

# Container naming prefix for cells.
CONTAINER_PREFIX = "brig-"


def container_name(cell_name: str) -> str:
    """Map a cell name to its podman container name."""
    return f"{CONTAINER_PREFIX}{cell_name}"

# Default runtime (gVisor).
RUNTIME = "runsc"

# Warden proxy container name.
PROXY_NAME = "warden"

# OpenTelemetry collector — sibling container to warden. Runs inside
# the Lima VM, receives metrics/traces/logs from warden over OTLP,
# serves Prometheus + log queries to the host CLI.
#
# Bump COLLECTOR_IMAGE_TAG then run `./scripts/pin-collector-image.sh`
# to refresh COLLECTOR_IMAGE_DIGEST against the published image. The
# collector lifecycle (observability/collector.py) refuses to start
# if the digest is empty — fail closed, no unverified pulls.
COLLECTOR_NAME = "brig-otel"
COLLECTOR_IMAGE_REPO = "docker.io/otel/opentelemetry-collector-contrib"
COLLECTOR_IMAGE_TAG = "0.96.0"
COLLECTOR_IMAGE_DIGEST = "sha256:7d165be14571ef423f0394756bfa8b377a882d3ca8052394c69402fa68305158"
COLLECTOR_OTLP_GRPC_PORT = 4317
COLLECTOR_OTLP_HTTP_PORT = 4318
COLLECTOR_PROMETHEUS_PORT = 9464

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
SENSITIVE_PATTERNS = {"password", "secret", "key", "token", "credential", "auth", "value"}

# Valid memory suffixes.
MEMORY_PATTERN = r"^\d+[kmgKMG]?$"

# Valid domain pattern for policy.
DOMAIN_PATTERN = r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"

# Suspicious domain patterns that could enable DNS rebinding attacks.
SUSPICIOUS_DOMAIN_PATTERNS = [
    "*", "*.*", "*.local", "*.internal", "*.localhost",
    "*.home", "*.lan", "*.corp", "*.private",
]

# Host services (cell → host forwarding through Warden).
# The .host.brig suffix is also defined as HOST_SERVICE_SUFFIX in
# src/addons/enforce.py — addons can't import from brig.* so the suffix
# lives in both places. Keep them in sync.
#
# Single-tenant flattened model (see also host_sockets): cell yaml
# declares both the name AND the host port. There is no separate
# global registry — declaring in yaml IS the authorization. The
# operator who wrote the yaml is the trust principal.
HOST_SERVICE_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9-]{0,30}$')
MAX_HOST_SERVICES_PER_CELL = 16

# Ingress (authenticated reverse proxy through Warden).
INGRESS_PORT = 8443
MAX_INGRESS_PER_CELL = 8
INGRESS_AUTH_METHODS = {"token"}
INGRESS_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9-]{0,30}$')
INGRESS_PATH_PREFIX_PATTERN = re.compile(r'^/[a-zA-Z0-9/_-]+$')

# Host sockets — kernel-side channel between a cell and a macOS host
# service via a bind-mounted unix socket. Bypasses Warden by design
# (the bytes never reach the proxy), so the validators here are the
# only thing standing between a cell yaml and a host file.
HOST_SOCKET_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9-]{0,30}$')
MAX_HOST_SOCKETS_PER_CELL = 8
HOST_SOCKET_MOUNT_PREFIX = "/run/host/"
HOST_SOCKET_MODES = {"ro", "rw"}
# Container-engine sockets — granting these to a cell is root-equivalent
# on the host. Denied at parse time unless the operator passes the
# (future) --allow-engine-socket override.
HOST_SOCKET_ENGINE_DENYLIST = (
    "docker.sock", "podman.sock", "containerd.sock",
    "crio.sock", "firecracker.sock", "limactl.sock",
)

# Unsafe file extensions for --sanitize mode.
UNSAFE_EXTENSIONS = {
    ".app", ".command", ".scpt", ".dmg", ".pkg", ".webloc",
    ".jar", ".exe", ".bat", ".cmd", ".msi", ".vbs", ".ps1",
}


# --- Host paths (macOS side) ---

class HostPaths:
    """Paths on the macOS host, used directly by the CLI.

    Coordination state (subnet-map, per-cell policies, ingress routes) lives
    under STATE_DIR/system. Lima mounts STATE_DIR at /state inside the VM,
    and warden mounts /state/system at /var/run/cells inside its container,
    so host writes flow to warden via virtiofs without any sync step.
    """
    # BRIG_HOME defaults to ~/.brig but can be overridden via the
    # $BRIG_HOME environment variable. Tests use this to point at a
    # tmpdir (see tests/conftest.py); operators can use it for
    # multi-profile setups. Resolved at class-definition time, so set
    # the env var before any `import brig` happens. `.strip()` so
    # `BRIG_HOME="  "` doesn't silently route every path to a
    # relative dir named two spaces.
    BRIG_HOME = Path(
        os.environ.get("BRIG_HOME", "").strip() or Path.home() / ".brig"
    )
    CELLS_DIR = BRIG_HOME / "cells"
    ADDONS_DIR = CELLS_DIR / "addons"
    SECRETS_DIR = BRIG_HOME / "secrets"
    PROFILES_DIR = BRIG_HOME / "profiles"
    STATE_DIR = BRIG_HOME / "state"
    LIMA_YAML = BRIG_HOME / "lima.yaml"
    NETWORK_POLICY = CELLS_DIR / "network-policy.json"
    CONFIG_FILE = CELLS_DIR / "config.json"

    # Coordination state — written by host CLI, read by warden via /state mount.
    SYSTEM_DIR = STATE_DIR / "system"
    POLICY_DIR = SYSTEM_DIR / "policies"
    INGRESS_ROUTES_FILE = SYSTEM_DIR / "ingress-routes.json"

    # host_sockets bridge dir — macOS-side launchd unit creates a socket
    # here that proxies to the operator's host_path; Lima exposes
    # ~/.brig under /state in the VM, so the same path is reachable
    # from inside the VM without a separate forward.
    HOST_SOCKETS_DIR = STATE_DIR / "system" / "host-sockets"

    # Rate limit state (host-side, used before entering VM).
    RATE_LIMIT_FILE = STATE_DIR / "system" / "rate_limit.json"

    # Operation logs (host-side, written by CLI).
    OPERATIONS_FILE = STATE_DIR / "system" / "operations.jsonl"
    HISTORY_FILE = STATE_DIR / "system" / "history.jsonl"
    LIFECYCLE_FILE = STATE_DIR / "system" / "lifecycle.jsonl"
    POLICY_AUDIT_FILE = STATE_DIR / "system" / "policy_audit.jsonl"


# --- VM paths (inside Lima VM) ---

class VMPaths:
    """Paths inside the Lima VM, used in podman commands.

    Coordination files (subnet-map, policies, ingress routes) live under
    /state/system, which Lima maps to the host's ~/.brig/state/system.
    Warden bind-mounts /state/system into its container at /var/run/cells.
    """
    STATE_DIR = Path("/state")
    SYSTEM_DIR = STATE_DIR / "system"
    CELLS_DIR = Path("/cells")
    SECRETS_DIR = Path("/secrets")
    ADDONS_DIR = CELLS_DIR / "addons"
    NETWORK_POLICY = CELLS_DIR / "network-policy.json"
    CONFIG_FILE = CELLS_DIR / "config.json"

    # Coordination state — host writes here via virtiofs, warden reads
    # the same files through its own bind mount of SYSTEM_DIR.
    SUBNET_STATE_FILE = SYSTEM_DIR / "subnets.json"
    SUBNET_MAP_FILE = SYSTEM_DIR / "subnet-map.json"
    ALLOCATOR_LOCK_FILE = SYSTEM_DIR / "allocator.lock"
    POLICY_DIR = SYSTEM_DIR / "policies"
    INGRESS_ROUTES_FILE = SYSTEM_DIR / "ingress-routes.json"

    # Logs (inside VM).
    LOG_DIR = Path("/var/log/brig/network")

    # host_sockets bridge dir — same files as HostPaths.HOST_SOCKETS_DIR,
    # reached via the /state virtiofs mount.
    HOST_SOCKETS_DIR = SYSTEM_DIR / "host-sockets"


# Backward-compatible aliases used by modules that haven't been updated.
BRIG_HOME = HostPaths.BRIG_HOME
STATE_DIR = HostPaths.STATE_DIR
CONFIG_FILE = HostPaths.CONFIG_FILE
HISTORY_FILE = HostPaths.HISTORY_FILE
OPERATIONS_FILE = HostPaths.OPERATIONS_FILE
LIFECYCLE_FILE = HostPaths.LIFECYCLE_FILE
POLICY_AUDIT_FILE = HostPaths.POLICY_AUDIT_FILE
RATE_LIMIT_FILE = HostPaths.RATE_LIMIT_FILE
# Coordination state runs on the host — warden sees the same files via the
# /state virtiofs mount (see HostPaths / VMPaths docstrings).
SUBNET_STATE_FILE = HostPaths.SYSTEM_DIR / "subnets.json"
SUBNET_MAP_FILE = HostPaths.SYSTEM_DIR / "subnet-map.json"
ALLOCATOR_LOCK_FILE = HostPaths.SYSTEM_DIR / "allocator.lock"
POLICY_DIR = HostPaths.POLICY_DIR
