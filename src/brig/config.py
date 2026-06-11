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
VERSION = "0.4.0"

# Lima VM name.
VM_NAME = "brig"

# Canonical cell name pattern: lowercase alphanumeric start, max 63 chars.
CELL_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9._-]{0,62}\Z')

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

# Brig-managed containers that are NOT cells. Cell-listing surfaces
# (brig cell list, sdk.list_cells, security.verify, system_cmd.prune)
# must skip these — otherwise the OTel collector shows up as a cell
# because its name (`brig-otel`) matches the `name=^brig-` ps filter.
# Single source of truth so adding a new infra sidecar means updating
# one tuple, not seven list sites.
INFRA_CONTAINER_NAMES = (PROXY_NAME, COLLECTOR_NAME)

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
MEMORY_PATTERN = r"^\d+[kmgKMG]?\Z"

# Valid domain pattern for policy.
DOMAIN_PATTERN = r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\Z"

# Suspicious domain patterns that could enable DNS rebinding attacks.
SUSPICIOUS_DOMAIN_PATTERNS = [
    "*", "*.*", "*.local", "*.internal", "*.localhost",
    "*.home", "*.lan", "*.corp", "*.private",
]

# Host services (cell → host forwarding through Warden).
# The .host.brig suffix is also defined as HOST_SERVICE_SUFFIX in
# src/brig/warden_addons/enforce.py — addons can't import from brig.* so the suffix
# lives in both places. Keep them in sync.
#
# Single-tenant flattened model (see also host_sockets): cell yaml
# declares both the name AND the host port. There is no separate
# global registry — declaring in yaml IS the authorization. The
# operator who wrote the yaml is the trust principal.
HOST_SERVICE_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9-]{0,30}\Z')
MAX_HOST_SERVICES_PER_CELL = 16

# Warden's HTTP(S) forward-proxy listen port — the egress choke point cells
# are pointed at via HTTP(S)_PROXY. Single source of truth for the proxy port.
PROXY_PORT = 8080

# Ingress (authenticated reverse proxy through Warden).
INGRESS_PORT = 8443
# Minimum ingress bearer-token length. The salted hash lives in the
# untrusted routes file (invariant 4) and is offline-crackable at SHA-256
# speed, so short tokens are rejected rather than warned. `openssl rand
# -hex 32` produces a 64-char token.
INGRESS_TOKEN_MIN_LEN = 32
MAX_INGRESS_PER_CELL = 8
# "token": brig is the gate (Bearer-token perimeter auth). "none": transparent
# pass-through — brig does NOT authenticate; the cell's own app is the gate
# (opt-in, rejected on the untrusted profile, audited at run time).
INGRESS_AUTH_METHODS = {"token", "none"}
INGRESS_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9-]{0,30}\Z')
INGRESS_PATH_PREFIX_PATTERN = re.compile(r'^/[a-zA-Z0-9/_-]+\Z')

# Host sockets — kernel-side channel between a cell and a macOS host
# service via a bind-mounted unix socket. Bypasses Warden by design
# (the bytes never reach the proxy), so the validators here are the
# only thing standing between a cell yaml and a host file.
HOST_SOCKET_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9-]{0,30}\Z')
MAX_HOST_SOCKETS_PER_CELL = 8
HOST_SOCKET_MOUNT_PREFIX = "/run/host/"
HOST_SOCKET_MODES = {"ro", "rw"}

# Scoped host-directory mounts — bind-mount an operator-chosen host directory
# into a non-untrusted cell (ro default / rw opt-in). Bytes bypass Warden, so
# the boundary is the validators + the mount_roots() allowlist + runtime
# realpath re-containment. A cell-side symlink can't escape the subtree
# (mount-namespace isolation); the residual host-side symlink risk is mitigated
# by `brig cell mount-scan`. See docs/design/host-mounts.md.
MOUNT_NAME_PATTERN = HOST_SOCKET_NAME_PATTERN
MAX_MOUNTS_PER_CELL = 8
MOUNT_MODES = HOST_SOCKET_MODES  # {"ro", "rw"}
# Container-engine sockets — granting these to a cell is root-equivalent
# on the host. Denied at parse time unless the operator passes the
# (future) --allow-engine-socket override.
HOST_SOCKET_ENGINE_DENYLIST = (
    "docker.sock", "podman.sock", "containerd.sock",
    "crio.sock", "firecracker.sock", "limactl.sock",
)

# Secret name pattern — restricts allowable filenames in ~/.brig/secrets/
# to a safe character set. Empty names, null bytes, leading dashes, and
# shell metacharacters are excluded; an empty name would otherwise collapse
# the per-secret bind mount to the whole secrets directory.
SECRET_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9._-]{0,62}\Z')

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

    # Root under which each declared mount_root is Lima-mounted, at
    # /mnt/host/<slug>. See mount_roots() / mount_root_slug().
    MOUNTS_DIR = Path("/mnt/host")


def mount_roots() -> list[str]:
    """Operator-declared host trees that may be exposed to cells via `mounts:`.

    Read lazily from CONFIG_FILE (key `mount_roots`) — VM-level, not per-cell,
    because Lima mounts are static and VM-wide (see docs/design/host-mounts.md).
    Accepts a JSON list or a comma-separated string; returns absolute,
    user-expanded, normalized paths. Empty (the default) means `mounts:` is
    disabled.
    """
    import json
    try:
        with open(HostPaths.CONFIG_FILE) as f:
            raw = json.load(f).get("mount_roots", [])
    except (OSError, ValueError):
        return []
    if isinstance(raw, str):
        raw = raw.split(",")
    if not isinstance(raw, list):
        return []
    out = []
    for p in raw:
        if isinstance(p, str) and p.strip():
            out.append(os.path.normpath(os.path.expanduser(p.strip())))
    return out


def mount_root_slug(root: str) -> str:
    """Stable VM-mount subdir name for a declared root (sanitized realpath
    basename).

    Resolved via realpath so EVERY caller derives the same slug for a given root
    — validation's collision check (config.py), the lima.yaml render
    (vm/lima_mounts.py), and the reconciler's bind (cell/reconciler.py). If the
    raw and realpath basenames differed, two symlinked roots could collide at one
    `/mnt/host/<slug>` while validation, using a different basis, saw no
    collision — silently shadowing one host tree with another.
    """
    base = os.path.basename(os.path.realpath(os.path.expanduser(root))) or "root"
    return re.sub(r"[^A-Za-z0-9._-]", "_", base)


def validate_mount_roots(roots: list[str]) -> list[str]:
    """Validate operator-declared mount_roots; return a list of error strings.

    These trees are exposed to cells (and to the VM via lima.yaml), so a too-broad
    or sensitive root, or one with a slug collision / YAML-hostile chars, is
    refused — the floor docs/design/host-mounts.md promises. Each must be an
    absolute, existing directory, not a catastrophe/secret tree (nor an ancestor
    or descendant of one), with a unique VM-mount slug.

    Comparison is by real path (symlinks resolved) plus on-disk identity, so a
    symlink, a realpath alias (/etc -> /private/etc), or a case variant on a
    case-insensitive filesystem (~/.SSH == ~/.ssh) cannot dodge the floor — the
    reconciler binds the realpath, so validation must reason about it too.
    """
    home = Path.home()

    def _real(p: object) -> str:
        return os.path.realpath(os.path.expanduser(str(p)))

    # "broad" trees: reject a root that EQUALS one or CONTAINS one (an ancestor
    # would expose it). Descendants are fine — mounting ~/work (under $HOME) is
    # the normal case; only mounting $HOME itself (or a parent) is too broad.
    broad = [_real(p) for p in ("/", home, HostPaths.BRIG_HOME, "/etc")]
    # secret trees: also reject a root that sits UNDER one (a slice of secrets).
    secrets = [_real(p) for p in (
        home / ".ssh", home / ".aws", home / ".gnupg",
        home / ".config" / "gcloud", home / ".kube", home / ".docker",
    )]
    errors: list[str] = []
    seen_slugs: dict[str, str] = {}
    for root in roots:
        if not isinstance(root, str) or not root.strip():
            errors.append("mount_roots entries must be non-empty strings")
            continue
        if "\n" in root or '"' in root:
            errors.append(f"mount_roots entry {root!r} contains an illegal character")
            continue
        # Check absoluteness on the literal path: realpath() would turn a
        # relative path into cwd-relative-but-absolute and mask the error.
        if not os.path.isabs(os.path.expanduser(root.strip())):
            errors.append(f"mount_root {root!r} must be an absolute path")
            continue
        rp_s = _real(root.strip())
        rp = Path(rp_s)
        bad = False
        for s in broad + secrets:
            if _same_dir(rp_s, s) or _is_ancestor(rp, Path(s)):  # root is s, or contains s
                errors.append(
                    f"mount_root {root!r} is or contains a protected path ({s}); "
                    f"choose a narrower directory"
                )
                bad = True
                break
        for s in secrets:
            if not bad and _is_ancestor(Path(s), rp):  # root is a slice of a secret tree
                errors.append(f"mount_root {root!r} is inside a secret directory ({s})")
                bad = True
                break
        if bad:
            continue
        if not rp.is_dir():
            errors.append(f"mount_root {root!r} is not an existing directory")
            continue
        slug = mount_root_slug(rp_s)
        if slug in seen_slugs:
            errors.append(
                f"mount_roots {seen_slugs[slug]!r} and {root!r} collide at "
                f"/mnt/host/{slug}; rename one so their basenames differ"
            )
            continue
        seen_slugs[slug] = root
    return errors


def _is_ancestor(ancestor: Path, descendant: Path) -> bool:
    """True if `descendant` is strictly under `ancestor`."""
    try:
        descendant.relative_to(ancestor)
        return descendant != ancestor
    except ValueError:
        return False


def _same_dir(a: str, b: str) -> bool:
    """True if `a` and `b` are the same directory on disk — by path, or by inode
    (catches case variants on case-insensitive filesystems where the realpath
    strings differ but resolve to one directory)."""
    if a == b:
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


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
