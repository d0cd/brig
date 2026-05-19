"""
Cell specification — dataclass, validation, and loading.

A CellSpec describes the desired state of a cell. It is the input to the
reconciler, which computes the actions needed to make reality match.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from brig.config import (
    CELL_NAME_PATTERN,
    DOMAIN_PATTERN,
    HOST_SERVICE_NAME_PATTERN,
    HOST_SOCKET_ENGINE_DENYLIST,
    HOST_SOCKET_MODES,
    HOST_SOCKET_MOUNT_PREFIX,
    HOST_SOCKET_NAME_PATTERN,
    INGRESS_AUTH_METHODS,
    INGRESS_NAME_PATTERN,
    INGRESS_PATH_PREFIX_PATTERN,
    MAX_HOST_SERVICES_PER_CELL,
    MAX_HOST_SOCKETS_PER_CELL,
    MAX_INGRESS_PER_CELL,
    MEMORY_PATTERN,
)
from brig.network.validation import is_suspicious_domain

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Size units for parse_size.
_SIZE_UNITS = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_size(size_str: str) -> int:
    """Parse a human-readable size string to bytes (e.g. '500m', '2g')."""
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


def parse_duration(duration_str: str) -> int | None:
    """Parse a duration string into seconds (e.g. '30s', '5m', '2h', '1d').

    Returns None if format is invalid.
    """
    duration_str = duration_str.strip()
    if duration_str.isdigit():
        return int(duration_str)
    match = re.match(r"^(\d+)([smhd])$", duration_str)
    if not match:
        return None
    value = int(match.group(1))
    unit = match.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


@dataclass
class CellSpec:
    """Desired state of a cell."""
    name: str
    image: str
    command: list[str] = field(default_factory=list)
    env: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    memory: str = "2g"
    cpus: str = "2"
    pids_limit: int = 512
    network: str = "default"  # "default" (per-cell isolated) or "none" (airgapped)
    policy_allow: list[str] = field(default_factory=list)
    policy_deny: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    timeout: str | None = None
    workspace_quota: str | None = None
    # Where the per-cell workspace is mounted inside the cell. Default /work
    # matches existing cells; agent-delegation scenarios may prefer the host
    # path basename (e.g. /workspace) so the in-cell and on-host paths agree.
    workspace_mount: str = "/work"
    # Cell rootfs writability. Default False (safe): podman runs the cell
    # with --read-only, plus sized tmpfs at /tmp and /run. The cell can
    # still write to /work (the workspace) — that's its persistence path.
    # A hostile cell with the rootfs writable could (a) DoS the shared
    # VM disk by filling its writable layer, and (b) hide state across
    # stop/start outside the workspace where the user wouldn't think to
    # look. The opt-out exists for images whose entrypoint genuinely
    # needs to write outside /work, /tmp, /run (legacy daemons that
    # write to /var/log, dev images that build at runtime, etc.).
    writable_rootfs: bool = False
    detach: bool = False
    rm: bool = False
    seccomp_profile: str | None = None
    workdir: str | None = None
    image_digest: str | None = None
    profile: str | None = None
    ingress: list[dict[str, Any]] = field(default_factory=list)
    # host_sockets — bind-mount macOS-side unix sockets into the cell.
    # Each entry: {name, host_path, mount_point, mode?}. See _v_host_sockets
    # for validation; bypasses Warden by design, so the validators here
    # are the entire security boundary on the cell-yaml → host-file path.
    host_sockets: list[dict[str, Any]] = field(default_factory=list)
    # host_services — HTTP-only forwarding from cell to a macOS host
    # port, through Warden. Each entry: {name, port}. Cell reaches
    # <name>.host.brig and Warden rewrites to (host_ip, port).
    # Declaring in yaml IS the grant — there is no separate global
    # registry. See _v_host_services for validation.
    host_services: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate inputs at construction time — the system boundary.

        Coerces string-typed numeric fields. Yaml authors naturally write
        `cpus: 4` (parsed as int) but `cpus` is declared `str` because
        podman accepts fractional values. Without coercion, the int slips
        through and crashes downstream when the subprocess args are
        scanned (`"=" in <int>` raises).
        """
        if not CELL_NAME_PATTERN.match(self.name):
            raise ValueError(
                f"Invalid cell name '{self.name}': must match {CELL_NAME_PATTERN.pattern}"
            )
        # Coerce numeric-yaml inputs on str-typed fields.
        for fname in ("cpus", "memory"):
            v = getattr(self, fname)
            if isinstance(v, (int, float)):
                object.__setattr__(self, fname, str(v))

    @property
    def is_airgapped(self) -> bool:
        """True if cell has no network access."""
        return self.network == "none"


# --- Per-field validators ---------------------------------------------------
#
# Each `_v_<field>` function returns a list of error strings (possibly empty).
# `validate_cell_definition` dispatches to these by key. Splitting them keeps
# the dispatch loop short and lets each validator be tested in isolation.


def _v_name(value: Any, context: str) -> list[str]:
    if not isinstance(value, str):
        return [f"'name' must be a string{context}"]
    if not CELL_NAME_PATTERN.match(value):
        return [f"'name' must match pattern {CELL_NAME_PATTERN.pattern}{context}"]
    return []


def _v_image(value: Any, context: str) -> list[str]:
    if not isinstance(value, str) or not value:
        return [f"'image' must be a non-empty string{context}"]
    return []


def _v_command(value: Any, context: str) -> list[str]:
    if not isinstance(value, (str, list)):
        return [f"'command' must be a string or list{context}"]
    if isinstance(value, list) and not all(isinstance(c, str) for c in value):
        return [f"'command' list items must be strings{context}"]
    return []


def _v_env(value: Any, context: str) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
                errors.append(f"'env' keys must be strings, values must be primitives{context}")
                break
    elif isinstance(value, list):
        for item in value:
            if not isinstance(item, str) or "=" not in item:
                errors.append(f"'env' list items must be 'KEY=value' strings{context}")
                break
    else:
        errors.append(f"'env' must be a dict or list{context}")
    return errors


def _v_secrets(value: Any, context: str) -> list[str]:
    if not isinstance(value, list):
        return [f"'secrets' must be a list{context}"]
    errors: list[str] = []
    for secret in value:
        if not isinstance(secret, str):
            errors.append(f"'secrets' items must be strings{context}")
        elif ".." in secret or "/" in secret:
            errors.append(f"Invalid secret name '{secret}': path traversal not allowed{context}")
    return errors


def _v_memory(value: Any, context: str) -> list[str]:
    mem = str(value)
    if not re.match(MEMORY_PATTERN, mem):
        return [f"Invalid 'memory' format '{mem}': use format like '512m', '2g'{context}"]
    return []


def _v_cpus(value: Any, context: str) -> list[str]:
    if not isinstance(value, (int, float, str)):
        return [f"'cpus' must be a number or string{context}"]
    try:
        float(value)
    except ValueError:
        return [f"'cpus' must be a valid number{context}"]
    return []


def _v_pids_limit(value: Any, context: str) -> list[str]:
    if not isinstance(value, int) or value < 1:
        return [f"'pids_limit' must be a positive integer{context}"]
    return []


def _v_policy(value: Any, context: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"'policy' must be a dict{context}"]
    errors: list[str] = []
    for key in ("allow", "deny"):
        if key not in value:
            continue
        if not isinstance(value[key], list):
            errors.append(f"'policy.{key}' must be a list{context}")
            continue
        for domain in value[key]:
            if not isinstance(domain, str):
                errors.append(f"'policy.{key}' items must be strings{context}")
            elif not re.match(DOMAIN_PATTERN, domain):
                errors.append(f"Invalid domain '{domain}' in policy.{key}{context}")
            elif key == "allow":
                suspicious = is_suspicious_domain(domain)
                if suspicious:
                    errors.append(f"Security: {suspicious}{context}")
    return errors


def _v_network(value: Any, context: str) -> list[str]:
    """Network — SECURITY INVARIANTS 1, 6, 8.

    Only "default" (per-cell isolated) and "none" (airgapped) are valid.
    "proxy-external" is rejected (invariant 6: only warden may attach).
    List values are rejected (invariant 8: cells must be single-homed).
    """
    if not isinstance(value, str):
        return [f"'network' must be a string ('default' or 'none'){context}"]
    if value not in ("default", "none"):
        return [
            f"Invalid 'network' value '{value}': must be 'default' or 'none'"
            f" (attaching cells to other networks violates single-homing){context}"
        ]
    return []


def _v_workspace_quota(value: Any, context: str) -> list[str]:
    if not isinstance(value, str):
        return [f"'workspace_quota' must be a string like '500m' or '2g'{context}"]
    try:
        parse_size(value)
    except ValueError:
        return [f"Invalid workspace_quota value: {value}{context}"]
    return []


def _v_writable_rootfs(value: Any, context: str) -> list[str]:
    if not isinstance(value, bool):
        return [f"'writable_rootfs' must be a boolean{context}"]
    return []


def _v_workspace_mount(value: Any, context: str) -> list[str]:
    """workspace_mount must be an absolute, non-traversal path that
    doesn't shadow brig-internal paths.

    Rejection covers three cases for each forbidden path P:
      - value == P                (exact shadow)
      - value.startswith(P + "/") (descends into P, masks subtree)
      - P.startswith(value + "/") (ANCESTOR of P — mounting at the
                                   ancestor masks P via mount-over-mount,
                                   so e.g. workspace_mount: /run hides
                                   the /run/secrets mount even though
                                   "/run" itself isn't in the forbidden
                                   set). Audit finding M3.
    Also reject "/" outright — shadowing rootfs breaks the cell in
    bizarre ways without offering any value.
    """
    if not isinstance(value, str):
        return [f"'workspace_mount' must be a string{context}"]
    if not value.startswith("/"):
        return [f"'workspace_mount' must be an absolute path{context}"]
    if ".." in value.split("/"):
        return [f"'workspace_mount' must not contain '..'{context}"]
    if value == "/":
        return [f"'workspace_mount' must not be '/' (shadows rootfs){context}"]
    forbidden_prefixes = ("/proc", "/sys", "/dev", "/run/secrets", "/etc")
    for p in forbidden_prefixes:
        # Exact match or descendant: workspace_mount masks P.
        if value == p or value.startswith(p + "/"):
            return [
                f"'workspace_mount' must not shadow {p}{context} "
                f"(would mask a required system path)"
            ]
        # Ancestor: workspace_mount masks P via mount-over-mount.
        if p.startswith(value + "/"):
            return [
                f"'workspace_mount' must not be an ancestor of {p}{context} "
                f"(would mask {p} via mount-over-mount)"
            ]
    return []


def _v_detach(value: Any, context: str) -> list[str]:
    if not isinstance(value, bool):
        return [f"'detach' must be a boolean{context}"]
    return []


def _v_host_socket_entry(
    i: int, entry: Any, seen_names: set, seen_mounts: set, context: str,
) -> list[str]:
    """Validate one host_socket entry. Mutates seen_* to track duplicates.

    Static checks only — does NOT touch the filesystem (no realpath,
    no S_ISSOCK). The runtime check happens in the reconciler at cell
    start, where TOCTOU is unavoidable anyway. Static rules:
      - name matches HOST_SOCKET_NAME_PATTERN, unique within cell
      - host_path is absolute, no '..', not on the engine denylist
      - mount_point starts with /run/host/, no '..', not literally /run/host/
      - mode in {ro, rw} if provided
    """
    if not isinstance(entry, dict):
        return [f"'host_sockets[{i}]' must be a dict{context}"]

    errors: list[str] = []

    name = entry.get("name")
    if not name or not isinstance(name, str):
        errors.append(
            f"'host_sockets[{i}].name' is required and must be a string{context}"
        )
    elif not HOST_SOCKET_NAME_PATTERN.match(name):
        errors.append(
            f"'host_sockets[{i}].name' must be lowercase alphanumeric "
            f"with hyphens, max 31 chars{context}"
        )
    elif name in seen_names:
        errors.append(f"Duplicate host_sockets name '{name}'{context}")
    else:
        seen_names.add(name)

    host_path = entry.get("host_path")
    if not host_path or not isinstance(host_path, str):
        errors.append(
            f"'host_sockets[{i}].host_path' is required and must be a string{context}"
        )
    elif not host_path.startswith("/"):
        errors.append(
            f"'host_sockets[{i}].host_path' must be absolute{context}"
        )
    elif ".." in host_path.split("/"):
        errors.append(
            f"'host_sockets[{i}].host_path' must not contain '..' (path traversal){context}"
        )
    else:
        # Engine-socket denylist: granting these is root-equivalent on
        # the host (docker/podman socket = exec arbitrary containers as
        # the daemon user, which is typically root).
        basename = host_path.rsplit("/", 1)[-1]
        if basename in HOST_SOCKET_ENGINE_DENYLIST:
            errors.append(
                f"'host_sockets[{i}].host_path' points at engine socket "
                f"'{basename}' — granting this is root-equivalent on the "
                f"host and is denied{context}"
            )

    mount_point = entry.get("mount_point")
    if not mount_point or not isinstance(mount_point, str):
        errors.append(
            f"'host_sockets[{i}].mount_point' is required and must be a string{context}"
        )
    elif ".." in mount_point.split("/"):
        errors.append(
            f"'host_sockets[{i}].mount_point' must not contain '..' (path traversal){context}"
        )
    elif not mount_point.startswith(HOST_SOCKET_MOUNT_PREFIX):
        errors.append(
            f"'host_sockets[{i}].mount_point' must start with "
            f"'{HOST_SOCKET_MOUNT_PREFIX}'{context}"
        )
    elif mount_point.rstrip("/") == HOST_SOCKET_MOUNT_PREFIX.rstrip("/"):
        errors.append(
            f"'host_sockets[{i}].mount_point' must be a file path under "
            f"'{HOST_SOCKET_MOUNT_PREFIX}', not the directory itself{context}"
        )
    else:
        # Normalize before duplicate-checking so /run/host/x and
        # /run/host//x and /run/host/./x all collide.
        import os.path as _ospath
        normalized = _ospath.normpath(mount_point)
        if normalized in seen_mounts:
            errors.append(
                f"Duplicate host_sockets mount_point '{mount_point}' "
                f"(normalizes to '{normalized}'){context}"
            )
        else:
            seen_mounts.add(normalized)

    mode = entry.get("mode", "ro")
    if not isinstance(mode, str) or mode not in HOST_SOCKET_MODES:
        errors.append(
            f"'host_sockets[{i}].mode' must be one of: "
            f"{', '.join(sorted(HOST_SOCKET_MODES))}{context}"
        )

    return errors


def _v_host_sockets(value: Any, cell_def: dict, context: str) -> list[str]:
    """Validate the cell's host_sockets list as a whole.

    Cross-cutting rules (per-entry checks live in _v_host_socket_entry):
      - must be a list
      - count bounded by MAX_HOST_SOCKETS_PER_CELL
      - the `untrusted` profile may not declare any host_sockets — the
        profile exists specifically to deny side channels like this
    """
    if not isinstance(value, list):
        return [f"'host_sockets' must be a list{context}"]

    errors: list[str] = []
    if len(value) > MAX_HOST_SOCKETS_PER_CELL:
        errors.append(
            f"Too many host_sockets entries ({len(value)}), "
            f"max {MAX_HOST_SOCKETS_PER_CELL}{context}"
        )

    # The `untrusted` profile is brig's "I am running adversarial code"
    # toggle. Bypassing Warden via a kernel side channel defeats the
    # point — reject at parse time so the operator can't accidentally
    # do it. We check both the declared name AND, for user-defined
    # profiles, whether they shadow / inherit the untrusted profile.
    if value and _profile_is_untrusted(cell_def.get("profile")):
        errors.append(
            f"'host_sockets' is not allowed with the untrusted profile — "
            f"untrusted cells must not have side channels to host services"
            f"{context}"
        )

    # Cell name with dots breaks launchd label parsing: the bridge
    # label is `com.brig.host-socket.<cell>.<socket>` and is split on
    # `.`. A cell named `my.cell` would mis-derive socket names; a
    # prefix-based stop_cell_bridges("my") would tear down bridges of
    # `my.cell`. CELL_NAME_PATTERN allows dots, so we forbid them
    # only when host_sockets are declared.
    cell_name = cell_def.get("name", "")
    if value and isinstance(cell_name, str) and "." in cell_name:
        errors.append(
            f"cell names with '.' may not declare host_sockets "
            f"(launchd label ambiguity){context}"
        )

    seen_names: set = set()
    seen_mounts: set = set()
    for i, entry in enumerate(value):
        errors.extend(
            _v_host_socket_entry(i, entry, seen_names, seen_mounts, context)
        )

    return errors


def _profile_is_untrusted(profile_name: Any) -> bool:
    """Decide whether a profile reference means the cell is untrusted.

    Direct string match handles the common case. For user-defined
    profiles that shadow the builtin name OR carry the same intent via
    a different name, we also check the resolved profile's labels for
    `brig.profile: untrusted` — the builtin signal.
    """
    if profile_name == "untrusted":
        return True
    if not isinstance(profile_name, str) or not profile_name:
        return False
    try:
        from brig.cell.profiles import load_profile
        prof = load_profile(profile_name)
    except (ValueError, FileNotFoundError, OSError):
        return False
    labels = prof.get("labels", {})
    if isinstance(labels, dict) and labels.get("brig.profile") == "untrusted":
        return True
    if isinstance(labels, list):
        for item in labels:
            if isinstance(item, str) and item == "brig.profile=untrusted":
                return True
    return False


def _v_host_service_entry(
    i: int, entry: Any, seen_names: set, context: str,
) -> list[str]:
    """Validate one host_services entry. Single-tenant model: cell yaml
    declares both name and port directly.

    Rules:
      - name: HOST_SERVICE_NAME_PATTERN, unique per cell
      - port: int in [1, 65535]
    No path/file checks (this is TCP-forwarding, not socket-mounting).
    """
    if not isinstance(entry, dict):
        return [f"'host_services[{i}]' must be a dict{context}"]

    errors: list[str] = []

    name = entry.get("name")
    if not name or not isinstance(name, str):
        errors.append(
            f"'host_services[{i}].name' is required and must be a string{context}"
        )
    elif not HOST_SERVICE_NAME_PATTERN.match(name):
        errors.append(
            f"'host_services[{i}].name' must be lowercase alphanumeric "
            f"with hyphens, max 31 chars{context}"
        )
    elif name in seen_names:
        errors.append(f"Duplicate host_services name '{name}'{context}")
    else:
        seen_names.add(name)

    port = entry.get("port")
    if port is None:
        errors.append(f"'host_services[{i}].port' is required{context}")
    elif not isinstance(port, int) or port < 1 or port > 65535:
        errors.append(
            f"'host_services[{i}].port' must be an integer 1-65535{context}"
        )

    return errors


def _v_host_services(value: Any, cell_def: dict, context: str) -> list[str]:
    """Validate the cell's host_services list as a whole.

    Cross-cutting rules:
      - must be a list
      - count bounded by MAX_HOST_SERVICES_PER_CELL
      - the `untrusted` profile may not declare host_services — same
        reasoning as host_sockets (Warden bypass via name resolution
        to host services defeats the profile)
    """
    if not isinstance(value, list):
        return [f"'host_services' must be a list{context}"]

    errors: list[str] = []
    if len(value) > MAX_HOST_SERVICES_PER_CELL:
        errors.append(
            f"Too many host_services entries ({len(value)}), "
            f"max {MAX_HOST_SERVICES_PER_CELL}{context}"
        )

    if value and _profile_is_untrusted(cell_def.get("profile")):
        errors.append(
            f"'host_services' is not allowed with the untrusted profile — "
            f"untrusted cells must not reach host services{context}"
        )

    seen_names: set = set()
    for i, entry in enumerate(value):
        errors.extend(
            _v_host_service_entry(i, entry, seen_names, context)
        )

    return errors


def _v_ingress_entry(i: int, entry: Any, seen_names: set, seen_prefixes: set,
                     context: str) -> list[str]:
    """Validate one ingress entry. Mutates seen_* sets to track duplicates."""
    if not isinstance(entry, dict):
        return [f"'ingress[{i}]' must be a dict{context}"]

    errors: list[str] = []

    name = entry.get("name")
    if not name or not isinstance(name, str):
        errors.append(f"'ingress[{i}].name' is required and must be a string{context}")
    elif not INGRESS_NAME_PATTERN.match(name):
        errors.append(
            f"'ingress[{i}].name' must be lowercase alphanumeric "
            f"with hyphens, max 31 chars{context}"
        )
    elif name in seen_names:
        errors.append(f"Duplicate ingress name '{name}'{context}")
    else:
        seen_names.add(name)

    port = entry.get("port")
    if port is None:
        errors.append(f"'ingress[{i}].port' is required{context}")
    elif not isinstance(port, int) or port < 1 or port > 65535:
        errors.append(f"'ingress[{i}].port' must be an integer 1-65535{context}")

    path_prefix = entry.get("path_prefix")
    if not path_prefix or not isinstance(path_prefix, str):
        errors.append(f"'ingress[{i}].path_prefix' is required and must be a string{context}")
    elif not path_prefix.startswith("/"):
        errors.append(f"'ingress[{i}].path_prefix' must start with '/'{context}")
    elif ".." in path_prefix:
        errors.append(f"'ingress[{i}].path_prefix' must not contain '..'{context}")
    elif not INGRESS_PATH_PREFIX_PATTERN.match(path_prefix):
        errors.append(
            f"'ingress[{i}].path_prefix' contains invalid characters "
            f"(only alphanumeric, /, -, _ allowed){context}"
        )
    elif path_prefix in seen_prefixes:
        errors.append(f"Duplicate ingress path_prefix '{path_prefix}'{context}")
    else:
        seen_prefixes.add(path_prefix)

    auth = entry.get("auth")
    if not auth or not isinstance(auth, str):
        errors.append(f"'ingress[{i}].auth' is required and must be a string{context}")
    elif auth not in INGRESS_AUTH_METHODS:
        errors.append(
            f"'ingress[{i}].auth' must be one of: "
            f"{', '.join(sorted(INGRESS_AUTH_METHODS))}{context}"
        )

    return errors


def _v_ingress(value: Any, cell_def: dict, context: str) -> list[str]:
    if not isinstance(value, list):
        return [f"'ingress' must be a list{context}"]

    errors: list[str] = []
    if len(value) > MAX_INGRESS_PER_CELL:
        errors.append(
            f"Too many ingress entries ({len(value)}), "
            f"max {MAX_INGRESS_PER_CELL}{context}"
        )

    seen_names: set = set()
    seen_prefixes: set = set()
    for i, entry in enumerate(value):
        errors.extend(_v_ingress_entry(i, entry, seen_names, seen_prefixes, context))

    # Ingress requires network=default (not airgapped).
    net = cell_def.get("network", "default")
    if isinstance(net, str) and net == "none" and value:
        errors.append(f"'ingress' cannot be used with network='none' (airgapped){context}")
    return errors


# Map field name -> validator that takes (value, context). Validators that
# need other fields (like ingress checking network) are handled below.
_SIMPLE_VALIDATORS = {
    "name": _v_name,
    "image": _v_image,
    "command": _v_command,
    "env": _v_env,
    "secrets": _v_secrets,
    "memory": _v_memory,
    "cpus": _v_cpus,
    "pids_limit": _v_pids_limit,
    "policy": _v_policy,
    "network": _v_network,
    "workspace_quota": _v_workspace_quota,
    "workspace_mount": _v_workspace_mount,
    "writable_rootfs": _v_writable_rootfs,
    "detach": _v_detach,
}


def validate_cell_definition(cell_def: dict[str, Any], file_path: str = "") -> list[str]:
    """Validate a cell definition dict and return list of errors.

    Enforces security invariants:
      - Invariant 1/6: Rejects network=proxy-external
      - Invariant 8: Rejects network=[list]
    """
    errors: list[str] = []
    context = f" in {file_path}" if file_path else ""

    for field_name, validator in _SIMPLE_VALIDATORS.items():
        if field_name in cell_def:
            errors.extend(validator(cell_def[field_name], context))

    if "ingress" in cell_def:
        errors.extend(_v_ingress(cell_def["ingress"], cell_def, context))

    if "host_sockets" in cell_def:
        errors.extend(_v_host_sockets(cell_def["host_sockets"], cell_def, context))

    if "host_services" in cell_def:
        errors.extend(_v_host_services(cell_def["host_services"], cell_def, context))

    return errors


def load_cell_definition(path: str) -> dict[str, Any]:
    """Load a cell definition from a JSON or YAML file.

    Raises BrigError on failure.
    """
    from brig.errors import BrigError

    p = Path(path)
    if not p.exists():
        raise BrigError(f"Cell definition file not found: {path}")

    content = p.read_text()
    suffix = p.suffix.lower()

    if suffix in (".yaml", ".yml"):
        if not YAML_AVAILABLE:
            raise BrigError(
                "YAML support requires pyyaml",
                suggestion="Install with: pip install pyyaml",
            )
        try:
            result = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise BrigError(
                f"Failed to parse YAML: {e}",
                suggestion="Check the YAML syntax and try again",
            )
    else:
        try:
            result = json.loads(content)
        except json.JSONDecodeError as e:
            raise BrigError(
                f"Failed to parse JSON: {e}",
                suggestion="Check the JSON syntax. Validate with: python -m json.tool FILE",
            )

    if not isinstance(result, dict):
        raise BrigError(f"Cell definition must be a mapping, got {type(result).__name__}")
    return result
