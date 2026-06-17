"""Per-field validators for cell definitions.

Each `_v_<field>` returns a list of error strings (possibly empty).
`validate_cell_definition` dispatches to these by key.

Validators import `parse_size` from spec but spec never imports back from
this module — keep that direction one-way to avoid circular imports.
"""

from __future__ import annotations

import math
import re
from typing import Any

from brig.config import (
    CELL_NAME_PATTERN,
    DOMAIN_PATTERN,
    HOST_SERVICE_NAME_PATTERN,
    INGRESS_AUTH_METHODS,
    INGRESS_NAME_PATTERN,
    INGRESS_PATH_PREFIX_PATTERN,
    MAX_HOST_SERVICES_PER_CELL,
    MAX_INGRESS_PER_CELL,
    MAX_MOUNTS_PER_CELL,
    MEMORY_PATTERN,
    MOUNT_MODES,
    MOUNT_NAME_PATTERN,
    SECRET_NAME_PATTERN,
)
from brig.network.validation import is_suspicious_domain


def _v_name(value: Any, context: str) -> list[str]:
    if not isinstance(value, str):
        return [f"'name' must be a string{context}"]
    if not CELL_NAME_PATTERN.match(value):
        return [f"'name' must match pattern {CELL_NAME_PATTERN.pattern}{context}"]
    return []


def _v_image(value: Any, context: str) -> list[str]:
    if not isinstance(value, str) or not value:
        return [f"'image' must be a non-empty string{context}"]
    # A leading '-' lets the image reference be parsed by `podman run` as a
    # flag (e.g. --runtime=runc downgrades gVisor, --privileged, -v /:/host),
    # since the image is a positional argument. The CLI positional is guarded
    # separately; this closes the yaml `image:` and SDK `image` paths.
    if value.startswith("-"):
        return [
            f"'image' must not start with '-' (would be parsed as a "
            f"podman flag){context}"
        ]
    return []


def _v_command(value: Any, context: str) -> list[str]:
    if not isinstance(value, (str, list)):
        return [f"'command' must be a string or list{context}"]
    if isinstance(value, list) and not all(isinstance(c, str) for c in value):
        return [f"'command' list items must be strings{context}"]
    return []


# POSIX environment variable name. Anchored so a padded/odd key (e.g. ' http_proxy')
# can't slip past the reconciler's proxy-override guard, which compares exact names.
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _v_env(value: Any, context: str) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
                errors.append(f"'env' keys must be strings, values must be primitives{context}")
                break
            if not _ENV_NAME_RE.match(k):
                errors.append(f"'env' key {k!r} is not a valid environment variable name{context}")
                break
    elif isinstance(value, list):
        for item in value:
            if not isinstance(item, str) or "=" not in item:
                errors.append(f"'env' list items must be 'KEY=value' strings{context}")
                break
            if not _ENV_NAME_RE.match(item.split("=", 1)[0]):
                errors.append(f"'env' entry {item!r} has an invalid variable name{context}")
                break
    else:
        errors.append(f"'env' must be a dict or list{context}")
    return errors


def _v_secrets(value: Any, context: str) -> list[str]:
    """Validate the cell's `secrets:` list.

    Each entry must match SECRET_NAME_PATTERN — the same lowercase
    alphanumeric (+ ._-) shape as cell names. An empty string would
    collapse `Path("/secrets") / ""` to `/secrets`, bind-mounting the
    whole secrets directory into the cell; any non-conforming name is
    refused here.
    """
    if not isinstance(value, list):
        return [f"'secrets' must be a list{context}"]
    errors: list[str] = []
    for secret in value:
        if not isinstance(secret, str):
            errors.append(f"'secrets' items must be strings{context}")
            continue
        if not secret:
            errors.append(f"'secrets' item must be a non-empty string{context}")
            continue
        if "\x00" in secret:
            errors.append(f"Invalid secret name (null byte not allowed){context}")
            continue
        if ".." in secret or "/" in secret:
            errors.append(f"Invalid secret name '{secret}': path traversal not allowed{context}")
            continue
        if not SECRET_NAME_PATTERN.match(secret):
            errors.append(
                f"Invalid secret name '{secret}': must match "
                f"{SECRET_NAME_PATTERN.pattern}{context}"
            )
    return errors


def _v_memory(value: Any, context: str) -> list[str]:
    mem = str(value)
    if not re.match(MEMORY_PATTERN, mem):
        return [f"Invalid 'memory' format '{mem}': use format like '512m', '2g'{context}"]
    # MEMORY_PATTERN matches "0"/"0g", but `podman run --memory 0` means
    # UNLIMITED — silently defeating the profile caps. Require a positive size
    # (mirrors _v_cpus rejecting <= 0).
    from brig.cell.spec import parse_size
    if parse_size(mem) <= 0:
        return [f"'memory' must be greater than 0{context}"]
    return []


def _v_cpus(value: Any, context: str) -> list[str]:
    # bool is an int subclass; reject it explicitly so True/False don't
    # slip through as 1.0/0.0.
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return [f"'cpus' must be a number or string{context}"]
    try:
        cpus = float(value)
    except ValueError:
        return [f"'cpus' must be a valid number{context}"]
    # float() accepts 'inf'/'nan'; reject them and non-positive values
    # rather than passing them to `podman run --cpus`, which fails opaquely.
    if not math.isfinite(cpus) or cpus <= 0:
        return [f"'cpus' must be a positive, finite number{context}"]
    return []


def _v_pids_limit(value: Any, context: str) -> list[str]:
    if not isinstance(value, int) or value < 1:
        return [f"'pids_limit' must be a positive integer{context}"]
    return []


def _v_policy(value: Any, cell_def: dict, context: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"'policy' must be a dict{context}"]
    errors: list[str] = []
    for key in ("allow", "deny", "tls_passthrough"):
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
    # Cross-field: every tls_passthrough host must be COVERED by an
    # allow entry — exact match OR a wildcard like *.example.com that
    # matches the passthrough host. The matcher is IDN-aware so unicode
    # passthrough hosts compare correctly against ASCII allow rules.
    from brig.policy.policy import domain_matches_rule
    passthrough = value.get("tls_passthrough") or []
    allow = value.get("allow") or []
    if isinstance(passthrough, list) and isinstance(allow, list):
        allow_strs = [a for a in allow if isinstance(a, str)]
        for host in passthrough:
            if not isinstance(host, str):
                continue
            if not any(domain_matches_rule(rule, host) for rule in allow_strs):
                errors.append(
                    f"'policy.tls_passthrough' host '{host}' must be covered by "
                    f"an entry in 'policy.allow' (exact or wildcard match){context}"
                )
    # Invariant 11: passthrough is an informed-consent security trade-off.
    # Untrusted cells don't get to make that choice.
    if passthrough and _profile_is_untrusted(cell_def.get("profile")):
        errors.append(
            f"'policy.tls_passthrough' is not allowed with the untrusted profile — "
            f"untrusted cells must have all egress MITM-inspected{context}"
        )
    return errors


def _v_network(value: Any, context: str) -> list[str]:
    """Network — SECURITY INVARIANTS 1, 6, 8.

    Only "default" (per-cell isolated) and "none" (airgapped) are valid.
    """
    if not isinstance(value, str):
        return [f"'network' must be a string ('default' or 'none'){context}"]
    if value not in ("default", "none"):
        return [
            f"Invalid 'network' value '{value}': must be 'default' or 'none'"
            f" (attaching cells to other networks violates single-homing){context}"
        ]
    return []


def _v_restart(value: Any, context: str) -> list[str]:
    """Restart policy — only "no" (default) or "always"."""
    if not isinstance(value, str) or value not in ("no", "always"):
        return [f"'restart' must be 'no' or 'always'{context}"]
    return []


# podman --user: uid[:gid] or name[:group]. Restrict to predictable, shell-safe
# tokens (alphanumeric/_/-/., optional :group) — it's passed as a single podman
# arg, but reject anything unexpected at the boundary anyway.
_USER_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,31})?\Z")


def _v_user(value: Any, context: str) -> list[str]:
    """Cell process user (podman --user) — uid[:gid] or name[:group]."""
    if not isinstance(value, str) or not _USER_PATTERN.match(value):
        return [f"'user' must be uid[:gid] or name[:group] (e.g. '0' or "
                f"'1000:1000'){context}"]
    return []


def _v_workspace_quota(value: Any, context: str) -> list[str]:
    from brig.cell.spec import parse_size
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


def _v_trust_warden_ca(value: Any, context: str) -> list[str]:
    if not isinstance(value, bool):
        return [f"'trust_warden_ca' must be a boolean{context}"]
    return []


def _v_workspace_mount(value: Any, context: str) -> list[str]:
    """workspace_mount must be an absolute, non-traversal path that
    doesn't shadow brig-internal paths.

    Three cases for each forbidden P:
      - value == P                (exact shadow)
      - value.startswith(P + "/") (descends into P, masks subtree)
      - P.startswith(value + "/") (ancestor of P — mounting at the
                                   ancestor masks P via mount-over-mount)
    Also reject "/" outright.
    """
    if not isinstance(value, str):
        return [f"'workspace_mount' must be a string{context}"]
    if not value.startswith("/"):
        return [f"'workspace_mount' must be an absolute path{context}"]
    if ".." in value.split("/"):
        return [f"'workspace_mount' must not contain '..'{context}"]
    # Reject non-normalized paths (doubled/trailing slashes, '.' segments).
    # The forbidden-prefix check below is lexical, so without this a value
    # like '/run//host' slips past it while the kernel collapses it back to
    # the protected '/run/host' at mount time.
    # `//` is checked explicitly: os.path.normpath preserves a leading
    # double slash (POSIX), so the normpath comparison alone would miss
    # '//etc' even though the kernel collapses it to '/etc'.
    import os.path as _ospath
    if "//" in value or _ospath.normpath(value) != value:
        return [
            f"'workspace_mount' must be a normalized path (no '.', repeated "
            f"slashes, or trailing slash){context}"
        ]
    if value == "/":
        return [f"'workspace_mount' must not be '/' (shadows rootfs){context}"]
    forbidden_prefixes = (
        "/proc", "/sys", "/dev", "/run/secrets", "/etc",
        # /run/brig is the bind-mount root for the downward-API metadata
        # and CA bundle; /run/host stays reserved (off-limits to cell mounts).
        "/run/host", "/run/brig",
    )
    for p in forbidden_prefixes:
        if value == p or value.startswith(p + "/"):
            return [
                f"'workspace_mount' must not shadow {p}{context} "
                f"(would mask a required system path)"
            ]
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


def _v_labels(value: Any, context: str) -> list[str]:
    if value is None:
        return []
    # Accept the dict form (cell yaml) or the flat list of 'KEY=value'
    # strings (the form CellSpec stores), matching how `env` is handled.
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
                return [f"'labels' keys must be strings, values must be primitives{context}"]
        return []
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, str) or "=" not in item:
                return [f"'labels' list items must be 'KEY=value' strings{context}"]
        return []
    return [f"'labels' must be a dict or list{context}"]


def _v_timeout(value: Any, context: str) -> list[str]:
    if value is None:
        return []
    from brig.cell.spec import parse_duration
    if not isinstance(value, str):
        return [f"'timeout' must be a string like '30s', '5m', '1h'{context}"]
    seconds = parse_duration(value)
    if seconds is None:
        return [f"Invalid 'timeout' value '{value}': use format like '30s', '5m', '1h'{context}"]
    # podman reads `--timeout 0` as "no timeout", silently disabling the cap;
    # require a positive duration so the field always means what it says.
    if seconds <= 0:
        return [f"'timeout' must be greater than 0{context}"]
    return []


def _v_seccomp_profile(value: Any, context: str) -> list[str]:
    # Mirrors the reconciler's runtime guard so a bad value fails at parse
    # time. The profile is a filename resolved under ~/.brig/cells/seccomp/;
    # a path or 'unconfined' would escape that directory or disable seccomp.
    if value is None:
        return []
    if not isinstance(value, str) or not value:
        return [f"'seccomp_profile' must be a non-empty string{context}"]
    if value.lower() == "unconfined":
        return [f"'seccomp_profile' must not be 'unconfined' (disables seccomp){context}"]
    if "/" in value or ".." in value:
        return [f"'seccomp_profile' must be a filename, not a path{context}"]
    return []


def _v_workdir(value: Any, context: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, str) or not value:
        return [f"'workdir' must be a non-empty string{context}"]
    if not value.startswith("/"):
        return [f"'workdir' must be an absolute path{context}"]
    parts = value.split("/")
    if ".." in parts or "." in parts:
        return [f"'workdir' must not contain '.' or '..' path segments{context}"]
    if "//" in value:
        return [f"'workdir' must not contain doubled slashes{context}"]
    return []


def _v_image_digest(value: Any, context: str) -> list[str]:
    if value is None:
        return []
    from brig.cell.lifecycle import _DIGEST_PATTERN
    if not isinstance(value, str) or not _DIGEST_PATTERN.match(value.strip()):
        return [
            f"Invalid 'image_digest' value: must be sha256:<64-hex> "
            f"(or sha384/sha512){context}"
        ]
    return []


def _profile_is_untrusted(profile_name: Any) -> bool:
    """Decide whether a profile reference means the cell is untrusted."""
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
    """Validate one host_services entry."""
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

    protocol = entry.get("protocol", "http")
    if protocol not in ("http", "tcp"):
        errors.append(
            f"'host_services[{i}].protocol' must be 'http' or 'tcp'{context}"
        )

    # TCP host_services become bound reverse-proxy listeners inside the warden
    # container, which runs as the non-root `mitmproxy` user under --cap-drop
    # ALL. A privileged port (<1024) can't be bound there and crashes the
    # single mitmdump process — warden then fails to come up for ANY cell.
    # HTTP services are virtual-domain rewrites, not bound listeners, so this
    # only applies to TCP.
    if protocol == "tcp" and isinstance(port, int):
        if port < 1024:
            errors.append(
                f"'host_services[{i}].port' {port} is privileged (<1024); the "
                f"non-root warden process can't bind it. Use a port >= 1024"
                f"{context}"
            )
        from warden.proxy import WARDEN_RESERVED_PORTS
        if port in WARDEN_RESERVED_PORTS:
            errors.append(
                f"'host_services[{i}].port' {port} is reserved by "
                f"warden (HTTP proxy / ingress); pick a different "
                f"upstream port{context}"
            )

    return errors


def _v_host_services(value: Any, cell_def: dict, context: str) -> list[str]:
    """Validate the cell's host_services list as a whole."""
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


# In-cell mount points that must never be shadowed by a `mounts:` entry —
# same set the workspace_mount validator protects.
_MOUNT_FORBIDDEN_PREFIXES = (
    "/proc", "/sys", "/dev", "/run/secrets", "/etc", "/run/host", "/run/brig",
)


def _v_cell_mount_point(value: Any, field: str, workspace_mount: str,
                        seen_mounts: set, context: str) -> list[str]:
    """Validate an in-cell mount point: absolute, normalized, not shadowing a
    system path or the cell's workspace mount, unique. Mirrors the
    `_v_workspace_mount` checks (kept separate to avoid touching that path)."""
    import os.path as _ospath
    if not value or not isinstance(value, str):
        return [f"'{field}' is required and must be a string{context}"]
    if not value.startswith("/"):
        return [f"'{field}' must be an absolute path{context}"]
    if ".." in value.split("/"):
        return [f"'{field}' must not contain '..'{context}"]
    if ":" in value:
        # ':' is the podman -v field separator — a mount point containing it
        # would be misparsed into source/options.
        return [f"'{field}' must not contain ':'{context}"]
    if "//" in value or _ospath.normpath(value) != value:
        return [f"'{field}' must be a normalized path (no '.', repeated or "
                f"trailing slashes){context}"]
    if value == "/":
        return [f"'{field}' must not be '/' (shadows rootfs){context}"]
    for p in _MOUNT_FORBIDDEN_PREFIXES:
        if value == p or value.startswith(p + "/"):
            return [f"'{field}' must not shadow {p}{context}"]
    ws = _ospath.normpath(workspace_mount or "/work")
    nv = _ospath.normpath(value)
    # Reject equality AND either ancestor relationship — a mount at /work/data
    # or at /work (when ws=/work/data) masks the workspace via mount-over-mount.
    if nv == ws or nv.startswith(ws + "/") or ws.startswith(nv + "/"):
        return [f"'{field}' must not shadow the workspace mount "
                f"({workspace_mount or '/work'}){context}"]
    norm = _ospath.normpath(value)
    if norm in seen_mounts:
        return [f"Duplicate mounts mount_point '{value}'{context}"]
    seen_mounts.add(norm)
    return []


def _v_mount_entry(i: int, entry: Any, seen_names: set, seen_mounts: set,
                   roots: list[str], workspace_mount: str,
                   context: str) -> list[str]:
    """Validate one `mounts:` entry.

    `roots` are the realpath-canonicalized, configured mount_roots; a
    host_path whose realpath isn't under one of them is refused (the
    allowlist is the boundary on the cell-yaml -> host-path edge).
    """
    if not isinstance(entry, dict):
        return [f"'mounts[{i}]' must be a dict{context}"]
    import os.path as _ospath
    errors: list[str] = []

    name = entry.get("name")
    if not name or not isinstance(name, str):
        errors.append(f"'mounts[{i}].name' is required and must be a string{context}")
    elif not MOUNT_NAME_PATTERN.match(name):
        errors.append(
            f"'mounts[{i}].name' must be lowercase alphanumeric with hyphens, "
            f"max 31 chars{context}"
        )
    elif name in seen_names:
        errors.append(f"Duplicate mounts name '{name}'{context}")
    else:
        seen_names.add(name)

    host_path = entry.get("host_path")
    if not host_path or not isinstance(host_path, str):
        errors.append(f"'mounts[{i}].host_path' is required and must be a string{context}")
    elif not host_path.startswith("/"):
        errors.append(f"'mounts[{i}].host_path' must be absolute{context}")
    elif ".." in host_path.split("/"):
        errors.append(f"'mounts[{i}].host_path' must not contain '..'{context}")
    elif not roots:
        errors.append(
            f"'mounts' requires mount_roots to be configured first: "
            f"brig config set mount_roots <dir>{context}"
        )
    else:
        real = _ospath.realpath(host_path)
        if not _ospath.isdir(real):
            errors.append(f"'mounts[{i}].host_path' must be an existing directory{context}")
        elif not any(real == r or real.startswith(r + "/") for r in roots):
            errors.append(
                f"'mounts[{i}].host_path' ({real}) must resolve under a "
                f"configured mount_roots entry{context}"
            )

    errors.extend(_v_cell_mount_point(
        entry.get("mount_point"), f"mounts[{i}].mount_point",
        workspace_mount, seen_mounts, context,
    ))

    mode = entry.get("mode", "ro")
    if not isinstance(mode, str) or mode not in MOUNT_MODES:
        errors.append(
            f"'mounts[{i}].mode' must be one of: {', '.join(sorted(MOUNT_MODES))}{context}"
        )

    return errors


def _v_mounts(value: Any, cell_def: dict, context: str) -> list[str]:
    """Validate the cell's `mounts:` list as a whole."""
    if not isinstance(value, list):
        return [f"'mounts' must be a list{context}"]

    errors: list[str] = []
    if len(value) > MAX_MOUNTS_PER_CELL:
        errors.append(
            f"Too many mounts entries ({len(value)}), max {MAX_MOUNTS_PER_CELL}{context}"
        )

    if value and _profile_is_untrusted(cell_def.get("profile")):
        errors.append(
            f"'mounts' is not allowed with the untrusted profile — untrusted "
            f"cells must not have host-directory mounts{context}"
        )

    import os.path as _ospath
    from brig.config import mount_roots, validate_mount_roots
    configured = mount_roots()
    # The roots themselves must be safe (not '/', $HOME, ~/.ssh, …; unique
    # slugs) — host_path-under-a-root is necessary but not sufficient.
    if value:
        errors.extend(f"{e}{context}" for e in validate_mount_roots(configured))
    roots = [_ospath.realpath(r.rstrip("/")) for r in configured]
    workspace_mount = cell_def.get("workspace_mount", "/work")

    seen_names: set = set()
    seen_mounts: set = set()
    for i, entry in enumerate(value):
        errors.extend(
            _v_mount_entry(i, entry, seen_names, seen_mounts, roots,
                           workspace_mount, context)
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

    net = cell_def.get("network", "default")
    if isinstance(net, str) and net == "none" and value:
        errors.append(f"'ingress' cannot be used with network='none' (airgapped){context}")

    # auth: none removes brig's perimeter gate — an untrusted cell must not be
    # openly reachable without it (consistent with tls_passthrough).
    if _profile_is_untrusted(cell_def.get("profile")):
        for i, entry in enumerate(value):
            if isinstance(entry, dict) and entry.get("auth") == "none":
                errors.append(
                    f"'ingress[{i}].auth: none' is not allowed with the untrusted "
                    f"profile — untrusted cells must keep brig's token gate{context}"
                )
    return errors


_SIMPLE_VALIDATORS = {
    "name": _v_name,
    "image": _v_image,
    "command": _v_command,
    "env": _v_env,
    "secrets": _v_secrets,
    "memory": _v_memory,
    "cpus": _v_cpus,
    "pids_limit": _v_pids_limit,
    "network": _v_network,
    "workspace_quota": _v_workspace_quota,
    "workspace_mount": _v_workspace_mount,
    "writable_rootfs": _v_writable_rootfs,
    "trust_warden_ca": _v_trust_warden_ca,
    "detach": _v_detach,
    "labels": _v_labels,
    "timeout": _v_timeout,
    "seccomp_profile": _v_seccomp_profile,
    "workdir": _v_workdir,
    "image_digest": _v_image_digest,
    "restart": _v_restart,
    "user": _v_user,
}


def unknown_cell_keys(cell_def: dict[str, Any]) -> list[str]:
    """Return the cell-yaml top-level keys brig doesn't recognize, sorted.

    Known keys are the `CellSpec` fields (derived dynamically, so the set can't
    drift as fields are added/removed) plus the nested `policy:` yaml alias,
    which folds into `policy_allow`/`policy_deny`/`policy_passthrough_tls`.

    brig builds the spec by filtering cell_def to known fields, so an unknown
    key (a typo, or a stale/removed field like `host_sockets:`) is otherwise
    silently dropped. This powers a warning so the operator finds out.
    """
    import dataclasses

    from brig.cell.spec import CellSpec  # lazy: spec imports this module.
    known = {f.name for f in dataclasses.fields(CellSpec)} | {"policy"}
    return sorted(k for k in cell_def if k not in known)


def warn_unknown_cell_keys(cell_def: dict[str, Any], file_path: str = "") -> None:
    """Warn (don't fail) about unrecognized cell-yaml keys — they're ignored
    at build time, so an unflagged typo silently does nothing."""
    unknown = unknown_cell_keys(cell_def)
    if unknown:
        from brig.ops.logging import warn
        where = f" in {file_path}" if file_path else ""
        warn(
            f"ignoring unknown cell key(s){where}: {', '.join(unknown)} "
            f"(typo, or a removed field — see docs/design/cell-definition.md)"
        )


def validate_cell_definition(cell_def: dict[str, Any], file_path: str = "") -> list[str]:
    """Validate a cell definition dict and return list of errors.

    Enforces security invariants:
      - Invariant 1/6: Rejects network=proxy-external
      - Invariant 8: Rejects network=[list]
    """
    errors: list[str] = []
    context = f" in {file_path}" if file_path else ""

    if "name" not in cell_def:
        errors.append(f"'name' is required{context}")

    # Accept either the yaml-style nested `policy: {allow, deny,
    # tls_passthrough}` or the flat `policy_allow / policy_deny /
    # policy_passthrough_tls` form the SDK and CLI use. Fold flat into
    # nested once here so _v_policy has exactly one shape to reason
    # about — keeps the SDK from having to know the nested layout.
    cell_def = _fold_flat_policy_into_nested(cell_def)

    for field_name, validator in _SIMPLE_VALIDATORS.items():
        if field_name in cell_def:
            errors.extend(validator(cell_def[field_name], context))

    if "policy" in cell_def:
        errors.extend(_v_policy(cell_def["policy"], cell_def, context))

    if "ingress" in cell_def:
        errors.extend(_v_ingress(cell_def["ingress"], cell_def, context))

    if "host_services" in cell_def:
        errors.extend(_v_host_services(cell_def["host_services"], cell_def, context))

    if "mounts" in cell_def:
        errors.extend(_v_mounts(cell_def["mounts"], cell_def, context))

    return errors


def _fold_flat_policy_into_nested(cell_def: dict[str, Any]) -> dict[str, Any]:
    """Merge `policy_allow / policy_deny / policy_passthrough_tls` keys
    into a single `policy: {allow, deny, tls_passthrough}` dict.

    Returns a shallow copy when any folding happened; otherwise the
    original dict is returned unchanged (cheap for the common
    yaml-path). The flat form is what CellSpec stores and what the SDK
    accepts; the nested form is what cell yaml uses and what
    `_v_policy` reads.
    """
    flat_keys = ("policy_allow", "policy_deny", "policy_passthrough_tls")
    if not any(cell_def.get(k) for k in flat_keys):
        return cell_def
    out = dict(cell_def)
    existing = out.get("policy") or {}
    nested = dict(existing) if isinstance(existing, dict) else {}
    for flat, target in (("policy_allow", "allow"),
                          ("policy_deny", "deny"),
                          ("policy_passthrough_tls", "tls_passthrough")):
        if out.get(flat):
            nested.setdefault(target, [])
            nested[target] = list(nested[target]) + list(out[flat])
    out["policy"] = nested
    return out
