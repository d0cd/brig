"""Per-field validators for cell definitions.

Each `_v_<field>` returns a list of error strings (possibly empty).
`validate_cell_definition` dispatches to these by key.

Validators import `parse_size` from spec but spec never imports back from
this module — keep that direction one-way to avoid circular imports.
"""

from __future__ import annotations

import re
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
    if value == "/":
        return [f"'workspace_mount' must not be '/' (shadows rootfs){context}"]
    forbidden_prefixes = (
        "/proc", "/sys", "/dev", "/run/secrets", "/etc",
        # /run/host and /run/brig are the bind-mount roots for
        # host_sockets and the downward-API metadata / CA bundle.
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


def _v_host_socket_entry(
    i: int, entry: Any, seen_names: set, seen_mounts: set, context: str,
) -> list[str]:
    """Validate one host_socket entry. Mutates seen_* to track duplicates.

    Static checks only — the runtime check happens in the reconciler at
    cell start, where TOCTOU is unavoidable anyway.
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
        # the host.
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
    """Validate the cell's host_sockets list as a whole."""
    if not isinstance(value, list):
        return [f"'host_sockets' must be a list{context}"]

    errors: list[str] = []
    if len(value) > MAX_HOST_SOCKETS_PER_CELL:
        errors.append(
            f"Too many host_sockets entries ({len(value)}), "
            f"max {MAX_HOST_SOCKETS_PER_CELL}{context}"
        )

    if value and _profile_is_untrusted(cell_def.get("profile")):
        errors.append(
            f"'host_sockets' is not allowed with the untrusted profile — "
            f"untrusted cells must not have side channels to host services"
            f"{context}"
        )

    # Cell name with dots breaks launchd label parsing.
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

    # Reject TCP services on warden's reserved ports.
    if protocol == "tcp" and isinstance(port, int):
        try:
            from warden.proxy import WARDEN_RESERVED_PORTS
            reserved = WARDEN_RESERVED_PORTS
        except ImportError:
            reserved = frozenset({8080, 8443})
        if port in reserved:
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
}


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

    for field_name, validator in _SIMPLE_VALIDATORS.items():
        if field_name in cell_def:
            errors.extend(validator(cell_def[field_name], context))

    if "policy" in cell_def:
        errors.extend(_v_policy(cell_def["policy"], cell_def, context))

    if "ingress" in cell_def:
        errors.extend(_v_ingress(cell_def["ingress"], cell_def, context))

    if "host_sockets" in cell_def:
        errors.extend(_v_host_sockets(cell_def["host_sockets"], cell_def, context))

    if "host_services" in cell_def:
        errors.extend(_v_host_services(cell_def["host_services"], cell_def, context))

    return errors
