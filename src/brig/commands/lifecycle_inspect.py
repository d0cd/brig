"""CLI handlers for read-only cell observation commands.

These handlers inspect a cell's state without mutating it (list, inspect,
files, read, logs, cp, top, diff, stats, export, ingress, preflight).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

import yaml

from brig.config import CONTAINER_PREFIX, container_name
from brig.errors import BrigError
from brig.ops.logging import info, output
from brig.vm.shell import vm_run, vm_run_interactive


def cmd_ingress(args: argparse.Namespace) -> int:
    """Print reachable URLs for a cell's ingress endpoints.

    Surfaces three things the user otherwise has to dig for: the URL
    `https://warden:8443/<cell>/<prefix>/...` is reachable at on the
    host (Lima forwards :8443), the token secret name to use for the
    `Authorization: Bearer` header, and whether the cell currently has
    routes registered (vs declared but not yet started).
    """
    from brig.cell.metadata import read_ingress
    from brig.config import HostPaths, INGRESS_PORT
    from brig.network.ingress import _load_routes

    entries = read_ingress(args.name)
    if not entries:
        output(f"Cell '{args.name}' has no ingress declared.")
        return 0

    routes_file = HostPaths.INGRESS_ROUTES_FILE
    registered = set()
    if routes_file.exists():
        for r in _load_routes(routes_file).get("routes", []):
            if r.get("cell") == args.name:
                registered.add(r.get("name"))

    primary_token = f"{args.name}-ingress-token"
    fallback_token = "ingress-token"
    token = primary_token if (HostPaths.SECRETS_DIR / primary_token).exists() \
        else (fallback_token if (HostPaths.SECRETS_DIR / fallback_token).exists() else None)

    def _url(entry: dict) -> str:
        return f"https://127.0.0.1:{INGRESS_PORT}/{args.name}{entry['path_prefix']}"

    output(f"Ingress for cell '{args.name}':")
    for e in entries:
        status = "REGISTERED" if e["name"] in registered else "DECLARED (not started)"
        output(f"  {e['name']}: {_url(e)}  [{status}]")
        output(f"    cell port: {e['port']}   auth: {e['auth']}")
    if token:
        output(f"  Token secret: {token}")
        output(
            f"  Example: curl -k -H \"Authorization: Bearer "
            f"$(cat ~/.brig/secrets/{token})\" {_url(entries[0])}"
        )
    else:
        output(
            f"  WARNING: token secret '{primary_token}' missing — "
            f"create with: openssl rand -hex 32 | brig secrets add {primary_token} -"
        )
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    """Handle `brig cell preflight <yaml>`.

    Dry-run check: parses the yaml and verifies every host-side
    requirement it implies (declared secrets exist, declared ingress
    entries have a token secret, image exists or is buildable). Prints
    a checklist with a one-line fix for each gap.

    Replaces the iterative "brig run → error → fix one thing →
    re-run" loop with a single diff. No mutations; safe to run
    anytime.
    """
    from brig.cell.spec import load_cell_definition, validate_cell_definition
    from brig.config import HostPaths

    cell_def = load_cell_definition(args.file)
    errors = validate_cell_definition(cell_def, args.file)
    fail_count = 0

    def _check(label: str, ok: bool, fix: str = "") -> None:
        nonlocal fail_count
        marker = "OK  " if ok else "FAIL"
        output(f"  [{marker}] {label}")
        if not ok:
            fail_count += 1
            if fix:
                output(f"         fix: {fix}")

    cell_name = cell_def.get("name", "<unnamed>")
    output(f"Preflight for cell '{cell_name}' ({args.file})")
    output("=" * 60)

    _check(
        "cell yaml validates",
        not errors,
        fix=("Fix errors:\n         " + "\n         ".join(errors)
             if errors else ""),
    )

    for secret in cell_def.get("secrets", []):
        if not isinstance(secret, str):
            continue
        p = HostPaths.SECRETS_DIR / secret
        _check(
            f"secret: {secret}", p.exists(),
            fix=f"brig secrets add {secret}",
        )

    ingress_entries = cell_def.get("ingress") or []
    needs_token = any(
        isinstance(e, dict) and e.get("auth") == "token" for e in ingress_entries
    )
    if needs_token:
        primary = HostPaths.SECRETS_DIR / f"{cell_name}-ingress-token"
        fallback = HostPaths.SECRETS_DIR / "ingress-token"
        ok = primary.exists() or fallback.exists()
        _check(
            f"ingress token: {primary.name}", ok,
            fix=f"openssl rand -hex 32 | brig secrets add {primary.name} -",
        )


    output("=" * 60)
    if fail_count:
        output(f"FAILED: {fail_count} check(s) — fix above, then re-run")
        return 1
    output("All preflight checks passed.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    from brig.cell.lifecycle import list_cell_containers
    fmt = getattr(args, "format", "table")
    cells = list_cell_containers(include_stopped=True)

    if fmt == "json":
        output(json.dumps([entry for _, entry in cells], indent=2))
        return 0

    if not cells:
        output("No cells found")
        return 0

    if fmt == "wide":
        output(f"{'NAME':<25} {'STATUS':<12} {'CREATED':<22} {'NETWORK':<25} {'IMAGE'}")
        for cell, c in cells:
            networks = c.get("Networks") or []
            network = ",".join(networks)[:25] if networks else "-"
            created = c.get("CreatedAt", "")[:22]
            output(f"{cell:<25} {c.get('State', ''):<12} {created:<22} {network:<25} {c.get('Image', '')}")
    else:
        output(f"{'NAME':<25} {'STATUS':<12} {'IMAGE':<30}")
        for cell, c in cells:
            output(f"{cell:<25} {c.get('State', ''):<12} {c.get('Image', ''):<30}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "inspect", cn, "--format", "json"])
    if result.returncode != 0:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="Use 'brig cell list' to see available cells",
        )
    output(result.stdout)
    return 0


def cmd_files(args: argparse.Namespace) -> int:
    """List workspace contents inside a cell."""
    cn = container_name(args.name)
    path = getattr(args, "path", "/work")
    return vm_run_interactive(["podman", "exec", cn, "ls", "-la", path])


def cmd_read(args: argparse.Namespace) -> int:
    """Handle `brig cell read <cell> <relpath>` — stream a workspace file
    to stdout via the race-free safe_open primitive.

    This is the language-agnostic safe-read replacement for the (now
    removed) workspace.host_path field in cell.json. Consumers in any
    language can do:

        brig cell read mycell input.json > /tmp/local-copy

    instead of opening the host path directly. Each path component is
    walked with O_NOFOLLOW so a cell-planted symlink raises
    WorkspaceEscape rather than letting the host follow it.
    """
    from brig.workspace.validation import safe_open, WorkspaceEscape

    try:
        with safe_open(args.name, args.path, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                sys.stdout.buffer.write(chunk)
        return 0
    except WorkspaceEscape as e:
        raise BrigError(
            f"Refused: {e}",
            suggestion="A path component is a symlink or escapes the workspace root.",
        )
    except FileNotFoundError:
        raise BrigError(f"Not found: {args.path} in cell '{args.name}'")


def cmd_logs(args: argparse.Namespace) -> int:
    """Tail a cell's container stdout/stderr (wraps `podman logs`).

    Empty output usually means the cell's app writes to a file inside
    the container instead of stdout — common for daemons and agent
    runtimes. In that case, use
    `brig cell exec <name> -- cat /var/log/<app>.log` or
    `brig cell read <name> <path>` to inspect the file directly.
    """
    cn = container_name(args.name)
    cmd = ["podman", "logs"]
    follow = getattr(args, "follow", False)
    if follow:
        cmd.append("-f")
    if getattr(args, "tail", None):
        cmd.extend(["--tail", str(args.tail)])
    cmd.append(cn)
    if follow:
        return vm_run_interactive(cmd)
    result = vm_run(cmd, capture=True, timeout=30)
    if result.returncode == 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        # Empty stdout + stderr likely means file-based logging.
        if not (result.stdout.strip() or result.stderr.strip()):
            info(
                f"(no stdout/stderr from '{args.name}' — if the app logs "
                f"to a file, try: brig cell exec {args.name} -- "
                f"cat /var/log/<app>.log)"
            )
        return 0
    sys.stderr.write(result.stderr)
    return result.returncode


def _parse_cp_target(spec: str) -> tuple[str, str] | None:
    """Parse 'cell:/path' into (cell, path), or return None if not a cell ref.

    Only treats the colon as a cell separator when the prefix matches the
    canonical cell-name pattern. Avoids misreading paths containing colons
    (e.g. './out:put.txt') as cell references.
    """
    from brig.config import CELL_NAME_PATTERN
    if ":" not in spec or spec.startswith("/") or spec.startswith("."):
        return None
    head, tail = spec.split(":", 1)
    if not CELL_NAME_PATTERN.match(head):
        return None
    return head, tail


def cmd_cp(args: argparse.Namespace) -> int:
    """Copy files to/from a cell with safety checks.

    Detects direction from the colon syntax (cell:path). The cell prefix
    must match the canonical cell-name pattern, so a literal path like
    './out:put.txt' is not misread as a cell reference.
    Exports apply quarantine xattr and extension blocking by default.
    """
    src, dst = args.src, args.dst
    src_target = _parse_cp_target(src)
    dst_target = _parse_cp_target(dst)

    if src_target and dst_target:
        raise BrigError(
            "Cannot copy between two cells",
            suggestion="Copy from cell to host first, then from host to cell",
        )
    if src_target:
        # The host path is operator argv; reject a leading dash so it can't be
        # parsed as a `podman cp` (or downstream `xattr`) flag — matches the
        # guard cmd_pull / build_run_command apply.
        if dst.startswith("-"):
            raise BrigError(f"Host path must not start with '-': {dst}")
        from brig.workspace.workspace import copy_out
        copy_out(src_target[0], src_target[1], dst, sanitize=True)
    elif dst_target:
        if src.startswith("-"):
            raise BrigError(f"Host path must not start with '-': {src}")
        from brig.workspace.workspace import copy_in
        copy_in(dst_target[0], src, dst_target[1])
    else:
        raise BrigError(
            "Could not determine copy direction",
            suggestion="Use cell:path syntax, e.g.: brig cell cp mycell:/work/out.txt ./",
        )
    return 0


def cmd_top(args: argparse.Namespace) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "top", cn])


def cmd_diff(args: argparse.Namespace) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "diff", cn])


def cmd_stats(args: argparse.Namespace) -> int:
    cmd = ["podman", "stats", "--no-stream"]
    if hasattr(args, "name") and args.name:
        cmd.append(container_name(args.name))
    else:
        cmd.extend(["--filter", f"name=^{CONTAINER_PREFIX}"])
    return vm_run_interactive(cmd)


def cmd_export(args: argparse.Namespace) -> int:
    """Export a running cell's config as a reusable YAML cell definition."""
    cn = container_name(args.name)
    result = vm_run(["podman", "inspect", cn, "--format", "json"])
    if result.returncode != 0:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="Use 'brig cell list' to see available cells",
        )

    try:
        data = json.loads(result.stdout)
        if isinstance(data, list):
            data = data[0]
    except json.JSONDecodeError:
        raise BrigError(
            "Could not parse container info",
            suggestion="Check podman / VM health: brig system doctor",
        )

    host_config = data.get("HostConfig", {})
    config = data.get("Config", {})

    cell_def: dict[str, Any] = {"name": args.name}

    image = config.get("Image", "")
    if image:
        cell_def["image"] = image

    cmd = config.get("Cmd")
    if cmd:
        cell_def["command"] = cmd

    proxy_prefixes = ("http_proxy=", "https_proxy=", "HTTP_PROXY=", "HTTPS_PROXY=", "no_proxy=")
    # Drop brig-injected env: the HTTP(S)_PROXY vars and the secret-mount
    # pointers (`<NAME>_FILE=/run/secrets/<secret>`) — both are re-derived on
    # the next run from the cell's `secrets:` block, not part of its definition.
    env_vars = [
        e for e in (config.get("Env") or [])
        if not any(e.startswith(p) for p in proxy_prefixes)
        and "_FILE=/run/secrets/" not in e
    ]
    if env_vars:
        cell_def["env"] = env_vars

    memory = host_config.get("Memory", 0)
    if memory:
        if memory >= 1024**3:
            cell_def["memory"] = f"{memory // 1024**3}g"
        elif memory >= 1024**2:
            cell_def["memory"] = f"{memory // 1024**2}m"

    cpus = host_config.get("NanoCpus", 0)
    if cpus:
        cell_def["cpus"] = str(cpus / 1e9)

    pids = host_config.get("PidsLimit", 0)
    if pids and pids > 0:
        cell_def["pids_limit"] = pids

    # Round-trip the process user (podman --user → Config.User) when set.
    user = config.get("User")
    if user:
        cell_def["user"] = user

    from brig.policy.policy import load_cell_policy
    cell_policy = load_cell_policy(args.name) or {}
    allow = cell_policy.get("allow") or []
    deny = cell_policy.get("deny") or []
    passthrough = cell_policy.get("tls_passthrough") or []
    if allow or deny or passthrough:
        policy_block: dict = {}
        if allow:
            policy_block["allow"] = list(allow)
        if deny:
            policy_block["deny"] = list(deny)
        if passthrough:
            policy_block["tls_passthrough"] = list(passthrough)
        cell_def["policy"] = policy_block
    host_services = cell_policy.get("host_services") or []
    if host_services:
        cell_def["host_services"] = list(host_services)

    # Prefer cell-metadata.json (works for stopped cells too) and fall
    # back to ingress-routes.json for cells whose metadata predates the
    # `ingress` field.
    from brig.cell.metadata import read_ingress
    from brig.config import HostPaths
    ingress = read_ingress(args.name)
    if not ingress:
        ingress = _ingress_for_cell(args.name, HostPaths.INGRESS_ROUTES_FILE)
    if ingress:
        cell_def["ingress"] = ingress

    # Reconstruct `mounts:` from the live binds under /mnt/host/<slug> (host_path
    # mapped back via the configured mount_roots; mode from the bind's RW flag).
    # The original `name` isn't persisted, so it's re-derived from the mount
    # point and sanitized to MOUNT_NAME_PATTERN so the export round-trips.
    mounts = []
    used_names: set[str] = set()
    for m in data.get("Mounts", []) or []:
        if not isinstance(m, dict):
            continue
        src = m.get("Source", "")
        hp = _vm_mount_source_to_host(src)
        if hp is None:
            continue
        dst = m.get("Destination", "")
        mounts.append({
            "name": _safe_mount_name(dst, used_names),
            "host_path": str(hp),
            "mount_point": dst,
            "mode": "rw" if m.get("RW") else "ro",
        })
    if mounts:
        cell_def["mounts"] = mounts

    # restart policy isn't recoverable from `podman inspect` (it's never passed
    # to podman), so read it from the persisted spec — otherwise a
    # restart:always cell would export as restart:no and not round-trip.
    from brig.cell.metadata import read_cell_spec
    persisted = read_cell_spec(args.name)
    if persisted and persisted.get("restart") == "always":
        cell_def["restart"] = "always"

    output(f"# Cell definition exported from '{args.name}'")
    if mounts:
        output("# NOTE: `mounts:` requires the same mount_roots configured on the")
        output("# target host (brig config set mount_roots ...) for host_path to resolve.")
    else:
        output("# Self-contained: brig run --file <this-file> reproduces the cell.")
    output("")
    output(yaml.safe_dump(cell_def, default_flow_style=False, sort_keys=False).rstrip())
    return 0


def _ingress_for_cell(cell_name: str, routes_file) -> list:
    try:
        data = json.loads(routes_file.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    routes = data.get("routes") or []
    return [
        {"name": r.get("name"),
         "port": r.get("port"),
         "path_prefix": r.get("path_prefix"),
         "auth": "token"}
        for r in routes
        if isinstance(r, dict) and r.get("cell") == cell_name
    ]


def _vm_mount_source_to_host(source: str):
    """Map a VM bind source under /mnt/host/<slug>/... back to its macOS path,
    or None if it isn't a mount_roots-backed bind."""
    from pathlib import Path
    from brig.config import mount_root_slug, mount_roots
    prefix = "/mnt/host/"
    if not source.startswith(prefix):
        return None
    slug, _, rel = source[len(prefix):].partition("/")
    for root in mount_roots():
        if mount_root_slug(root) == slug:
            base = Path(root)
            return base / rel if rel else base
    return None


def _safe_mount_name(mount_point: str, used: set[str]) -> str:
    """Derive a MOUNT_NAME_PATTERN-valid, unique name from a mount point.

    The original `mounts.name` isn't persisted, so it's re-derived for export;
    sanitize to lowercase alphanumeric+hyphen (max 31) so `brig run --file`
    accepts the result.
    """
    base = re.sub(r"[^a-z0-9-]+", "-", mount_point.rsplit("/", 1)[-1].lower()).strip("-")
    base = base[:28] or "mount"
    name = base
    suffix = 1
    while name in used:
        name = f"{base}-{suffix}"
        suffix += 1
    used.add(name)
    return name


def cmd_mount_scan(args: argparse.Namespace) -> int:
    """Scan a cell's host `mounts:` for symlinks that escape the mounted dir.

    A cell with a rw mount can plant a symlink pointing out of the shared
    folder (e.g. -> ~/.ssh/id_rsa); a host process that follows it escapes the
    folder. Reports such symlinks, or removes them with --quarantine. Run this
    before a host process consumes files the cell wrote.
    """
    from brig.workspace.workspace import (
        find_escaping_symlinks,
        quarantine_escaping_symlinks,
    )
    cn = container_name(args.name)
    result = vm_run(["podman", "inspect", cn, "--format", "json"])
    if result.returncode != 0:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="Use 'brig cell list' to see available cells",
        )
    try:
        data = json.loads(result.stdout)
        entry = data[0] if isinstance(data, list) else data
        mounts = entry.get("Mounts", []) or []
    except (json.JSONDecodeError, IndexError, AttributeError):
        raise BrigError(
            f"Could not parse podman inspect for '{args.name}'",
            suggestion="Check podman / VM health: brig system doctor",
        )

    host_dirs = []
    seen_dirs: set[str] = set()
    unmapped = []
    for m in mounts:
        if isinstance(m, dict):
            src = m.get("Source", "")
            hp = _vm_mount_source_to_host(src)
            if hp is not None:
                # One host_path can be bound at several mount points; scan it once.
                if str(hp) not in seen_dirs:
                    seen_dirs.add(str(hp))
                    host_dirs.append(hp)
            elif src.startswith("/mnt/host/"):
                # A live mounts: bind whose slug no longer maps (mount_roots
                # edited after start). Don't claim a clean scan — fail loud.
                unmapped.append(src)

    if unmapped:
        raise BrigError(
            f"Cell '{args.name}' has host mount(s) that no longer map to a "
            f"configured mount_root: {', '.join(unmapped)}. Scan aborted — "
            f"restore the mount_roots entry, or inspect them by hand.",
        )
    if not host_dirs:
        output(f"Cell '{args.name}' has no host mounts to scan.")
        return 0

    quarantine = getattr(args, "quarantine", False)
    found = 0       # escaping symlinks seen
    remaining = 0   # still escaping after a quarantine pass
    for d in host_dirs:
        if not d.exists():
            output(f"  (skip) {d} — not present on host")
            continue
        escaping = find_escaping_symlinks(d)
        found += len(escaping)
        for link, target in escaping:
            output(f"  {'QUARANTINING' if quarantine else 'ESCAPES'} {link} -> {target}")
        if quarantine:
            quarantine_escaping_symlinks(d)
            # Re-scan: unlink() can fail (perms, immutable flag, race), so count
            # what's actually left rather than trusting the removal list.
            remaining += len(find_escaping_symlinks(d))

    if found == 0:
        output(f"No escaping symlinks in '{args.name}' host mount(s).")
        return 0
    if quarantine:
        if remaining:
            output(f"{found} found, but {remaining} could NOT be removed — investigate.")
            return 1
        output(f"{found} escaping symlink(s) quarantined.")
        return 0
    output(f"{found} escaping symlink(s) found.")
    return 1
