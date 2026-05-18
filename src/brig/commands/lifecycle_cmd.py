"""
CLI handlers for cell lifecycle commands.

Thin wrappers: parse args -> call domain modules -> format output.
All podman commands route through vm_run() to execute inside the Lima VM.
"""

from __future__ import annotations

import json
from typing import Any

from brig.cell.lifecycle import kill_cell, rm_cell, run_cell, stop_cell
from brig.cell.profiles import apply_profile, load_profile
from brig.cell.spec import CellSpec, load_cell_definition, validate_cell_definition
from brig.config import CONTAINER_PREFIX, PROXY_NAME, container_name
from brig.errors import BrigError
from brig.ops.logging import info, output
from brig.vm.shell import vm_run, vm_run_interactive


def cmd_run(args: Any) -> int:
    """Handle `brig run`."""
    # Catch the common foot-gun: `brig run alpine -m 512m sh` puts -m and 512m
    # into the container command instead of being parsed as a brig flag.
    # nargs=REMAINDER swallows everything after the image, so flags must
    # precede the image. If args.image looks like a flag, the user almost
    # certainly meant to put it before the image.
    if args.image and args.image.startswith("-"):
        raise BrigError(
            f"'{args.image}' looks like a flag but appears in image position",
            suggestion="Brig flags must precede the image name. Did you forget '--' "
                       "before the container command? e.g. brig run --memory 512m alpine -- sh",
        )

    # Strip leading -- from REMAINDER args.
    container_cmd = args.container_cmd or []
    if container_cmd and container_cmd[0] == "--":
        container_cmd = container_cmd[1:]

    if not args.image and not args.file:
        raise BrigError("Image is required unless --file is specified")

    # Name resolution: --name flag wins, then the yaml's name: field (if any),
    # then auto-generate. The previous order auto-generated before loading the
    # file, which made `--file foo.yaml` with `name: hermes` get an auto-name.
    spec_kwargs: dict[str, Any] = {
        "name": args.name or "",  # may be filled from yaml below
        "image": args.image or "",
        "command": container_cmd,
        "env": args.env or [],
        "secrets": args.secret or [],
        "labels": args.label or [],
        "detach": args.detach,
        "rm": args.rm,
        "image_digest": getattr(args, "image_digest", None),
        "workdir": getattr(args, "workdir", None),
    }

    if args.file:
        cell_def = load_cell_definition(args.file)
        errors = validate_cell_definition(cell_def, args.file)
        if errors:
            raise BrigError("Invalid cell definition:\n  - " + "\n  - ".join(errors))
        # Special-cased fields:
        #   - image / name: --flag wins over yaml.
        #   - command: --container_cmd (positional) wins over yaml.
        #   - env: additive — yaml entries appended to --env entries.
        # All other CellSpec-valid fields fall through to the generic merge
        # below.
        for key in ("image", "name"):
            if key in cell_def and not getattr(args, key, None):
                spec_kwargs[key] = cell_def[key]
        if "command" in cell_def and not args.container_cmd:
            cmd_val = cell_def["command"]
            spec_kwargs["command"] = cmd_val if isinstance(cmd_val, list) else [cmd_val]
        if "env" in cell_def:
            env_list = cell_def["env"]
            if isinstance(env_list, dict):
                env_list = [f"{k}={v}" for k, v in env_list.items()]
            spec_kwargs["env"] = (args.env or []) + env_list
        # Generic merge: pull any other CellSpec-valid fields from the yaml.
        # CLI flag overrides below still fire (they're `if args.flag: set`),
        # so precedence stays: CLI flag > yaml > defaults. The previous
        # behavior silently dropped yaml `memory:`, `cpus:`, `workspace_*`,
        # `secrets:`, `labels:`, etc. — even though the validator accepts
        # them and the design doc shows them as supported.
        import dataclasses as _dc
        _spec_field_names = {f.name for f in _dc.fields(CellSpec)}
        _already_handled = {"image", "name", "command", "env", "ingress"}
        for key, val in cell_def.items():
            if key in _spec_field_names and key not in _already_handled:
                spec_kwargs[key] = val

    if args.profile:
        profile = load_profile(args.profile)
        merged = apply_profile(spec_kwargs, profile)
        spec_kwargs.update(merged)

    if args.memory:
        spec_kwargs["memory"] = args.memory
    if args.cpus:
        spec_kwargs["cpus"] = args.cpus
    if args.pids_limit:
        spec_kwargs["pids_limit"] = args.pids_limit
    if args.network:
        spec_kwargs["network"] = args.network
    if args.timeout:
        spec_kwargs["timeout"] = args.timeout
    if args.workspace_quota:
        spec_kwargs["workspace_quota"] = args.workspace_quota
    if args.policy_allow:
        spec_kwargs["policy_allow"] = args.policy_allow
    if args.policy_deny:
        spec_kwargs["policy_deny"] = args.policy_deny

    # Ingress from cell definition file (no CLI flag — file-only).
    if args.file:
        if "ingress" in cell_def:
            spec_kwargs["ingress"] = cell_def["ingress"]

    # Last resort: auto-generate name if neither --name nor yaml provided one.
    if not spec_kwargs.get("name"):
        from brig.cell.names import generate_name
        spec_kwargs["name"] = generate_name()
        info(f"Auto-generated name: {spec_kwargs['name']}")

    # Filter to CellSpec fields only — profiles may add extra keys like 'runtime'.
    import dataclasses
    valid_fields = {f.name for f in dataclasses.fields(CellSpec)}
    spec_kwargs = {k: v for k, v in spec_kwargs.items() if k in valid_fields}

    spec = CellSpec(**spec_kwargs)

    from brig.ops.logging import Spinner
    with Spinner(f"Starting cell '{spec.name}'...") as spinner:
        result = run_cell(spec)
        if result.success:
            spinner.success(f"Cell '{spec.name}' started")
        else:
            spinner.fail(f"Cell '{spec.name}' failed")

    if result.container_id:
        output(result.container_id[:12])
    return 0


def cmd_stop(args: Any) -> int:
    stop_cell(args.name)
    return 0


def cmd_kill(args: Any) -> int:
    kill_cell(args.name)
    return 0


def cmd_rm(args: Any) -> int:
    rm_cell(args.name, force=args.force)
    return 0


def cmd_list(args: Any) -> int:
    result = vm_run(
        ["podman", "ps", "-a", "--format", "json", "--filter", f"name=^{CONTAINER_PREFIX}"],
    )
    if result.returncode != 0:
        return 1

    try:
        containers = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        return 1

    fmt = getattr(args, "format", "table")
    if fmt == "json":
        output(json.dumps(containers, indent=2))
        return 0

    cells = []
    for c in containers:
        names = c.get("Names", "")
        # Podman 4.x returns Names as a string; 5.x as a list.
        name = names[0] if isinstance(names, list) else names
        if name == PROXY_NAME:
            continue
        cells.append((name, c))

    if not cells:
        output("No cells found")
        return 0

    if fmt == "wide":
        output(f"{'NAME':<25} {'STATUS':<12} {'CREATED':<22} {'NETWORK':<25} {'IMAGE'}")
        for name, c in cells:
            cell = name[len(CONTAINER_PREFIX):] if name.startswith(CONTAINER_PREFIX) else name
            networks = c.get("Networks") or []
            network = ",".join(networks)[:25] if networks else "-"
            created = c.get("CreatedAt", "")[:22]
            output(f"{cell:<25} {c.get('State', ''):<12} {created:<22} {network:<25} {c.get('Image', '')}")
    else:
        output(f"{'NAME':<25} {'STATUS':<12} {'IMAGE':<30}")
        for name, c in cells:
            cell = name[len(CONTAINER_PREFIX):] if name.startswith(CONTAINER_PREFIX) else name
            output(f"{cell:<25} {c.get('State', ''):<12} {c.get('Image', ''):<30}")
    return 0


def cmd_inspect(args: Any) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "inspect", cn, "--format", "json"])
    if result.returncode != 0:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="Use 'brig list' to see available cells",
        )
    output(result.stdout)
    return 0


def cmd_files(args: Any) -> int:
    """List workspace contents inside a cell."""
    cn = container_name(args.name)
    path = getattr(args, "path", "/work")
    return vm_run_interactive(["podman", "exec", cn, "ls", "-la", path])


def cmd_logs(args: Any) -> int:
    cn = container_name(args.name)
    cmd = ["podman", "logs"]
    if getattr(args, "follow", False):
        cmd.append("-f")
    if getattr(args, "tail", None):
        cmd.extend(["--tail", str(args.tail)])
    cmd.append(cn)
    return vm_run_interactive(cmd)


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


def cmd_cp(args: Any) -> int:
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
        from brig.workspace.workspace import copy_out
        copy_out(src_target[0], src, dst, sanitize=True)
    elif dst_target:
        from brig.workspace.workspace import copy_in
        copy_in(dst_target[0], src, dst)
    else:
        raise BrigError(
            "Could not determine copy direction",
            suggestion="Use cell:path syntax, e.g.: brig cp mycell:/work/out.txt ./",
        )
    return 0


def cmd_exec(args: Any) -> int:
    cn = container_name(args.name)
    cmd = ["podman", "exec"]
    if getattr(args, "interactive", False):
        cmd.append("-it")
    cmd.append(cn)
    cmd.extend(args.exec_cmd)
    return vm_run_interactive(cmd)


def cmd_shell(args: Any) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "exec", "-it", cn, "/bin/sh"])


def cmd_attach(args: Any) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "attach", cn])


def cmd_start(args: Any) -> int:
    # Invariant 9: proxy must be running before starting cells.
    from brig.network.proxy import proxy_running
    if not proxy_running():
        raise BrigError(
            "Warden proxy is not running",
            suggestion="Start with: brig up",
        )
    cn = container_name(args.name)
    result = vm_run(["podman", "start", cn])
    if result.returncode != 0:
        raise BrigError(
            f"Failed to start cell '{args.name}': {result.stderr.strip()}",
            suggestion="Check if cell exists with: brig list",
        )
    info(f"Cell '{args.name}' started")
    return 0


def cmd_wait(args: Any) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "wait", cn], timeout=None)
    if result.returncode != 0:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="Use 'brig list' to see available cells",
        )
    exit_code = result.stdout.strip()
    output(exit_code)
    return int(exit_code) if exit_code.isdigit() else 1


def cmd_pause(args: Any) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "pause", cn])
    if result.returncode != 0:
        raise BrigError(f"Failed to pause cell '{args.name}': {result.stderr.strip()}")
    info(f"Cell '{args.name}' paused")
    return 0


def cmd_unpause(args: Any) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "unpause", cn])
    if result.returncode != 0:
        raise BrigError(f"Failed to unpause cell '{args.name}': {result.stderr.strip()}")
    info(f"Cell '{args.name}' unpaused")
    return 0


def cmd_rename(args: Any) -> int:
    from brig.config import CELL_NAME_PATTERN
    if not CELL_NAME_PATTERN.match(args.new_name):
        raise BrigError(
            f"Invalid cell name '{args.new_name}': must match {CELL_NAME_PATTERN.pattern}",
            suggestion="Cell names: lowercase alphanumeric, hyphens, dots, max 63 chars",
        )
    old_cn = container_name(args.old_name)
    new_cn = container_name(args.new_name)
    result = vm_run(["podman", "rename", old_cn, new_cn])
    if result.returncode != 0:
        raise BrigError(f"Failed to rename: {result.stderr.strip()}")
    info(f"Renamed '{args.old_name}' to '{args.new_name}'")
    return 0


def cmd_top(args: Any) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "top", cn])


def cmd_diff(args: Any) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "diff", cn])


def cmd_stats(args: Any) -> int:
    cmd = ["podman", "stats", "--no-stream"]
    if hasattr(args, "name") and args.name:
        cmd.append(container_name(args.name))
    else:
        cmd.extend(["--filter", f"name=^{CONTAINER_PREFIX}"])
    return vm_run_interactive(cmd)


def cmd_export(args: Any) -> int:
    """Export a running cell's config as a reusable YAML cell definition."""
    cn = container_name(args.name)
    result = vm_run(["podman", "inspect", cn, "--format", "json"])
    if result.returncode != 0:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="Use 'brig list' to see available cells",
        )

    try:
        data = json.loads(result.stdout)
        if isinstance(data, list):
            data = data[0]
    except json.JSONDecodeError:
        raise BrigError("Could not parse container info")

    # Extract cell definition from container inspect.
    host_config = data.get("HostConfig", {})
    config = data.get("Config", {})

    cell_def = {"name": args.name}

    image = config.get("Image", "")
    if image:
        cell_def["image"] = image

    cmd = config.get("Cmd")
    if cmd:
        cell_def["command"] = cmd

    # Extract non-proxy env vars.
    proxy_prefixes = ("http_proxy=", "https_proxy=", "HTTP_PROXY=", "HTTPS_PROXY=", "no_proxy=")
    env_vars = [
        e for e in (config.get("Env") or [])
        if not any(e.startswith(p) for p in proxy_prefixes)
        and not e.endswith("_FILE=/run/secrets/" + e.split("=")[0].replace("_FILE", "").lower())
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

    # Output as YAML-like format (no pyyaml dependency needed for output).
    output(f"# Cell definition exported from '{args.name}'")
    output(f"# Save as: {args.name}.yaml")
    output(f"# Run with: brig run --file {args.name}.yaml")
    output("")
    for key, val in cell_def.items():
        if isinstance(val, list):
            output(f"{key}:")
            for item in val:
                output(f"  - {json.dumps(item) if not isinstance(item, str) else item}")
        elif isinstance(val, dict):
            output(f"{key}:")
            for k, v in val.items():
                output(f"  {k}: {v}")
        else:
            output(f"{key}: {val}")

    return 0
