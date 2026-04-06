"""Inspect commands: logs, exec, shell, attach, top, diff, stats, inspect, export."""

import json

import brig.commands._helpers as _helpers
from brig.commands._helpers import (
    CONTAINER_PREFIX,
    cell_exists,
    cell_running,
    container_name,
    error,
    error_cell_not_found,
    error_cell_not_running,
    load_cell_policy,
    output,
    print_error,
    run,
    validate_cell_name,
)


def cmd_logs(args) -> int:
    """View cell logs."""
    cell_name = args.name
    validate_cell_name(cell_name)

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
    validate_cell_name(cell_name)

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
    return int(result.returncode)


def cmd_shell(args) -> int:
    """Open interactive shell in a running cell."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    if not cell_running(cell_name):
        error_cell_not_running(cell_name)

    shell_cmd = getattr(args, "shell_cmd", "/bin/sh")

    cmd = ["podman", "exec", "-it", container_name(cell_name), shell_cmd]

    try:
        result = run(cmd, check=False)
        return int(result.returncode)
    except KeyboardInterrupt:
        return 0


def cmd_attach(args) -> int:
    """Attach to a cell's console."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    if not cell_running(cell_name):
        error_cell_not_running(cell_name)

    # Attach to container.
    cmd = ["podman", "attach", container_name(cell_name)]

    try:
        result = run(cmd, check=False)
        return int(result.returncode)
    except KeyboardInterrupt:
        return 0


def cmd_top(args) -> int:
    """Show processes running inside a cell."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    if not cell_running(cell_name):
        error_cell_not_running(cell_name)

    cmd = ["podman", "top", container_name(cell_name)]
    result = run(cmd, check=False)
    return int(result.returncode)


def cmd_diff(args) -> int:
    """Show filesystem changes from base image."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    cmd = ["podman", "diff"]
    if args.format == "json":
        cmd.append("--format=json")
    cmd.append(container_name(cell_name))

    result = run(cmd, check=False, capture=True)
    if result.returncode != 0:
        print_error(result.stderr.strip(), "Ensure the cell exists: brig list")
        return int(result.returncode)

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
    # Validate cell name if provided.
    if args.name:
        validate_cell_name(args.name)

    # JSON output mode uses podman's JSON format.
    if getattr(args, "output", "text") == "json":
        cmd = ["podman", "stats", "--format", "json", "--no-stream"]
        if args.name:
            if not cell_exists(args.name):
                error_cell_not_found(args.name)
            cmd.append(container_name(args.name))
        else:
            cmd.extend(["--filter", f"name={CONTAINER_PREFIX}"])
        result = run(cmd, check=False, capture=True)
        if result.returncode != 0:
            error(
                f"Failed to get stats: {result.stderr}",
                "Check cell status with: brig list"
            )
        try:
            stats = json.loads(result.stdout) if result.stdout.strip() else []
            # Strip container prefix from names.
            for s in stats:
                name = s.get("name", s.get("Name", ""))
                if name.startswith(CONTAINER_PREFIX):
                    s["cell"] = name[len(CONTAINER_PREFIX):]
            output(json.dumps(stats, indent=2))
        except json.JSONDecodeError:
            output(result.stdout)
        return 0

    cmd = ["podman", "stats", "--format",
           "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.PIDs}}"]

    if args.no_stream:
        cmd.append("--no-stream")

    if args.name:
        if not cell_exists(args.name):
            error_cell_not_found(args.name)
        cmd.append(container_name(args.name))
    else:
        # Filter to only cell containers.
        cmd.extend(["--filter", f"name={CONTAINER_PREFIX}"])

    try:
        result = run(cmd, check=False)
        return int(result.returncode)
    except KeyboardInterrupt:
        return 0


def cmd_inspect(args) -> int:
    """Show cell details."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    # Get container details.
    result = run(
        ["podman", "inspect", container_name(cell_name), "--format", "json"],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(
            f"Failed to inspect cell: {result.stderr}",
            "Check cell status with: brig list"
        )

    try:
        data = json.loads(result.stdout)
        if not data:
            error(
                "No container data returned",
                "Run with --debug for more details"
            )
        container = data[0]
    except (json.JSONDecodeError, IndexError) as e:
        error(
            f"Failed to parse container data: {e}",
            f"Try: brig rm -f {cell_name}"
        )

    if args.format == "json":
        output(json.dumps(container, indent=2))
    else:
        # Table format.
        name = container.get("Name", "").lstrip("/")
        state = container.get("State", {})
        config = container.get("Config", {})
        host_config = container.get("HostConfig", {})
        networks = container.get("NetworkSettings", {}).get("Networks", {})

        output(f"Name:    {name}")
        output(f"Status:  {state.get('Status', 'unknown')}")
        output(f"Runtime: {host_config.get('Runtime', 'unknown')}")
        output(f"Image:   {config.get('Image', 'unknown')}")
        output(f"Network: {', '.join(networks.keys())}")
        output(f"Pid:     {state.get('Pid', 'N/A')}")

        # Show mounts.
        mounts = container.get("Mounts", [])
        if mounts:
            output("Mounts:")
            for m in mounts:
                src = m.get("Source", "")
                dst = m.get("Destination", "")
                rw = "rw" if m.get("RW", True) else "ro"
                output(f"  {src} -> {dst} ({rw})")

    return 0


def cmd_export(args) -> int:
    """Export cell definition as YAML."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    # Get container details.
    result = run(
        ["podman", "inspect", container_name(cell_name), "--format", "json"],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(
            f"Failed to inspect cell: {result.stderr}",
            "Check cell status with: brig list"
        )

    try:
        data = json.loads(result.stdout)
        if not data:
            error(
                "No container data returned",
                "Run with --debug for more details"
            )
        container = data[0]
    except (json.JSONDecodeError, IndexError) as e:
        error(
            f"Failed to parse container data: {e}",
            f"Try: brig rm -f {cell_name}"
        )

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
        if _helpers.YAML_AVAILABLE:
            import yaml  # type: ignore[import-untyped]
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
