"""Lifecycle commands: run, stop, kill, wait, rm, start, list, pause, unpause, rename, checkpoint, restore."""

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

import brig.commands._helpers as _helpers
from brig.commands._helpers import (
    BRIG_SUBNET_BIN,
    CONTAINER_PREFIX,
    PROXY_NAME,
    RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW,
    RUNTIME,
    Spinner,
    _apply_profile,
    cell_exists,
    cell_running,
    check_rate_limit,
    container_name,
    debug,
    delete_cell_policy,
    error,
    error_cell_already_exists,
    error_cell_not_found,
    error_cell_not_running,
    error_cell_running,
    error_proxy_not_running,
    get_proxy_ip,
    invalidate_cell_cache,
    load_cell_definition,
    load_cell_policy,
    log_lifecycle,
    log_operation,
    network_name,
    output,
    parse_duration,
    print_error,
    proxy_running,
    run,
    save_cell_policy,
    status_color,
    validate_cell_definition,
    validate_cell_name,
    verify_image_signature,
    warn,
)


def _merge_cell_def_into_args(args, cell_def: dict) -> None:
    """Merge cell definition fields into args, preserving CLI overrides.

    Fields from the cell definition only apply if not already set by CLI flags.
    Lists (env, secrets, labels, policy) are appended rather than replaced.
    """
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
    if "tor" in cell_def and not getattr(args, "tor", False):
        args.tor = cell_def["tor"]
    if "workspace_quota" in cell_def and not getattr(args, "workspace_quota", None):
        args.workspace_quota = cell_def["workspace_quota"]
    if "detach" in cell_def and not getattr(args, "detach", False):
        args.detach = cell_def["detach"]
    if "timeout" in cell_def and not getattr(args, "timeout", None):
        args.timeout = cell_def["timeout"]
    if "network" in cell_def and getattr(args, "network", None) is None:
        args.network = cell_def["network"]
    if "labels" in cell_def:
        args.label = (args.label or []) + [
            f"{k}={v}" for k, v in cell_def["labels"].items()
        ]


def _build_run_command(args, cell_name: str, airgapped: bool, net_name: str | None,
                       proxy_ip: str | None, timeout_seconds: int | None,
                       cleanup_on_failure) -> list:
    """Build the podman run command for a cell.

    Returns the full command list. Calls cleanup_on_failure on validation errors.
    """
    cmd = [
        "podman", "run",
        "--name", container_name(cell_name),
        "--runtime", RUNTIME,
    ]

    if airgapped:
        # Air-gapped: no network at all.
        cmd.extend(["--network", "none"])
    else:
        assert net_name is not None  # Guaranteed by caller for non-airgapped.
        cmd.extend([
            "--network", net_name,

            # Proxy environment variables.
            "-e", f"http_proxy=http://{proxy_ip}:8080",
            "-e", f"https_proxy=http://{proxy_ip}:8080",
            "-e", f"HTTP_PROXY=http://{proxy_ip}:8080",
            "-e", f"HTTPS_PROXY=http://{proxy_ip}:8080",
            "-e", "no_proxy=localhost,127.0.0.1",
        ])

    # Security hardening.
    cmd.extend(["--cap-drop", "ALL", "--security-opt", "no-new-privileges"])

    # Resource limits.
    cmd.extend([
        "--memory", args.memory,
        "--cpus", args.cpus,
        "--pids-limit", str(args.pids_limit),
    ])

    # Timeout: Podman --timeout flag kills container after N seconds.
    if timeout_seconds:
        cmd.extend(["--timeout", str(timeout_seconds)])

    # Labels for orchestration metadata.
    if getattr(args, "label", None):
        for label in args.label:
            if "=" not in label:
                cleanup_on_failure(
                    f"Invalid label format: {label}",
                    "Labels must be key=value format"
                )
            cmd.extend(["--label", label])

    # Seccomp profile (defense-in-depth on top of gVisor).
    if not getattr(args, "no_seccomp", False):
        seccomp_profile = getattr(args, "seccomp_profile", None)
        if seccomp_profile is None:
            # Use built-in default profile.
            default_profile = Path(__file__).parent.parent.parent / "seccomp" / "default.json"
            if default_profile.exists():
                seccomp_profile = str(default_profile)
        if seccomp_profile:
            profile_path = Path(seccomp_profile)
            if not profile_path.exists():
                cleanup_on_failure(f"Seccomp profile not found: {seccomp_profile}")
            # Validate it's valid JSON.
            try:
                with open(profile_path, "r") as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                cleanup_on_failure(f"Invalid seccomp profile JSON: {e}")
            cmd.extend(["--security-opt", f"seccomp={profile_path.absolute()}"])
            debug(f"Applying seccomp profile: {profile_path}")

    # Detach mode.
    if args.detach:
        cmd.append("-d")

    # Auto-remove.
    if args.rm:
        cmd.append("--rm")

    # Additional environment variables.
    # Process user env vars BEFORE proxy setup would matter, but reject
    # proxy-related overrides to prevent bypassing Warden.
    _PROXY_ENV_NAMES = {"http_proxy", "https_proxy", "no_proxy", "all_proxy", "ftp_proxy"}
    if args.env:
        for env in args.env:
            env_key = env.split("=", 1)[0].lower() if "=" in env else env.lower()
            if env_key in _PROXY_ENV_NAMES:
                cleanup_on_failure(
                    f"Cannot override proxy environment variable: {env.split('=', 1)[0]}",
                    "Proxy configuration is managed by Brig and cannot be overridden"
                )
            cmd.extend(["-e", env])

    # Workspace mount (each cell gets its own, never shared).
    workspace_dir = _helpers.STATE_DIR / cell_name / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    cmd.extend(["-v", f"{workspace_dir}:/work:rw"])
    cmd.extend(["-w", "/work"])

    # Secrets mounting.
    if args.secret:
        secrets_dir = Path("/secrets")
        for secret_name in args.secret:
            # Validate secret name: alphanumeric, hyphens, underscores, dots only.
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', secret_name):
                cleanup_on_failure(
                    f"Invalid secret name: {secret_name}",
                    "Secret names must start with alphanumeric and contain only alphanumeric, dash, underscore, dot"
                )

            secret_path = secrets_dir / secret_name
            # Resolve symlinks and verify path stays within secrets directory.
            resolved = secret_path.resolve()
            try:
                resolved.relative_to(secrets_dir.resolve())
            except ValueError:
                cleanup_on_failure(
                    f"Secret path escapes secrets directory: {secret_name}",
                    "Secrets must not be symlinks pointing outside the secrets directory"
                )
            # Check secret exists.
            if not resolved.exists():
                cleanup_on_failure(
                    f"Secret not found: {secret_name}",
                    f"Create the secret at {secret_path}"
                )

            # Mount resolved path read-only at /run/secrets/{name}.
            cmd.extend(["-v", f"{resolved}:/run/secrets/{secret_name}:ro"])

            # Set env var pointing to secret path (not value).
            # Convert filename to env var name: test-api-key.txt -> TEST_API_KEY_FILE
            env_name = secret_name.rsplit(".", 1)[0]  # Remove extension.
            env_name = env_name.upper().replace("-", "_") + "_FILE"
            cmd.extend(["-e", f"{env_name}=/run/secrets/{secret_name}"])

    # Working directory override.
    if getattr(args, "workdir", None):
        cmd.extend(["--workdir", args.workdir])

    # Image and command.
    cmd.append(args.image)
    if args.container_cmd:
        cmd.extend(args.container_cmd)

    return cmd


def _verify_image_digest(args) -> None:
    """Verify image digest matches expected value. Exits on mismatch."""
    expected = getattr(args, "image_digest", None)
    if not expected:
        return
    result = run(["podman", "image", "inspect", args.image,
                  "--format", "{{.Digest}}"], check=False, capture=True)
    if result.returncode != 0:
        # Image not local — pull it first.
        run(["podman", "pull", args.image], check=False, capture=True)
        result = run(["podman", "image", "inspect", args.image,
                      "--format", "{{.Digest}}"], check=False, capture=True)
    actual_digest = result.stdout.strip()
    if not actual_digest:
        error(
            f"Could not retrieve image digest for {args.image}",
            "Ensure the image exists locally or can be pulled."
        )
    if actual_digest != expected:
        error(
            f"Image digest mismatch: expected {expected[:24]}..., "
            f"got {actual_digest[:24]}...",
            "The image may have been tampered with or updated. "
            "Verify the digest and retry."
        )


def _process_canary_file(args) -> Optional[dict]:
    """Read and delete canary token file. Returns canary tokens dict or None."""
    canary_path = getattr(args, "canary_file", None)
    if not canary_path:
        return None
    path = Path(canary_path)
    # Validate path: must be in temp directory with expected prefix.
    basename = path.name
    if not basename.startswith("brig_canary_") or ".." in str(path):
        warn(f"Ignoring canary file with unexpected path: {basename}")
        return None
    # Resolve symlinks and verify the resolved path is within the temp directory.
    import tempfile
    resolved_path = path.resolve()
    tmp_dir = Path(tempfile.gettempdir()).resolve()
    try:
        resolved_path.relative_to(tmp_dir)
    except ValueError:
        warn(f"Ignoring canary file outside temp directory: {basename}")
        return None
    try:
        canary_data = json.loads(resolved_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        # Clean up the file on parse failure.
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        warn(f"Failed to read canary file: {e}")
        return None
    try:
        path.unlink()  # Delete tempfile immediately after reading.
    except OSError:
        pass
    result_dict: dict = canary_data.get("canary_tokens", {})
    return result_dict


def cmd_run(args) -> int:
    """Run a new cell."""
    # Apply trust profile if specified (profile defaults -> cell def -> CLI flags).
    if getattr(args, "profile", None):
        _apply_profile(args)

    # Load cell definition from file if provided.
    if args.file:
        cell_def = load_cell_definition(args.file)
        # Validate cell definition.
        validation_errors = validate_cell_definition(cell_def, args.file)
        if validation_errors:
            error_details = "\n  - ".join(validation_errors)
            error(
                f"Invalid cell definition '{args.file}':\n  - {error_details}",
                "Fix the errors above and try again"
            )
        _merge_cell_def_into_args(args, cell_def)

    # Apply hardcoded defaults for any still-None fields.
    # These match the "supervised" profile — a reasonable middle ground.
    if args.memory is None:
        args.memory = "2g"
    if args.cpus is None:
        args.cpus = "2"
    if args.pids_limit is None:
        args.pids_limit = 512
    if getattr(args, "network", None) is None:
        args.network = "default"

    cell_name = args.name
    if not cell_name:
        error(
            "Cell name is required",
            "Use --name NAME or include 'name:' in a -f definition file"
        )
    validate_cell_name(cell_name)
    if not args.image:
        error(
            "Image is required",
            "Provide an image as argument (e.g., brig run --name mycell alpine) or use -f"
        )

    # Determine if this is an air-gapped cell.
    airgapped = getattr(args, "network", "default") == "none"

    # Validate timeout if specified.
    timeout_seconds = None
    if getattr(args, "timeout", None):
        timeout_seconds = parse_duration(args.timeout)
        if timeout_seconds is None:
            error(
                f"Invalid timeout format: {args.timeout}",
                "Use a duration like '30s', '5m', '2h', or '1d'"
            )

    # Optional image signature verification.
    if getattr(args, "verify_image", False):
        with Spinner(f"Verifying image signature for {args.image}") as spinner:
            verified, message, details = verify_image_signature(
                args.image,
                key=getattr(args, "verify_key", None),
                keyless=getattr(args, "verify_keyless", False),
                certificate_identity=getattr(args, "certificate_identity", None),
                certificate_oidc_issuer=getattr(args, "certificate_oidc_issuer", None),
            )
            if verified:
                spinner.success(message)
            else:
                spinner.fail(message)
                error(
                    f"Image signature verification failed for {args.image}",
                    "Use a signed image or remove --verify-image to skip verification"
                )

    # Image digest verification — pre-start, no resources allocated on mismatch.
    _verify_image_digest(args)

    # Fail-fast: Check proxy is running (skip for air-gapped cells).
    if not airgapped and not proxy_running():
        error_proxy_not_running()

    # Fail-fast: --tor requires the Tor stack and Warden upstream mode.
    if getattr(args, "tor", False):
        try:
            import warden as _warden
            if not _warden.privoxy_running():
                error(
                    "Tor stack is not running",
                    "Start with: warden tor start && warden restart"
                )
            if not _warden._is_warden_tor_mode():
                error(
                    "Warden is not in Tor upstream mode",
                    "Restart Warden to activate Tor: warden restart"
                )
        except ImportError:
            error("Could not import warden module for Tor check")

    # Rate limit check.
    if not check_rate_limit():
        error(
            f"Rate limit exceeded ({RATE_LIMIT_MAX} cells per {RATE_LIMIT_WINDOW}s)",
            f"Wait {RATE_LIMIT_WINDOW} seconds before creating more cells"
        )

    # Check cell doesn't already exist.
    if cell_exists(cell_name):
        error_cell_already_exists(cell_name)

    # Track allocated resources for cleanup on failure.
    resources_allocated = {
        "policy": False,
        "subnet": False,
        "network": False,
        "proxy_connected": False,
    }

    def cleanup_on_failure(msg: str, suggestion: str | None = None):
        """Clean up all allocated resources and exit with error."""
        debug(f"Cleaning up after failure: {msg}")
        if resources_allocated["proxy_connected"]:
            run(["podman", "network", "disconnect", network_name(cell_name), PROXY_NAME],
                check=False, capture=True)
        if resources_allocated["network"]:
            run([BRIG_SUBNET_BIN, "remove-network", cell_name], check=False, capture=True)
        if resources_allocated["subnet"]:
            run([BRIG_SUBNET_BIN, "free", cell_name], check=False, capture=True)
        if resources_allocated["policy"]:
            delete_cell_policy(cell_name)
        error(msg, suggestion)

    # Save workspace quota if specified.
    quota_str = getattr(args, "workspace_quota", None)
    if quota_str:
        try:
            max_bytes = _helpers.parse_size(quota_str)
            _helpers.save_workspace_quota(cell_name, max_bytes)
        except ValueError as e:
            cleanup_on_failure(f"Invalid workspace quota: {e}", "Use format like 500m or 2g")

    # Create per-cell policy if custom policy specified (not for air-gapped).
    if not airgapped and (args.policy_allow or args.policy_deny):
        policy = {
            "allow": args.policy_allow or [],
            "deny": args.policy_deny or [],
        }
        if not save_cell_policy(cell_name, policy):
            cleanup_on_failure("Failed to save cell policy", "Check disk space and permissions")
        resources_allocated["policy"] = True

    # Merge canary tokens into cell policy if provided.
    canary_tokens = _process_canary_file(args)
    if canary_tokens:
        policy = load_cell_policy(cell_name)
        policy["canary_tokens"] = canary_tokens
        if not save_cell_policy(cell_name, policy):
            cleanup_on_failure("Failed to save cell policy with canary tokens",
                               "Check disk space and permissions")
        resources_allocated["policy"] = True

    # Network setup depends on mode.
    net_name = None
    proxy_ip = None
    if airgapped:
        debug(f"Air-gapped mode: skipping network allocation for {cell_name}")
    else:
        # Allocate subnet.
        output(f"Allocating network for {cell_name}...")
        result = run([BRIG_SUBNET_BIN, "allocate", cell_name], check=False, capture=True)
        if result.returncode != 0:
            debug(f"Subnet allocation stderr: {result.stderr}")
            cleanup_on_failure("Failed to allocate subnet for cell")
        resources_allocated["subnet"] = True

        # Create internal network.
        result = run([BRIG_SUBNET_BIN, "create-network", cell_name], check=False, capture=True)
        if result.returncode != 0:
            debug(f"Network creation stderr: {result.stderr}")
            cleanup_on_failure("Failed to create cell network")
        resources_allocated["network"] = True

        net_name = network_name(cell_name)

        # Connect proxy to cell network.
        result = run(["podman", "network", "connect", net_name, PROXY_NAME], check=False, capture=True)
        if result.returncode != 0 and "already" not in result.stderr.lower():
            debug(f"Proxy connect stderr: {result.stderr}")
            cleanup_on_failure("Failed to connect proxy to cell network")
        resources_allocated["proxy_connected"] = True

        # Get proxy IP on cell network.
        proxy_ip = get_proxy_ip(net_name)
        if not proxy_ip:
            # Proxy might need a moment.
            time.sleep(1)
            proxy_ip = get_proxy_ip(net_name)

        if not proxy_ip:
            cleanup_on_failure(
                "Could not determine proxy IP on cell network",
                "Check that warden is running: warden status"
            )

    # Add Tor label for auditing.
    if getattr(args, "tor", False):
        if not args.label:
            args.label = []
        args.label.append("brig.tor=true")

    # Build container command.
    cmd = _build_run_command(args, cell_name, airgapped, net_name, proxy_ip,
                             timeout_seconds, cleanup_on_failure)

    # Dry-run mode: show what would be done.
    if getattr(args, "dry_run", False):
        print("=== Dry Run - No changes will be made ===\n")
        print(f"Cell name:    {cell_name}")
        print(f"Image:        {args.image}")
        print(f"Command:      {' '.join(args.container_cmd) if args.container_cmd else '(default)'}")
        print(f"Network:      {'none (air-gapped)' if airgapped else net_name}")
        print(f"Runtime:      {RUNTIME}")
        print(f"Memory:       {args.memory}")
        print(f"CPUs:         {args.cpus}")
        print(f"PIDs limit:   {args.pids_limit}")
        print(f"Detach:       {args.detach}")
        print(f"Auto-remove:  {args.rm}")
        if timeout_seconds:
            print(f"Timeout:      {args.timeout} ({timeout_seconds}s)")
        if getattr(args, "label", None):
            print(f"Labels:       {', '.join(args.label)}")
        if args.env:
            # Redact env var values to avoid leaking secrets.
            redacted_env = []
            for env_entry in args.env:
                if "=" in env_entry:
                    key = env_entry.split("=", 1)[0]
                    redacted_env.append(f"{key}=<REDACTED>")
                else:
                    redacted_env.append(env_entry)
            print(f"Environment:  {', '.join(redacted_env)}")
        if args.secret:
            # Show secret names only, not mount paths.
            print(f"Secrets:      {', '.join(args.secret)}")
        if args.policy_allow or args.policy_deny:
            print(f"Policy allow: {', '.join(args.policy_allow or [])}")
            print(f"Policy deny:  {', '.join(args.policy_deny or [])}")
        # Redact sensitive values from podman command before printing.
        redacted_cmd: list[str] = []
        skip_next = False
        for i, part in enumerate(cmd):
            if skip_next:
                # Redact the value argument following -e or -v.
                if redacted_cmd and redacted_cmd[-1] == "-e":
                    key = part.split("=", 1)[0] if "=" in part else part
                    redacted_cmd.append(f"{key}=<REDACTED>")
                elif redacted_cmd and redacted_cmd[-1] == "-v":
                    # Redact host path in volume mounts (show container path only).
                    parts = part.split(":")
                    if len(parts) >= 2:
                        redacted_cmd.append(f"<REDACTED>:{':'.join(parts[1:])}")
                    else:
                        redacted_cmd.append("<REDACTED>")
                else:
                    redacted_cmd.append(part)
                skip_next = False
                continue
            if part in ("-e", "-v"):
                skip_next = True
            redacted_cmd.append(part)
        print("\nPodman command:")
        print(f"  {' '.join(redacted_cmd)}")
        # Clean up resources allocated during planning.
        if resources_allocated.get("proxy_connected"):
            try:
                run(["podman", "network", "disconnect", network_name(cell_name), PROXY_NAME],
                    check=False, capture=True)
            except Exception:
                pass
        if resources_allocated["subnet"]:
            try:
                run([BRIG_SUBNET_BIN, "free", cell_name], check=False, capture=True)
            except Exception:
                pass
        if resources_allocated["network"]:
            try:
                run(["podman", "network", "rm", network_name(cell_name)], check=False, capture=True)
            except Exception:
                pass
        if resources_allocated["policy"]:
            try:
                policy_path = _helpers.POLICY_DIR / f"{cell_name}.json"
                if policy_path.exists():
                    policy_path.unlink()
            except Exception:
                pass
        return 0

    # Run container.
    with Spinner(f"Starting cell {cell_name}") as spinner:
        result = run(cmd, check=False, capture=True)
        if result.returncode != 0:
            spinner.fail(f"Failed to start cell {cell_name}")
            # Clean up all allocated resources on failure.
            if resources_allocated["proxy_connected"] and net_name:
                run(["podman", "network", "disconnect", net_name, PROXY_NAME], check=False)
            if resources_allocated["network"]:
                run([BRIG_SUBNET_BIN, "remove-network", cell_name], check=False)
            if resources_allocated["subnet"]:
                run([BRIG_SUBNET_BIN, "free", cell_name], check=False)
            if resources_allocated["policy"]:
                delete_cell_policy(cell_name)
            print_error(
                result.stderr.strip() if result.stderr else "Unknown error",
                "Try: brig diagnose " + cell_name
            )
            return 1
        spinner.success(f"Cell {cell_name} started")

    # Invalidate cache after state change.
    invalidate_cell_cache(cell_name)

    # Get container ID from podman output.
    cell_id = result.stdout.strip()[:12] if result.stdout.strip() else ""

    # Structured JSON output.
    if getattr(args, "output", "text") == "json":
        run_result = {
            "cell": cell_name,
            "cell_id": cell_id,
            "image": args.image,
            "status": "running" if args.detach else "started",
            "network": "none" if airgapped else net_name,
            "runtime": RUNTIME,
        }
        if timeout_seconds:
            run_result["timeout_seconds"] = timeout_seconds
        if getattr(args, "label", None):
            run_result["labels"] = dict(lbl.split("=", 1) for lbl in args.label)
        print(json.dumps(run_result, indent=2))

    # Log operation and lifecycle event.
    log_operation("run", cell_name, {
        "image": args.image,
        "detach": args.detach,
        "airgapped": airgapped,
        "timeout": args.timeout if getattr(args, "timeout", None) else None,
    })
    log_lifecycle("start", cell_name, {
        "image": args.image,
        "command": args.container_cmd if args.container_cmd else None,
        "detach": args.detach,
        "airgapped": airgapped,
    })

    return 0


def cmd_stop(args) -> int:
    """Gracefully stop a cell."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    if not cell_running(cell_name):
        output(f"Cell {cell_name} is not running")
        return 0

    with Spinner(f"Stopping cell {cell_name}") as spinner:
        result = run(
            ["podman", "stop", "-t", "10", container_name(cell_name)],
            check=False, capture=True
        )

        if result.returncode != 0:
            spinner.fail(f"Failed to stop cell {cell_name}")
            print_error(
                result.stderr.strip() if result.stderr else "Unknown error",
                "Try: brig kill " + cell_name
            )
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
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    output(f"Killing cell {cell_name}...")
    result = run(
        ["podman", "kill", container_name(cell_name)],
        check=False, capture=True
    )

    if result.returncode != 0 and "not running" not in result.stderr.lower():
        error(
            f"Failed to kill cell: {result.stderr}",
            "Check cell status with: brig list"
        )

    # Invalidate cache after state change.
    invalidate_cell_cache(cell_name)

    # Log lifecycle event.
    log_lifecycle("kill", cell_name)

    output(f"Cell {cell_name} killed")
    return 0


def cmd_wait(args) -> int:
    """Block until a cell exits, returning its exit code."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    # Parse optional timeout.
    timeout_seconds = None
    if getattr(args, "timeout", None):
        timeout_seconds = parse_duration(args.timeout)
        if timeout_seconds is None:
            error(
                f"Invalid timeout format: {args.timeout}",
                "Use a duration like '30s', '5m', '2h', or '1d'"
            )

    debug(f"Waiting for cell {cell_name} to exit")

    # Use podman wait to block until container exits.
    cmd = ["podman", "wait", container_name(cell_name)]
    try:
        result = run(cmd, check=False, capture=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        error(
            f"Timeout waiting for cell {cell_name} after {args.timeout}",
            "Increase timeout with --timeout or check cell status with: brig list"
        )

    if result.returncode != 0:
        # Container might already be removed.
        if "no such container" in result.stderr.lower():
            error(
                f"Cell '{cell_name}' no longer exists (may have been removed with --rm)",
                "Check cell status with: brig list"
            )
        error(
            f"Failed to wait for cell: {result.stderr.strip()}",
            "Check cell status with: brig list"
        )

    # podman wait outputs the exit code of the container.
    try:
        cell_exit_code = int(result.stdout.strip())
    except ValueError:
        error(
            f"Unexpected output from podman wait: {result.stdout.strip()}",
            "Run with --debug for more details"
        )

    # Structured JSON output.
    if getattr(args, "output", None) == "json":
        print(json.dumps({
            "cell": cell_name,
            "exit_code": cell_exit_code,
        }))
    else:
        output(f"Cell {cell_name} exited with code {cell_exit_code}")

    return cell_exit_code


def cmd_rm(args) -> int:
    """Remove a cell and clean up resources."""
    cell_name = args.name
    validate_cell_name(cell_name)

    # Stop container if running.
    if cell_running(cell_name):
        if args.force:
            run(["podman", "kill", container_name(cell_name)], check=False)
        else:
            error_cell_running(cell_name)

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
        run([BRIG_SUBNET_BIN, "remove-network", cell_name], check=False)

        # Remove per-cell policy if exists.
        delete_cell_policy(cell_name)

        # Invalidate cache after state change.
        invalidate_cell_cache(cell_name)

        # Optionally remove workspace.
        if args.purge:
            workspace_dir = _helpers.STATE_DIR / cell_name
            if workspace_dir.exists():
                import shutil
                try:
                    # Remove symlinks in workspace before rmtree to prevent traversal.
                    for root, dirs, files in os.walk(workspace_dir, topdown=False):
                        for name in files:
                            p = Path(root) / name
                            if p.is_symlink():
                                p.unlink()
                        for name in dirs:
                            p = Path(root) / name
                            if p.is_symlink():
                                p.unlink()
                    shutil.rmtree(workspace_dir)
                except OSError as e:
                    warn(f"Failed to purge workspace for {cell_name}: {e}")
                    log_operation("rm", cell_name, {"purge": True, "purge_error": str(e)})
                    spinner.success(f"Cell {cell_name} removed (workspace purge failed)")
                    return 0
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
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    if cell_running(cell_name):
        output(f"Cell {cell_name} is already running")
        return 0

    # Skip proxy connection for air-gapped cells.
    cell_name_full = container_name(cell_name)
    result = run(["podman", "inspect", cell_name_full, "--format",
                   "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}"],
                  check=False, capture=True)
    cell_networks = result.stdout.strip().split() if result.returncode == 0 else []
    is_airgapped = not any(n.startswith("brig-") for n in cell_networks)

    if is_airgapped:
        debug(f"Cell {cell_name} is air-gapped, skipping proxy connection")
    else:
        # Fail-fast: Check proxy is running.
        if not proxy_running():
            error_proxy_not_running()

        # Ensure proxy is connected to cell network.
        net_name = network_name(cell_name)
        run(["podman", "network", "connect", net_name, PROXY_NAME], check=False)

    output(f"Starting cell {cell_name}...")
    result = run(
        ["podman", "start", container_name(cell_name)],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(
            f"Failed to start cell: {result.stderr}",
            "Ensure the VM is running: brig vm status"
        )

    # Invalidate cache after state change.
    invalidate_cell_cache(cell_name)

    output(f"Cell {cell_name} started")
    return 0


def cmd_list(args) -> int:
    """List all cells."""
    # Get all containers with brig- prefix.
    result = run(
        ["podman", "ps", "-a", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(
            f"Failed to list cells: {result.stderr}",
            "Ensure the VM is running: brig vm status"
        )

    containers = []
    if result.stdout.strip():
        try:
            containers = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            debug(f"Failed to parse container list: {e}")

    if args.format == "json":
        cells = []
        for c in containers:
            names = c.get("Names", [])
            if not names:
                continue
            name = names[0]
            if name.startswith(CONTAINER_PREFIX):
                cell_name = name[len(CONTAINER_PREFIX):]
                cells.append({
                    "name": cell_name,
                    "status": c.get("State", "unknown"),
                    "image": c.get("Image", "unknown"),
                })
        output(json.dumps(cells, indent=2))
    else:
        # Table format.
        output(f"{'NAME':<20} {'STATUS':<15} {'IMAGE':<30}")
        output("-" * 65)
        for c in containers:
            names = c.get("Names", [])
            if not names:
                continue
            name = names[0]
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
                if _helpers.COLOR_ENABLED:
                    colored_status = status_color(status) + " " * (15 - len(status))
                else:
                    colored_status = padded_status
                output(f"{cell_name:<20} {colored_status} {image:<30}")

    return 0


def cmd_pause(args) -> int:
    """Pause a running cell."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    if not cell_running(cell_name):
        error_cell_not_running(cell_name)

    result = run(
        ["podman", "pause", container_name(cell_name)],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(
            f"Failed to pause cell: {result.stderr}",
            f"Check cell status with: brig inspect {cell_name}"
        )

    # Invalidate cache after state change.
    invalidate_cell_cache(cell_name)

    output(f"Cell {cell_name} paused")
    return 0


def cmd_unpause(args) -> int:
    """Unpause a paused cell."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    result = run(
        ["podman", "unpause", container_name(cell_name)],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(
            f"Failed to unpause cell: {result.stderr}",
            f"Check cell status with: brig inspect {cell_name}"
        )

    # Invalidate cache after state change.
    invalidate_cell_cache(cell_name)

    output(f"Cell {cell_name} unpaused")
    return 0


def cmd_rename(args) -> int:
    """Rename a cell."""
    old_name = args.old_name
    new_name = args.new_name
    validate_cell_name(old_name)
    validate_cell_name(new_name)

    if not cell_exists(old_name):
        error_cell_not_found(old_name)

    if cell_exists(new_name):
        error_cell_already_exists(new_name)

    if cell_running(old_name):
        error_cell_running(old_name)

    # Rename container.
    old_container = container_name(old_name)
    new_container = container_name(new_name)

    result = run(
        ["podman", "rename", old_container, new_container],
        check=False, capture=True
    )

    if result.returncode != 0:
        error(
            f"Failed to rename container: {result.stderr}",
            "Ensure the cell is stopped first: brig stop CELL"
        )

    # Rename policy file if it exists.
    old_policy = _helpers.POLICY_DIR / f"{old_name}.json"
    new_policy = _helpers.POLICY_DIR / f"{new_name}.json"
    if old_policy.exists():
        try:
            old_policy.rename(new_policy)
        except OSError as e:
            warn(f"Could not rename policy file: {e}")

    # Rename workspace if it exists.
    old_workspace = _helpers.STATE_DIR / old_name
    new_workspace = _helpers.STATE_DIR / new_name
    if old_workspace.exists():
        try:
            old_workspace.rename(new_workspace)
        except OSError as e:
            warn(f"Could not rename workspace: {e}")

    # Update subnet allocation (old_name -> new_name).
    result = run([BRIG_SUBNET_BIN, "get", old_name], check=False, capture=True)
    if result.returncode == 0 and result.stdout.strip():
        # Free old allocation and re-allocate under new name.
        run([BRIG_SUBNET_BIN, "free", old_name], check=False, capture=True)
        run([BRIG_SUBNET_BIN, "allocate", new_name], check=False, capture=True)

    # Rename network if it exists.
    old_net = network_name(old_name)
    new_net = network_name(new_name)
    # Podman doesn't support network rename, so recreate.
    result = run(["podman", "network", "exists", old_net], check=False, capture=True)
    if result.returncode == 0:
        warn(f"Cell network '{old_net}' cannot be renamed in-place. "
             f"It will be recreated as '{new_net}' on next start.")

    # Log the rename operation.
    log_operation("rename", old_name, {"new_name": new_name})

    output(f"Renamed cell '{old_name}' to '{new_name}'")
    return 0


def cmd_checkpoint(args) -> int:
    """Checkpoint a running cell's state using CRIU."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)
    if not cell_running(cell_name):
        error(
            f"Cell '{cell_name}' is not running",
            "Only running cells can be checkpointed"
        )

    checkpoint_name = getattr(args, "checkpoint_name", None) or f"{cell_name}-checkpoint"
    # Validate checkpoint name to prevent path traversal.
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$", checkpoint_name):
        error(
            "Invalid checkpoint name: must be alphanumeric with dashes, underscores, and dots",
            "Example valid names: my-checkpoint, backup_v1, save.2024"
        )

    cmd = ["podman", "container", "checkpoint"]
    if getattr(args, "keep_running", False):
        cmd.append("--keep")
    cmd.extend(["--export", f"/state/checkpoints/{checkpoint_name}.tar.gz"])
    cmd.append(container_name(cell_name))

    # Ensure checkpoint directory exists.
    Path("/state/checkpoints").mkdir(parents=True, exist_ok=True)

    with Spinner(f"Checkpointing cell {cell_name}") as spinner:
        result = run(cmd, check=False, capture=True)
        if result.returncode != 0:
            spinner.fail(f"Failed to checkpoint {cell_name}")
            print_error(
                result.stderr.strip() if result.stderr else "Unknown error",
                "Ensure the cell is running: brig list"
            )
            return 1
        spinner.success(f"Cell {cell_name} checkpointed as {checkpoint_name}")

    log_operation("checkpoint", cell_name, {"checkpoint": checkpoint_name})
    return 0


def cmd_restore(args) -> int:
    """Restore a cell from a checkpoint."""
    checkpoint_name = args.checkpoint
    # Validate checkpoint name to prevent path traversal.
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$", checkpoint_name):
        error(
            "Invalid checkpoint name: must be alphanumeric with dashes, underscores, and dots",
            "Example valid names: my-checkpoint, backup_v1, save.2024"
        )
    cell_name = getattr(args, "name", None) or checkpoint_name.replace("-checkpoint", "")
    validate_cell_name(cell_name)

    checkpoint_path = Path(f"/state/checkpoints/{checkpoint_name}.tar.gz")
    if not checkpoint_path.exists():
        error(
            f"Checkpoint not found: {checkpoint_name}",
            "List checkpoints with: ls /state/checkpoints/"
        )

    # Check cell doesn't already exist.
    if cell_exists(cell_name):
        error_cell_already_exists(cell_name)

    cmd = [
        "podman", "container", "restore",
        "--import", str(checkpoint_path),
        "--name", container_name(cell_name),
    ]

    with Spinner(f"Restoring cell {cell_name} from {checkpoint_name}") as spinner:
        result = run(cmd, check=False, capture=True)
        if result.returncode != 0:
            spinner.fail(f"Failed to restore {cell_name}")
            print_error(
                result.stderr.strip() if result.stderr else "Unknown error",
                "Check that the checkpoint exists: podman container checkpoint --list"
            )
            return 1
        spinner.success(f"Cell {cell_name} restored from {checkpoint_name}")

    invalidate_cell_cache(cell_name)
    log_operation("restore", cell_name, {"checkpoint": checkpoint_name})
    return 0
