"""System commands: diagnose, health, preflight, metrics, verify, history, upgrade, init."""

import json
import os
import time
from pathlib import Path

import brig.commands._helpers as _helpers
from brig.commands._helpers import (
    CONTAINER_PREFIX,
    DEFAULT_LIMA_YAML,
    DEFAULT_NETWORK_POLICY,
    PROXY_NAME,
    RUNTIME,
    SCHEMA_VERSION,
    cell_exists,
    cell_running,
    colorize,
    container_name,
    debug,
    error,
    error_cell_not_found,
    info,
    log_operation,
    network_name,
    output,
    print_error,
    proxy_running,
    run,
    validate_cell_name,
    warn,
)


def cmd_init(args) -> int:
    """Initialize the brig directory structure."""
    import platform

    # Check we're on macOS.
    if platform.system() != "Darwin":
        warn("Brig is designed for macOS. Some features may not work.")

    force = getattr(args, "force", False)

    # Check if already initialized.
    if _helpers.BRIG_HOME.exists() and not force:
        if (_helpers.BRIG_HOME / "lima.yaml").exists():
            info(f"Brig is already initialized at {_helpers.BRIG_HOME}")
            info("Use --force to reinitialize (preserves existing files)")
            return 0

    output(f"Initializing brig at {_helpers.BRIG_HOME}...")

    # Create directory structure.
    directories = [
        _helpers.BRIG_HOME,
        _helpers.BRIG_HOME / "cells",
        _helpers.BRIG_HOME / "secrets",
        _helpers.BRIG_HOME / "state",
        _helpers.BRIG_HOME / "state" / "system",
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
        output(f"  Created {directory}")

    # Set restrictive permissions on secrets directory.
    secrets_dir = _helpers.BRIG_HOME / "secrets"
    secrets_dir.chmod(0o700)
    output(f"  Set permissions 700 on {secrets_dir}")

    # Create default network policy if not exists.
    policy_file = _helpers.BRIG_HOME / "cells" / "network-policy.json"
    if not policy_file.exists() or force:
        with open(policy_file, "w") as f:
            json.dump(DEFAULT_NETWORK_POLICY, f, indent=2)
        output(f"  Created {policy_file}")
    else:
        output(f"  Skipped {policy_file} (already exists)")

    # Create Lima config if not exists.
    lima_file = _helpers.BRIG_HOME / "lima.yaml"
    if not lima_file.exists() or force:
        with open(lima_file, "w") as f:
            f.write(DEFAULT_LIMA_YAML)
        output(f"  Created {lima_file}")
    else:
        output(f"  Skipped {lima_file} (already exists)")

    # Create example cell definition.
    example_cell = _helpers.BRIG_HOME / "cells" / "example.yaml"
    if not example_cell.exists():
        example_content = """# Example cell definition
# Run with: brig run -f ~/.brig/cells/example.yaml

name: example
image: python:3.11-slim

# Environment variables (non-sensitive)
env:
  PYTHONUNBUFFERED: "1"

# Secrets to mount (create files in ~/.brig/secrets/)
# secrets:
#   - my-api-key

# Resource limits
memory: 2g
cpus: 2
pids_limit: 512

# Run in background
detach: true

# Command to run
command: ["python", "-c", "print('Hello from brig cell!')"]
"""
        with open(example_cell, "w") as f:
            f.write(example_content)
        output(f"  Created {example_cell}")

    # Create brig config file.
    config_file = _helpers.BRIG_HOME / "cells" / "config.json"
    if not config_file.exists():
        default_config = {
            "operation_logging": {
                "enabled": True,
                "level": "all",
                "redact_secrets": True,
                "redact_env_values": True
            }
        }
        with open(config_file, "w") as f:
            json.dump(default_config, f, indent=2)
        output(f"  Created {config_file}")

    # Write schema version for fresh installs.
    _write_schema_version(SCHEMA_VERSION)
    output(f"  Schema version: {SCHEMA_VERSION}")

    output("")
    output("Brig initialized successfully!")
    output("")
    output("Next steps:")
    output("  1. Install Lima if not already installed:")
    output("       brew install lima")
    output("")
    output("  2. Create the brig VM:")
    output(f"       limactl create --name=brig {lima_file}")
    output("")
    output("  3. Start the VM:")
    output("       limactl start brig")
    output("")
    output("  4. Start the warden proxy:")
    output("       limactl shell brig -- warden start")
    output("")
    output("  5. Run your first cell:")
    output("       brig run --name test --image alpine -- echo 'Hello!'")
    output("")
    output(f"Edit {policy_file} to configure allowed domains.")

    return 0


def cmd_diagnose(args) -> int:
    """Run diagnostic checks on a cell."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    info(f"Diagnosing cell: {cell_name}")
    print("-" * 40)
    issues = []

    # Check 1: Container status.
    if cell_running(cell_name):
        print("[OK] Container is running")
    else:
        print("[WARN] Container is not running")
        issues.append("Container stopped - use 'brig start' to restart")

    # Check 2: Proxy running.
    if proxy_running():
        print("[OK] Proxy is running")
    else:
        print("[FAIL] Proxy is not running")
        issues.append("Start proxy with: warden start")

    # Check 3: Network exists.
    net_name = network_name(cell_name)
    result = run(
        ["podman", "network", "exists", net_name],
        check=False, capture=True
    )
    if result.returncode == 0:
        print(f"[OK] Network {net_name} exists")
    else:
        print(f"[FAIL] Network {net_name} missing")
        issues.append("Cell network missing - recreate cell")

    # Check 4: Proxy connected to cell network.
    if proxy_running():
        result = run(
            ["podman", "inspect", PROXY_NAME, "--format",
             "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}"],
            check=False, capture=True
        )
        if net_name in result.stdout.strip().split():
            print(f"[OK] Proxy connected to {net_name}")
        else:
            print(f"[WARN] Proxy not connected to {net_name}")
            issues.append(f"Connect proxy: podman network connect {net_name} {PROXY_NAME}")

    # Check 5: gVisor runtime.
    if cell_running(cell_name):
        result = run(
            ["podman", "exec", container_name(cell_name), "dmesg"],
            check=False, capture=True
        )
        if "gVisor" in result.stdout:
            print("[OK] gVisor runtime active")
        else:
            print("[WARN] gVisor may not be active")
            issues.append("Container may not be using gVisor runtime")

    # Check 6: Recent blocked requests.
    log_file = Path(f"/var/log/brig/network/{cell_name}.jsonl")
    if log_file.exists():
        result = run(
            ["tail", "-n", "100", str(log_file)],
            check=False, capture=True
        )
        blocked_count = result.stdout.count('"blocked": true') + result.stdout.count('"blocked":true')
        if blocked_count > 0:
            print(f"[INFO] {blocked_count} requests blocked in recent logs")
        else:
            print("[OK] No recent blocked requests")
    else:
        print("[INFO] No network log file yet")

    # Summary.
    print("-" * 40)
    if issues:
        print(f"\nFound {len(issues)} issue(s):")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
        return 1
    else:
        print("\nAll checks passed")
        return 0


# ──────────────────────────────────────────────────────────────────
# Schema Versioning and Upgrade
# ──────────────────────────────────────────────────────────────────

def _read_schema_version() -> str:
    """Read the current schema version from disk. Returns '0.0.0' if absent."""
    if not _helpers.VERSION_FILE.exists():
        return "0.0.0"
    try:
        with open(_helpers.VERSION_FILE, "r") as f:
            data = json.load(f)
            return str(data.get("schema_version", "0.0.0"))
    except (json.JSONDecodeError, IOError, OSError):
        return "0.0.0"


def _write_schema_version(version: str) -> None:
    """Write the schema version to disk atomically."""
    _helpers.VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _helpers.VERSION_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump({
            "schema_version": version,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    tmp.rename(_helpers.VERSION_FILE)


def _parse_version(v: str) -> tuple:
    """Parse 'X.Y.Z' into (X, Y, Z) tuple for comparison."""
    try:
        parts = v.split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return (0, 0, 0)


def _backup_brig_home() -> Path:
    """Create a timestamped backup of ~/.brig before upgrading.

    Returns the backup directory path.
    """
    import shutil as _shutil
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_dir = _helpers.BRIG_HOME.parent / f".brig-backup-{timestamp}"

    info(f"Backing up {_helpers.BRIG_HOME} → {backup_dir}")
    _shutil.copytree(_helpers.BRIG_HOME, backup_dir, dirs_exist_ok=False)

    # Restrict backup permissions to match original secrets directory.
    secrets_backup = backup_dir / "secrets"
    if secrets_backup.exists():
        secrets_backup.chmod(0o700)
        for f in secrets_backup.iterdir():
            f.chmod(0o600)

    return Path(backup_dir)


# Migration registry: ordered list of (target_version, description, function).
# Each function receives no args and returns True on success.
# Migrations run in order; only those newer than current version execute.
_MIGRATIONS = []


def _register_migration(target: str, description: str):
    """Decorator to register a migration function."""
    def decorator(fn):
        _MIGRATIONS.append((target, description, fn))
        return fn
    return decorator


@_register_migration("1.0.0", "Initialize schema version and add version to config")
def _migrate_to_1_0_0() -> bool:
    """Migration for fresh installs and pre-versioning upgrades.

    Adds schema_version to config.json and creates the version file.
    """
    config_file = _helpers.BRIG_HOME / "cells" / "config.json"
    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                config = json.load(f)

            if "schema_version" not in config:
                config["schema_version"] = "1.0.0"
                tmp = config_file.with_suffix(".tmp")
                with open(tmp, "w") as f:
                    json.dump(config, f, indent=2)
                tmp.rename(config_file)
                debug("Added schema_version to config.json")
        except (json.JSONDecodeError, IOError, OSError) as e:
            warn(f"Could not update config.json: {e}")

    # Ensure state directories exist.
    (_helpers.BRIG_HOME / "state" / "system").mkdir(parents=True, exist_ok=True)

    return True


def cmd_upgrade(args) -> int:
    """Upgrade brig state to the current schema version.

    Backs up ~/.brig before making changes, then runs any pending migrations.
    """
    if not _helpers.BRIG_HOME.exists():
        error(
            "Brig is not initialized",
            "Run 'brig init' first"
        )

    current = _read_schema_version()
    target = SCHEMA_VERSION

    info(f"Current schema version: {current}")
    info(f"Target schema version:  {target}")

    if _parse_version(current) >= _parse_version(target):
        output("Already up to date. No migrations needed.")
        return 0

    # Collect pending migrations.
    pending = [
        (v, desc, fn) for v, desc, fn in _MIGRATIONS
        if _parse_version(v) > _parse_version(current)
    ]

    if not pending:
        output("No migrations to run.")
        _write_schema_version(target)
        return 0

    output(f"Migrations to apply: {len(pending)}")
    for v, desc, _ in pending:
        output(f"  {v}: {desc}")
    output("")

    # Backup before migrating.
    dry_run = getattr(args, "dry_run", False)
    if dry_run:
        output("Dry run — no changes will be made.")
        return 0

    skip_backup = getattr(args, "no_backup", False)
    backup_dir = None
    if not skip_backup:
        try:
            backup_dir = _backup_brig_home()
            output(f"Backup created at {backup_dir}")
        except (IOError, OSError) as e:
            error(
                f"Failed to create backup: {e}",
                "Use --no-backup to skip (not recommended)"
            )

    # Run migrations in order.
    for v, desc, fn in pending:
        output(f"Running migration {v}: {desc}...")
        try:
            success = fn()
            if not success:
                print_error(f"Migration {v} failed", "Try: brig upgrade --dry-run")
                if backup_dir:
                    print_error(f"Restore from backup: {backup_dir}", f"cp -a {backup_dir} ~/.brig")
                return 1
            output("  Done.")
        except Exception as e:
            print_error(f"Migration {v} raised an error: {e}", "Try: brig upgrade --dry-run")
            if backup_dir:
                print_error(f"Restore from backup: {backup_dir}", f"cp -a {backup_dir} ~/.brig")
            return 1

    # Write final version.
    _write_schema_version(target)
    output(f"\nUpgrade complete. Schema version is now {target}.")

    log_operation("upgrade", details={
        "from_version": current,
        "to_version": target,
        "migrations": len(pending),
    })

    return 0


def cmd_health(args) -> int:
    """Check system health for monitoring."""
    checks = {
        "proxy": False,
        "network": False,
        "runtime": False,
    }
    details = {}

    # Check 1: Proxy running.
    if proxy_running():
        checks["proxy"] = True
        details["proxy"] = "running"
    else:
        details["proxy"] = "not running"

    # Check 2: Network (proxy-external exists).
    result = run(
        ["podman", "network", "exists", "proxy-external"],
        check=False, capture=True
    )
    if result.returncode == 0:
        checks["network"] = True
        details["network"] = "proxy-external exists"
    else:
        details["network"] = "proxy-external missing"

    # Check 3: Runtime (gVisor available).
    result = run(
        ["podman", "info", "--format", "{{.Host.OCIRuntime.Name}}"],
        check=False, capture=True
    )
    runtime = result.stdout.strip()
    if "runsc" in runtime:
        checks["runtime"] = True
        details["runtime"] = runtime
    else:
        details["runtime"] = runtime or "unknown"

    # Count running cells.
    result = run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={CONTAINER_PREFIX}"],
        check=False, capture=True
    )
    cell_count = len([n for n in result.stdout.strip().split("\n") if n and n != PROXY_NAME])
    details["cells_running"] = str(cell_count)

    all_healthy = all(checks.values())

    if args.format == "json":
        health_data = {
            "healthy": all_healthy,
            "checks": checks,
            "details": details,
        }
        print(json.dumps(health_data, indent=2))
    else:
        status = colorize("HEALTHY", "green") if all_healthy else colorize("UNHEALTHY", "red")
        print(f"Status: {status}")
        print()
        for check, passed in checks.items():
            icon = colorize("✓", "green") if passed else colorize("✗", "red")
            detail = details.get(check, "")
            print(f"  {icon} {check}: {detail}")
        print(f"\nCells running: {cell_count}")

    return 0 if all_healthy else 1


def cmd_preflight(args) -> int:
    """Run preflight validation checks before starting work."""
    from brig.commands.vm import _lima_installed, _vm_status

    checks = []
    all_passed = True

    def check(name: str, passed: bool, detail: str, suggestion: str | None = None):
        nonlocal all_passed
        if not passed:
            all_passed = False
        checks.append({
            "name": name,
            "passed": passed,
            "detail": detail,
            "suggestion": suggestion,
        })

    # Check 1: VM running (if Lima is used).
    if _lima_installed():
        vm_status = _vm_status()
        vm_running = vm_status.get("status") == "Running"
        check(
            "VM",
            vm_running,
            f"status: {vm_status.get('status', 'unknown')}",
            "Start with: brig vm start" if not vm_running else None
        )

    # Check 2: Warden proxy running.
    warden_running = proxy_running()
    check(
        "Warden",
        warden_running,
        "running" if warden_running else "not running",
        "Start with: warden start" if not warden_running else None
    )

    # Check 3: State directory writable.
    state_writable = False
    try:
        _helpers.STATE_DIR.mkdir(parents=True, exist_ok=True)
        test_file = _helpers.STATE_DIR / ".preflight_test"
        test_file.write_text("test")
        test_file.unlink()
        state_writable = True
        state_detail = f"{_helpers.STATE_DIR} writable"
    except (IOError, OSError) as e:
        state_detail = f"{_helpers.STATE_DIR} not writable: {e}"
    check(
        "State directory",
        state_writable,
        state_detail,
        f"Check permissions on {_helpers.STATE_DIR}" if not state_writable else None
    )

    # Check 4: Policy file valid JSON.
    policy_file = Path("/cells/network-policy.json")
    policy_valid = False
    if policy_file.exists():
        try:
            with open(policy_file, "r") as f:
                json.load(f)
            policy_valid = True
            policy_detail = f"{policy_file} valid"
        except json.JSONDecodeError as e:
            policy_detail = f"invalid JSON: {e.msg}"
        except (IOError, OSError) as e:
            policy_detail = f"cannot read: {e}"
    else:
        policy_detail = f"{policy_file} not found"
    check(
        "Policy file",
        policy_valid,
        policy_detail,
        "Create policy file or run: brig init" if not policy_valid else None
    )

    # Check 5: Runtime (gVisor) available.
    result = run(
        ["podman", "info", "--format", "{{range .Host.Remotes}}{{.OCIRuntime.Name}}{{end}}"],
        check=False, capture=True
    )
    runtime_available = RUNTIME in result.stdout
    check(
        "Runtime",
        runtime_available,
        f"{RUNTIME} available" if runtime_available else f"{RUNTIME} not found",
        "Install gVisor (runsc) and configure Podman" if not runtime_available else None
    )

    # Check 6: Network infrastructure.
    result = run(
        ["podman", "network", "exists", "proxy-external"],
        check=False, capture=True
    )
    network_exists = result.returncode == 0
    check(
        "Network",
        network_exists,
        "proxy-external exists" if network_exists else "proxy-external missing",
        "Start warden to create network" if not network_exists else None
    )

    # Output results.
    if getattr(args, "format", "table") == "json":
        output_data = {
            "passed": all_passed,
            "checks": checks,
        }
        print(json.dumps(output_data, indent=2))
    else:
        status = colorize("PASSED", "green") if all_passed else colorize("FAILED", "red")
        print(f"Preflight: {status}")
        print()
        for c in checks:
            icon = colorize("✓", "green") if c["passed"] else colorize("✗", "red")
            print(f"  {icon} {c['name']}: {c['detail']}")
            if not c["passed"] and c["suggestion"]:
                print(f"      {colorize('→', 'yellow')} {c['suggestion']}")
        print()

    return 0 if all_passed else 1


def _fetch_warden_metrics() -> dict:
    """Fetch metrics from warden via Unix socket."""
    import socket
    metrics_socket = Path("/var/run/cells/metrics.sock")
    if not metrics_socket.exists():
        return {}

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect(str(metrics_socket))
        sock.sendall(b"all")
        # Read response in loop. Cap at 10MB to prevent unbounded memory use.
        max_response = 10 * 1024 * 1024
        chunks = []
        total = 0
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_response:
                break
            chunks.append(chunk)
        response = b"".join(chunks).decode("utf-8")
        data: dict = json.loads(response)
        return data
    except Exception as e:
        debug(f"Failed to fetch metrics from socket: {e}")
        return {}
    finally:
        sock.close()


def _add_per_cell_metrics(add_metric, cells_data: dict) -> None:
    """Emit per-cell request/bytes/latency metrics and aggregate totals."""
    total_requests = 0
    total_blocked = 0
    total_rate_limited = 0
    total_errors = 0
    total_bytes_sent = 0
    total_bytes_received = 0

    for cell_name, cell_metrics in cells_data.items():
        labels = {"cell": cell_name}

        # Request counters.
        requests = cell_metrics.get("total_requests", 0)
        total_requests += requests
        add_metric("brig_cell_requests_total", requests,
                   "Total requests from cell", "counter", labels)

        blocked = cell_metrics.get("blocked_requests", 0)
        total_blocked += blocked
        add_metric("brig_cell_requests_blocked_total", blocked,
                   "Blocked requests from cell", "counter", labels)

        rate_limited = cell_metrics.get("rate_limited_requests", 0)
        total_rate_limited += rate_limited
        add_metric("brig_cell_requests_rate_limited_total", rate_limited,
                   "Rate-limited requests from cell", "counter", labels)

        errors = cell_metrics.get("error_requests", 0)
        total_errors += errors
        add_metric("brig_cell_requests_errors_total", errors,
                   "Error requests from cell", "counter", labels)

        # Bytes counters.
        bytes_sent = cell_metrics.get("bytes_sent", 0)
        total_bytes_sent += bytes_sent
        add_metric("brig_cell_bytes_sent_total", bytes_sent,
                   "Bytes sent by cell", "counter", labels)

        bytes_recv = cell_metrics.get("bytes_received", 0)
        total_bytes_received += bytes_recv
        add_metric("brig_cell_bytes_received_total", bytes_recv,
                   "Bytes received by cell", "counter", labels)

        # Latency gauges.
        p50 = cell_metrics.get("latency_p50_ms", 0)
        add_metric("brig_cell_latency_p50_ms", p50,
                   "50th percentile request latency", "gauge", labels)

        p95 = cell_metrics.get("latency_p95_ms", 0)
        add_metric("brig_cell_latency_p95_ms", p95,
                   "95th percentile request latency", "gauge", labels)

        p99 = cell_metrics.get("latency_p99_ms", 0)
        add_metric("brig_cell_latency_p99_ms", p99,
                   "99th percentile request latency", "gauge", labels)

    # Aggregate totals.
    add_metric("brig_requests_total", total_requests,
               "Total requests across all cells", "counter")
    add_metric("brig_requests_blocked_total", total_blocked,
               "Total blocked requests", "counter")
    add_metric("brig_requests_rate_limited_total", total_rate_limited,
               "Total rate-limited requests", "counter")
    add_metric("brig_requests_errors_total", total_errors,
               "Total error requests", "counter")
    add_metric("brig_bytes_sent_total", total_bytes_sent,
               "Total bytes sent", "counter")
    add_metric("brig_bytes_received_total", total_bytes_received,
               "Total bytes received", "counter")


def _count_operations_last_hour() -> int:
    """Count operations in the last hour from history file."""
    if not _helpers.HISTORY_FILE.exists():
        return 0

    count = 0
    try:
        import datetime
        one_hour_ago = time.time() - 3600
        with open(_helpers.HISTORY_FILE, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    ts_str = entry.get("timestamp", "")
                    if ts_str:
                        ts = datetime.datetime.strptime(
                            ts_str, "%Y-%m-%dT%H:%M:%SZ"
                        ).timestamp()
                        if ts > one_hour_ago:
                            count += 1
                except (json.JSONDecodeError, ValueError):
                    continue
    except IOError as e:
        debug(f"Failed to read operations log for metrics: {e}")

    return count


def _generate_metrics() -> list:
    """Generate all Prometheus metrics."""
    lines = []
    seen_help = set()

    def add_metric(name: str, value: float, help_text: str, metric_type: str = "gauge",
                   labels: dict | None = None):
        # Only add HELP and TYPE once per metric name.
        if name not in seen_help:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {metric_type}")
            seen_help.add(name)
        if labels:
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")

    # Proxy status.
    proxy_up = 1 if proxy_running() else 0
    add_metric("brig_proxy_up", proxy_up, "Whether the warden proxy is running")

    # Cell counts by state.
    result = run(
        ["podman", "ps", "-a", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
        check=False, capture=True
    )

    state_counts = {"running": 0, "paused": 0, "exited": 0, "created": 0}
    total_cells = 0

    if result.stdout.strip():
        try:
            containers = json.loads(result.stdout)
            for c in containers:
                name = c.get("Names", [""])[0]
                if name == PROXY_NAME:
                    continue
                if name.startswith(CONTAINER_PREFIX):
                    total_cells += 1
                    state = c.get("State", "unknown").lower()
                    if state in state_counts:
                        state_counts[state] += 1
        except json.JSONDecodeError as e:
            debug(f"Failed to parse container stats for metrics: {e}")

    add_metric("brig_cells_total", total_cells, "Total number of cells")

    for state, count in state_counts.items():
        add_metric("brig_cells_by_state", count, "Number of cells by state",
                   labels={"state": state})

    # Network count.
    result = run(
        ["podman", "network", "ls", "--format", "{{.Name}}"],
        check=False, capture=True
    )
    cell_networks = len([
        n for n in result.stdout.strip().split("\n")
        if n.startswith(CONTAINER_PREFIX)
    ])
    add_metric("brig_networks_total", cell_networks, "Number of cell networks")

    # Per-cell request/bytes/latency metrics from Warden.
    warden_metrics = _fetch_warden_metrics()
    _add_per_cell_metrics(add_metric, warden_metrics.get("cells", {}))

    # History operations (last hour).
    add_metric("brig_operations_last_hour", _count_operations_last_hour(),
               "Number of operations in the last hour")

    return lines


def cmd_metrics(args) -> int:
    """Output metrics in Prometheus format."""
    import http.server
    import socketserver

    # If --serve specified, start HTTP server.
    if getattr(args, "serve", False):
        port = getattr(args, "port", 9090)

        class MetricsHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                if self.path == "/metrics" or self.path == "/":
                    metrics_lines = _generate_metrics()
                    content = "\n".join(metrics_lines) + "\n"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(content.encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()

        print(f"Serving metrics on http://127.0.0.1:{port}/metrics")
        print("Press Ctrl+C to stop")
        try:
            with socketserver.TCPServer(("127.0.0.1", port), MetricsHandler) as server:
                server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped")
        return 0

    # Otherwise, output metrics once.
    metrics_lines = _generate_metrics()
    for line in metrics_lines:
        print(line)

    return 0


def _fix_proxy_not_running() -> bool:
    """Attempt to start the warden proxy. Returns True if fixed."""
    print("  [FIX] Attempting to start warden...")
    result = run(["warden", "start"], check=False, capture=True)
    if result.returncode == 0:
        print("  [FIXED] Warden started successfully")
        return True
    else:
        print(f"  [FAIL] Could not start warden: {result.stderr}")
        return False


def _fix_proxy_network() -> bool:
    """Attempt to connect proxy to proxy-external. Returns True if fixed."""
    print("  [FIX] Attempting to connect proxy to proxy-external...")
    result = run(
        ["podman", "network", "connect", "proxy-external", PROXY_NAME],
        check=False, capture=True
    )
    if result.returncode == 0:
        print("  [FIXED] Proxy connected to proxy-external")
        return True
    else:
        print(f"  [FAIL] Could not connect proxy: {result.stderr}")
        return False


def _fix_cell_network(cell_name: str) -> bool:
    """Attempt to reconnect proxy to a cell's network. Returns True if fixed."""
    net_name = network_name(cell_name)
    print(f"  [FIX] Reconnecting proxy to {net_name}...")
    result = run(
        ["podman", "network", "connect", net_name, PROXY_NAME],
        check=False, capture=True
    )
    if result.returncode == 0:
        print(f"  [FIXED] Proxy connected to {net_name}")
        return True
    else:
        # Might already be connected.
        if "already" in result.stderr.lower():
            print(f"  [OK] Proxy already connected to {net_name}")
            return True
        print(f"  [FAIL] Could not connect proxy to {net_name}: {result.stderr}")
        return False


def _verify_proxy_status(issues: list, fixed: list, fix_mode: bool) -> None:
    """Check 1: Verify proxy is running."""
    print("\n[Check 1] Proxy status")
    if proxy_running():
        print("  [OK] Proxy is running")
    else:
        print("  [FAIL] Proxy is not running")
        if fix_mode:
            if _fix_proxy_not_running():
                fixed.append("Started warden proxy")
            else:
                issues.append("Proxy must be running")
        else:
            issues.append("Proxy must be running")


def _verify_proxy_network(issues: list, fixed: list, fix_mode: bool) -> None:
    """Check 2: Verify proxy is on proxy-external network."""
    print("\n[Check 2] Proxy network attachment")
    result = run(
        ["podman", "inspect", PROXY_NAME, "--format",
         "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}"],
        check=False, capture=True
    )
    if "proxy-external" in result.stdout.strip().split():
        print("  [OK] Proxy attached to proxy-external")
    else:
        print("  [FAIL] Proxy not on proxy-external network")
        if fix_mode:
            if _fix_proxy_network():
                fixed.append("Connected proxy to proxy-external")
            else:
                issues.append("Proxy must be on proxy-external network")
        else:
            issues.append("Proxy must be on proxy-external network")


def _verify_gvisor_runtime(issues: list) -> None:
    """Check 3: Verify all cells use gVisor runtime."""
    print("\n[Check 3] gVisor runtime")
    result = run(
        ["podman", "ps", "-a", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
        check=False, capture=True
    )
    if not result.stdout.strip():
        print("  [INFO] No cells running")
        return

    try:
        containers = json.loads(result.stdout)
        cell_names = [
            c.get("Names", [""])[0] for c in containers
            if c.get("Names", [""])[0] != PROXY_NAME
        ]
        if not cell_names:
            print("  [INFO] No cells found")
            return

        # Batch inspect to check runtime.
        inspect = run(
            ["podman", "inspect", "--format", "json"] + cell_names,
            check=False, capture=True
        )
        container_infos = json.loads(inspect.stdout)
        for c_info in container_infos:
            name = c_info.get("Name", "").lstrip("/")
            cell = name[len(CONTAINER_PREFIX):] if name.startswith(CONTAINER_PREFIX) else name
            # Check OCI runtime from container config.
            oci_runtime = c_info.get("HostConfig", {}).get("Runtime", "")
            if oci_runtime == RUNTIME:
                print(f"  [OK] {cell} configured with {RUNTIME}")
            elif oci_runtime:
                print(f"  [FAIL] {cell} uses {oci_runtime} instead of {RUNTIME}")
                issues.append(f"{cell} must use gVisor runtime")
            else:
                # Fallback: check dmesg for running containers.
                state = c_info.get("State", {}).get("Status", "")
                if state == "running":
                    dmesg = run(
                        ["podman", "exec", name, "dmesg"],
                        check=False, capture=True, timeout=5
                    )
                    if "gVisor" in dmesg.stdout:
                        print(f"  [OK] {cell} running gVisor (verified via dmesg)")
                    else:
                        print(f"  [WARN] {cell} runtime unverified")
                else:
                    print(f"  [INFO] {cell} not running, runtime not verified")
    except json.JSONDecodeError:
        print("  [WARN] Could not parse container info")


def _verify_network_isolation(issues: list) -> None:
    """Check 4: Verify cell networks are internal."""
    print("\n[Check 4] Network isolation")
    result = run(
        ["podman", "network", "ls", "--format", "{{.Name}}"],
        check=False, capture=True
    )
    cell_networks = [
        net for net in result.stdout.strip().split("\n")
        if net.startswith(CONTAINER_PREFIX) and net != "proxy-external"
    ]
    if not cell_networks:
        return

    # Batch inspect all cell networks at once.
    inspect = run(
        ["podman", "network", "inspect"] + cell_networks,
        check=False, capture=True
    )
    try:
        networks_info = json.loads(inspect.stdout)
        for net_info in networks_info:
            net_name = net_info.get("name", "")
            is_internal = net_info.get("internal", False)
            if is_internal:
                print(f"  [OK] {net_name} is internal")
            else:
                print(f"  [WARN] {net_name} may not be internal")
                issues.append(f"Network {net_name} should be internal")
    except json.JSONDecodeError:
        print("  [WARN] Could not parse network info")


def _verify_single_homed(issues: list) -> None:
    """Check 5: Verify cells are single-homed (one network only)."""
    print("\n[Check 5] Single-homed cells")
    result = run(
        ["podman", "ps", "-a", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
        check=False, capture=True
    )
    if not result.stdout.strip():
        return

    try:
        containers = json.loads(result.stdout)
        cell_names = [
            c.get("Names", [""])[0] for c in containers
            if c.get("Names", [""])[0] != PROXY_NAME
        ]
        if not cell_names:
            return

        # Batch inspect all containers at once.
        inspect = run(
            ["podman", "inspect", "--format", "json"] + cell_names,
            check=False, capture=True
        )
        container_infos = json.loads(inspect.stdout)
        for c_info in container_infos:
            name = c_info.get("Name", "").lstrip("/")
            networks = list(c_info.get("NetworkSettings", {}).get("Networks", {}).keys())
            if len(networks) == 1:
                print(f"  [OK] {name} has 1 network")
            else:
                print(f"  [WARN] {name} has {len(networks)} networks")
                issues.append(f"{name} should be single-homed")
    except json.JSONDecodeError as e:
        debug(f"Failed to parse container info for single-homed check: {e}")


def _verify_cell_isolation(issues: list) -> None:
    """Check 6: Verify inter-cell isolation (no east-west traffic)."""
    print("\n[Check 6] Inter-cell isolation")
    result = run(
        ["podman", "ps", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
        check=False, capture=True
    )
    if not result.stdout.strip():
        print("  [INFO] No running cells to test")
        return

    try:
        containers = json.loads(result.stdout)
        cell_names = [
            c.get("Names", [""])[0] for c in containers
            if c.get("Names", [""])[0] != PROXY_NAME and c.get("State") == "running"
        ]
        if len(cell_names) < 2:
            print("  [INFO] Need 2+ running cells to test isolation")
            return

        # Get IPs for each cell.
        running_cells = []
        for name in cell_names:
            inspect = run(
                ["podman", "inspect", name, "--format",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
                check=False, capture=True
            )
            ip = inspect.stdout.strip()
            if ip:
                running_cells.append({"name": name, "ip": ip})

        if len(running_cells) < 2:
            print("  [INFO] Need 2+ running cells with IPs to test isolation")
            return

        # Test connectivity from first cell to second.
        src_cell = running_cells[0]
        dst_cell = running_cells[1]
        print(f"  Testing {src_cell['name']} -> {dst_cell['name']} ({dst_cell['ip']})")
        ping_result = run(
            ["podman", "exec", src_cell["name"], "ping", "-c", "1", "-W", "1", dst_cell["ip"]],
            check=False, capture=True, timeout=5
        )
        if ping_result.returncode != 0:
            print("  [OK] Cells cannot reach each other (isolation verified)")
        else:
            print(f"  [FAIL] Cell {src_cell['name']} can ping {dst_cell['name']}")
            issues.append("Inter-cell isolation broken: cells can communicate")
    except (json.JSONDecodeError, KeyError):
        print("  [WARN] Could not determine cell IPs")


def _verify_proxy_enforcement(issues: list) -> None:
    """Check 7: Verify proxy is responsive and enforcing policy."""
    print("\n[Check 7] Proxy enforcement")
    if not proxy_running():
        print("  [SKIP] Proxy not running")
        return

    # Get proxy IP.
    result = run(
        ["podman", "inspect", PROXY_NAME, "--format",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
        check=False, capture=True
    )
    proxy_ip = result.stdout.strip().split()[0] if result.stdout.strip() else ""
    if not proxy_ip:
        print("  [WARN] Could not determine proxy IP")
        return

    # Check if proxy port is listening.
    import socket
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        conn_result = sock.connect_ex((proxy_ip, 8080))
        if conn_result == 0:
            print(f"  [OK] Proxy listening on {proxy_ip}:8080")
        else:
            print("  [FAIL] Proxy not responding on port 8080")
            issues.append("Proxy not responding on port 8080")
    except Exception as e:
        print(f"  [WARN] Could not check proxy port: {e}")
    finally:
        if sock:
            sock.close()


def cmd_verify(args) -> int:
    """Verify security invariants across all cells."""
    fix_mode = getattr(args, "fix", False)

    info("Verifying security invariants...")
    if fix_mode:
        info("(Auto-fix mode enabled)")
    print("=" * 50)
    issues: list[str] = []
    fixed: list[str] = []

    _verify_proxy_status(issues, fixed, fix_mode)
    _verify_proxy_network(issues, fixed, fix_mode)
    _verify_gvisor_runtime(issues)
    _verify_network_isolation(issues)
    _verify_single_homed(issues)
    _verify_cell_isolation(issues)
    _verify_proxy_enforcement(issues)

    # Summary.
    print("\n" + "=" * 50)
    if fixed:
        print(f"FIXED: {len(fixed)} issue(s) auto-repaired")
        for fix in fixed:
            print(f"  - {fix}")
    if issues:
        print(f"FAILED: {len(issues)} issue(s) found")
        for issue in issues:
            print(f"  - {issue}")
        if not fix_mode:
            print("\nTip: Run 'brig verify --fix' to attempt auto-repair")
        return 1
    else:
        if fixed:
            print("RECOVERED: All issues fixed, invariants verified")
        else:
            print("PASSED: All security invariants verified")
        return 0


def cmd_history(args) -> int:
    """Show operation history."""
    if not _helpers.HISTORY_FILE.exists():
        info("No history recorded yet")
        return 0

    entries = []
    try:
        with open(_helpers.HISTORY_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except IOError as e:
        error(
            f"Failed to read history: {e}",
            "History file may be corrupted. Check: brig config show"
        )

    # Filter by cell if specified.
    if args.cell:
        entries = [e for e in entries if e.get("cell") == args.cell]

    # Limit to last N entries.
    if args.tail:
        entries = entries[-args.tail:]

    if args.format == "json":
        print(json.dumps(entries, indent=2))
    else:
        # Table format.
        print(f"{'TIMESTAMP':<22} {'OPERATION':<12} {'CELL':<15} {'DETAILS':<30}")
        print("-" * 80)
        for entry in entries:
            ts = entry.get("timestamp", "")[:19]  # Truncate timezone.
            op = entry.get("operation", "")
            cell = entry.get("cell", "-")
            details = entry.get("details", {})
            detail_str = ", ".join(f"{k}={v}" for k, v in details.items()) if details else ""
            if len(detail_str) > 28:
                detail_str = detail_str[:25] + "..."
            print(f"{ts:<22} {op:<12} {cell:<15} {detail_str:<30}")

    return 0


def cmd_doctor(args) -> int:
    """Comprehensive system diagnostic with actionable suggestions."""
    from brig.commands.vm import _lima_installed, _vm_status

    checks = []
    fixes_applied = 0
    do_fix = getattr(args, "fix", False)

    def check(name, passed, detail, suggestion=None, fixable=False):
        checks.append({
            "name": name, "passed": passed, "detail": detail,
            "suggestion": suggestion, "fixable": fixable,
        })

    # --- Infrastructure ---

    # VM status.
    if _lima_installed():
        vm = _vm_status()
        vm_ok = vm.get("status") == "Running"
        check("VM", vm_ok, f"status: {vm.get('status', 'unknown')}",
              "Start with: brig vm start" if not vm_ok else None)

    # Warden proxy.
    warden_ok = proxy_running()
    check("Warden", warden_ok, "running" if warden_ok else "not running",
          "Start with: warden start" if not warden_ok else None, fixable=True)
    if do_fix and not warden_ok:
        result = run(["warden", "start"], check=False, capture=True)
        if result.returncode == 0:
            fixes_applied += 1

    # proxy-external network.
    net_result = run(["podman", "network", "exists", "proxy-external"], check=False, capture=True)
    check("Network", net_result.returncode == 0, "proxy-external exists" if net_result.returncode == 0 else "missing",
          "Recreate with: brig vm recreate" if net_result.returncode != 0 else None)

    # gVisor runtime.
    rt_result = run(["podman", "info", "--format", "{{.Host.OCIRuntime.Name}}"], check=False, capture=True)
    runtime = rt_result.stdout.strip()
    check("Runtime", "runsc" in runtime, runtime or "unknown",
          "Install gVisor: https://gvisor.dev/docs/user_guide/install/" if "runsc" not in runtime else None)

    # --- State ---

    # State directory writable.
    state_ok = False
    try:
        _helpers.STATE_DIR.mkdir(parents=True, exist_ok=True)
        tf = _helpers.STATE_DIR / ".doctor_test"
        tf.write_text("test")
        tf.unlink()
        state_ok = True
    except (IOError, OSError):
        pass
    check("State directory", state_ok, str(_helpers.STATE_DIR),
          "Check permissions on ~/.brig/state/" if not state_ok else None)

    # Disk space.
    import shutil
    try:
        usage = shutil.disk_usage(str(_helpers.STATE_DIR))
        pct_used = (usage.used / usage.total) * 100
        disk_ok = pct_used < 90
        check("Disk space", disk_ok, f"{pct_used:.0f}% used ({_helpers.format_size(usage.free)} free)",
              "Free disk space — state directory is nearly full" if not disk_ok else None)
    except OSError:
        check("Disk space", False, "could not check", None)

    # Schema version.
    from brig.commands._helpers import SCHEMA_VERSION, VERSION_FILE
    version_ok = True
    if VERSION_FILE.exists():
        try:
            current = VERSION_FILE.read_text().strip()
            version_ok = current == SCHEMA_VERSION
            check("Schema version", version_ok, f"{current} (expected {SCHEMA_VERSION})",
                  "Run: brig upgrade" if not version_ok else None)
        except IOError:
            check("Schema version", False, "cannot read", None)
    else:
        check("Schema version", True, f"{SCHEMA_VERSION} (no version file, assumed current)")

    # --- Security tools ---

    # Cosign availability.
    cosign_result = run(["which", "cosign"], check=False, capture=True)
    cosign_ok = cosign_result.returncode == 0
    check("Cosign", cosign_ok, "installed" if cosign_ok else "not installed",
          "Install from https://docs.sigstore.dev/cosign/ for image verification" if not cosign_ok else None)

    # Default seccomp profile.
    seccomp_path = Path(__file__).parent.parent.parent / "seccomp" / "default.json"
    check("Seccomp profile", seccomp_path.exists(), str(seccomp_path) if seccomp_path.exists() else "not found",
          "Reinstall brig to restore default seccomp profile" if not seccomp_path.exists() else None)

    # --- Cell hygiene ---

    # Stale cells (exited > 7 days ago).
    stale_cells = []
    try:
        result = run(
            ["podman", "ps", "-a", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}",
             "--filter", "status=exited"],
            check=False, capture=True
        )
        if result.returncode == 0 and result.stdout.strip():
            import datetime
            exited = json.loads(result.stdout)
            for c in exited:
                name = c.get("Names", [""])[0] if isinstance(c.get("Names"), list) else c.get("Names", "")
                if name.startswith(CONTAINER_PREFIX) and name != PROXY_NAME:
                    # Check age from ExitedAt or Created.
                    created = c.get("Created", "")
                    if created:
                        try:
                            ts = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
                            age = datetime.datetime.now(datetime.timezone.utc) - ts
                            if age.days > 7:
                                stale_cells.append(name[len(CONTAINER_PREFIX):])
                        except (ValueError, TypeError):
                            pass
    except Exception:
        pass

    stale_ok = len(stale_cells) == 0
    stale_detail = f"{len(stale_cells)} stale" if stale_cells else "none"
    check("Stale cells", stale_ok, stale_detail,
          f"Clean up with: brig rm {' '.join(stale_cells[:3])}" if stale_cells else None,
          fixable=True)
    if do_fix and stale_cells:
        for cell in stale_cells:
            run(["podman", "rm", "-f", f"{CONTAINER_PREFIX}{cell}"], check=False, capture=True)
            fixes_applied += 1

    # Orphan networks.
    orphan_nets = []
    try:
        net_list = run(["podman", "network", "ls", "--format", "{{.Name}}"], check=False, capture=True)
        cell_list = run(["podman", "ps", "-a", "--format", "{{.Names}}"], check=False, capture=True)
        active_cells = set(cell_list.stdout.strip().split("\n")) if cell_list.stdout.strip() else set()

        for net in net_list.stdout.strip().split("\n"):
            if net.startswith(CONTAINER_PREFIX) and net != "proxy-external":
                expected_container = net  # Network name = container name.
                if expected_container not in active_cells:
                    orphan_nets.append(net)
    except Exception:
        pass

    orphan_ok = len(orphan_nets) == 0
    check("Orphan networks", orphan_ok, f"{len(orphan_nets)} orphaned" if orphan_nets else "none",
          "Clean with: brig verify --fix" if orphan_nets else None, fixable=True)
    if do_fix and orphan_nets:
        for net in orphan_nets:
            run(["podman", "network", "rm", net], check=False, capture=True)
            fixes_applied += 1

    # Workspace quota status.
    cells_over_quota = []
    try:
        for cell_dir in _helpers.STATE_DIR.iterdir():
            if cell_dir.is_dir() and (cell_dir / "workspace").exists():
                cell_name = cell_dir.name
                within, current, max_b = _helpers.check_workspace_quota(cell_name)
                if not within:
                    cells_over_quota.append(f"{cell_name} ({_helpers.format_size(current)}/{_helpers.format_size(max_b)})")
    except OSError:
        pass

    quota_ok = len(cells_over_quota) == 0
    check("Workspace quotas", quota_ok,
          f"{len(cells_over_quota)} over quota" if cells_over_quota else "all within limits",
          f"Over quota: {', '.join(cells_over_quota[:3])}" if cells_over_quota else None)

    # --- Output ---

    fmt = getattr(args, "format", "text")
    if fmt == "json":
        print(json.dumps({
            "checks": checks,
            "all_passed": all(c["passed"] for c in checks),
            "fixes_applied": fixes_applied,
        }, indent=2))
    else:
        passed = sum(1 for c in checks if c["passed"])
        total = len(checks)
        print(f"Brig Doctor: {passed}/{total} checks passed")
        print()
        for c in checks:
            icon = colorize("[OK]", "green") if c["passed"] else colorize("[FAIL]", "red")
            print(f"  {icon}  {c['name']}: {c['detail']}")
            if not c["passed"] and c.get("suggestion"):
                print(f"         {c['suggestion']}")
        if fixes_applied:
            print(f"\nApplied {fixes_applied} fix(es)")
        elif not all(c["passed"] for c in checks):
            fixable = sum(1 for c in checks if not c["passed"] and c.get("fixable"))
            if fixable:
                print(f"\n{fixable} issue(s) auto-fixable. Run: brig doctor --fix")

    return 0 if all(c["passed"] for c in checks) else 1
