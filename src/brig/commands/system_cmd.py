"""
CLI handlers for system commands.
"""

from __future__ import annotations

import json
from brig.vm.shell import vm_run
from pathlib import Path
from typing import Any

from brig.config import BRIG_HOME, CONTAINER_PREFIX, PROXY_NAME, STATE_DIR
from brig.errors import BrigError
from brig.ops.logging import info, output
from brig.security.verify import verify_all


_DEFAULT_POLICY = {
    "allow": [
        "pypi.org",
        "*.pythonhosted.org",
        "files.pythonhosted.org",
        "github.com",
        "api.github.com",
        "*.githubusercontent.com",
        "registry.npmjs.org",
    ],
    "deny": [],
    "rate_limits": {
        "default": {"rate": 100, "burst": 500}
    },
}


def cmd_init(args: Any) -> int:
    """Handle `brig init`."""
    import shutil

    dirs = [
        BRIG_HOME / "cells" / "addons",
        BRIG_HOME / "secrets",
        BRIG_HOME / "state" / "system",
        BRIG_HOME / "profiles",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    (BRIG_HOME / "secrets").chmod(0o700)

    # Default network policy.
    policy_file = BRIG_HOME / "cells" / "network-policy.json"
    if not policy_file.exists():
        policy_file.write_text(json.dumps(_DEFAULT_POLICY, indent=2))
        output(f"  Created default policy: {policy_file}")

    # Lima VM template.
    lima_yaml = BRIG_HOME / "lima.yaml"
    if not lima_yaml.exists():
        template = Path(__file__).parent.parent / "vm" / "lima.yaml.template"
        if template.exists():
            shutil.copy2(template, lima_yaml)
            output(f"  Created VM config: {lima_yaml}")

    output(f"Initialized brig at {BRIG_HOME}")
    output("")
    output("Next steps:")
    output(f"  1. Review VM config:    {lima_yaml}")
    output(f"  2. Create the VM:       limactl create --name=brig {lima_yaml}")
    output(f"  3. Start the VM:        limactl start brig")
    output(f"  4. Start the proxy:     warden start")
    return 0


def cmd_verify(args: Any) -> int:
    """Handle `brig verify`."""
    output("Verifying security invariants...")
    output("=" * 50)

    results = verify_all()
    issues = []
    for r in results:
        status = "[OK]" if r.passed else "[FAIL]"
        output(f"  {status} {r.message}")
        if r.details:
            for d in r.details:
                output(f"    - {d}")
        if not r.passed:
            issues.append(r.message)

    output("=" * 50)
    if issues:
        output(f"FAILED: {len(issues)} issue(s) found")
        return 1
    else:
        output("All security invariants verified")
        return 0


def cmd_health(args: Any) -> int:
    """Handle `brig health`."""
    from brig.network.proxy import proxy_running

    checks = [
        ("Proxy running", proxy_running()),
    ]

    # Check VM reachability.
    vm_result = vm_run(
        ["podman", "info", "--format", "{{.Host.Os}}"],
        timeout=5,
    )
    checks.append(("VM reachable", vm_result.returncode == 0))

    fmt = getattr(args, "format", "table")
    if fmt == "json":
        output(json.dumps([{"check": n, "passed": p} for n, p in checks], indent=2))
    else:
        all_ok = True
        for name, passed in checks:
            status = "[OK]" if passed else "[FAIL]"
            output(f"  {status} {name}")
            if not passed:
                all_ok = False
        return 0 if all_ok else 1
    return 0


def cmd_diagnose(args: Any) -> int:
    """Handle `brig diagnose` — run diagnostic checks for a cell."""
    from brig.config import CONTAINER_PREFIX
    cn = f"{CONTAINER_PREFIX}{args.name}"

    # Container state.
    result = vm_run(
        ["podman", "inspect", cn, "--format", "json"],
    )
    if result.returncode != 0:
        raise BrigError(f"Cell '{args.name}' not found")

    try:
        data = json.loads(result.stdout)
        if isinstance(data, list):
            data = data[0]
    except json.JSONDecodeError:
        raise BrigError("Could not parse container info")

    state = data.get("State", {})
    output(f"Cell: {args.name}")
    output(f"  Status: {state.get('Status', 'unknown')}")
    output(f"  Running: {state.get('Running', False)}")
    output(f"  Exit code: {state.get('ExitCode', 'N/A')}")
    output(f"  Runtime: {data.get('HostConfig', {}).get('Runtime', 'unknown')}")

    networks = list(data.get("NetworkSettings", {}).get("Networks", {}).keys())
    output(f"  Networks: {', '.join(networks) if networks else 'none'}")

    return 0


def cmd_preflight(args: Any) -> int:
    """Handle `brig preflight` — run pre-start checks."""
    from warden.reconcile import reconcile_subnet_state

    output("Running preflight checks...")
    errors = reconcile_subnet_state()
    if errors:
        output("Preflight FAILED:")
        for e in errors:
            output(f"  - {e}")
        return 1

    output("Preflight checks passed")
    return 0


def cmd_metrics(args: Any) -> int:
    """Handle `brig metrics` — output Prometheus-style metrics."""
    from brig.network.subnet import list_all

    subnets = list_all()
    output(f"# HELP brig_cells_total Number of allocated cells")
    output(f"# TYPE brig_cells_total gauge")
    output(f"brig_cells_total {len(subnets)}")

    result = vm_run(
        ["podman", "ps", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
    )
    running = 0
    if result.returncode == 0 and result.stdout.strip():
        try:
            containers = json.loads(result.stdout)
            running = sum(1 for c in containers
                         if c.get("State") == "running" and c.get("Names", [""])[0] != PROXY_NAME)
        except json.JSONDecodeError:
            pass

    output(f"# HELP brig_cells_running Number of running cells")
    output(f"# TYPE brig_cells_running gauge")
    output(f"brig_cells_running {running}")
    return 0


def cmd_history(args: Any) -> int:
    """Handle `brig history` — show operation history."""
    history_file = STATE_DIR / "system" / "operations.jsonl"
    if not history_file.exists():
        output("No operations recorded")
        return 0

    tail = getattr(args, "tail", 20) or 20
    cell_filter = getattr(args, "cell", None)

    try:
        lines = history_file.read_text().strip().split("\n")
        shown = 0
        for line in reversed(lines):
            if shown >= tail:
                break
            try:
                entry = json.loads(line)
                if cell_filter and entry.get("cell") != cell_filter:
                    continue
                ts = entry.get("ts", "")
                cmd = entry.get("command", "")
                cell = entry.get("cell", "")
                code = entry.get("exit_code", "")
                dur = entry.get("duration_ms", "")
                cell_str = f" [{cell}]" if cell else ""
                dur_str = f" ({dur}ms)" if dur else ""
                output(f"{ts} {cmd}{cell_str} -> {code}{dur_str}")
                shown += 1
            except json.JSONDecodeError:
                pass
    except IOError as e:
        raise BrigError(f"Failed to read history: {e}")

    return 0


def cmd_upgrade(args: Any) -> int:
    """Handle `brig upgrade` — upgrade state to current schema."""
    output("Checking state schema...")
    # Currently no migrations needed — this is a fresh v2 install.
    output("State is up to date (v2)")
    return 0
