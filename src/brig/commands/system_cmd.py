"""
CLI handlers for system commands.
"""

from __future__ import annotations

import json
from brig.vm.shell import vm_run
from pathlib import Path
from typing import Any

from brig.config import BRIG_HOME, CONTAINER_PREFIX, PROXY_NAME, STATE_DIR, container_name
from brig.errors import BrigError
from brig.ops.atomic import atomic_write_json
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

    # Sensitive dirs must not be readable/writable by other users on the host.
    # secrets: holds API keys, tokens.
    # cells/addons: an attacker who can write here can replace enforce.py.
    # state/system: holds subnet allocator state and operation history.
    for sensitive in (BRIG_HOME / "secrets",
                      BRIG_HOME / "cells" / "addons",
                      BRIG_HOME / "state" / "system"):
        sensitive.chmod(0o700)

    # Default network policy.
    policy_file = BRIG_HOME / "cells" / "network-policy.json"
    if not policy_file.exists():
        atomic_write_json(policy_file, _DEFAULT_POLICY)
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
    output("  brig up                 # create VM, start VM, start warden")
    output("  brig run alpine echo hi # run your first cell")
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


def cmd_doctor(args: Any) -> int:
    """Handle `brig doctor` — deep environment + system check.

    Goes beyond `brig health`: verifies tooling on PATH, Lima version, gVisor
    presence inside the VM, addons installed, port collisions, and disk
    space. Prints a checklist with actionable suggestions on each failure.
    """
    import shutil as _shutil
    from brig.config import HostPaths
    from brig.network.proxy import proxy_running

    failures = []
    output("Running brig doctor...")
    output("=" * 50)

    def _check(label: str, ok: bool, detail: str = "", suggestion: str = ""):
        status = "[OK]" if ok else "[FAIL]"
        output(f"  {status} {label}")
        if detail:
            output(f"    {detail}")
        if not ok:
            failures.append((label, suggestion))

    # 1. Required commands on PATH.
    for cmd, hint in [
        ("limactl", "brew install lima"),
        ("podman", "brew install podman (optional on host)"),
        ("cosign", "brew install cosign (image signature verification)"),
    ]:
        path = _shutil.which(cmd)
        _check(f"{cmd} on PATH", bool(path), detail=path or "not found",
               suggestion=hint)

    # 2. Lima VM exists and is running.
    if _shutil.which("limactl"):
        import subprocess
        result = subprocess.run(
            ["limactl", "list", "--format", "{{.Name}}={{.Status}}"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        vm_states = dict(
            line.split("=", 1) for line in result.stdout.strip().splitlines()
            if "=" in line
        )
        brig_status = vm_states.get("brig", "missing")
        _check("Lima VM 'brig' exists", brig_status != "missing",
               detail=f"status: {brig_status}",
               suggestion="limactl create --name=brig ~/.brig/lima.yaml")
        _check("Lima VM 'brig' running", brig_status == "Running",
               detail=f"status: {brig_status}",
               suggestion="limactl start brig")

    # 3. ~/.brig directories exist with safe permissions. Use a different
    # name from `path` (which mypy infers as `str | None` from the earlier
    # `_shutil.which()` loop) to keep the type checker happy.
    for dir_path, expected_mode in [
        (HostPaths.SECRETS_DIR, 0o700),
        (HostPaths.ADDONS_DIR, 0o700),
        (HostPaths.STATE_DIR / "system", 0o700),
    ]:
        if dir_path.exists():
            actual_mode = dir_path.stat().st_mode & 0o777
            _check(f"{dir_path} has 0700 perms", actual_mode == expected_mode,
                   detail=f"mode: {oct(actual_mode)}",
                   suggestion=f"chmod 0700 {dir_path}")
        else:
            _check(f"{dir_path} exists", False, suggestion="brig init")

    # 4. Required addons present.
    for addon in ["enforce.py", "logger.py", "_common.py"]:
        addon_path = HostPaths.ADDONS_DIR / addon
        _check(f"addon: {addon}", addon_path.exists(),
               suggestion="make _copy-addons (re-install addons from source)")

    # 5. Network policy file exists and parses.
    policy_path = HostPaths.NETWORK_POLICY
    if policy_path.exists():
        try:
            json.loads(policy_path.read_text())
            _check(f"policy: {policy_path.name}", True)
        except json.JSONDecodeError as e:
            _check(f"policy: {policy_path.name}", False,
                   detail=str(e), suggestion="brig policy show global")
    else:
        _check(f"policy: {policy_path.name}", False, suggestion="brig init")

    # 6. Warden running.
    _check("warden proxy running", proxy_running(),
           suggestion="brig up")

    output("=" * 50)
    if failures:
        output(f"FAILED: {len(failures)} check(s)")
        for label, suggestion in failures:
            if suggestion:
                output(f"  fix '{label}': {suggestion}")
        return 1
    output("All checks passed")
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
    cn = container_name(args.name)

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
    output("# HELP brig_cells_total Number of allocated cells")
    output("# TYPE brig_cells_total gauge")
    output(f"brig_cells_total {len(subnets)}")

    result = vm_run(
        ["podman", "ps", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
    )
    running = 0
    if result.returncode == 0 and result.stdout.strip():
        try:
            containers = json.loads(result.stdout)
            def _name(c):
                n = c.get("Names", "")
                return n[0] if isinstance(n, list) else n
            running = sum(1 for c in containers
                         if c.get("State") == "running" and _name(c) != PROXY_NAME)
        except json.JSONDecodeError:
            pass

    output("# HELP brig_cells_running Number of running cells")
    output("# TYPE brig_cells_running gauge")
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
                cmd = entry.get("operation", "")
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
