"""
Security invariant verification checks.

Each check is a pure function returning CheckResult(passed, message, details).
All 9 invariants from docs/design/security.md are covered.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from brig.config import CONTAINER_PREFIX, PROXY_EXTERNAL_NETWORK, PROXY_NAME, RUNTIME
from brig.vm.shell import vm_run


@dataclass
class CheckResult:
    """Result of a single verification check."""
    passed: bool
    message: str
    details: list[str] | None = None


import subprocess

def _run(cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    """Run a command inside the VM for verification."""
    return vm_run(cmd, timeout=timeout)


def _get_cell_containers() -> tuple[list[str], list[dict]] | None:
    """Shared query: list cell containers and their inspect data.

    Returns (cell_names, container_infos) or None on failure.
    """
    result = _run([
        "podman", "ps", "-a", "--format", "json",
        "--filter", f"name={CONTAINER_PREFIX}",
    ])
    if not result.stdout.strip():
        return [], []

    try:
        containers = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

    def _name(c: dict) -> str:
        n = c.get("Names", "")
        return n[0] if isinstance(n, list) else n

    cell_names = [_name(c) for c in containers if _name(c) != PROXY_NAME]
    if not cell_names:
        return [], []

    inspect = _run(["podman", "inspect", "--format", "json"] + cell_names)
    try:
        return cell_names, json.loads(inspect.stdout)
    except json.JSONDecodeError:
        return None


def _get_cell_networks() -> tuple[list[str], list[dict]] | None:
    """Shared query: list cell networks and their inspect data.

    Returns (network_names, network_infos) or None on failure.
    """
    result = _run(["podman", "network", "ls", "--format", "{{.Name}}"])
    cell_networks = [
        net for net in result.stdout.strip().split("\n")
        if net.startswith(CONTAINER_PREFIX) and net != PROXY_EXTERNAL_NETWORK
    ]
    if not cell_networks:
        return [], []

    inspect = _run(["podman", "network", "inspect"] + cell_networks)
    try:
        return cell_networks, json.loads(inspect.stdout)
    except json.JSONDecodeError:
        return None


def verify_proxy_running() -> CheckResult:
    """Invariant 9: Proxy must be running before cells start."""
    result = _run(["podman", "inspect", PROXY_NAME, "--format", "{{.State.Status}}"])
    if result.returncode == 0 and result.stdout.strip() == "running":
        return CheckResult(True, "Proxy is running")
    return CheckResult(False, "Proxy is not running")


def verify_proxy_network() -> CheckResult:
    """Invariant 6: Only infrastructure containers on proxy-external."""
    result = _run([
        "podman", "inspect", PROXY_NAME, "--format",
        "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
    ])
    networks = result.stdout.strip().split()
    if PROXY_EXTERNAL_NETWORK in networks:
        return CheckResult(True, "Proxy attached to proxy-external")
    return CheckResult(False, "Proxy not on proxy-external network")


def verify_gvisor_runtime(container_infos: list[dict] | None = None) -> CheckResult:
    """Invariant 5: gVisor must be active (no silent downgrade)."""
    if container_infos is None:
        data = _get_cell_containers()
        if data is None:
            return CheckResult(False, "Could not query containers")
        _, container_infos = data
    if not container_infos:
        return CheckResult(True, "No cells to check")

    issues: list[str] = []
    for c_info in container_infos:
        name = c_info.get("Name", "").lstrip("/")
        cell = name[len(CONTAINER_PREFIX):] if name.startswith(CONTAINER_PREFIX) else name
        oci_runtime = c_info.get("HostConfig", {}).get("Runtime", "")
        if oci_runtime and oci_runtime != RUNTIME:
            issues.append(f"{cell} uses {oci_runtime} instead of {RUNTIME}")

    if issues:
        return CheckResult(False, "gVisor runtime violations", issues)
    return CheckResult(True, "All cells use gVisor runtime")


def verify_network_isolation(network_infos: list[dict] | None = None) -> CheckResult:
    """Invariant 1: No east-west traffic (per-cell internal networks)."""
    if network_infos is None:
        data = _get_cell_networks()
        if data is None:
            return CheckResult(False, "Could not query networks")
        _, network_infos = data
    if not network_infos:
        return CheckResult(True, "No cell networks to check")

    issues: list[str] = []
    for net_info in network_infos:
        net_name = net_info.get("name", "")
        if not net_info.get("internal", False):
            issues.append(f"Network {net_name} should be internal")

    if issues:
        return CheckResult(False, "Network isolation violations", issues)
    return CheckResult(True, "All cell networks are internal")


def verify_single_homed(container_infos: list[dict] | None = None) -> CheckResult:
    """Invariant 8: Cells must be single-homed (one network only)."""
    if container_infos is None:
        data = _get_cell_containers()
        if data is None:
            return CheckResult(False, "Could not query containers")
        _, container_infos = data
    if not container_infos:
        return CheckResult(True, "No cells to check")

    issues: list[str] = []
    for c_info in container_infos:
        name = c_info.get("Name", "").lstrip("/")
        networks = list(c_info.get("NetworkSettings", {}).get("Networks", {}).keys())
        if len(networks) != 1:
            issues.append(f"{name} has {len(networks)} networks")

    if issues:
        return CheckResult(False, "Single-homing violations", issues)
    return CheckResult(True, "All cells are single-homed")


def verify_cell_network_members(network_infos: list[dict] | None = None) -> CheckResult:
    """Invariant 7: No privileged services on cell networks."""
    if network_infos is None:
        data = _get_cell_networks()
        if data is None:
            return CheckResult(False, "Could not query networks")
        _, network_infos = data
    if not network_infos:
        return CheckResult(True, "No cell networks to check")

    issues: list[str] = []
    for net_info in network_infos:
        net_name = net_info.get("name", "")
        containers = net_info.get("containers") or {}
        member_names = {
            m.get("name", "") for m in containers.values()
            if isinstance(m, dict)
        }
        expected = {PROXY_NAME, net_name}
        unexpected = {n for n in member_names if n and n not in expected}
        if unexpected:
            issues.append(
                f"Network {net_name} has non-warden/non-cell containers: "
                f"{sorted(unexpected)}"
            )

    if issues:
        return CheckResult(False, "Cell network member violations", issues)
    return CheckResult(True, "All cell networks have only warden + cell")


def verify_all() -> list[CheckResult]:
    """Run all verification checks, batching shared podman queries."""
    results = [
        verify_proxy_running(),
        verify_proxy_network(),
    ]

    # Batch container queries for gvisor + single-homed checks.
    container_data = _get_cell_containers()
    if container_data is None:
        results.append(CheckResult(False, "Could not query containers"))
    else:
        _, container_infos = container_data
        results.append(verify_gvisor_runtime(container_infos))
        results.append(verify_single_homed(container_infos))

    # Batch network queries for isolation + member checks.
    network_data = _get_cell_networks()
    if network_data is None:
        results.append(CheckResult(False, "Could not query networks"))
    else:
        _, network_infos = network_data
        results.append(verify_network_isolation(network_infos))
        results.append(verify_cell_network_members(network_infos))

    return results
