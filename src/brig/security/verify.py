"""
Security invariant verification checks.

Each check is a pure function returning CheckResult(passed, message, details).
Covers the 6 of the 12 invariants that are verifiable at runtime via podman
inspect: 1 (network isolation), 5 (gVisor), 6 (proxy-external membership),
7 (cell-network members), 8 (single-homed), 9 (proxy running). The others are
enforced at cell-definition parse / build time, not re-checked here.
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


def _get_cell_containers() -> list[dict] | None:
    """Shared query: inspect data for all cell containers.

    Returns the container info list ([] if none) or None on failure. Uses the
    module-local `_run` alias for both calls so tests can mock the verify-side
    subprocess seam independently of list_cell_containers.
    """
    result = _run([
        "podman", "ps", "-a", "--format", "json",
        "--filter", f"name=^{CONTAINER_PREFIX}",
    ])
    if not result.stdout.strip():
        return []

    try:
        containers = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

    def _name(c: dict) -> str:
        n = c.get("Names", "")
        if isinstance(n, list):
            return str(n[0]) if n else ""
        return str(n)

    from brig.config import INFRA_CONTAINER_NAMES
    cell_names = [_name(c) for c in containers if _name(c) not in INFRA_CONTAINER_NAMES]
    if not cell_names:
        return []

    inspect = _run(["podman", "inspect", "--format", "json"] + cell_names)
    try:
        return json.loads(inspect.stdout)  # type: ignore[no-any-return]
    except json.JSONDecodeError:
        return None


def _get_cell_networks() -> list[dict] | None:
    """Shared query: inspect data for all cell networks.

    Returns the network info list ([] if none) or None on failure.
    """
    result = _run(["podman", "network", "ls", "--format", "{{.Name}}"])
    cell_networks = [
        net for net in result.stdout.strip().split("\n")
        if net.startswith(CONTAINER_PREFIX) and net != PROXY_EXTERNAL_NETWORK
    ]
    if not cell_networks:
        return []

    inspect = _run(["podman", "network", "inspect"] + cell_networks)
    try:
        return json.loads(inspect.stdout)  # type: ignore[no-any-return]
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
    if PROXY_EXTERNAL_NETWORK not in networks:
        return CheckResult(False, "Proxy not on proxy-external network")

    # Confirming warden is attached is not enough: a second container on
    # proxy-external would share warden's egress-capable (non-internal)
    # network and defeat the choke point. Enumerate the members and assert
    # only infrastructure containers are attached.
    from brig.config import INFRA_CONTAINER_NAMES
    inspect = _run(["podman", "network", "inspect", PROXY_EXTERNAL_NETWORK])
    try:
        net_infos = json.loads(inspect.stdout)
    except json.JSONDecodeError:
        return CheckResult(False, "Could not inspect proxy-external network")

    members: set[str] = set()
    for net_info in net_infos:
        containers = net_info.get("containers") or {}
        for cid, m in containers.items():
            if not isinstance(m, dict):
                continue
            # A member with no name still occupies the network and must be
            # accounted for — fall back to the container ID so it can't slip
            # past the enumeration (fail closed, not open).
            members.add(m.get("name") or f"<unnamed:{cid}>")
    unexpected = sorted(n for n in members if n not in INFRA_CONTAINER_NAMES)
    if unexpected:
        return CheckResult(
            False, "Non-infrastructure containers on proxy-external", unexpected
        )
    return CheckResult(True, "Proxy-external has only infrastructure containers")


def verify_gvisor_runtime(container_infos: list[dict] | None = None) -> CheckResult:
    """Invariant 5: gVisor must be active (no silent downgrade)."""
    if container_infos is None:
        data = _get_cell_containers()
        if data is None:
            return CheckResult(False, "Could not query containers")
        container_infos = data
    if not container_infos:
        return CheckResult(True, "No cells to check")

    issues: list[str] = []
    for c_info in container_infos:
        name = c_info.get("Name", "").lstrip("/")
        cell = name[len(CONTAINER_PREFIX):] if name.startswith(CONTAINER_PREFIX) else name
        # podman reports the OCI *category* ("oci") in HostConfig.Runtime;
        # the named runtime (runsc/crun) lives in the top-level OCIRuntime
        # field. Reading HostConfig.Runtime cannot tell runsc from a crun
        # downgrade.
        oci_runtime = c_info.get("OCIRuntime", "")
        if oci_runtime != RUNTIME:
            issues.append(
                f"{cell} uses {oci_runtime or '<unset>'} instead of {RUNTIME}"
            )

    if issues:
        return CheckResult(False, "gVisor runtime violations", issues)
    return CheckResult(True, "All cells use gVisor runtime")


def verify_network_isolation(network_infos: list[dict] | None = None) -> CheckResult:
    """Invariant 1: No east-west traffic (per-cell internal networks)."""
    if network_infos is None:
        data = _get_cell_networks()
        if data is None:
            return CheckResult(False, "Could not query networks")
        network_infos = data
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
        container_infos = data
    if not container_infos:
        return CheckResult(True, "No cells to check")

    issues: list[str] = []
    for c_info in container_infos:
        name = c_info.get("Name", "").lstrip("/")
        networks = list(c_info.get("NetworkSettings", {}).get("Networks", {}).keys())
        # Airgapped cells (--network none) legitimately have 0 networks and
        # are strictly more isolated than single-homed; only >1 is a violation.
        if len(networks) > 1:
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
        network_infos = data
    if not network_infos:
        return CheckResult(True, "No cell networks to check")

    issues: list[str] = []
    for net_info in network_infos:
        net_name = net_info.get("name", "")
        containers = net_info.get("containers") or {}
        member_names = {
            (m.get("name") or f"<unnamed:{cid}>")
            for cid, m in containers.items()
            if isinstance(m, dict)
        }
        expected = {PROXY_NAME, net_name}
        unexpected = {n for n in member_names if n not in expected}
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
        container_infos = container_data
        results.append(verify_gvisor_runtime(container_infos))
        results.append(verify_single_homed(container_infos))

    # Batch network queries for isolation + member checks.
    network_data = _get_cell_networks()
    if network_data is None:
        results.append(CheckResult(False, "Could not query networks"))
    else:
        network_infos = network_data
        results.append(verify_network_isolation(network_infos))
        results.append(verify_cell_network_members(network_infos))

    return results
