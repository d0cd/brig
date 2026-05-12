"""
Subnet state reconciliation for Warden.

Cross-checks subnets.json, subnet-map.json, and podman networks for consistency.
Used during preflight to refuse startup on drifted state.
"""

from __future__ import annotations

import fcntl
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from brig.config import (
    ALLOCATOR_LOCK_FILE, CONTAINER_PREFIX, PROXY_EXTERNAL_NETWORK,
    SUBNET_MAP_FILE, SUBNET_STATE_FILE,
)
from brig.vm.shell import vm_run


@dataclass
class _LoadResult:
    """Result of loading a JSON file."""
    data: Any = None
    malformed: bool = False


def _load_json_result(path: Path) -> _LoadResult:
    """Load JSON from path gracefully."""
    if not path.exists():
        return _LoadResult(data=None)
    try:
        with open(path) as f:
            return _LoadResult(data=json.load(f))
    except (json.JSONDecodeError, IOError, OSError):
        return _LoadResult(malformed=True)


def _network_subnet(net_name: str) -> str:
    """Return the first IPv4 subnet for a podman network, or '' on failure."""
    result = vm_run(
        ["podman", "network", "inspect", net_name, "--format",
         "{{range .Subnets}}{{.Subnet}} {{end}}"],
    )
    if result.returncode != 0:
        return ""
    out = result.stdout.strip().split()
    return out[0] if out else ""


def _get_cell_networks() -> list[str]:
    """Get list of brig-* cell networks from podman."""
    result = vm_run(["podman", "network", "ls", "--format", "{{.Name}}"])
    if result.returncode != 0:
        return []
    return [
        net for net in result.stdout.strip().split("\n")
        if net.startswith(CONTAINER_PREFIX) and net != PROXY_EXTERNAL_NETWORK
    ]


def reconcile_subnet_state(
    subnets_file: Path = SUBNET_STATE_FILE,
    subnet_map_file: Path = SUBNET_MAP_FILE,
    lock_file: Path = ALLOCATOR_LOCK_FILE,
    networks: list[str] | None = None,
) -> list[str]:
    """Check subnets.json, subnet-map.json, and podman networks for consistency.

    Takes a shared flock on the allocator lock to avoid racing concurrent
    allocate/free operations.

    Returns list of human-readable error messages (empty = consistent).
    """
    errors: list[str] = []

    # Acquire shared lock.
    lock_fh = None
    if lock_file.parent.exists():
        try:
            lock_fh = open(lock_file, "w")
            fcntl.flock(lock_fh, fcntl.LOCK_SH)
        except OSError:
            if lock_fh is not None:
                try:
                    lock_fh.close()
                except OSError:
                    pass
                lock_fh = None

    try:
        subnets_res = _load_json_result(subnets_file)
        map_res = _load_json_result(subnet_map_file)
        if networks is None:
            try:
                networks = _get_cell_networks()
            except Exception:
                networks = []
        network_set = set(networks)

        # Fresh install: nothing anywhere.
        if (subnets_res.data is None and not subnets_res.malformed
                and map_res.data is None and not map_res.malformed
                and not network_set):
            return []

        if subnets_res.malformed:
            return [f"{subnets_file} is malformed"]
        if map_res.malformed:
            return [f"{subnet_map_file} is malformed"]

        if subnets_res.data is None and (map_res.data is not None or network_set):
            return [
                f"Allocator state {subnets_file} is missing but subnet-map "
                f"or brig-* networks exist; state has drifted"
            ]

        subnets_data = subnets_res.data
        allocated = subnets_data.get("allocated", {}) if isinstance(subnets_data, dict) else {}
        if not isinstance(allocated, dict):
            allocated = {}

        # Expected derivations from the allocator (authoritative).
        expected_networks = {f"brig-{cell}" for cell in allocated.keys()}
        expected_map: dict[str, str] = {}
        expected_cidr_by_net: dict[str, str] = {}
        for cell, info in allocated.items():
            if isinstance(info, dict) and isinstance(info.get("index"), int):
                cidr = f"10.60.{info['index']}.0/24"
                expected_map[cidr] = cell
                expected_cidr_by_net[f"brig-{cell}"] = cidr

        # 1) Every allocated cell has a network.
        for net in sorted(expected_networks - network_set):
            errors.append(f"Allocator has cell but network {net} does not exist")

        # 2) Every network is tracked by the allocator.
        for net in sorted(network_set - expected_networks):
            errors.append(f"Network {net} exists but is not in {subnets_file}")

        # 3) Each allocated network carries the expected CIDR.
        for net in sorted(network_set & expected_networks):
            expected_cidr = expected_cidr_by_net.get(net)
            if not expected_cidr:
                continue
            actual_cidr = _network_subnet(net)
            if actual_cidr and actual_cidr != expected_cidr:
                errors.append(
                    f"{net} has CIDR {actual_cidr}, "
                    f"expected {expected_cidr} per {subnets_file}"
                )

        # 4) subnet-map.json agrees with allocator.
        map_data = map_res.data
        if map_data is None:
            if allocated:
                errors.append(
                    f"{subnet_map_file} is missing but {subnets_file} has "
                    f"{len(allocated)} allocated cell(s)"
                )
        elif not isinstance(map_data, dict):
            errors.append(f"{subnet_map_file} is not a JSON object")
        else:
            for subnet, cell_expected in expected_map.items():
                actual = map_data.get(subnet)
                if actual is None:
                    errors.append(
                        f"{subnet_map_file} missing entry {subnet} -> {cell_expected}"
                    )
                elif actual != cell_expected:
                    errors.append(
                        f"{subnet_map_file} mismatch at {subnet}: "
                        f"has {actual}, expected {cell_expected}"
                    )
            for subnet, cell_in_map in map_data.items():
                if subnet not in expected_map:
                    errors.append(
                        f"{subnet_map_file} has stale entry {subnet} -> {cell_in_map}"
                    )

        return errors
    finally:
        if lock_fh is not None:
            try:
                fcntl.flock(lock_fh, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                lock_fh.close()
            except OSError:
                pass
