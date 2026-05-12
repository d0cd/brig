"""
Proxy state queries and network management.

All podman commands route through vm_run() to execute inside the Lima VM.
"""

from __future__ import annotations

import json

from brig.config import CONTAINER_PREFIX, PROXY_NAME
from brig.ops.cache import cached, set_cache
from brig.ops.logging import debug
from brig.vm.shell import vm_run


def proxy_running() -> bool:
    """Check if the Warden proxy container is running. Cached for 2 seconds."""
    hit, val = cached("proxy_running")
    if hit:
        return val  # type: ignore[return-value]

    result = vm_run(
        ["podman", "inspect", PROXY_NAME, "--format", "{{.State.Status}}"],
        timeout=5,
    )
    running = result.returncode == 0 and result.stdout.strip() == "running"
    set_cache("proxy_running", running)
    return running


def get_proxy_ip(cell_name: str) -> str | None:
    """Get the proxy's IP address on a cell's network."""
    network_name = f"{CONTAINER_PREFIX}{cell_name}"
    result = vm_run(
        ["podman", "inspect", PROXY_NAME, "--format", "json"],
        timeout=5,
    )
    if result.returncode != 0:
        return None

    try:
        info = json.loads(result.stdout)
        if isinstance(info, list):
            info = info[0]
        networks = info.get("NetworkSettings", {}).get("Networks", {})
        ip = networks.get(network_name, {}).get("IPAddress", "")
        return ip if ip else None
    except json.JSONDecodeError:
        return None


def connect_proxy_to_network(cell_name: str) -> bool:
    """Connect the proxy container to a cell's network."""
    network_name = f"{CONTAINER_PREFIX}{cell_name}"
    result = vm_run(["podman", "network", "connect", network_name, PROXY_NAME])
    if result.returncode != 0:
        debug(f"Failed to connect proxy to {network_name}: {result.stderr}")
        return False
    return True


def disconnect_proxy_from_network(cell_name: str) -> bool:
    """Disconnect the proxy container from a cell's network."""
    network_name = f"{CONTAINER_PREFIX}{cell_name}"
    result = vm_run(["podman", "network", "disconnect", network_name, PROXY_NAME])
    if result.returncode != 0:
        debug(f"Failed to disconnect proxy from {network_name}: {result.stderr}")
        return False
    return True
