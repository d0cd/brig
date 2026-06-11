"""
Proxy state queries and network management.

All podman commands route through vm_run() to execute inside the Lima VM.
"""

from __future__ import annotations

from brig.config import PROXY_NAME
from brig.ops.cache import cached, set_cache
from brig.vm.shell import vm_run


def proxy_running() -> bool:
    """Check if the Warden proxy container is running. Cached for 2 seconds."""
    hit, val = cached("proxy_running")
    if hit:
        return bool(val)

    result = vm_run(
        ["podman", "inspect", PROXY_NAME, "--format", "{{.State.Status}}"],
        timeout=5,
    )
    running = result.returncode == 0 and result.stdout.strip() == "running"
    set_cache("proxy_running", running)
    return running
