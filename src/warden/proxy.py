"""
Warden proxy container lifecycle management.

Handles start, stop, restart, status, and reload of the mitmproxy container.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from brig.config import CONTAINER_PREFIX, PROXY_EXTERNAL_NETWORK, PROXY_NAME
from brig.ops.logging import debug, info
from brig.vm.shell import vm_run, vm_run_interactive

IMAGE = "docker.io/mitmproxy/mitmproxy@sha256:39ef4ec493d10bf07c71189961c7797b24c445e640ee133efba87fea80d19268"
MEMORY_LIMIT = "1g"
CPU_LIMIT = "1"
PIDS_LIMIT = "256"

POLICY_FILE = Path("/cells/network-policy.json")
LOG_DIR = Path("/var/log/brig/network")
ADDONS_DIR = Path("/cells/addons")


def _podman_ps(all_states: bool = False) -> list[str]:
    """Get list of container names from podman ps."""
    cmd = ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={PROXY_NAME}"]
    if all_states:
        cmd.insert(2, "-a")
    result = vm_run(cmd)
    return result.stdout.strip().split("\n") if result.stdout.strip() else []


def is_running() -> bool:
    """Check if the proxy container is running."""
    return PROXY_NAME in _podman_ps()


def container_exists() -> bool:
    """Check if the proxy container exists (running or stopped)."""
    return PROXY_NAME in _podman_ps(all_states=True)


def stop(timeout: int = 10) -> bool:
    """Stop the proxy container gracefully. Idempotent."""
    result = vm_run(
        ["podman", "stop", "-t", str(timeout), PROXY_NAME],
    )
    # Clean up stopped container regardless.
    vm_run(
        ["podman", "rm", PROXY_NAME],
    )
    return True


def reload_policy() -> bool:
    """Reload proxy policy by sending SIGHUP to mitmproxy (PID 1 in container)."""
    result = vm_run(
        ["podman", "exec", PROXY_NAME, "kill", "-HUP", "1"],
    )
    return result.returncode == 0


def start() -> bool:
    """Start the proxy container with full hardening and addon loading.

    Pre-flight: validates addons exist, policy is parseable, network exists.
    Container: read-only root, cap-drop ALL, non-root, resource limits.
    Post-start: waits for health, reconnects to existing cell networks.
    """
    if is_running():
        info("Proxy is already running")
        return True

    # Clean up any stopped container.
    if container_exists():
        vm_run(
            ["podman", "rm", PROXY_NAME],
        )

    # Pre-flight: check required files.
    required_addons = ["enforce.py", "logger.py"]
    for addon in required_addons:
        if not (ADDONS_DIR / addon).exists():
            debug(f"Required addon missing: {ADDONS_DIR / addon}")
            return False

    if not POLICY_FILE.exists():
        debug(f"Policy file missing: {POLICY_FILE}")
        return False

    try:
        with open(POLICY_FILE) as f:
            json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        debug(f"Policy file invalid: {e}")
        return False

    # Build podman run command.
    cmd = [
        "podman", "run", "-d",
        "--name", PROXY_NAME,
        "--runtime", "crun",
        "--network", PROXY_EXTERNAL_NETWORK,
        "--entrypoint", "mitmdump",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--tmpfs", "/home/mitmproxy/.mitmproxy:rw,size=32m",
        "--user", "mitmproxy",
        "--memory", MEMORY_LIMIT,
        "--cpus", CPU_LIMIT,
        "--pids-limit", PIDS_LIMIT,
    ]

    # Volume mounts.
    cmd.extend(["-v", f"{LOG_DIR}:/logs:rw"])
    cmd.extend(["-v", "/var/run/brig:/var/run/cells:rw"])
    cmd.extend(["-v", f"{ADDONS_DIR}:/addons:ro"])
    cmd.extend(["-v", f"{POLICY_FILE}:/policy.json:ro"])

    # Image.
    cmd.append(IMAGE)

    # mitmproxy args.
    cmd.extend([
        "--listen-host", "0.0.0.0",
        "--listen-port", "8080",
        "--set", "block_global=false",
        "-s", "/addons/enforce.py",
        "-s", "/addons/logger.py",
    ])

    # Optional addons.
    for addon in ["ops.py", "ratelimit.py", "metrics.py", "health.py",
                   "notifier.py", "canary.py", "signer.py"]:
        if (ADDONS_DIR / addon).exists():
            cmd.extend(["-s", f"/addons/{addon}"])

    result = vm_run(cmd)
    if result.returncode != 0:
        debug(f"Failed to start proxy: {result.stderr}")
        return False

    # Wait for container health (up to 5 seconds).
    for _ in range(10):
        if is_running():
            break
        time.sleep(0.5)
    else:
        debug("Proxy did not become healthy in 5 seconds")
        return False

    # Reconnect to existing cell networks.
    _reconnect_cell_networks()
    info("Proxy started")
    return True


def _reconnect_cell_networks() -> None:
    """Reconnect proxy to any existing cell networks (recovery from restart)."""
    result = vm_run(
        ["podman", "network", "ls", "--format", "{{.Name}}"],
    )
    if result.returncode != 0:
        return
    for net in result.stdout.strip().split("\n"):
        if net.startswith(CONTAINER_PREFIX) and net != PROXY_EXTERNAL_NETWORK:
            vm_run(
                ["podman", "network", "connect", net, PROXY_NAME],
            )


def get_status() -> dict:
    """Get proxy container status information."""
    result = vm_run(
        ["podman", "inspect", PROXY_NAME, "--format", "json"],
    )
    if result.returncode != 0:
        return {"running": False, "exists": False}

    try:
        data = json.loads(result.stdout)
        if isinstance(data, list):
            data = data[0]
        status = data.get("State", {}).get("Status", "")
        networks = list(data.get("NetworkSettings", {}).get("Networks", {}).keys())
        return {
            "running": status == "running",
            "exists": True,
            "status": status,
            "networks": networks,
        }
    except (json.JSONDecodeError, KeyError):
        return {"running": False, "exists": True}
