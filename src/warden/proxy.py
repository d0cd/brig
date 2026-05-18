"""
Warden proxy container lifecycle management.

Handles start, stop, restart, status, and reload of the mitmproxy container.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from brig.config import (
    CONTAINER_PREFIX,
    HostPaths,
    INGRESS_PORT,
    PROXY_EXTERNAL_NETWORK,
    PROXY_NAME,
    VMPaths,
)
from brig.ops.logging import debug, info
from brig.vm.shell import vm_run, vm_run_interactive

IMAGE = "docker.io/mitmproxy/mitmproxy@sha256:39ef4ec493d10bf07c71189961c7797b24c445e640ee133efba87fea80d19268"
MEMORY_LIMIT = "1g"
CPU_LIMIT = "1"
PIDS_LIMIT = "256"

# VM-side paths (used in podman volume mounts).
VM_POLICY_FILE = VMPaths.NETWORK_POLICY
VM_LOG_DIR = VMPaths.LOG_DIR
VM_ADDONS_DIR = VMPaths.ADDONS_DIR
# Warden bind-mounts /state/system → /var/run/cells so it sees the same
# subnet-map / per-cell policies / ingress routes the host CLI writes.
VM_SYSTEM_DIR = VMPaths.SYSTEM_DIR


def _podman_ps(all_states: bool = False) -> list[str]:
    """Get list of container names from podman ps.

    The filter is regex-anchored so `name=warden-old` doesn't match `warden`.
    """
    cmd = [
        "podman", "ps", "--format", "{{.Names}}",
        "--filter", f"name=^{PROXY_NAME}$",
    ]
    if all_states:
        cmd.insert(2, "-a")
    result = vm_run(cmd)
    return result.stdout.strip().split("\n") if result.stdout.strip() else []


def is_running() -> bool:
    """Check if the proxy container is running.

    Verifies State.Status == "running" via inspect, not just presence in
    `podman ps`. An exited container can briefly appear in ps after a crash;
    we want a strict "actually serving traffic" answer.
    """
    result = vm_run(
        ["podman", "inspect", PROXY_NAME, "--format", "{{.State.Status}}"],
        timeout=5,
    )
    return result.returncode == 0 and result.stdout.strip() == "running"


def container_exists() -> bool:
    """Check if the proxy container exists (running or stopped)."""
    return PROXY_NAME in _podman_ps(all_states=True)


def stop(timeout: int = 10) -> bool:
    """Stop the proxy container gracefully. Idempotent."""
    vm_run(["podman", "stop", "-t", str(timeout), PROXY_NAME])
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

    # Pre-flight: check host-side files (these get mounted into the VM).
    required_addons = ["enforce.py", "logger.py"]
    for addon in required_addons:
        if not (HostPaths.ADDONS_DIR / addon).exists():
            debug(f"Required addon missing: {HostPaths.ADDONS_DIR / addon}")
            info("Run: make install (to copy addons)")
            return False

    if not HostPaths.NETWORK_POLICY.exists():
        debug(f"Policy file missing: {HostPaths.NETWORK_POLICY}")
        info("Run: brig init")
        return False

    try:
        with open(HostPaths.NETWORK_POLICY) as f:
            json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        debug(f"Policy file invalid: {e}")
        return False

    # Ensure proxy-external network exists in VM.
    vm_run(["podman", "network", "create", PROXY_EXTERNAL_NETWORK], timeout=10)
    # Ensure VM-side log directory exists (rootful, so created here, not on
    # host) and is writable by the mitmproxy user (uid 1000) inside warden.
    # The mitmproxy image uses uid:gid 1000:1000; without chown the addon's
    # log writer hits EACCES on /logs/<cell>.jsonl.
    vm_run(["mkdir", "-p", str(VM_LOG_DIR)], timeout=5)
    vm_run(["chown", "1000:1000", str(VM_LOG_DIR)], timeout=5)
    # Ensure host-side coordination dirs exist; warden bind-mounts them in
    # via the /state virtiofs mount.
    HostPaths.SYSTEM_DIR.mkdir(parents=True, exist_ok=True)
    HostPaths.POLICY_DIR.mkdir(parents=True, exist_ok=True)

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

    # Check if ingress addon is available.
    has_ingress = (HostPaths.ADDONS_DIR / "ingress.py").exists()

    # Volume mounts (VM-side paths — podman runs inside the VM).
    cmd.extend(["-v", f"{VM_LOG_DIR}:/logs:rw"])
    cmd.extend(["-v", f"{VM_SYSTEM_DIR}:/var/run/cells:rw"])
    cmd.extend(["-v", f"{VM_ADDONS_DIR}:/addons:ro"])
    cmd.extend(["-v", f"{VM_POLICY_FILE}:/policy.json:ro"])

    # Expose ingress port if addon exists.
    if has_ingress:
        cmd.extend(["-p", f"{INGRESS_PORT}:{INGRESS_PORT}"])

    # Image.
    cmd.append(IMAGE)

    if has_ingress:
        # Multi-mode: forward proxy on 8080, ingress on INGRESS_PORT.
        # mitmproxy 10+ supports multiple --mode flags with port binding.
        # ingress.py MUST load before enforce.py so it can authenticate
        # and tag requests before enforce.py checks the ingress flag.
        cmd.extend([
            "--mode", "regular@8080",
            "--mode", f"regular@{INGRESS_PORT}",
            "--set", "block_global=false",
            "-s", "/addons/ingress.py",
            "-s", "/addons/enforce.py",
            "-s", "/addons/logger.py",
        ])
    else:
        cmd.extend([
            "--listen-host", "0.0.0.0",
            "--listen-port", "8080",
            "--set", "block_global=false",
            "-s", "/addons/enforce.py",
            "-s", "/addons/logger.py",
        ])

    # Optional addons (check host-side, mount VM-side).
    for addon in ["ops.py", "notifier.py"]:
        if (HostPaths.ADDONS_DIR / addon).exists():
            cmd.extend(["-s", f"/addons/{addon}"])

    result = vm_run(cmd, timeout=120)
    if result.returncode != 0:
        info(f"Failed to start proxy: {result.stderr.strip()}")
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
