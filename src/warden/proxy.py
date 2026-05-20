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

# Warden runs a thin custom image: mitmproxy + OpenTelemetry SDK.
# Build with `./scripts/build-warden-image.sh` (runs inside the VM
# so wheels match arch), commit the resulting WARDEN_IMAGE_DIGEST.
# Until the digest is populated, warden falls back to the bare
# mitmproxy image — no OTel exports, but proxy still works.
WARDEN_IMAGE_TAG = "0.4.0-otel-1.27"
WARDEN_IMAGE_DIGEST = "sha256:d6e66f7c196e7d89a92858da2fc62e4c92fe725d605ef5daa99432d19cf9cb38"
BASE_IMAGE = "docker.io/mitmproxy/mitmproxy@sha256:39ef4ec493d10bf07c71189961c7797b24c445e640ee133efba87fea80d19268"


def _warden_image() -> str:
    """The image reference passed to podman run.

    For the OTel-enabled build, returns the local tag form (the
    digest can't be used directly with `podman run` against a
    locally-built image — podman tries to pull from a "localhost"
    registry). Caller is expected to verify the local image's id
    matches WARDEN_IMAGE_DIGEST first; see _verify_warden_image.
    Falls back to the upstream mitmproxy image when no digest is
    pinned (no OTel exports in that mode).
    """
    if WARDEN_IMAGE_DIGEST and WARDEN_IMAGE_DIGEST.startswith("sha256:"):
        return f"localhost/brig-warden:{WARDEN_IMAGE_TAG}"
    return BASE_IMAGE


def _verify_warden_image() -> bool:
    """If a digest is pinned, confirm the local image's id matches.
    Returns True if no digest is pinned (nothing to verify) or if
    the local image matches the pin. False on mismatch.
    """
    if not WARDEN_IMAGE_DIGEST or not WARDEN_IMAGE_DIGEST.startswith("sha256:"):
        return True  # No pin → no verification needed.
    expected = WARDEN_IMAGE_DIGEST[len("sha256:"):]
    tag = f"localhost/brig-warden:{WARDEN_IMAGE_TAG}"
    result = vm_run(
        ["podman", "inspect", tag, "--format", "{{.Id}}"],
        timeout=10,
    )
    if result.returncode != 0:
        info(
            f"warden image {tag} not found in VM. "
            f"Build it: ./scripts/build-warden-image.sh"
        )
        return False
    actual = result.stdout.strip()
    if actual != expected:
        info(
            f"warden image digest mismatch: "
            f"expected {expected}, local has {actual}. "
            f"Rebuild: ./scripts/build-warden-image.sh"
        )
        return False
    return True


MEMORY_LIMIT = "1g"
CPU_LIMIT = "1"
PIDS_LIMIT = "256"

# VM-side paths (used in podman volume mounts).
VM_POLICY_FILE = VMPaths.NETWORK_POLICY
VM_LOG_DIR = VMPaths.LOG_DIR
VM_ADDONS_DIR = VMPaths.ADDONS_DIR
# Persistent home for warden's mitmproxy state (CA cert + private key).
# Bind-mounted into warden at /home/mitmproxy/.mitmproxy, owned by uid
# 1000 (mitmproxy user inside the container). Persistent so:
#   - the CA survives warden restarts (cells trust the same cert across
#     up/down cycles instead of seeing a new CA every time)
#   - brig.cell.ca_bundle reads it directly via `cat` from the VM
#     filesystem, no `podman exec` needed (eliminates the auto-sudo
#     trap where vm_run only sudo's for cmd[0] in a small whitelist —
#     `sh -c '...podman exec...'` falls through and silently runs
#     unprivileged, which aitelier hit hard on fresh installs)
VM_WARDEN_STATE_DIR = Path("/var/lib/warden/mitmproxy-state")
# Path inside the VM to warden's CA cert. brig.cell.ca_bundle reads from
# here. Stays in lockstep with WARDEN_CA_PATH_IN_CONTAINER if you bump.
VM_WARDEN_CA_FILE = VM_WARDEN_STATE_DIR / "mitmproxy-ca-cert.pem"
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

    # If running the pinned OTel image, verify the local build matches
    # the recorded digest before launching (since locally-built images
    # can't be digest-pulled, we verify by inspect).
    if not _verify_warden_image():
        return False

    # Ensure proxy-external network exists in VM.
    vm_run(["podman", "network", "create", PROXY_EXTERNAL_NETWORK], timeout=10)
    # Ensure VM-side log directory exists (rootful, so created here, not on
    # host) and is writable by the mitmproxy user (uid 1000) inside warden.
    # The mitmproxy image uses uid:gid 1000:1000; without chown the addon's
    # log writer hits EACCES on /logs/<cell>.jsonl.
    vm_run(["mkdir", "-p", str(VM_LOG_DIR)], timeout=5)
    vm_run(["chown", "1000:1000", str(VM_LOG_DIR)], timeout=5)
    # Warden's mitmproxy-state dir. Persistent + uid-1000-owned so
    # mitmproxy can write the CA cert + key it generates on first run.
    # We force-generate the cert at the end of start() so brig.cell.ca_bundle
    # can rely on the file existing before any cell starts.
    vm_run(["mkdir", "-p", str(VM_WARDEN_STATE_DIR)], timeout=5)
    vm_run(["chown", "1000:1000", str(VM_WARDEN_STATE_DIR)], timeout=5)
    # Ensure host-side coordination dirs exist; warden bind-mounts them in
    # via the /state virtiofs mount.
    HostPaths.SYSTEM_DIR.mkdir(parents=True, exist_ok=True)
    HostPaths.POLICY_DIR.mkdir(parents=True, exist_ok=True)

    # Build podman run command.
    cmd = [
        "podman", "run", "-d",
        "--name", PROXY_NAME,
        "--runtime", "crun",
        "--pull=never",  # local image is verified by digest above
        "--network", PROXY_EXTERNAL_NETWORK,
        "--entrypoint", "mitmdump",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
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
    # Persistent mitmproxy state — CA cert + key go here.
    cmd.extend(["-v", f"{VM_WARDEN_STATE_DIR}:/home/mitmproxy/.mitmproxy:rw"])

    # Expose ingress port if addon exists.
    if has_ingress:
        cmd.extend(["-p", f"{INGRESS_PORT}:{INGRESS_PORT}"])

    # Point warden at the OTel collector if it's a sibling container.
    # The exporter is no-op if these env vars are missing (no metrics
    # produced), so it's safe to always set them; they only take
    # effect when the OTel-enabled warden image is in use.
    from brig.config import COLLECTOR_NAME, COLLECTOR_OTLP_GRPC_PORT
    cmd.extend([
        "-e", f"OTEL_EXPORTER_OTLP_ENDPOINT=http://{COLLECTOR_NAME}:{COLLECTOR_OTLP_GRPC_PORT}",
        "-e", "OTEL_SERVICE_NAME=warden",
        "-e", "OTEL_RESOURCE_ATTRIBUTES=service.namespace=brig",
    ])

    # Image.
    cmd.append(_warden_image())

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
    for addon in ["ops.py", "notifier.py", "otel_export.py"]:
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

    # Eager CA generation. mitmproxy creates its CA on first traffic, not
    # at container start — which makes brig.cell.ca_bundle.stage_bundle
    # race the first cell start (the cert file doesn't exist yet, so the
    # bundle gets silently truncated to just system roots and HTTPS in
    # the cell fails with "unknown ca"). Force generation here so cells
    # can rely on the CA being on disk by the time they're staged.
    # Idempotent: if the cert already exists (warden restart on a
    # persisted state dir), this is a no-op fast-path.
    if not _ensure_warden_ca_exists():
        debug("Warden CA generation failed — cells will not trust warden")
        return False

    # Reconnect to existing cell networks.
    _reconnect_cell_networks()
    info("Proxy started")
    return True


def _ensure_warden_ca_exists(timeout_s: float = 30.0) -> bool:
    """Wait for mitmproxy's CertStore init to write the CA cert.

    The mitmproxy daemon emits the CA + private key under
    /home/mitmproxy/.mitmproxy at startup as part of CertStore
    initialization — NOT lazily on first proxied request, contrary
    to common belief. So we just poll VM_WARDEN_CA_FILE; no need to
    spawn a separate mitmdump (which would race the main one for the
    same state dir and may even deadlock on a file lock).

    Fast-path: if the cert already exists from a prior `warden start`
    on the persisted state dir, returns immediately.

    Generous timeout because warden start = podman pull-or-verify +
    container init + mitmproxy boot (which compiles certificates
    using OpenSSL). On a cold VM this is ~5–15s; we cap at 30s.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if vm_run(["test", "-f", str(VM_WARDEN_CA_FILE)], timeout=5).returncode == 0:
            return True
        time.sleep(0.5)
    return False


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
