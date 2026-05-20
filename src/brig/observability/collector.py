"""OpenTelemetry Collector lifecycle.

Runs as a sibling container to warden inside the Lima VM. Receives
OTLP from warden, exposes a Prometheus endpoint for the brig CLI to
read, and writes traces/logs to rotated files. Started before warden
on `brig system up` so warden has an emit target from cold start.

Failure-closed: refuses to start if the image digest is not pinned in
brig.config.COLLECTOR_IMAGE_DIGEST (run scripts/pin-collector-image.sh
to populate it).
"""

from __future__ import annotations

import time
from pathlib import Path

from brig.config import (
    COLLECTOR_IMAGE_DIGEST,
    COLLECTOR_IMAGE_REPO,
    COLLECTOR_NAME,
    COLLECTOR_OTLP_GRPC_PORT,
    COLLECTOR_OTLP_HTTP_PORT,
    COLLECTOR_PROMETHEUS_PORT,
    HostPaths,
)
from brig.errors import BrigError
from brig.ops.logging import debug, info
from brig.vm.shell import vm_run

CONFIG_RESOURCE = "collector_config.yaml"
VM_CONFIG_PATH = "/etc/brig-otel/config.yaml"
VM_DATA_DIR = "/var/lib/otel"
HEALTH_TIMEOUT_S = 10
HEALTH_POLL_S = 0.5


def _resolved_image() -> str:
    """The fully-pinned image reference. Raises if the digest hasn't
    been populated by scripts/pin-collector-image.sh."""
    if not COLLECTOR_IMAGE_DIGEST:
        raise BrigError(
            "OTel collector image digest is not pinned",
            suggestion="Run: ./scripts/pin-collector-image.sh",
        )
    if not COLLECTOR_IMAGE_DIGEST.startswith("sha256:"):
        raise BrigError(
            f"COLLECTOR_IMAGE_DIGEST must start with 'sha256:', "
            f"got {COLLECTOR_IMAGE_DIGEST!r}",
        )
    return f"{COLLECTOR_IMAGE_REPO}@{COLLECTOR_IMAGE_DIGEST}"


def _config_source() -> Path:
    """Path on host to the collector config template."""
    return Path(__file__).parent / CONFIG_RESOURCE


def is_running() -> bool:
    """True if the collector container reports State.Status == 'running'."""
    result = vm_run(
        ["podman", "inspect", COLLECTOR_NAME,
         "--format", "{{.State.Status}}"],
        timeout=5,
    )
    return result.returncode == 0 and result.stdout.strip() == "running"


def exists() -> bool:
    """True if the container exists in any state."""
    result = vm_run(
        ["podman", "ps", "-a", "--format", "{{.Names}}",
         "--filter", f"name=^{COLLECTOR_NAME}$"],
        timeout=5,
    )
    return COLLECTOR_NAME in result.stdout.split()


def stop(timeout: int = 5) -> None:
    """Best-effort stop + remove of the collector container."""
    vm_run(["podman", "stop", "-t", str(timeout), COLLECTOR_NAME], timeout=15)
    vm_run(["podman", "rm", COLLECTOR_NAME], timeout=10)


def start() -> bool:
    """Start the collector container. Returns True on healthy launch.

    Idempotent: if already running, returns True without restart.
    If the container exists but is stopped, it's removed and re-run
    so the config + image refresh take effect.
    """
    image = _resolved_image()

    if is_running():
        debug(f"{COLLECTOR_NAME} already running")
        return True

    if exists():
        debug(f"removing stale {COLLECTOR_NAME} container")
        stop()

    # Stage the config inside the VM. The collector binary reads it
    # at startup; the file must exist on the VM filesystem (not just
    # in a bind mount from host) because /etc is rootful.
    config_src = _config_source()
    if not config_src.exists():
        raise BrigError(f"collector config template missing: {config_src}")
    vm_run(["mkdir", "-p", "/etc/brig-otel"], timeout=5)
    vm_run(["mkdir", "-p", VM_DATA_DIR], timeout=5)
    # Lima exposes the host file at /Users/<user>/... inside the VM
    # via virtiofs; copy that into /etc to escape the user mount.
    vm_run(
        ["cp", str(config_src), VM_CONFIG_PATH],
        timeout=10,
    )

    cmd = [
        "podman", "run", "-d",
        "--name", COLLECTOR_NAME,
        "--runtime", "crun",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
        "--memory", "256m",
        "--cpus", "1",
        "--pids-limit", "128",
        "-p", f"{COLLECTOR_OTLP_GRPC_PORT}:{COLLECTOR_OTLP_GRPC_PORT}",
        "-p", f"{COLLECTOR_OTLP_HTTP_PORT}:{COLLECTOR_OTLP_HTTP_PORT}",
        "-p", f"{COLLECTOR_PROMETHEUS_PORT}:{COLLECTOR_PROMETHEUS_PORT}",
        "-v", f"{VM_CONFIG_PATH}:/etc/otelcol-contrib/config.yaml:ro",
        "-v", f"{VM_DATA_DIR}:/var/lib/otel:rw",
        image,
    ]

    result = vm_run(cmd, timeout=60)
    if result.returncode != 0:
        info(f"Failed to start {COLLECTOR_NAME}: {result.stderr.strip()}")
        return False

    deadline = time.monotonic() + HEALTH_TIMEOUT_S
    while time.monotonic() < deadline:
        if is_running():
            info(f"{COLLECTOR_NAME} started")
            return True
        time.sleep(HEALTH_POLL_S)

    debug(f"{COLLECTOR_NAME} did not become healthy in {HEALTH_TIMEOUT_S}s")
    return False


def otlp_endpoint_for_warden() -> str:
    """OTLP gRPC endpoint warden uses to push signals.

    Both warden and collector run as containers on the VM's podman
    network. From inside warden, the collector is reachable at the
    container name via podman's built-in DNS.
    """
    return f"{COLLECTOR_NAME}:{COLLECTOR_OTLP_GRPC_PORT}"


def prometheus_url_for_host() -> str:
    """Where the host CLI scrapes metrics.

    The collector port is published to the VM's loopback via -p; the
    host reaches it through Lima's port forwarding. Default Lima
    forwards 127.0.0.1:N → vm:N.
    """
    return f"http://127.0.0.1:{COLLECTOR_PROMETHEUS_PORT}/metrics"
