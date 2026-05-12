"""
Declarative cell reconciler.

Instead of imperative multi-phase scripts with manual rollback, the reconciler:
  1. observe() — queries podman for actual state
  2. plan()    — computes actions to converge actual to desired
  3. apply()   — executes the action plan (each action independently retryable)

If the process dies mid-creation, running `brig run` again converges to the
desired state because plan() recomputes from current reality.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

from brig.cell.spec import CellSpec
from brig.config import CONTAINER_PREFIX, PROXY_NAME, RUNTIME, VMPaths
from brig.ops.logging import debug
from brig.vm.shell import vm_run


class ActionType(Enum):
    """Types of reconciliation actions."""
    ALLOCATE_SUBNET = auto()
    CREATE_NETWORK = auto()
    CONNECT_PROXY = auto()
    PODMAN_RUN = auto()
    PODMAN_STOP = auto()
    PODMAN_KILL = auto()
    PODMAN_RM = auto()
    DISCONNECT_PROXY = auto()
    REMOVE_NETWORK = auto()
    FREE_SUBNET = auto()


@dataclass
class Action:
    """A single reconciliation action."""
    type: ActionType
    cell_name: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class CellState:
    """Observable state of a cell from podman."""
    exists: bool = False
    running: bool = False
    container_name: str = ""
    network_name: str = ""
    network_exists: bool = False
    proxy_connected: bool = False
    proxy_ip: str = ""
    runtime: str = ""
    status: str = ""


@dataclass
class ReconcileResult:
    """Result of applying a reconciliation plan."""
    success: bool
    actions_completed: list[Action] = field(default_factory=list)
    actions_failed: list[tuple[Action, str]] = field(default_factory=list)
    container_id: str = ""


def _run_cmd(cmd: list[str], timeout: int = 30) -> Any:
    """Run a podman command inside the VM."""
    return vm_run(cmd, timeout=timeout)


def _podman_inspect_json(name: str) -> dict | None:
    """Run podman inspect and return parsed JSON, or None on failure."""
    result = _run_cmd(["podman", "inspect", name, "--format", "json"])
    if result.returncode != 0:
        return None
    try:
        info = json.loads(result.stdout)
        return info[0] if isinstance(info, list) else info
    except json.JSONDecodeError:
        return None


def observe(cell_name: str) -> CellState:
    """Query podman for the actual state of a cell."""
    state = CellState()
    name = f"{CONTAINER_PREFIX}{cell_name}"
    state.container_name = name
    state.network_name = name

    info = _podman_inspect_json(name)
    if info:
        state.exists = True
        state.status = info.get("State", {}).get("Status", "")
        state.running = state.status == "running"
        state.runtime = info.get("HostConfig", {}).get("Runtime", "")

    result = _run_cmd(["podman", "network", "exists", name])
    state.network_exists = result.returncode == 0

    if state.network_exists:
        proxy_info = _podman_inspect_json(PROXY_NAME)
        if proxy_info:
            proxy_networks = proxy_info.get("NetworkSettings", {}).get("Networks", {})
            if name in proxy_networks:
                state.proxy_connected = True
                state.proxy_ip = proxy_networks[name].get("IPAddress", "")

    return state


def plan_run(spec: CellSpec, actual: CellState) -> list[Action]:
    """Compute actions to create/start a cell.

    Handles partial states from interrupted previous runs:
      - Network exists but container doesn't: connect proxy + run
      - Container exists but stopped: remove and recreate
      - Already running: no actions
    """
    actions: list[Action] = []

    if actual.exists and actual.running:
        return []

    # Stopped container from a previous run — clean up first.
    if actual.exists and not actual.running:
        actions.append(Action(ActionType.PODMAN_RM, spec.name))

    if not actual.network_exists:
        actions.append(Action(ActionType.ALLOCATE_SUBNET, spec.name))
        actions.append(Action(ActionType.CREATE_NETWORK, spec.name))

    if not spec.is_airgapped and not actual.proxy_connected:
        actions.append(Action(ActionType.CONNECT_PROXY, spec.name))

    actions.append(Action(ActionType.PODMAN_RUN, spec.name, {"spec": spec}))
    return actions


def plan_destroy(cell_name: str, actual: CellState) -> list[Action]:
    """Compute actions to fully remove a cell."""
    actions: list[Action] = []

    if actual.exists and actual.running:
        actions.append(Action(ActionType.PODMAN_KILL, cell_name))
    if actual.exists:
        actions.append(Action(ActionType.PODMAN_RM, cell_name))
    if actual.proxy_connected:
        actions.append(Action(ActionType.DISCONNECT_PROXY, cell_name))
    if actual.network_exists:
        actions.append(Action(ActionType.REMOVE_NETWORK, cell_name))
        actions.append(Action(ActionType.FREE_SUBNET, cell_name))

    return actions


def plan_stop(cell_name: str, actual: CellState) -> list[Action]:
    """Compute actions to gracefully stop a cell."""
    if actual.exists and actual.running:
        return [Action(ActionType.PODMAN_STOP, cell_name)]
    return []


_PROXY_ENV_NAMES = {"http_proxy", "https_proxy", "no_proxy", "all_proxy", "ftp_proxy"}


def build_run_command(spec: CellSpec, proxy_ip: str | None) -> list[str]:
    """Build the podman run command for a cell.

    Enforces invariant 5: --runtime runsc is always set.
    """
    name = f"{CONTAINER_PREFIX}{spec.name}"

    cmd = [
        "podman", "run",
        "--name", name,
        "--runtime", RUNTIME,
    ]

    if spec.is_airgapped:
        cmd.extend(["--network", "none"])
    else:
        assert proxy_ip is not None
        cmd.extend([
            "--network", name,
            "-e", f"http_proxy=http://{proxy_ip}:8080",
            "-e", f"https_proxy=http://{proxy_ip}:8080",
            "-e", f"HTTP_PROXY=http://{proxy_ip}:8080",
            "-e", f"HTTPS_PROXY=http://{proxy_ip}:8080",
            "-e", "no_proxy=localhost,127.0.0.1",
        ])

    cmd.extend(["--cap-drop", "ALL", "--security-opt", "no-new-privileges"])
    cmd.extend([
        "--memory", spec.memory,
        "--cpus", spec.cpus,
        "--pids-limit", str(spec.pids_limit),
    ])

    if spec.timeout:
        from brig.cell.spec import parse_duration
        timeout_seconds = parse_duration(spec.timeout)
        if timeout_seconds:
            cmd.extend(["--timeout", str(timeout_seconds)])

    for label in spec.labels:
        cmd.extend(["--label", label])

    if spec.seccomp_profile:
        # Block "unconfined" which disables seccomp entirely.
        if spec.seccomp_profile.lower() == "unconfined":
            raise ValueError("seccomp_profile='unconfined' is not allowed — it disables seccomp")
        cmd.extend(["--security-opt", f"seccomp={spec.seccomp_profile}"])

    if spec.detach:
        cmd.append("-d")
    if spec.rm:
        cmd.append("--rm")

    for env in spec.env:
        env_key = env.split("=", 1)[0].lower() if "=" in env else env.lower()
        if env_key in _PROXY_ENV_NAMES:
            raise ValueError(
                f"Cannot override proxy environment variable: {env.split('=', 1)[0]}"
            )
        cmd.extend(["-e", env])

    workspace_dir = VMPaths.STATE_DIR / spec.name / "workspace"
    cmd.extend(["-v", f"{workspace_dir}:/work:rw", "-w", "/work"])

    if spec.secrets:
        secrets_dir = Path("/secrets")
        for secret_name in spec.secrets:
            resolved = secrets_dir / secret_name
            cmd.extend(["-v", f"{resolved}:/run/secrets/{secret_name}:ro"])
            env_name = secret_name.rsplit(".", 1)[0].upper().replace("-", "_") + "_FILE"
            cmd.extend(["-e", f"{env_name}=/run/secrets/{secret_name}"])

    if spec.workdir:
        cmd.extend(["--workdir", spec.workdir])

    cmd.append(spec.image)
    cmd.extend(spec.command)

    return cmd


_ROLLBACK_MAP = {
    ActionType.ALLOCATE_SUBNET: ActionType.FREE_SUBNET,
    ActionType.CREATE_NETWORK: ActionType.REMOVE_NETWORK,
    ActionType.CONNECT_PROXY: ActionType.DISCONNECT_PROXY,
    ActionType.PODMAN_RUN: ActionType.PODMAN_RM,
}


def apply(actions: list[Action]) -> ReconcileResult:
    """Execute a reconciliation plan. On failure, rolls back completed actions."""
    result = ReconcileResult(success=True)

    for action in actions:
        try:
            _execute_action(action, result)
            result.actions_completed.append(action)
        except Exception as e:
            result.actions_failed.append((action, str(e)))
            result.success = False
            _rollback(result.actions_completed)
            break

    return result


def _rollback(completed: list[Action]) -> None:
    """Best-effort rollback of completed actions in reverse order."""
    for action in reversed(completed):
        rollback_type = _ROLLBACK_MAP.get(action.type)
        if rollback_type is None:
            continue
        try:
            rollback_action = Action(rollback_type, action.cell_name)
            _execute_action(rollback_action, ReconcileResult(success=True))
        except Exception as e:
            debug(f"Rollback failed for {rollback_type.name}: {e}")


def _execute_action(action: Action, result: ReconcileResult) -> None:
    """Execute a single reconciliation action."""
    name = f"{CONTAINER_PREFIX}{action.cell_name}"

    if action.type == ActionType.ALLOCATE_SUBNET:
        from brig.network.subnet import allocate
        allocate(action.cell_name)

    elif action.type == ActionType.CREATE_NETWORK:
        from brig.network.subnet import get
        info = get(action.cell_name)
        if info is None:
            raise RuntimeError(f"No subnet allocated for {action.cell_name}")
        r = _run_cmd([
            "podman", "network", "create", "--internal", "--subnet", info.subnet, name,
        ])
        if r.returncode != 0:
            raise RuntimeError(f"Failed to create network: {r.stderr}")

    elif action.type == ActionType.CONNECT_PROXY:
        r = _run_cmd(["podman", "network", "connect", name, PROXY_NAME])
        if r.returncode != 0:
            debug(f"Proxy connect stderr (may be already connected): {r.stderr}")

    elif action.type == ActionType.PODMAN_RUN:
        spec = action.params["spec"]
        # Ensure workspace directory exists inside the VM before podman mounts it.
        workspace = VMPaths.STATE_DIR / spec.name / "workspace"
        _run_cmd(["mkdir", "-p", str(workspace)])
        proxy_ip = None
        if not spec.is_airgapped:
            # Retry — network connect may not have propagated yet.
            import time
            for attempt in range(5):
                proxy_info = _podman_inspect_json(PROXY_NAME)
                if proxy_info:
                    proxy_ip = (proxy_info.get("NetworkSettings", {})
                                .get("Networks", {}).get(name, {}).get("IPAddress", ""))
                if proxy_ip:
                    break
                time.sleep(1)
            if not proxy_ip:
                raise RuntimeError(f"Could not determine proxy IP on {name}")

        cmd = build_run_command(spec, proxy_ip)
        r = _run_cmd(cmd, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"podman run failed: {r.stderr}")
        result.container_id = r.stdout.strip()

    elif action.type == ActionType.PODMAN_STOP:
        _run_cmd(["podman", "stop", name])

    elif action.type == ActionType.PODMAN_KILL:
        _run_cmd(["podman", "kill", name])

    elif action.type == ActionType.PODMAN_RM:
        _run_cmd(["podman", "rm", "-f", name])

    elif action.type == ActionType.DISCONNECT_PROXY:
        _run_cmd(["podman", "network", "disconnect", name, PROXY_NAME])

    elif action.type == ActionType.REMOVE_NETWORK:
        _run_cmd(["podman", "network", "rm", name])

    elif action.type == ActionType.FREE_SUBNET:
        from brig.network.subnet import free
        try:
            free(action.cell_name)
        except ValueError:
            pass  # Already freed — idempotent.
