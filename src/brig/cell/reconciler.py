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
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

from brig.cell.ca_bundle import (
    IN_CELL_PATH as CA_BUNDLE_IN_CELL_PATH,
    default_env as ca_bundle_default_env,
    vm_bundle_path as ca_bundle_vm_path,
)
from brig.cell.metadata import IN_CELL_PATH, vm_source_path, write_metadata
from brig.cell.spec import CellSpec
from brig.config import HostPaths, PROXY_NAME, PROXY_PORT, RUNTIME, VMPaths, container_name
from brig.errors import BrigError
from brig.ops.logging import debug
from brig.security.secrets import validate_secret_path
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
    network_internal: bool = False
    proxy_connected: bool = False
    proxy_ip: str = ""
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
    except json.JSONDecodeError:
        return None
    if isinstance(info, list):
        info = info[0] if info else None
    return info if isinstance(info, dict) else None


def _network_internal(name: str) -> bool:
    """True if the named podman network exists AND is --internal (no egress).

    Cell networks must be internal — that is what delivers east-west isolation
    (invariant 1) and keeps Warden the only egress path. The VM's network set is
    untrusted (invariant 4), so a pre-existing same-named network is verified,
    not assumed safe.
    """
    result = _run_cmd(["podman", "network", "inspect", name])
    if result.returncode != 0:
        return False
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    if isinstance(data, list):
        data = data[0] if data else None
    if not isinstance(data, dict):
        return False
    return bool(data.get("internal", data.get("Internal", False)))


def observe(cell_name: str) -> CellState:
    """Query podman for the actual state of a cell."""
    state = CellState()
    name = container_name(cell_name)
    state.container_name = name
    state.network_name = name

    info = _podman_inspect_json(name)
    if info:
        state.exists = True
        state.status = info.get("State", {}).get("Status", "")
        state.running = state.status == "running"

    result = _run_cmd(["podman", "network", "exists", name])
    state.network_exists = result.returncode == 0

    if state.network_exists:
        state.network_internal = _network_internal(name)
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

    # Fail closed: never adopt a pre-existing same-named network that isn't
    # --internal. CREATE_NETWORK (the only place --internal is applied) is
    # skipped on the reuse path below, so a leftover/tampered/operator-made
    # non-internal `brig-<cell>` network would otherwise give the cell
    # off-segment routes (invariant 1) and a path around Warden. The VM network
    # set is untrusted (invariant 4), so verify rather than assume.
    if actual.network_exists and not actual.network_internal:
        raise BrigError(
            f"Refusing to start '{spec.name}': network '{actual.network_name}' "
            f"already exists but is not --internal. A non-internal cell network "
            f"would break east-west isolation and bypass Warden. Remove it first: "
            f"brig system down && podman network rm {actual.network_name}"
        )

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


def _verify_secrets_for_run(spec: CellSpec) -> None:
    """Validate every requested secret against the host secrets dir.

    Ensures each entry in spec.secrets resolves to a real file inside
    HostPaths.SECRETS_DIR — no missing files, no symlinks that escape
    the directory. Called from _execute_action just before the podman
    bind-mount is emitted.
    """
    if not spec.secrets:
        return
    host_secrets_dir = HostPaths.SECRETS_DIR
    for secret_name in spec.secrets:
        try:
            validate_secret_path(secret_name, host_secrets_dir)
        except FileNotFoundError:
            raise BrigError(
                f"Secret '{secret_name}' not found in {host_secrets_dir}",
                suggestion=f"Create it with: brig secrets add {secret_name}",
            )
        except ValueError as e:
            raise BrigError(
                f"Refusing to mount secret '{secret_name}': {e}",
                suggestion=(
                    "Check ~/.brig/secrets/ for symlinks that escape "
                    "the secrets directory and remove them."
                ),
            )


def build_run_command(spec: CellSpec, proxy_ip: str | None) -> list[str]:
    """Build the podman run command for a cell.

    Enforces invariant 5: --runtime runsc is always set.
    """
    name = container_name(spec.name)

    cmd = [
        "podman", "run",
        "--name", name,
        "--runtime", RUNTIME,
    ]

    if spec.is_airgapped:
        cmd.extend(["--network", "none"])
    else:
        if not proxy_ip:
            raise BrigError(
                "proxy_ip is required for non-airgapped cells",
                suggestion=(
                    "Warden's per-cell IP could not be determined. "
                    "Try: brig system doctor"
                ),
            )
        cmd.extend([
            "--network", name,
            "-e", f"http_proxy=http://{proxy_ip}:{PROXY_PORT}",
            "-e", f"https_proxy=http://{proxy_ip}:{PROXY_PORT}",
            "-e", f"HTTP_PROXY=http://{proxy_ip}:{PROXY_PORT}",
            "-e", f"HTTPS_PROXY=http://{proxy_ip}:{PROXY_PORT}",
            "-e", "no_proxy=localhost,127.0.0.1",
        ])

    cmd.extend(["--cap-drop", "ALL", "--security-opt", "no-new-privileges"])

    # Safe-by-default rootfs. The cell's container-writable layer would
    # otherwise let a hostile cell (a) fill the VM disk (shared across
    # all cells; workspace_quota only bounds /work), and (b) stash
    # state outside the workspace where the user wouldn't see it across
    # stop/start. Read-only rootfs + sized tmpfs for the dirs every
    # Linux app expects to write to. workspace_quota still applies to
    # /work; opt-out via writable_rootfs: true in the cell spec.
    if not spec.writable_rootfs:
        cmd.extend([
            "--read-only",
            "--tmpfs", "/tmp:rw,size=64m,noexec,nosuid,nodev",
            "--tmpfs", "/run:rw,size=16m,noexec,nosuid,nodev",
        ])

    cmd.extend([
        "--memory", spec.memory,
        "--cpus", spec.cpus,
        "--pids-limit", str(spec.pids_limit),
    ])

    if spec.timeout:
        from brig.cell.spec import parse_duration
        timeout_seconds = parse_duration(spec.timeout)
        if timeout_seconds is not None:
            cmd.extend(["--timeout", str(timeout_seconds)])

    for label in spec.labels:
        cmd.extend(["--label", label])

    if spec.seccomp_profile:
        if spec.seccomp_profile.lower() == "unconfined":
            raise BrigError("seccomp_profile='unconfined' is not allowed")
        if "/" in spec.seccomp_profile or ".." in spec.seccomp_profile:
            raise BrigError("seccomp_profile must be a filename, not a path")
        profile_path = VMPaths.CELLS_DIR / "seccomp" / spec.seccomp_profile
        cmd.extend(["--security-opt", f"seccomp={profile_path}"])

    if spec.detach:
        cmd.append("-d")
    if spec.rm:
        cmd.append("--rm")

    for env in spec.env:
        env_key = (env.split("=", 1)[0] if "=" in env else env).strip().lower()
        if env_key in _PROXY_ENV_NAMES:
            raise BrigError(
                f"Cannot override proxy environment variable: {env.split('=', 1)[0]}"
            )
        cmd.extend(["-e", env])

    if spec.user:
        cmd.extend(["--user", spec.user])

    workspace_dir = VMPaths.STATE_DIR / spec.name / "workspace"
    cmd.extend([
        "-v", f"{workspace_dir}:{spec.workspace_mount}:rw",
        "-w", spec.workspace_mount,
    ])
    # Downward-API: read-only bind mount of the metadata JSON. The host
    # writes it (see reconciler PODMAN_RUN handler), the cell reads it
    # to learn its own name, workspace host path, and policy ACL.
    cmd.extend(["-v", f"{vm_source_path(spec.name)}:{IN_CELL_PATH}:ro"])

    # Warden CA bundle (system roots + Warden's MITM CA) — auto-mounted
    # so HTTPS clients trust Warden out of the box. Skipped for airgapped
    # cells (no egress to validate) and when the cell opts out via
    # trust_warden_ca: false. The bundle file is staged by the PODMAN_RUN
    # action (brig.cell.ca_bundle.stage_bundle). See INVARIANTS doc.
    if spec.trust_warden_ca and not spec.is_airgapped:
        cmd.extend([
            "-v",
            f"{ca_bundle_vm_path(spec.name)}:{CA_BUNDLE_IN_CELL_PATH}:ro",
        ])
        for env in ca_bundle_default_env(spec.env):
            cmd.extend(["-e", env])

    if spec.secrets:
        # Note: the host-side symlink / existence check for each secret
        # happens in _execute_action(PODMAN_RUN) via _verify_secrets_for_run
        # so build_run_command stays pure and unit-testable. Without that
        # check, a symlink in ~/.brig/secrets/<name> could redirect the
        # bind-mount to an arbitrary host path.
        secrets_dir = Path("/secrets")  # in-VM virtiofs view
        for secret_name in spec.secrets:
            resolved = secrets_dir / secret_name
            cmd.extend(["-v", f"{resolved}:/run/secrets/{secret_name}:ro"])
            # Strip a trailing extension, then map any non-alphanumeric (dots,
            # dashes) to '_' so the result is a valid POSIX env name —
            # `api.key.prod` -> `API_KEY_FILE`, not the unusable `API.KEY_FILE`.
            env_base = secret_name.rsplit(".", 1)[0]
            env_name = re.sub(r"[^A-Za-z0-9]", "_", env_base).upper() + "_FILE"
            cmd.extend(["-e", f"{env_name}=/run/secrets/{secret_name}"])

    if spec.workdir:
        cmd.extend(["--workdir", spec.workdir])

    _attach_host_sockets(spec, cmd)
    _attach_mounts(spec, cmd)

    # End-of-options marker so an image reference (or command token) that
    # begins with '-' can never be parsed by podman as a flag.
    cmd.append("--")
    cmd.append(spec.image)
    cmd.extend(spec.command)

    return cmd


def _attach_host_sockets(spec: CellSpec, cmd: list[str]) -> None:
    """Append `--volume` args for each declared host_socket, after
    re-checking that the bridge socket is actually present and is a
    real unix socket file (not a symlink, not a regular file).

    This is the runtime TOCTOU defense — the static checks at yaml
    parse time can't see the bridge directory, and the bridge is
    populated by the macOS-side launchd unit (Phase 4). If the bridge
    is missing, refuse cell start with a clear error rather than
    letting podman create an empty dir at the source path.
    """
    if not spec.host_sockets:
        return

    from brig.config import VMPaths
    # Per-cell bridge dir so two cells declaring the same physical host
    # service (e.g. both want /tmp/postgres.sock) each get their own
    # bridge socket. No reference counting; bridges live with the cell.
    #
    # CRITICAL: this code runs in the HOST (macOS) process, but the `-v`
    # mount source must be the VM-namespace path (podman runs inside the VM
    # and sees the bridge dir at /state/..., not ~/.brig/...). So validate the
    # HOST path (the same inode, shared into the VM via virtio-fs) and emit the
    # VM path as the mount source. Validating the VM path here would lstat a
    # nonexistent /state on macOS — breaking the feature and leaving the real
    # bridge socket unchecked.
    host_bridge_dir = HostPaths.HOST_SOCKETS_DIR / spec.name
    vm_bridge_dir = Path(str(VMPaths.HOST_SOCKETS_DIR)) / spec.name
    for entry in spec.host_sockets:
        name = entry["name"]
        mount_point = entry["mount_point"]
        mode = entry.get("mode", "ro")
        source = host_bridge_dir / f"{name}.sock"

        # lstat (NOT stat) so symlinks don't get followed silently.
        # Symlinks AT the bridge path OR anywhere in its ancestor
        # chain could redirect the bind-mount to attacker-controlled
        # storage. We require:
        #   - source exists, is a real socket, not a symlink
        #   - every ancestor directory is also not a symlink
        #   - realpath of source still lives under bridge_dir
        import os as _os
        import stat as _stat
        try:
            st = source.lstat()
        except FileNotFoundError:
            raise BrigError(
                f"host_socket '{name}': bridge socket not found at {source}",
                suggestion="Is the launchd bridge running? Try: brig system up",
            )
        if _stat.S_ISLNK(st.st_mode):
            raise BrigError(
                f"host_socket '{name}': bridge path {source} is a symlink. "
                f"Refusing to mount — bridge sockets must be real files."
            )
        if not _stat.S_ISSOCK(st.st_mode):
            raise BrigError(
                f"host_socket '{name}': bridge path {source} is not a "
                f"unix socket (mode={oct(st.st_mode)})."
            )
        # Realpath canonicalizes the entire ancestor chain in one
        # call — any symlinked parent dir (e.g. someone replaced the
        # per-cell bridge dir with a link elsewhere) gets resolved
        # here, defeating a post-lstat parent-dir swap. Then require
        # the canonical path to live under the canonical bridge_dir
        # (resolve both sides; macOS /tmp → /private/tmp makes a raw
        # comparison falsely flag every real path as escaping).
        real_source = _os.path.realpath(str(source))
        real_root = _os.path.realpath(str(host_bridge_dir))
        if not real_source.startswith(real_root + "/"):
            raise BrigError(
                f"host_socket '{name}': bridge socket realpath {real_source} "
                f"escapes bridge dir {real_root}"
            )

        # Validation passed against the host path; mount the VM-namespace path.
        cmd.extend(["-v", f"{vm_bridge_dir / f'{name}.sock'}:{mount_point}:{mode}"])


def _resolved_mount_roots() -> list[tuple[str, str]]:
    """[(realpath_root, slug), ...] for the configured mount_roots.

    Fails closed (BrigError) if the configured roots don't validate or two
    roots share a slug — independent of the lima-render guard, so the bind
    can't resolve against the wrong (but still allowlisted) tree under drift.
    """
    import os.path as _ospath
    from brig.config import mount_root_slug, mount_roots, validate_mount_roots
    roots = mount_roots()
    errs = validate_mount_roots(roots)
    if errs:
        raise BrigError("Invalid mount_roots: " + "; ".join(errs))
    return [(_ospath.realpath(r.rstrip("/")), mount_root_slug(r)) for r in roots]


def _verify_mount_sources_for_run(spec: CellSpec) -> None:
    """Refuse to start a cell whose mount source isn't a live VM mount.

    mount_roots changed without a VM recreate => /mnt/host/<slug> is absent;
    podman -v would auto-create an empty dir and the cell would silently mount
    VM-local storage instead of the host files. Fail closed (mirrors the
    host_socket bridge guard).
    """
    if not spec.mounts:
        return
    roots = _resolved_mount_roots()
    for entry in spec.mounts:
        vm_src = _mount_bind_arg(entry, roots).rsplit(":", 2)[0]
        r = _run_cmd(["test", "-d", vm_src])
        if r.returncode != 0:
            raise BrigError(
                f"mount source {vm_src} is not present in the VM — mount_roots "
                f"likely changed without recreating the VM.",
                suggestion="brig system down --vm, then `limactl delete brig`, "
                           "then brig system up",
            )


def _mount_bind_arg(entry: dict, roots: list[tuple[str, str]]) -> str:
    """Translate a validated `mounts:` entry to a podman `-v` value
    (`<vm_path>:<mount_point>:<mode>`).

    Re-resolves host_path's realpath and re-confirms containment under a
    configured root — the runtime check is the real boundary (invariant 4:
    the cell yaml is untrusted), not the parse-time validator.
    """
    import os.path as _ospath
    real = _ospath.realpath(entry["host_path"])
    for root_real, slug in roots:
        if real == root_real or real.startswith(root_real + "/"):
            vm_path = VMPaths.MOUNTS_DIR / slug
            rel = _ospath.relpath(real, root_real)
            if rel != ".":
                vm_path = vm_path / rel
            return f"{vm_path}:{entry['mount_point']}:{entry.get('mode', 'ro')}"
    raise BrigError(
        f"mount host_path {real} is not under any configured mount_roots"
    )


def _attach_mounts(spec: CellSpec, cmd: list[str]) -> None:
    """Append `--volume` args for each declared `mounts:` entry.

    A cell-created symlink in the mount can't escape the subtree to a VM path
    (container mount-namespace isolation — verified runtime-independent; see
    docs/design/mount-symlink-hardening.md), so no in-VM symlink hardening is
    applied here. The host-side symlink risk is mitigated by `brig cell
    mount-scan`. We bind the realpath and re-check containment per entry.
    """
    if not spec.mounts:
        return
    roots = _resolved_mount_roots()
    for entry in spec.mounts:
        cmd.extend(["-v", _mount_bind_arg(entry, roots)])


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
    name = container_name(action.cell_name)

    if action.type == ActionType.ALLOCATE_SUBNET:
        from brig.network.subnet import allocate
        allocate(action.cell_name)

    elif action.type == ActionType.CREATE_NETWORK:
        from brig.network.subnet import get
        info = get(action.cell_name)
        if info is None:
            raise BrigError(f"No subnet allocated for {action.cell_name}")
        r = _run_cmd([
            "podman", "network", "create", "--internal", "--subnet", info.subnet, name,
        ])
        if r.returncode != 0:
            raise BrigError(
                f"Failed to create network for {action.cell_name}: {r.stderr.strip()}",
                suggestion="Check VM state with: brig system doctor",
            )

    elif action.type == ActionType.CONNECT_PROXY:
        r = _run_cmd(["podman", "network", "connect", name, PROXY_NAME])
        if r.returncode != 0:
            debug(f"Proxy connect stderr (may be already connected): {r.stderr}")

    elif action.type == ActionType.PODMAN_RUN:
        spec = action.params["spec"]
        # Host-side secret-path validation: refuse to start the cell if
        # any requested secret is missing or its path escapes the secrets
        # directory via symlink. Runs here — not in build_run_command —
        # so unit tests can drive build_run_command without needing real
        # files on disk.
        _verify_secrets_for_run(spec)
        _verify_mount_sources_for_run(spec)
        # Ensure workspace directory exists inside the VM before podman mounts it.
        workspace = VMPaths.STATE_DIR / spec.name / "workspace"
        _run_cmd(["mkdir", "-p", str(workspace)])
        # Write the cell metadata file (downward API) so it's in place when
        # podman creates the read-only bind mount at /run/brig/cell.json.
        write_metadata(spec.name, spec.workspace_mount,
                       host_sockets=spec.host_sockets,
                       ingress=spec.ingress,
                       image_digest=spec.image_digest)
        # Stage the combined CA bundle inside the VM so HTTPS clients in
        # the cell trust Warden's MITM cert. Re-extracted from Warden
        # every start so a CA rotation doesn't leave cells with stale
        # trust. Skipped for airgapped cells and explicit opt-outs.
        if spec.trust_warden_ca and not spec.is_airgapped:
            from brig.cell.ca_bundle import stage_bundle
            stage_bundle(spec.name)
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
                raise BrigError(
                    f"Could not determine proxy IP on network {name}",
                    suggestion=(
                        "Warden may not be connected to the cell network. "
                        "Try: brig system up"
                    ),
                )

        cmd = build_run_command(spec, proxy_ip)
        r = _run_cmd(cmd, timeout=120)
        if r.returncode != 0:
            raise BrigError(
                f"podman run failed: {r.stderr.strip()}",
                suggestion=(
                    f"Check the cell's logs: brig cell logs {spec.name}\n"
                    "Or run diagnostics:    brig system doctor"
                ),
            )
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
