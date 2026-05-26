"""
High-level cell lifecycle operations.

These wrap the reconciler with validation, logging, and error handling.
The proxy_check parameter decouples the domain layer from subprocess calls,
making it testable without mocking subprocess.
"""

from __future__ import annotations

import re
from typing import Callable

from brig.cell.reconciler import (
    Action,
    ActionType,
    ReconcileResult,
    apply,
    observe,
    plan_destroy,
    plan_run,
    plan_stop,
)
from brig.cell.spec import CellSpec
from brig.errors import BrigError
from brig.ops.history import log_lifecycle, log_operation, log_policy_change
from brig.ops.logging import debug, info
from brig.ops.ratelimit import check_rate_limit
from brig.vm.shell import vm_run


def _register_cell_ingress(spec: CellSpec, result: ReconcileResult) -> None:
    """Register ingress routes for a newly started cell.

    Reads the cell's IP from podman inspect, reads the auth token from
    the mounted ingress-token secret, and registers routes.
    """
    from brig.network.ingress import register_ingress

    # Get the cell's IP on its dedicated network.
    container_name = f"brig-{spec.name}"
    network_name = container_name
    from brig.cell.reconciler import _podman_inspect_json
    container_info = _podman_inspect_json(container_name)
    if not container_info:
        debug(f"Could not inspect {container_name} for ingress registration")
        return

    cell_ip = (
        container_info.get("NetworkSettings", {})
        .get("Networks", {})
        .get(network_name, {})
        .get("IPAddress", "")
    )
    if not cell_ip:
        debug("Could not determine cell IP for ingress registration")
        return

    # Read ingress auth token from secrets. Validate the path resolves inside
    # the secrets dir to prevent symlink escape (an attacker who plants a
    # symlink in ~/.brig/secrets pointing at /etc/passwd would otherwise
    # have its contents adopted as the ingress token).
    from brig.config import HostPaths
    from brig.security.secrets import validate_secret_path

    # Every ingress entry today uses auth: token (the only supported
    # method). A missing token means routes get registered but every
    # request 401s — silent failure that aitelier flagged. Promote to
    # a hard error: the cell starts (containers are already up), but
    # ingress registration refuses, and the operator gets a clear
    # message instead of a buried WARN line.
    token_name = f"{spec.name}-ingress-token"
    try:
        token_path = validate_secret_path(token_name, HostPaths.SECRETS_DIR)
    except (ValueError, FileNotFoundError):
        try:
            token_path = validate_secret_path("ingress-token", HostPaths.SECRETS_DIR)
        except (ValueError, FileNotFoundError):
            raise BrigError(
                f"Cell '{spec.name}' declares ingress with auth: token "
                f"but no token secret exists. Ingress would register "
                f"routes that reject every request.",
                suggestion=(
                    f"Create the token (32+ random chars), then re-run:\n"
                    f"  openssl rand -hex 32 | brig secrets add {token_name} -\n"
                    f"  brig cell rm {spec.name} && brig run --file <yaml>"
                ),
            )

    auth_token = token_path.read_text().strip()
    if not auth_token:
        raise BrigError(
            f"Ingress token for '{spec.name}' is empty",
            suggestion=f"openssl rand -hex 32 | brig secrets add {token_name} -",
        )
    if len(auth_token) < 32:
        info(
            f"WARNING: Ingress token for '{spec.name}' is short. "
            f"Use at least 32 characters."
        )

    register_ingress(spec.name, cell_ip, spec.ingress, auth_token)


def _default_proxy_check() -> bool:
    """Default proxy check — imports and calls proxy_running()."""
    from brig.network.proxy import proxy_running
    return proxy_running()


def _container_name_from_entry(entry: dict) -> str:
    """Extract the container name from a `podman ps` JSON entry.

    Podman 4.x returns Names as a string; 5.x as a list. This handles
    both shapes so callers don't have to remember which one this version
    of podman emits.
    """
    names = entry.get("Names", "")
    if isinstance(names, list):
        return names[0] if names else ""
    return names


def list_cell_containers(*, include_stopped: bool = True) -> list[tuple[str, dict]]:
    """Return `(cell_name, container_entry)` pairs for every brig-managed cell.

    Filters by `name=^brig-` (the CONTAINER_PREFIX), then drops infra
    sidecars (warden, OTel collector — see config.INFRA_CONTAINER_NAMES)
    so they don't masquerade as cells in `brig cell list`, security
    invariant checks, or the prune surface.

    Returns the unprefixed cell name (`brig-foo` → `foo`) alongside the
    raw podman entry so callers needing extra fields (Image, State,
    Networks) don't re-fetch.
    """
    import json

    from brig.config import CONTAINER_PREFIX, INFRA_CONTAINER_NAMES

    cmd = ["podman", "ps", "--format", "json",
           "--filter", f"name=^{CONTAINER_PREFIX}"]
    if include_stopped:
        cmd.insert(2, "-a")
    result = vm_run(cmd)
    if result.returncode != 0:
        return []
    try:
        entries = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        return []

    out: list[tuple[str, dict]] = []
    for entry in entries:
        name = _container_name_from_entry(entry)
        if not name or name in INFRA_CONTAINER_NAMES:
            continue
        cell_name = (
            name[len(CONTAINER_PREFIX):] if name.startswith(CONTAINER_PREFIX) else name
        )
        out.append((cell_name, entry))
    return out


_DIGEST_PATTERN = re.compile(r"^sha(?:256|384|512):[0-9a-fA-F]{64,}$")


def _apply_image_digest_pin(spec: CellSpec) -> None:
    """Rewrite spec.image to `image@digest` form when image_digest is set.

    Podman natively enforces digest pinning when the image reference
    contains `@sha256:...`, so converting the soft-pin into a hard
    reference before invoking podman lets podman refuse any mismatch
    at pull time.

    Raises BrigError if:
      - image_digest is set but malformed (must be sha{256,384,512}:HEX)
      - image already contains a digest that disagrees with image_digest
    """
    if not spec.image_digest:
        return
    digest = spec.image_digest.strip()
    if not _DIGEST_PATTERN.match(digest):
        raise BrigError(
            f"Invalid image_digest '{digest}'",
            suggestion="Format must be sha256:<64-hex> (or sha384/sha512)",
        )
    if "@" in spec.image:
        repo, _, existing = spec.image.partition("@")
        if existing != digest:
            raise BrigError(
                f"image_digest '{digest}' disagrees with the digest already "
                f"present on image reference '{spec.image}'",
                suggestion="Remove one of the two so the source of truth is unambiguous",
            )
        return  # Already in image@digest form and matches.
    spec.image = f"{spec.image}@{digest}"


def run_cell(
    spec: CellSpec,
    proxy_check: Callable[[], bool] = _default_proxy_check,
) -> ReconcileResult:
    """Run a new cell.

    Args:
        spec: Cell specification.
        proxy_check: Callable returning True if proxy is running.
            Injected for testability; defaults to the real proxy_running().

    Enforces:
      - Invariant 9: proxy must be running (unless airgapped)
      - Rate limiting
      - image_digest pinning (when set, image is rewritten to image@digest
        so podman refuses any mismatch at pull time)
    """
    _apply_image_digest_pin(spec)

    if not spec.is_airgapped and not proxy_check():
        raise BrigError(
            "Warden proxy is not running",
            suggestion="Start with: brig up",
        )

    if not check_rate_limit():
        raise BrigError(
            "Rate limit exceeded: too many cells created recently",
            suggestion="Wait a moment and try again, or increase the rate limit",
        )

    actual = observe(spec.name)
    if actual.exists and actual.running:
        raise BrigError(
            f"Cell '{spec.name}' is already running",
            suggestion=(
                f"brig cell rm -f {spec.name}  # remove and re-run\n"
                f"  OR  brig cell stop {spec.name}\n"
                f"  OR  brig run --name <different-name> ..."
            ),
        )

    actions = plan_run(spec, actual)
    if not actions:
        raise BrigError(
            f"Cell '{spec.name}' already exists",
            suggestion=(
                f"brig cell rm {spec.name}     # remove the old one first\n"
                f"  OR  brig run --name <different-name> ..."
            ),
        )

    # Bring up host_socket bridges BEFORE reconcile — the reconciler's
    # runtime check needs the bridge sockets to exist. start_cell_bridges
    # is idempotent and a no-op if spec.host_sockets is empty.
    if spec.host_sockets:
        from brig.cell.host_sockets_bridge import start_cell_bridges
        start_cell_bridges(spec.name, spec.host_sockets)

    debug(f"Reconciliation plan: {[a.type.name for a in actions]}")
    try:
        result = apply(actions)
    except Exception:
        # apply() rolled back its own actions, but it doesn't know about
        # bridges. Tear them down so we don't leak a socat process for
        # a cell that never started.
        if spec.host_sockets:
            from brig.cell.host_sockets_bridge import stop_cell_bridges
            stop_cell_bridges(spec.name)
        raise

    if not result.success:
        # Same rollback as the exception path: apply()'s _rollback handles
        # network/subnet/podman actions, but bridges are ours to clean up.
        if spec.host_sockets:
            from brig.cell.host_sockets_bridge import stop_cell_bridges
            stop_cell_bridges(spec.name)
        failed = result.actions_failed[0] if result.actions_failed else (None, "unknown")
        raise BrigError(f"Failed to start cell '{spec.name}': {failed[1]}")

    # From here the cell is up. Any post-start step that fails (e.g.
    # ingress registration with no token) must roll the cell back —
    # leaving a partially-configured cell running is worse than failing
    # to start at all.
    try:
        log_operation("run", cell_name=spec.name, details={"image": spec.image})
        log_lifecycle("start", spec.name, details={"image": spec.image})
        # Log per-cell policy to the audit trail when specified.
        if spec.policy_allow or spec.policy_deny:
            log_policy_change(
                spec.name, "create",
                changes={"allow": spec.policy_allow, "deny": spec.policy_deny},
            )
        # Register ingress routes if the cell has ingress endpoints.
        if spec.ingress:
            _register_cell_ingress(spec, result)
        # Audit any host_sockets that were mounted. The bytes flowing
        # over these sockets bypass Warden, so the attach event is the
        # only thing we can record — make sure it's loud.
        if spec.host_sockets:
            for entry in spec.host_sockets:
                log_lifecycle(
                    "host_socket_attach", spec.name,
                    details={"socket": entry["name"],
                             "mount_point": entry["mount_point"],
                             "mode": entry.get("mode", "ro")},
                )
            info(
                f"NOTE: cell '{spec.name}' has {len(spec.host_sockets)} "
                f"host_sockets — Warden does not see traffic over these."
            )
        info(f"Cell '{spec.name}' started")
    except BrigError:
        # Roll the cell back — container is running, but post-start
        # config failed. Better to fail clean than ship a half-cell.
        info(f"post-start failure for '{spec.name}'; rolling back cell")
        try:
            rm_cell(spec.name, force=True)
        except Exception as cleanup_err:
            debug(f"rollback rm_cell failed: {cleanup_err}")
        raise

    return result


def stop_cell(cell_name: str) -> None:
    """Gracefully stop a running cell."""
    actual = observe(cell_name)
    if not actual.exists:
        raise BrigError(
            f"Cell '{cell_name}' does not exist",
            suggestion="Use 'brig list' to see available cells",
        )
    if not actual.running:
        raise BrigError(
            f"Cell '{cell_name}' is not running",
            suggestion=f"Use 'brig start {cell_name}' to start it",
        )

    # Deregister ingress routes before stopping (prevents stale routes
    # from forwarding to a dead cell or a reused subnet).
    from brig.network.ingress import deregister_ingress
    deregister_ingress(cell_name)

    # Tear down any host_socket bridges (idempotent — no-op if there
    # are none). Done before the podman stop so launchd doesn't keep
    # trying to forward to a dead cell.
    from brig.cell.host_sockets_bridge import stop_cell_bridges
    stop_cell_bridges(cell_name)

    actions = plan_stop(cell_name, actual)
    result = apply(actions)

    if result.success:
        log_operation("stop", cell_name=cell_name)
        log_lifecycle("stop", cell_name)
    else:
        failed = result.actions_failed[0] if result.actions_failed else (None, "unknown")
        raise BrigError(f"Failed to stop cell '{cell_name}': {failed[1]}")


def kill_cell(cell_name: str) -> None:
    """Immediately kill a running cell."""
    actual = observe(cell_name)
    if not actual.exists:
        raise BrigError(
            f"Cell '{cell_name}' does not exist",
            suggestion="Use 'brig list' to see available cells",
        )

    # Deregister ingress routes before killing.
    from brig.network.ingress import deregister_ingress
    deregister_ingress(cell_name)

    # Tear down host_socket bridges (idempotent).
    from brig.cell.host_sockets_bridge import stop_cell_bridges
    stop_cell_bridges(cell_name)

    actions = [Action(ActionType.PODMAN_KILL, cell_name)] if actual.running else []
    result = apply(actions)

    if result.success:
        log_operation("kill", cell_name=cell_name)
        log_lifecycle("kill", cell_name)


def rm_cell(
    cell_name: str,
    force: bool = False,
    keep_workspace: bool = False,
) -> None:
    """Remove a cell and all associated resources.

    By default also deletes the cell's workspace directory (under
    ~/.brig/state/<cell>/). Pass `keep_workspace=True` to preserve it;
    callers that want to extract files first should `brig cell cp` them
    out before calling rm.

    Why default-delete (was leave-on-disk in earlier versions): the
    workspace can contain cell-controlled content including symlinks
    pointing at host files. If a new cell takes the same name later, it
    inherits the prior cell's planted bait. Cleaning by default closes
    that re-use foot-gun; users who need the data ask for it.
    """
    actual = observe(cell_name)
    if not actual.exists and not actual.network_exists:
        raise BrigError(
            f"Cell '{cell_name}' does not exist",
            suggestion="Use 'brig list' to see available cells",
        )

    if actual.running and not force:
        raise BrigError(
            f"Cell '{cell_name}' is running. Stop it first or use --force.",
            suggestion=f"brig stop {cell_name}  OR  brig rm -f {cell_name}",
        )

    # Deregister ingress routes before destroying the cell.
    from brig.network.ingress import deregister_ingress
    deregister_ingress(cell_name)

    # Tear down host_socket bridges (idempotent).
    from brig.cell.host_sockets_bridge import stop_cell_bridges
    stop_cell_bridges(cell_name)

    actions = plan_destroy(cell_name, actual)
    result = apply(actions)

    if not result.success:
        failed = result.actions_failed[0] if result.actions_failed else (None, "unknown")
        raise BrigError(f"Failed to remove cell '{cell_name}': {failed[1]}")

    # Clean up host-side per-cell state (workspace + metadata file).
    # Deletion is destructive but matches the principle that `rm` should
    # leave nothing behind for the next cell with the same name to
    # inadvertently inherit.
    if not keep_workspace:
        _remove_cell_state_dir(cell_name)

    log_operation("rm", cell_name=cell_name)
    log_lifecycle("rm", cell_name)


def _workspace_has_content(cell_name: str) -> bool:
    """True if the cell's workspace dir contains any files. Used to gate
    the rm confirmation prompt — empty workspaces don't warrant asking."""
    from brig.config import HostPaths
    ws = HostPaths.STATE_DIR / cell_name / "workspace"
    if not ws.exists():
        return False
    try:
        return any(ws.iterdir())
    except OSError:
        return False


def _remove_cell_state_dir(cell_name: str) -> None:
    """Best-effort recursive removal of ~/.brig/state/<cell>/.

    Contains the workspace + cell-metadata.json. Errors are logged at
    debug level — a leftover dir isn't a correctness failure, just
    leakage of disk and (in the symlink-bait case) attack surface for a
    same-name reuse.
    """
    import shutil
    from brig.config import HostPaths
    from brig.ops.logging import debug
    cell_state = HostPaths.STATE_DIR / cell_name
    if not cell_state.exists():
        return
    try:
        shutil.rmtree(cell_state)
    except OSError as e:
        debug(f"Could not remove cell state dir {cell_state}: {e}")
