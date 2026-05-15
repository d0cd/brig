"""
High-level cell lifecycle operations.

These wrap the reconciler with validation, logging, and error handling.
The proxy_check parameter decouples the domain layer from subprocess calls,
making it testable without mocking subprocess.
"""

from __future__ import annotations

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

    token_name = f"{spec.name}-ingress-token"
    try:
        token_path = validate_secret_path(token_name, HostPaths.SECRETS_DIR)
    except (ValueError, FileNotFoundError):
        try:
            token_path = validate_secret_path("ingress-token", HostPaths.SECRETS_DIR)
        except (ValueError, FileNotFoundError):
            info(
                f"WARNING: No ingress token found for '{spec.name}'. "
                f"Create one with: brig secrets add {token_name}"
            )
            return

    auth_token = token_path.read_text().strip()
    if not auth_token:
        info(f"WARNING: Ingress token for '{spec.name}' is empty")
        return
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
    """
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
            suggestion=f"Use 'brig stop {spec.name}' first, or 'brig rm -f {spec.name}'",
        )

    actions = plan_run(spec, actual)
    if not actions:
        raise BrigError(
            f"Cell '{spec.name}' already exists",
            suggestion=f"Remove it first with: brig rm {spec.name}",
        )

    debug(f"Reconciliation plan: {[a.type.name for a in actions]}")
    result = apply(actions)

    if result.success:
        log_operation("run", cell_name=spec.name, details={"image": spec.image})
        log_lifecycle("start", spec.name, details={"image": spec.image})
        # Log per-cell policy if specified (audit trail gap fix).
        if spec.policy_allow or spec.policy_deny:
            log_policy_change(
                spec.name, "create",
                changes={"allow": spec.policy_allow, "deny": spec.policy_deny},
            )
        # Register ingress routes if the cell has ingress endpoints.
        if spec.ingress:
            _register_cell_ingress(spec, result)
        info(f"Cell '{spec.name}' started")
    else:
        failed = result.actions_failed[0] if result.actions_failed else (None, "unknown")
        raise BrigError(f"Failed to start cell '{spec.name}': {failed[1]}")

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

    actions = [Action(ActionType.PODMAN_KILL, cell_name)] if actual.running else []
    result = apply(actions)

    if result.success:
        log_operation("kill", cell_name=cell_name)
        log_lifecycle("kill", cell_name)


def rm_cell(cell_name: str, force: bool = False) -> None:
    """Remove a cell and all associated resources."""
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

    actions = plan_destroy(cell_name, actual)
    result = apply(actions)

    if result.success:
        log_operation("rm", cell_name=cell_name)
        log_lifecycle("rm", cell_name)
    else:
        failed = result.actions_failed[0] if result.actions_failed else (None, "unknown")
        raise BrigError(f"Failed to remove cell '{cell_name}': {failed[1]}")
