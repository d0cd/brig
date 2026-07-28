"""
High-level cell lifecycle operations.

These wrap the reconciler with validation, logging, and error handling.
The proxy_check parameter decouples the domain layer from subprocess calls,
making it testable without mocking subprocess.
"""

from __future__ import annotations

import re
from typing import Any, Callable

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
from brig.ops.ratelimit import check_rate_limit, record_rate_limit
from brig.vm.shell import vm_run


def register_ingress_for(cell_name: str, ingress_spec: list[dict]) -> None:
    """Inspect `cell_name`, look up the ingress token, and register routes.

    Shared by the create-time path (run_cell) and the start-time path
    (cmd_start replaying registration after `brig system down/up`).
    Raises BrigError if ingress is declared but the auth token is missing
    or empty — registering would-be-rejected routes is worse than failing
    loudly.

    The replay path reads `ingress_spec` from `cell-metadata.json`, which
    invariant 4 names as untrusted. Each entry is re-run through the
    same per-entry validator that gates cell yaml at parse time before
    any persistence happens.
    """
    if not ingress_spec:
        return

    from brig.cell.validators import _v_ingress_entry
    from brig.config import MAX_INGRESS_PER_CELL
    errors: list[str] = []
    # The replay path (cell start) reads ingress from untrusted
    # cell-metadata.json (invariant 4); apply the same count cap that
    # _v_ingress enforces at parse time, not just the per-entry shape check.
    if len(ingress_spec) > MAX_INGRESS_PER_CELL:
        errors.append(
            f"too many ingress entries ({len(ingress_spec)}), "
            f"max {MAX_INGRESS_PER_CELL}"
        )
    seen_names: set = set()
    seen_prefixes: set = set()
    for i, entry in enumerate(ingress_spec):
        errors.extend(_v_ingress_entry(i, entry, seen_names, seen_prefixes, ""))
    if errors:
        raise BrigError(
            f"Refusing to register ingress for '{cell_name}': "
            f"invalid entry shape — " + "; ".join(errors),
            suggestion=(
                f"~/.brig/state/{cell_name}/cell-metadata.json may have been "
                f"hand-edited or corrupted. Re-create the cell from yaml: "
                f"brig cell rm {cell_name} && brig run --file <yaml>"
            ),
        )

    from brig.config import HostPaths, INGRESS_TOKEN_MIN_LEN
    from brig.network.ingress import register_ingress
    from brig.security.secrets import validate_secret_path

    cn = f"brig-{cell_name}"
    from brig.cell.reconciler import _podman_inspect_json
    container_info = _podman_inspect_json(cn)
    if not container_info:
        raise BrigError(
            f"Cannot register ingress for '{cell_name}': container {cn} "
            f"is not inspectable. Declared ingress routes would be silently "
            f"unregistered.",
            suggestion=f"brig cell logs {cell_name}  # check why the cell isn't up",
        )
    cell_ip = (
        container_info.get("NetworkSettings", {})
        .get("Networks", {})
        .get(cn, {})
        .get("IPAddress", "")
    )
    if not cell_ip:
        raise BrigError(
            f"Cannot register ingress for '{cell_name}': cell IP could not "
            f"be determined. Declared ingress routes would be silently "
            f"unregistered.",
            suggestion=f"brig cell logs {cell_name}",
        )

    # Re-apply the untrusted-profile auth:none gate. Derive untrusted-ness from
    # the TRUSTED podman container label (set as `--label brig.profile=...` at
    # create, immutable, read from podman's store) — NOT cell-metadata.json,
    # which invariant 4 names as untrusted and which this gate exists to police.
    # Reading the trust decision from that file would let a tampered copy bypass
    # the gate by dropping the profile.
    labels = (container_info.get("Config", {}) or {}).get("Labels", {}) or {}
    if labels.get("brig.profile") == "untrusted":
        for i, entry in enumerate(ingress_spec):
            if isinstance(entry, dict) and entry.get("auth") == "none":
                raise BrigError(
                    f"Refusing ingress for '{cell_name}': ingress[{i}].auth: "
                    f"none is not allowed with the untrusted profile — untrusted "
                    f"cells must keep brig's token gate",
                    suggestion=(
                        f"~/.brig/state/{cell_name}/cell-metadata.json may have "
                        f"been hand-edited. Re-create from yaml: brig cell rm "
                        f"{cell_name} && brig run --file <yaml>"
                    ),
                )

    # A token is needed only if at least one route is auth: token. An
    # all-`auth: none` cell (transparent pass-through) requires no secret.
    needs_token = any(e.get("auth") == "token" for e in ingress_spec)
    auth_token: str | None = None
    if needs_token:
        token_name = f"{cell_name}-ingress-token"
        try:
            token_path = validate_secret_path(token_name, HostPaths.SECRETS_DIR)
        except (ValueError, FileNotFoundError):
            try:
                token_path = validate_secret_path("ingress-token", HostPaths.SECRETS_DIR)
            except (ValueError, FileNotFoundError):
                raise BrigError(
                    f"Cell '{cell_name}' declares ingress with auth: token "
                    f"but no token secret exists. Ingress would register "
                    f"routes that reject every request.",
                    suggestion=(
                        f"Create the token (32+ random chars), then re-run:\n"
                        f"  openssl rand -hex 32 | brig secrets add {token_name} -\n"
                        f"  brig cell rm {cell_name} && brig run --file <yaml>"
                    ),
                )

        auth_token = token_path.read_text().strip()
        if not auth_token:
            raise BrigError(
                f"Ingress token for '{cell_name}' is empty",
                suggestion=f"openssl rand -hex 32 | brig secrets add {token_name} -",
            )
        if len(auth_token) < INGRESS_TOKEN_MIN_LEN:
            raise BrigError(
                f"Ingress token for '{cell_name}' is too short "
                f"({len(auth_token)} chars); minimum is {INGRESS_TOKEN_MIN_LEN}",
                suggestion=f"openssl rand -hex 32 | brig secrets add {token_name} -",
            )

    register_ingress(cell_name, cell_ip, ingress_spec, auth_token)


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
        return str(names[0]) if names else ""
    return str(names)


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


# Only sha256 is accepted: OCI registry manifest digests — what podman matches
# at pull time and reports as {{.ImageDigest}} for the start-time re-check — are
# sha256, so a sha384/sha512 pin could never match and the cell would fail to
# start with a spurious "digest drift". Exact 64 hex chars (not an open {64,})
# so an over-long value can't slip through as well-formed.
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-fA-F]{64}\Z")


def _apply_image_digest_pin(spec: CellSpec) -> None:
    """Rewrite spec.image to `image@digest` form when image_digest is set.

    Podman natively enforces digest pinning when the image reference
    contains `@sha256:...`, so converting the soft-pin into a hard
    reference before invoking podman lets podman refuse any mismatch
    at pull time.

    Raises BrigError if:
      - image_digest is set but malformed (must be sha256:<64-hex>)
      - image already contains a digest that disagrees with image_digest
    """
    if not spec.image_digest:
        return
    digest = spec.image_digest.strip()
    if not _DIGEST_PATTERN.match(digest):
        raise BrigError(
            f"Invalid image_digest '{digest}'",
            suggestion="Format must be sha256:<64-hex>",
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


def sync_cell_policy(spec: CellSpec) -> None:
    """Write the cell's allow / deny / host_services / tls_passthrough to its
    per-cell policy file (`<cell>.json`). Replace semantics — the spec is the
    source of truth. Skips the write when the on-disk policy already matches
    so idempotent re-runs don't churn mtime (which would trigger a warden
    reload). Called by run_cell so BOTH the CLI and the SDK persist policy —
    without this, a cell launched via the SDK has no per-cell policy file and
    warden default-denies all its egress.
    """
    from brig.policy.policy import mutate_cell_policy

    desired = {
        "allow": list(spec.policy_allow or []),
        "deny": list(spec.policy_deny or []),
        "host_services": list(spec.host_services or []),
        "tls_passthrough": list(spec.policy_passthrough_tls or []),
    }
    current_holder: dict[str, Any] = {}

    def _mutate(existing: dict[str, Any] | None) -> dict[str, Any] | None:
        existing = existing or {}
        current = {
            "allow": existing.get("allow", []),
            "deny": existing.get("deny", []),
            "host_services": existing.get("host_services", []),
            "tls_passthrough": existing.get("tls_passthrough", []),
        }
        current_holder.update(current)
        if desired == current:
            return None  # No change — skip the write.
        merged = dict(existing)
        merged.update(desired)
        return merged

    written = mutate_cell_policy(spec.name, _mutate)
    if written is None:
        return
    current = current_holder

    def _names(items: Any) -> set[str]:
        return {e["name"] for e in items if isinstance(e, dict) and "name" in e}
    added = _names(desired["host_services"]) - _names(current["host_services"])
    removed = _names(current["host_services"]) - _names(desired["host_services"])
    for n in sorted(added):
        info(f"host_service granted: {spec.name} → {n} (from cell yaml)")
    for n in sorted(removed):
        info(f"host_service revoked: {spec.name} → {n} (no longer in cell yaml)")


def run_cell(
    spec: CellSpec,
    proxy_check: Callable[[], bool] = _default_proxy_check,
    count_against_rate_limit: bool = True,
) -> ReconcileResult:
    """Run a new cell.

    Args:
        spec: Cell specification.
        proxy_check: Callable returning True if proxy is running.
            Injected for testability; defaults to the real proxy_running().
        count_against_rate_limit: when False, skip the creation rate limiter.
            Set by restore (replaying already-authorized restart:always cells),
            which would otherwise throttle past the limit and strand the rest.

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
            suggestion="Start with: brig system up",
        )

    if count_against_rate_limit and not check_rate_limit():
        raise BrigError(
            "Rate limit exceeded: too many cells created recently",
            suggestion="Wait a moment and try again, or increase the rate limit",
        )

    # Persist the cell's per-cell policy before it starts so warden enforces
    # the intended allow/deny (not default-deny). Done here, not in the CLI,
    # so SDK-launched cells get it too. Track whether a policy already existed
    # so a failed reconcile can clean up a file THIS run created without
    # deleting a legitimate policy on an idempotent re-run of a live cell.
    from brig.policy.policy import load_cell_policy
    policy_preexisted = load_cell_policy(spec.name) is not None
    sync_cell_policy(spec)

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

    def _rollback_reconcile_side_effects() -> None:
        # apply() rolls back its own network/subnet/podman actions, but the
        # pre-written policy file is ours to clean up.
        if not policy_preexisted:
            from brig.policy.policy import delete_cell_policy
            delete_cell_policy(spec.name)

    debug(f"Reconciliation plan: {[a.type.name for a in actions]}")
    try:
        result = apply(actions)
    except Exception:
        _rollback_reconcile_side_effects()
        raise

    if not result.success:
        _rollback_reconcile_side_effects()
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
            register_ingress_for(spec.name, spec.ingress)
            # An auth: none route removes brig's perimeter gate — the cell's
            # app is the authenticator. Surface it loudly (audit + operator
            # NOTE), the way mounts announce their bypass.
            open_routes = [e for e in spec.ingress if e.get("auth") == "none"]
            for e in open_routes:
                log_lifecycle(
                    "ingress_unauthenticated", spec.name,
                    details={"route": e.get("name"), "path_prefix": e.get("path_prefix")},
                )
            if open_routes:
                info(
                    f"NOTE: cell '{spec.name}' has {len(open_routes)} ingress "
                    f"route(s) with auth: none — brig does NOT authenticate "
                    f"these; the cell's app must be the gate."
                )
        # Audit host-directory mounts. The cell reads/writes these host files
        # directly (Warden not in the path); a rw mount lets it modify files a
        # host process later consumes — surface it loudly.
        if spec.mounts:
            for entry in spec.mounts:
                log_lifecycle(
                    "mount_attach", spec.name,
                    details={"mount": entry["name"],
                             "host_path": entry["host_path"],
                             "mount_point": entry["mount_point"],
                             "mode": entry.get("mode", "ro")},
                )
            rw = [m for m in spec.mounts if m.get("mode") == "rw"]
            info(
                f"NOTE: cell '{spec.name}' has {len(spec.mounts)} host mount(s) "
                f"({len(rw)} rw) — Warden does not see these bytes. Treat files "
                f"the cell writes as untrusted; scan with: brig cell mount-scan "
                f"{spec.name}"
            )
        info(f"Cell '{spec.name}' started")
    except BrigError:
        # Roll the cell back — container is running, but post-start
        # config failed. Preserve the workspace: a post-start failure
        # is brig's fault, not the user's, and if the cell name was
        # reused for an already-populated workspace (the
        # exists-but-stopped recovery path), wiping it would destroy
        # the user's data.
        info(f"post-start failure for '{spec.name}'; rolling back cell")
        try:
            rm_cell(spec.name, force=True, keep_workspace=True)
        except Exception as cleanup_err:
            debug(f"rollback rm_cell failed: {cleanup_err}")
        raise

    # The cell is up: desired state is "running", so clear any intentional-stop
    # marker and a later crash/reboot auto-recovers it. Only on success — a
    # rolled-back run must not re-arm recovery for a cell the operator stopped.
    from brig.cell.metadata import clear_cell_stopped
    clear_cell_stopped(spec.name)

    # Persist the spec for restart:always cells so `brig system up` can
    # re-launch them after a VM restart. Best-effort — a persistence failure
    # must not fail an otherwise-healthy cell.
    try:
        from brig.cell.metadata import write_cell_spec
        write_cell_spec(spec)
    except Exception as e:
        debug(f"failed to persist restart spec for '{spec.name}': {e}")

    # The cell is fully up and configured — count it against the creation
    # quota now, so no-ops (already running, empty plan), rolled-back
    # reconciles, AND rolled-back post-start failures never burned a slot.
    if count_against_rate_limit:
        record_rate_limit()
    return result


def restore_persisted_cells() -> None:
    """Re-launch `restart: always` cells that are down but whose desired state
    is running — they crashed, were SIGKILLed, or the VM dropped them. Called
    by `brig system up` (once warden is up) and by the watchdog loop.

    A cell the operator intentionally stopped (`brig cell stop`/`kill`, which
    sets the stop marker) is left down until an explicit `brig cell start` —
    the systemd `Restart=always` / Docker `unless-stopped` distinction:
    unexpected exits recover, a deliberate stop is respected.

    The persisted spec is re-validated before launch (the state dir is
    untrusted, invariant 4) and replayed without counting against the creation
    rate limit (these cells were already authorized).
    """
    import dataclasses
    from brig.cell.metadata import cell_marked_stopped, restorable_cell_specs
    from brig.cell.spec import validate_cell_definition

    valid = {f.name for f in dataclasses.fields(CellSpec)}
    for raw in restorable_cell_specs():
        name = raw.get("name")
        if not name:
            continue
        state = observe(name)
        # Running → healthy. Intentionally stopped → respect it. Otherwise the
        # cell is down unexpectedly (crashed / VM-dropped) → recover it.
        if state.running or cell_marked_stopped(name):
            continue
        errs = validate_cell_definition(raw)
        if errs:
            info(f"  (warn) skipping restore of '{name}': invalid persisted spec: {errs[0]}")
            continue
        verb = "Recovering" if state.exists else "Restoring"
        info(f"{verb} cell '{name}' (restart: always)...")
        try:
            spec = CellSpec(**{k: v for k, v in raw.items() if k in valid})
            run_cell(spec, count_against_rate_limit=False)
        except Exception as e:
            info(f"  (warn) could not restore cell '{name}': {e}")


def stop_cell(cell_name: str, mark_stopped: bool = True) -> None:
    """Gracefully stop a running cell.

    `mark_stopped=False` stops the cell WITHOUT recording the intentional-stop
    marker — for `brig system down`, which takes the whole harness down rather
    than expressing intent about any one cell. Marking there would opt every
    cell out of `restart: always` recovery permanently, so the next `brig
    system up` (or watchdog tick) would leave a VM-dropped cell down until a
    manual per-cell `brig cell start`.
    """
    actual = observe(cell_name)
    if not actual.exists:
        raise BrigError(
            f"Cell '{cell_name}' does not exist",
            suggestion="Use 'brig cell list' to see available cells",
        )
    if not actual.running:
        raise BrigError(
            f"Cell '{cell_name}' is not running",
            suggestion=f"Use 'brig cell start {cell_name}' to start it",
        )

    # Deregister ingress routes before stopping (prevents stale routes
    # from forwarding to a dead cell or a reused subnet).
    from brig.network.ingress import deregister_ingress
    deregister_ingress(cell_name)

    actions = plan_stop(cell_name, actual)
    result = apply(actions)

    if result.success:
        if mark_stopped:
            # Desired state is now "stopped": recovery (brig system up +
            # watchdog) leaves a restart:always cell down until an explicit
            # start.
            from brig.cell.metadata import mark_cell_stopped
            mark_cell_stopped(cell_name)
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
            suggestion="Use 'brig cell list' to see available cells",
        )

    # observe() reports a paused container as running=False; a paused cell can
    # still be killed (unpause first). Anything else that isn't running has
    # nothing to kill — reject like stop_cell rather than deregister ingress
    # and log a false "kill" success for a cell that's already stopped.
    should_kill = actual.running or actual.status == "paused"
    if not should_kill:
        raise BrigError(
            f"Cell '{cell_name}' is not running",
            suggestion=f"Use 'brig cell start {cell_name}' to start it",
        )

    # Deregister ingress routes before killing.
    from brig.network.ingress import deregister_ingress
    deregister_ingress(cell_name)

    # podman refuses to SIGKILL a paused container, so unpause it first.
    if actual.status == "paused":
        from brig.config import container_name
        vm_run(["podman", "unpause", container_name(cell_name)])

    result = apply([Action(ActionType.PODMAN_KILL, cell_name)])
    if result.success:
        # Operator take-down → desired state "stopped" (see stop_cell).
        from brig.cell.metadata import mark_cell_stopped
        mark_cell_stopped(cell_name)
        log_operation("kill", cell_name=cell_name)
        log_lifecycle("kill", cell_name)
    else:
        failed = result.actions_failed[0] if result.actions_failed else (None, "unknown")
        raise BrigError(f"Failed to kill cell '{cell_name}': {failed[1]}")


def enforce_workspace_quotas() -> list[tuple[str, int, int]]:
    """Stop every running cell whose workspace exceeds its `workspace_quota`.

    Reactive (soft) enforcement. The workspace lives on a virtiofs mount where
    a hard block-quota isn't available, so instead of preventing the write we
    periodically measure and stop over-quota cells — halting further disk
    growth on the shared VM disk while preserving the workspace for the
    operator to inspect or clean up. Intended to be called from a periodic
    context (see `brig system watchdog`); it is a no-op for cells with no quota.

    Returns `(cell_name, size_bytes, quota_bytes)` for each cell found over
    quota (whether or not the stop succeeded) so the caller can report it.
    """
    from brig.cell.metadata import read_workspace_quota
    from brig.cell.spec import parse_size
    from brig.workspace.workspace import _get_workspace_size

    breached: list[tuple[str, int, int]] = []
    for cell_name, _entry in list_cell_containers(include_stopped=False):
        quota = read_workspace_quota(cell_name)
        if not quota:
            continue
        try:
            quota_bytes = parse_size(quota)
        except (ValueError, TypeError):
            continue
        size = _get_workspace_size(cell_name)
        if size is None:
            continue  # Best-effort reactive sweep: skip if we can't measure.
        if size > quota_bytes:
            breached.append((cell_name, size, quota_bytes))
            try:
                stop_cell(cell_name)
            except BrigError:
                pass  # Best-effort; the breach is reported regardless.
    return breached


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

    Why default-delete: the workspace can contain cell-controlled content
    including symlinks pointing at host files. If a new cell takes the same
    name later, it inherits the prior cell's planted bait. Cleaning by
    default closes that re-use foot-gun; users who need the data ask for it.
    """
    # Validate before any path construction: rm_cell does a destructive
    # rmtree of ~/.brig/state/<cell>/, so gate on the name pattern (forbids
    # '/' and '..') rather than relying on a downstream existence check.
    from brig.config import CELL_NAME_PATTERN
    if not CELL_NAME_PATTERN.match(cell_name):
        raise BrigError(f"Invalid cell name: '{cell_name}'")

    actual = observe(cell_name)
    if not actual.exists and not actual.network_exists:
        raise BrigError(
            f"Cell '{cell_name}' does not exist",
            suggestion="Use 'brig cell list' to see available cells",
        )

    if actual.running and not force:
        raise BrigError(
            f"Cell '{cell_name}' is running. Stop it first or use --force.",
            suggestion=f"brig cell stop {cell_name}  OR  brig cell rm -f {cell_name}",
        )

    # Deregister ingress routes before destroying the cell.
    from brig.network.ingress import deregister_ingress
    deregister_ingress(cell_name)


    actions = plan_destroy(cell_name, actual)
    result = apply(actions)

    if not result.success:
        failed = result.actions_failed[0] if result.actions_failed else (None, "unknown")
        raise BrigError(f"Failed to remove cell '{cell_name}': {failed[1]}")

    # Delete the per-cell policy file so a future cell reusing this name
    # doesn't inherit the removed cell's allow/deny (the workspace + subnet
    # are freed by plan_destroy; the policy file lives separately).
    from brig.policy.policy import delete_cell_policy
    delete_cell_policy(cell_name)

    # Drop the persisted restart spec unconditionally — even with
    # keep_workspace — so a removed cell can't be resurrected by restart:always
    # on the next `brig system up` (the spec is a sibling of the workspace).
    from brig.cell.metadata import remove_cell_spec
    remove_cell_spec(cell_name)

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
