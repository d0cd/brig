"""CLI handlers for cell state-changing commands.

stop/kill/rm/start/restart/pause/unpause/wait/rename/exec/shell/attach.
Read-only commands live in lifecycle_inspect; `brig run` lives in
lifecycle_run.
"""

from __future__ import annotations

import argparse
import sys

from brig.cell.lifecycle import kill_cell, rm_cell, stop_cell
from brig.config import container_name
from brig.errors import BrigError
from brig.ops.logging import info, output
from brig.vm.shell import vm_run, vm_run_interactive


def cmd_stop(args: argparse.Namespace) -> int:
    stop_cell(args.name)
    return 0


def cmd_kill(args: argparse.Namespace) -> int:
    kill_cell(args.name)
    return 0


def cmd_rm(args: argparse.Namespace) -> int:
    from brig.cell.lifecycle import _workspace_has_content

    keep = getattr(args, "keep_workspace", False)
    # Closes the silent-data-loss foot-gun where the user expects docker
    # semantics (rm preserves volumes) and loses unexpected data.
    if not keep and not args.force and _workspace_has_content(args.name):
        if not sys.stdin.isatty():
            raise BrigError(
                f"Cell '{args.name}' has files in its workspace; refusing to "
                f"delete non-interactively.",
                suggestion=(
                    f"brig cell rm {args.name} --keep-workspace   # preserve files\n"
                    f"  OR  brig cell rm -f {args.name}            # force delete"
                ),
            )
        prompt = (
            f"Cell '{args.name}' workspace contains files. "
            f"Delete? [y/N/keep] "
        )
        try:
            answer = input(prompt).strip().lower()
        except EOFError:
            answer = ""
        if answer in ("k", "keep"):
            keep = True
        elif answer not in ("y", "yes"):
            output("Aborted.")
            return 1

    rm_cell(args.name, force=args.force, keep_workspace=keep)
    return 0


def cmd_exec(args: argparse.Namespace) -> int:
    cn = container_name(args.name)
    cmd = ["podman", "exec"]
    if getattr(args, "interactive", False):
        cmd.append("-it")
    cmd.append(cn)
    # argparse.REMAINDER keeps a leading '--' separator in the list; drop it
    # so `brig cell exec mycell -- ls` runs `ls`, not `-- ls`.
    exec_cmd = args.exec_cmd
    if exec_cmd and exec_cmd[0] == "--":
        exec_cmd = exec_cmd[1:]
    cmd.extend(exec_cmd)
    return vm_run_interactive(cmd)


def cmd_shell(args: argparse.Namespace) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "exec", "-it", cn, "/bin/sh"])


def cmd_attach(args: argparse.Namespace) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "attach", cn])


def cmd_start(args: argparse.Namespace) -> int:
    # Invariant 9: proxy must be running before starting cells.
    from brig.network.proxy import proxy_running
    if not proxy_running():
        raise BrigError(
            "Warden proxy is not running",
            suggestion="Start with: brig system up",
        )
    _verify_image_digest_on_start(args.name)
    _refresh_metadata_for_start(args.name)
    cn = container_name(args.name)
    result = vm_run(["podman", "start", cn])
    if result.returncode != 0:
        raise BrigError(
            f"Failed to start cell '{args.name}': {result.stderr.strip()}",
            suggestion="Check if cell exists with: brig cell list",
        )
    # Post-start configuration must be all-or-nothing: a cell that comes up
    # but can't be fully wired (ingress unrouteable, etc.) is worse than one
    # that didn't start. Roll back (stop) on any failure so the operator isn't
    # left with a misleading half-configured cell.
    try:
        _verify_proxy_connected_after_start(args.name)

        # Re-stage the Warden CA bundle. ca_bundle's design is per-start
        # re-extraction; a `system down`/`up` cycle otherwise leaves a stale
        # bundle and the cell's HTTPS fails "unknown ca" (and `brig verify`
        # even suggests `restart` as the fix). Best-effort + idempotent —
        # harmless for cells that don't mount it (airgapped / trust_warden_ca
        # false).
        try:
            from brig.cell.ca_bundle import stage_bundle
            stage_bundle(args.name)
        except Exception as e:  # noqa: BLE001 — never fail start on a re-stage hiccup
            from brig.ops.logging import debug
            debug(f"CA bundle re-stage on start failed: {e}")

        # host_sockets bridges are torn down on stop and are NOT recreated
        # here: re-bridging needs the host_path, which is deliberately absent
        # from the cell-readable metadata (it must not leak to the cell). Warn
        # so the operator doesn't get a silently-dead mount.
        from brig.cell.metadata import read_host_sockets
        if read_host_sockets(args.name):
            from brig.ops.logging import warn
            warn(
                f"Cell '{args.name}' declares host_sockets, but launchd bridges "
                f"are not recreated on start. Re-run from yaml for working "
                f"host_sockets: brig run --file <yaml>"
            )

        from brig.cell.lifecycle import register_ingress_for
        from brig.cell.metadata import read_ingress
        ingress_entries = read_ingress(args.name)
        if ingress_entries:
            register_ingress_for(args.name, ingress_entries)
    except BrigError:
        stop_cell(args.name)
        raise
    info(f"Cell '{args.name}' started")
    return 0


def _verify_image_digest_on_start(cell_name: str) -> None:
    """If the cell was created with a pinned image_digest, re-verify the
    container's current image digest matches before letting it start.

    Closes the window where an operator could `podman commit` a new
    image on top of the cell's pinned reference between stop and start.
    No-op for cells that weren't pinned at create time.
    """
    from brig.cell.metadata import read_image_digest
    pinned = read_image_digest(cell_name)
    if not pinned:
        return
    cn = container_name(cell_name)
    inspect = vm_run(["podman", "inspect", "--format", "{{.ImageDigest}}", cn])
    if inspect.returncode != 0:
        raise BrigError(
            f"Cannot verify image digest for '{cell_name}': "
            f"{inspect.stderr.strip()}"
        )
    actual = inspect.stdout.strip()
    # Fail closed: a pin was recorded at create time, so an empty/absent
    # ImageDigest (e.g. a locally committed image with no registry digest)
    # means we CANNOT prove the content matches — refuse rather than start on
    # unverified content, which is the exact commit-swap window this closes.
    if actual != pinned:
        observed = actual or "<none>"
        raise BrigError(
            f"Image digest drift on '{cell_name}': pinned {pinned}, "
            f"container now references {observed}",
            suggestion=(
                f"Recreate the cell from yaml: "
                f"brig cell rm -f {cell_name} && brig run --file <yaml>"
            ),
        )


def _verify_proxy_connected_after_start(cell_name: str) -> None:
    """Refuse to leave a non-airgapped cell running when warden isn't
    actually connected to its network.

    proxy_running() only proves warden is up — it doesn't prove warden
    is attached to *this* cell's per-cell network. After `brig system
    down`/`up` the proxy_connected attachment may be gone; without this
    check the cell would start with no egress path and every outbound
    request would silently fail.
    """
    from brig.cell.lifecycle import observe
    state = observe(cell_name)
    if not (state.exists and state.running):
        return
    # Airgapped cells have no per-cell network — they were started with
    # --network none and warden was never meant to be attached.
    if not state.network_exists:
        return
    if state.proxy_connected:
        return
    from brig.cell.reconciler import _run_cmd
    from brig.config import PROXY_NAME
    cn = container_name(cell_name)
    info(f"Reconnecting warden to cell network for '{cell_name}'")
    _run_cmd(["podman", "network", "connect", cn, PROXY_NAME])
    state = observe(cell_name)
    if not state.proxy_connected:
        raise BrigError(
            f"Cell '{cell_name}' started but warden isn't connected "
            f"to its network. Egress will fail until reconnected.",
            suggestion=f"brig cell rm -f {cell_name} && brig run --file <yaml>",
        )


def _refresh_metadata_for_start(cell_name: str) -> None:
    """Rewrite /run/brig/cell.json on restart with a fresh `started_at`.

    Preserves the original workspace_mount, host_sockets, and ingress —
    bind mounts and ingress configuration are fixed at create time, so
    these come from the prior metadata write rather than being re-derived.
    If the file is missing or unreadable (cell predates cell.json), write
    a default-mount fallback.
    """
    from brig.cell.metadata import refresh_metadata_if_present, write_metadata
    if refresh_metadata_if_present(cell_name) is None:
        write_metadata(cell_name, "/work")


def cmd_restart(args: argparse.Namespace) -> int:
    """Handle `brig cell restart <name>` — stop (if running) then start.

    Composite of stop_cell + cmd_start. Refreshes the cell metadata's
    started_at via cmd_start's existing path.
    """
    from brig.cell.lifecycle import observe, stop_cell
    actual = observe(args.name)
    if not actual.exists:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="brig cell list  # see what's there",
        )
    if actual.running:
        stop_cell(args.name)
    return cmd_start(args)


def cmd_wait(args: argparse.Namespace) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "wait", cn], timeout=None)
    if result.returncode != 0:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="Use 'brig cell list' to see available cells",
        )
    exit_code = result.stdout.strip()
    output(exit_code)
    return int(exit_code) if exit_code.isdigit() else 1


def cmd_pause(args: argparse.Namespace) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "pause", cn])
    if result.returncode != 0:
        raise BrigError(f"Failed to pause cell '{args.name}': {result.stderr.strip()}")
    info(f"Cell '{args.name}' paused")
    return 0


def cmd_unpause(args: argparse.Namespace) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "unpause", cn])
    if result.returncode != 0:
        raise BrigError(f"Failed to unpause cell '{args.name}': {result.stderr.strip()}")
    info(f"Cell '{args.name}' unpaused")
    return 0


def cmd_rename(args: argparse.Namespace) -> int:
    # Renaming only the podman container would orphan the cell's per-cell
    # network, subnet allocation, state dir, per-cell policy file, and ingress
    # routes — all keyed by the OLD name — leaving a half-renamed,
    # inconsistent cell. A correct rename would have to migrate all of those
    # atomically (network/subnet rename isn't atomic in podman), so it's not
    # supported: recreate under the new name instead.
    raise BrigError(
        f"Renaming a cell is not supported — it can't safely migrate the "
        f"cell's network, subnet, state, and policy (all keyed to "
        f"'{args.old_name}').",
        suggestion=(
            f"Recreate it under the new name:\n"
            f"  brig cell rm {args.old_name}\n"
            f"  brig run --name {args.new_name} ...   (or: brig run --file <yaml>)"
        ),
    )
