"""
Convenience commands: brig system up, brig system down, brig system profiles.

These reduce the multi-step setup to single commands.
"""

from __future__ import annotations

import subprocess
import argparse

from brig.config import VM_NAME, HostPaths
from brig.errors import BrigError
from brig.ops.logging import info, output


def cmd_up(args: argparse.Namespace) -> int:
    """Handle `brig system up` — ensure VM + warden are running.

    Steps:
      1. Run brig system init if ~/.brig doesn't exist.
      2. Create Lima VM if it doesn't exist.
      3. Start Lima VM if not running.
      4. Start warden if not running.
    """
    # Step 1: init.
    if not HostPaths.BRIG_HOME.exists():
        info("Initializing brig...")
        from brig.commands.system_cmd import cmd_init
        cmd_init(argparse.Namespace())

    from brig.vm.shell import vm_exists, vm_running as check_vm

    # Keep the VM's mount_roots block in sync with config — both the template
    # (used on VM create) and the live instance config (read on `limactl start`),
    # so a restart applies a mount_roots change. The drift check below confirms
    # against the running VM.
    from brig.vm.lima_mounts import sync_all_lima_mount_roots
    try:
        sync_all_lima_mount_roots()
    except BrigError as e:
        output(f"  (warn) {e} — cells using `mounts:` may not start until the VM "
               f"config's brig:mount_roots markers are repaired.")

    # Keep the deployed warden addons in lockstep with the installed package, so
    # editing an addon can't leave warden running stale code. If anything
    # changed, warden is reloaded below (mitmproxy doesn't reliably hot-reload
    # sibling helper modules).
    from brig.ops.addon_deploy import sync_addons
    addons_changed = sync_addons()

    # Step 2: create VM if needed.
    if not vm_exists():
        lima_yaml = HostPaths.LIMA_YAML
        if not lima_yaml.exists():
            output(f"ERROR: VM config not found at {lima_yaml}")
            output("  Run: brig system init")
            return 1
        info(f"Creating VM '{VM_NAME}'...")
        result = subprocess.run(
            ["limactl", "create", f"--name={VM_NAME}", str(lima_yaml)],
        )
        if result.returncode != 0:
            return 1

    # Step 3: start VM if not running.
    if not check_vm():
        info(f"Starting VM '{VM_NAME}'...")
        result = subprocess.run(["limactl", "start", VM_NAME])
        if result.returncode != 0:
            return 1
    else:
        info("VM is running")

    # Step 3.5: start the OTel collector BEFORE warden so warden has an emit
    # target from cold start (warden is always pointed at the collector's OTLP
    # endpoint). Best-effort: observability is non-critical, so a collector
    # failure (e.g. unpinned image) must not block bringing the harness up.
    from brig.observability import collector
    if collector.is_running():
        info("OTel collector is running")
    else:
        info("Starting OTel collector...")
        try:
            if not collector.start():
                output("  (warn) OTel collector failed to start — "
                       "metrics / `brig cell network --otel` will be unavailable")
        except BrigError as e:
            output(f"  (warn) OTel collector not started ({e}) — "
                   f"metrics / --otel unavailable")

    # Step 4: start warden if not running. Use warden.proxy.is_running()
    # (the same check warden.proxy.start() uses internally) so cmd_up and
    # start() can't disagree about state.
    from warden.proxy import is_running, start, stop
    if is_running():
        if addons_changed:
            info("Reloading warden (addons changed)...")
            stop()
            if not start():
                output("ERROR: Failed to restart warden after addon sync")
                return 1
        else:
            info("Warden is running")
    else:
        info("Starting warden...")
        if not start():
            output("ERROR: Failed to start warden")
            return 1

    # Re-launch any `restart: always` cells that went away (e.g. the VM
    # restart that dropped every container). Best-effort; runs after warden so
    # restored cells have an egress proxy.
    from brig.cell.lifecycle import restore_persisted_cells
    restore_persisted_cells()

    # Drift check: warn if a configured mount_root isn't actually mounted in the
    # already-running VM. The instance config is synced above, so the fix is a
    # lossless stop/start (vz applies the new mounts on restart; images survive).
    # Fires whenever the VM lacks a root, not just on the run that edited config.
    from brig.config import mount_root_slug, mount_roots
    from brig.vm.shell import vm_run
    missing = [
        r for r in mount_roots()
        if vm_run(["test", "-d", f"/mnt/host/{mount_root_slug(r)}"]).returncode != 0
    ]
    if missing:
        info(
            f"NOTE: mount_roots {missing} are configured but not yet mounted in "
            f"the running VM — apply with a lossless restart: brig system down "
            f"--vm && brig system up (your images are preserved)."
        )

    info("")
    info("Brig is ready. Run a cell with:")
    info("  brig run alpine -- echo hello")
    return 0


def cmd_down(args: argparse.Namespace) -> int:
    """Handle `brig system down` — stop everything.

    Steps:
      1. Stop all running cells (via stop_cell so ingress is torn down
         consistently per-cell). Taking the harness down is not per-cell
         operator intent, so no intentional-stop marker is recorded — a
         `restart: always` cell still comes back on the next `system up`.
      2. Sweep orphan ingress routes whose cell already exited (subnet reuse
         would otherwise let a future cell inherit the prior cell's hashed
         auth token).
      3. Stop warden.
      4. Optionally stop VM (--vm flag).

    A stop failure on one cell is logged and counted but doesn't strand
    the others; the command exits non-zero when any cell stop failed so
    the operator notices.
    """
    from brig.cell.lifecycle import list_cell_containers, stop_cell
    from brig.network.ingress import sweep_orphan_routes
    from brig.network.subnet import list_all, reclaim_orphan_subnets

    failures = 0
    for cell_name, _entry in list_cell_containers(include_stopped=False):
        info(f"Stopping {cell_name}...")
        try:
            stop_cell(cell_name, mark_stopped=False)
        except BrigError as e:
            output(f"  ERROR: {e}")
            failures += 1

    # Self-heal subnet allocations whose podman network is gone (raw-podman
    # kills, crashes mid-rm), then sweep ingress routes against what's left —
    # so orphans don't accumulate until a manual prune.
    reclaimed = reclaim_orphan_subnets()
    if reclaimed:
        info(f"Reclaimed {len(reclaimed)} orphan subnet allocation(s)")
    allocated = {info.cell_name for info in list_all()}
    swept = sweep_orphan_routes(live_cells=allocated)
    if swept:
        info(f"Swept {swept} orphan ingress route(s)")

    # Stop warden.
    from warden.proxy import stop
    info("Stopping warden...")
    stop()

    # Stop the OTel collector (started by cmd_up). Best-effort.
    from brig.observability import collector
    if collector.is_running():
        info("Stopping OTel collector...")
        try:
            collector.stop()
        except Exception as e:  # noqa: BLE001 — teardown must not fail `down`
            output(f"  (warn) failed to stop OTel collector: {e}")

    # Optionally stop VM.
    if getattr(args, "vm", False):
        info(f"Stopping VM '{VM_NAME}'...")
        subprocess.run(["limactl", "stop", VM_NAME], check=False)

    if failures:
        output(f"Brig stopped with {failures} cell shutdown error(s)")
        return 1
    info("Brig stopped")
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    """Handle `brig system profiles` — list available trust profiles."""
    from brig.cell.profiles import BUILTIN_PROFILES

    output(f"{'NAME':<15} {'MEMORY':<8} {'CPUS':<6} {'PIDS':<6} {'NETWORK':<10} {'NOTES'}")
    output("-" * 70)
    for name, profile in BUILTIN_PROFILES.items():
        network = profile.get("network", "default")
        notes = ""
        policy = profile.get("policy", {})
        if policy.get("deny") == ["*"]:
            notes = "deny-all policy"
        elif network == "none":
            notes = "no network access"
        output(
            f"{name:<15} {profile.get('memory', '-'):<8} "
            f"{profile.get('cpus', '-'):<6} {profile.get('pids_limit', '-'):<6} "
            f"{network:<10} {notes}"
        )

    # User profiles.
    from brig.config import HostPaths
    profiles_dir = HostPaths.PROFILES_DIR
    if profiles_dir.exists():
        user_profiles = [
            f.stem for f in profiles_dir.iterdir()
            if f.suffix in (".yaml", ".yml", ".json")
        ]
        if user_profiles:
            output("")
            output(f"User profiles ({profiles_dir}):")
            for name in sorted(user_profiles):
                output(f"  {name}")

    output("")
    output("Usage: brig run --profile <name> alpine -- echo hello")
    return 0
