"""
Convenience commands: brig up, brig down, brig profiles.

These reduce the multi-step setup to single commands.
"""

from __future__ import annotations

import subprocess
from typing import Any

from brig.config import CONTAINER_PREFIX, PROXY_NAME, VM_NAME, HostPaths
from brig.ops.logging import info, output, warn


def cmd_up(args: Any) -> int:
    """Handle `brig up` — ensure VM + warden are running.

    Steps:
      1. Run brig init if ~/.brig doesn't exist.
      2. Create Lima VM if it doesn't exist.
      3. Start Lima VM if not running.
      4. Start warden if not running.
    """
    # Step 1: init.
    if not HostPaths.BRIG_HOME.exists():
        output("Initializing brig...")
        from brig.commands.system_cmd import cmd_init
        import types
        cmd_init(types.SimpleNamespace())

    from brig.vm.shell import vm_exists, vm_running as check_vm

    # Step 2: create VM if needed.
    if not vm_exists():
        lima_yaml = HostPaths.LIMA_YAML
        if not lima_yaml.exists():
            output(f"ERROR: VM config not found at {lima_yaml}")
            output("  Run: brig init")
            return 1
        output(f"Creating VM '{VM_NAME}'...")
        result = subprocess.run(
            ["limactl", "create", f"--name={VM_NAME}", str(lima_yaml)],
        )
        if result.returncode != 0:
            return 1

    # Step 3: start VM if not running.
    if not check_vm():
        output(f"Starting VM '{VM_NAME}'...")
        result = subprocess.run(["limactl", "start", VM_NAME])
        if result.returncode != 0:
            return 1
    else:
        output("VM is running")

    # Step 4: start warden if not running. Use warden.proxy.is_running()
    # (the same check warden.proxy.start() uses internally) so cmd_up and
    # start() can't disagree about state.
    from warden.proxy import is_running, start
    if is_running():
        output("Warden is running")
    else:
        output("Starting warden...")
        if not start():
            output("ERROR: Failed to start warden")
            return 1

    output("")
    output("Brig is ready. Run a cell with:")
    output("  brig run alpine -- echo hello")
    return 0


def cmd_down(args: Any) -> int:
    """Handle `brig down` — stop everything.

    Steps:
      1. Stop all running cells.
      2. Stop warden.
      3. Optionally stop VM (--vm flag).
    """
    from brig.vm.shell import vm_run

    # Stop all cells.
    from brig.config import INFRA_CONTAINER_NAMES
    result = vm_run(["podman", "ps", "--format", "{{.Names}}", "--filter", f"name=^{CONTAINER_PREFIX}"])
    if result.returncode == 0 and result.stdout.strip():
        for name in result.stdout.strip().split("\n"):
            if name and name not in INFRA_CONTAINER_NAMES:
                output(f"Stopping {name}...")
                vm_run(["podman", "stop", "-t", "5", name])

    # Tear down ALL host_socket bridges — not just the cells we know
    # about, but every loaded launchd plist with our prefix. Otherwise
    # socat keeps running across `brig down` for cells that are gone.
    _bootout_all_host_socket_bridges()

    # Stop warden.
    from warden.proxy import stop
    output("Stopping warden...")
    stop()

    # Optionally stop VM.
    if getattr(args, "vm", False):
        output(f"Stopping VM '{VM_NAME}'...")
        subprocess.run(["limactl", "stop", VM_NAME], check=False)

    output("Brig stopped")
    return 0


def _bootout_all_host_socket_bridges() -> None:
    """Enumerate every loaded host_socket bridge plist and bootout it,
    regardless of which cell it belongs to. Used by `brig down` so we
    don't leak orphan bridges across system restarts.
    """
    from brig.cell.host_sockets_bridge import (
        LABEL_PREFIX, PLIST_DIR, stop_cell_bridges,
    )
    if not PLIST_DIR.exists():
        return
    cells_with_bridges: set[str] = set()
    for plist in PLIST_DIR.iterdir():
        name = plist.name
        if not name.startswith(LABEL_PREFIX) or not name.endswith(".plist"):
            continue
        rest = name[len(LABEL_PREFIX):-len(".plist")]
        if "." not in rest:
            continue
        cell_name = rest.split(".", 1)[0]
        cells_with_bridges.add(cell_name)
    for cell_name in cells_with_bridges:
        output(f"Tearing down host_socket bridges for {cell_name}...")
        try:
            stop_cell_bridges(cell_name)
        except Exception as e:
            output(f"  (warn) failed to bootout bridges for {cell_name}: {e}")


def cmd_profiles(args: Any) -> int:
    """Handle `brig profiles` — list available trust profiles."""
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
