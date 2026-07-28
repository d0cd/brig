"""
Brig watchdog — keeps the whole harness healthy at a configurable interval.

Each interval it:
  - ensures the warden proxy is reachable, bringing the *entire stack* up via
    `brig system up` when it isn't — which starts the Lima VM if the host slept
    and dropped it (a bare warden restart can't), then warden; and
  - recovers any `restart: always` cell that went down unexpectedly (crashed /
    SIGKILLed / VM-dropped) while leaving a cell the operator intentionally
    stopped down; and
  - enforces per-cell workspace_quota, stopping any cell whose workspace has
    outgrown its quota (reactive soft-quota — see enforce_workspace_quotas).

Designed to run persistently (e.g. a process-compose entry or launchd agent)
so cells self-heal after host sleep/reboot with no manual step.
"""

from __future__ import annotations

import signal
import time
import argparse

from brig.ops.logging import info, output, warn


def cmd_watchdog(args: argparse.Namespace) -> int:
    """Handle `brig system watchdog` — keep VM + warden + cells healthy."""
    from brig.network.proxy import proxy_running

    interval = getattr(args, "interval", 30)
    max_restarts = getattr(args, "max_restarts", 5)
    failures = 0
    running = True

    def handle_signal(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    output(f"Watchdog started (interval={interval}s, max_restarts={max_restarts})")

    while running:
        if proxy_running():
            failures = 0  # Healthy → recover any down cells (cheap path).
            from brig.cell.lifecycle import restore_persisted_cells
            try:
                restore_persisted_cells()
            except Exception as e:
                warn(f"restart:always cell reconcile failed: {e}")
        else:
            failures += 1
            warn(f"Warden unreachable (recovery {failures}/{max_restarts})")
            if failures > max_restarts:
                output(f"ERROR: Max recoveries ({max_restarts}) exceeded. Giving up.")
                return 1
            # Bring the whole stack up: starts the Lima VM if the host slept and
            # dropped it (a bare warden restart can't), then warden, then
            # recovers restart:always cells. Idempotent; blocks while the VM
            # boots. A success resets the counter so a transient VM absence
            # (sleep/wake) never exhausts the cap.
            info("Bringing brig up (VM + warden + cells)...")
            from brig.commands.convenience_cmd import cmd_up
            try:
                if cmd_up(argparse.Namespace()) == 0:
                    info("brig recovered")
                    failures = 0
                else:
                    warn("brig bring-up returned non-zero; will retry")
            except Exception as e:
                warn(f"brig bring-up failed: {e}; will retry")

        # Reactive workspace-quota enforcement: stop cells that have outgrown
        # their workspace_quota (soft quota — the workspace is on virtiofs where
        # a hard block-quota isn't available). Runs regardless of warden health.
        from brig.cell.lifecycle import enforce_workspace_quotas
        try:
            for cell, size, quota in enforce_workspace_quotas():
                warn(
                    f"Stopped cell '{cell}': workspace {size} bytes exceeds "
                    f"workspace_quota ({quota} bytes)"
                )
        except Exception as e:
            warn(f"Workspace-quota sweep failed: {e}")

        time.sleep(interval)

    output("Watchdog stopped")
    return 0
