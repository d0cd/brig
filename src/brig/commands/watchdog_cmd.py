"""
Warden watchdog — monitors proxy health and restarts on failure.

Runs in the foreground, checking warden health at a configurable interval.
If the proxy dies, it restarts it automatically (up to max_restarts).
"""

from __future__ import annotations

import signal
import time
import argparse

from brig.ops.logging import info, output, warn


def cmd_watchdog(args: argparse.Namespace) -> int:
    """Handle `brig watchdog` — monitor and restart warden."""
    from brig.network.proxy import proxy_running
    from warden.proxy import start, stop

    interval = getattr(args, "interval", 30)
    max_restarts = getattr(args, "max_restarts", 5)
    restarts = 0
    running = True

    def handle_signal(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    output(f"Watchdog started (interval={interval}s, max_restarts={max_restarts})")

    while running:
        if proxy_running():
            restarts = 0  # Reset counter on healthy check.
        else:
            restarts += 1
            warn(f"Warden is down (restart {restarts}/{max_restarts})")

            if restarts > max_restarts:
                output(f"ERROR: Max restarts ({max_restarts}) exceeded. Giving up.")
                return 1

            info("Restarting warden...")
            stop()
            if start():
                info("Warden restarted successfully")
            else:
                warn("Warden restart failed, will retry")

        time.sleep(interval)

    output("Watchdog stopped")
    return 0
