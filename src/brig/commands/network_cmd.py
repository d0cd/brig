"""
CLI handlers for network and event commands.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from brig.config import CONTAINER_PREFIX, STATE_DIR
from brig.errors import BrigError
from brig.ops.logging import output


def cmd_network(args: Any) -> int:
    """Handle `brig network` — view cell network activity from proxy logs."""
    cell_name = args.name
    log_dir = Path("/var/log/brig/network")
    log_file = log_dir / f"{cell_name}.jsonl"

    if not log_file.exists():
        output(f"No network logs for cell '{cell_name}'")
        return 0

    tail = getattr(args, "tail", 20) or 20
    try:
        lines = log_file.read_text().strip().split("\n")
        for line in lines[-tail:]:
            try:
                entry = json.loads(line)
                ts = entry.get("timestamp", "")
                method = entry.get("method", "")
                url = entry.get("url", "")
                status = entry.get("status_code", "")
                output(f"{ts} {method} {url} -> {status}")
            except json.JSONDecodeError:
                pass
    except IOError as e:
        raise BrigError(f"Failed to read logs: {e}")

    return 0


def cmd_events(args: Any) -> int:
    """Handle `brig events` — stream lifecycle events."""
    lifecycle_file = STATE_DIR / "system" / "lifecycle.jsonl"

    if not lifecycle_file.exists():
        output("No lifecycle events recorded")
        return 0

    tail = getattr(args, "tail", 20) or 20
    cell_filter = getattr(args, "name", None)

    try:
        lines = lifecycle_file.read_text().strip().split("\n")
        for line in lines[-tail * 3:]:  # Read extra to account for filtering.
            try:
                entry = json.loads(line)
                if cell_filter and entry.get("cell") != cell_filter:
                    continue
                ts = entry.get("ts", "")
                event = entry.get("event", "")
                cell = entry.get("cell", "")
                output(f"{ts} [{event}] {cell}")
                tail -= 1
                if tail <= 0:
                    break
            except json.JSONDecodeError:
                pass
    except IOError as e:
        raise BrigError(f"Failed to read events: {e}")

    return 0
