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
    """Handle `brig network` — view cell network activity from proxy logs.

    Use --blocked to filter to only requests that warden blocked. This is the
    fastest way to answer "why was my request blocked?" — the block reason
    is in the same line.
    """
    cell_name = args.name
    log_dir = Path("/var/log/brig/network")
    log_file = log_dir / f"{cell_name}.jsonl"

    if not log_file.exists():
        output(f"No network logs for cell '{cell_name}'")
        return 0

    tail = getattr(args, "tail", 20) or 20
    only_blocked = getattr(args, "blocked", False)
    try:
        lines = log_file.read_text().strip().split("\n")
        # When filtering, scan from the end to collect only `tail` matches.
        matches = []
        for line in reversed(lines):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if only_blocked and not entry.get("blocked"):
                continue
            matches.append(entry)
            if len(matches) >= tail:
                break
        for entry in reversed(matches):
            ts = entry.get("ts") or entry.get("timestamp", "")
            method = entry.get("method", "")
            host = entry.get("host", "")
            path = entry.get("path", "")
            status = entry.get("status", entry.get("status_code", ""))
            blocked = entry.get("blocked")
            tag = " [BLOCKED]" if blocked else ""
            reason = f" ({entry.get('block_reason', '')})" if blocked else ""
            output(f"{ts} {method} {host}{path} -> {status}{tag}{reason}")
    except IOError as e:
        raise BrigError(f"Failed to read logs: {e}")

    return 0


def cmd_events(args: Any) -> int:
    """Handle `brig events` — print lifecycle events.

    With --follow, blocks and prints new events as they appear.
    """
    lifecycle_file = STATE_DIR / "system" / "lifecycle.jsonl"

    if not lifecycle_file.exists():
        output("No lifecycle events recorded")
        return 0

    tail = getattr(args, "tail", 20) or 20
    cell_filter = getattr(args, "name", None)
    follow = getattr(args, "follow", False)

    def _print_entry(entry: dict) -> None:
        ts = entry.get("ts", "")
        event = entry.get("event", "")
        cell = entry.get("cell", "")
        output(f"{ts} [{event}] {cell}")

    try:
        lines = lifecycle_file.read_text().strip().split("\n")
        # Print last `tail` matching entries.
        recent = []
        for line in reversed(lines):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if cell_filter and entry.get("cell") != cell_filter:
                continue
            recent.append(entry)
            if len(recent) >= tail:
                break
        for entry in reversed(recent):
            _print_entry(entry)
    except IOError as e:
        raise BrigError(f"Failed to read events: {e}")

    if not follow:
        return 0

    # Follow mode: tail the file, parsing new lines as they appear.
    import time as _time
    try:
        with open(lifecycle_file, "r") as f:
            f.seek(0, 2)  # Seek to end.
            while True:
                line = f.readline()
                if not line:
                    _time.sleep(0.5)
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if cell_filter and entry.get("cell") != cell_filter:
                    continue
                _print_entry(entry)
    except KeyboardInterrupt:
        return 0
    except IOError as e:
        raise BrigError(f"Failed to follow events: {e}")
