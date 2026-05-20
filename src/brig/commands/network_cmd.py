"""
CLI handlers for network and event commands.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from brig.config import CONTAINER_PREFIX, STATE_DIR, VMPaths
from brig.errors import BrigError
from brig.ops.logging import output
from brig.vm.shell import vm_run


def cmd_network(args: Any) -> int:
    """Handle `brig network` — view cell network activity from proxy logs.

    Use --blocked to filter to only requests that warden blocked. This is the
    fastest way to answer "why was my request blocked?" — the block reason
    is in the same line.

    --otel switches the source from per-cell JSONL files to the OTel
    collector's log file. The output shape is identical so downstream
    scripts continue to work.
    """
    cell_name = args.name
    if getattr(args, "otel", False):
        return _cmd_network_from_otel(args)

    # Logs live inside the VM under /var/log/brig/network/, owned by uid 1000
    # (the mitmproxy user in the warden container). The host has no direct
    # view of that path, and the Lima user can't read mitmproxy-owned files,
    # so read them with sudo via vm_run.
    log_path = VMPaths.LOG_DIR / f"{cell_name}.jsonl"
    result = vm_run(["sudo", "cat", str(log_path)], timeout=10)
    if result.returncode != 0:
        output(f"No network logs for cell '{cell_name}'")
        return 0

    tail = getattr(args, "tail", 20) or 20
    only_blocked = getattr(args, "blocked", False)
    try:
        content = result.stdout.strip()
        if not content:
            output(f"No network logs for cell '{cell_name}'")
            return 0
        lines = content.split("\n")
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
            _print_network_line(entry)
    except IOError as e:
        raise BrigError(f"Failed to read logs: {e}")

    return 0


def _cmd_network_from_otel(args: Any) -> int:
    """Read the cell's request log from the OTel collector's logs file.

    The collector's file/logs exporter writes one OTLP ResourceLogs
    batch per line. We flatten, filter to this cell, and render the
    same shape as the JSONL path.
    """
    cell_name = args.name
    tail = getattr(args, "tail", 20) or 20
    only_blocked = getattr(args, "blocked", False)

    OTEL_LOGS_PATH = "/var/lib/otel/logs.jsonl"
    result = vm_run(["cat", OTEL_LOGS_PATH], timeout=10)
    if result.returncode != 0 or not result.stdout.strip():
        output("No collector logs available")
        return 0

    matches: list[dict] = []
    for line in reversed(result.stdout.splitlines()):
        if not line.strip():
            continue
        try:
            batch = json.loads(line)
        except json.JSONDecodeError:
            continue
        for rl in batch.get("resourceLogs", []):
            for sl in rl.get("scopeLogs", []):
                for rec in sl.get("logRecords", []):
                    attrs = _attrs_to_dict(rec.get("attributes", []))
                    if attrs.get("cell") != cell_name:
                        continue
                    blocked = attrs.get("decision") == "blocked"
                    if only_blocked and not blocked:
                        continue
                    matches.append({
                        "ts": rec.get("observedTimeUnixNano", ""),
                        "method": attrs.get("method", ""),
                        "host": attrs.get("host", ""),
                        "path": attrs.get("path", ""),
                        "status": attrs.get("status", ""),
                        "blocked": blocked,
                        "block_reason": attrs.get("block_reason", ""),
                        "ingress_route": attrs.get("ingress_route", ""),
                        "src_ip": attrs.get("src_ip", ""),
                    })
                    if len(matches) >= tail:
                        break
        if len(matches) >= tail:
            break

    for entry in reversed(matches):
        _print_network_line(entry)
    return 0


def _print_network_line(entry: dict) -> None:
    ts = entry.get("ts") or entry.get("timestamp", "")
    method = entry.get("method", "")
    host = entry.get("host", "")
    path = entry.get("path", "")
    status = entry.get("status", entry.get("status_code", ""))
    blocked = entry.get("blocked")
    tag = " [BLOCKED]" if blocked else ""
    reason = f" ({entry.get('block_reason', '')})" if blocked else ""
    ingress_route = entry.get("ingress_route")
    if ingress_route:
        ingress_src = entry.get("ingress_src_ip", entry.get("src_ip", "?"))
        output(
            f"{ts} INGRESS: {ingress_src} -> {method} {host}{path} "
            f"-> {status} (route={ingress_route}){tag}{reason}"
        )
    else:
        output(f"{ts} OUT: {method} {host}{path} -> {status}{tag}{reason}")


def _attrs_to_dict(attrs: list[dict]) -> dict:
    out: dict = {}
    for a in attrs:
        key = a.get("key")
        val = a.get("value", {})
        for typ in ("stringValue", "intValue", "doubleValue", "boolValue"):
            if typ in val:
                out[key] = val[typ]
                break
    return out


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
