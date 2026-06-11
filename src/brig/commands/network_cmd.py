"""
CLI handlers for network and event commands.
"""

from __future__ import annotations

import argparse
import json
import re

from brig.config import CELL_NAME_PATTERN, STATE_DIR, VMPaths
from brig.errors import BrigError
from brig.ops.logging import output
from brig.vm.shell import vm_run


def _require_valid_cell_name(name: str) -> None:
    # `name` is a plain CLI positional; it flows into a VM log path read with
    # `cat ... sudo`. Validate against CELL_NAME_PATTERN (which forbids '/')
    # so a crafted name can't traverse to an arbitrary file (e.g.
    # '../../etc/passwd' -> '/etc/passwd.jsonl').
    if not isinstance(name, str) or not CELL_NAME_PATTERN.match(name):
        raise BrigError(
            f"Invalid cell name '{name}': must start with a lowercase letter or "
            f"digit, then up to 62 of [a-z0-9._-] — no uppercase, no '/'."
        )


def cmd_network(args: argparse.Namespace) -> int:
    """Handle `brig cell network` — view cell network activity from proxy logs.

    Use --blocked to filter to only requests that warden blocked. This is the
    fastest way to answer "why was my request blocked?" — the block reason
    is in the same line.

    --otel switches the source from per-cell JSONL files to the OTel
    collector's log file. The output shape is identical so downstream
    scripts continue to work.
    """
    cell_name = args.name
    _require_valid_cell_name(cell_name)
    if getattr(args, "otel", False):
        return _cmd_network_from_otel(args)

    # Logs live inside the VM under /var/log/brig/network/, owned by uid 1000
    # (the mitmproxy user in the warden container). The host has no direct
    # view of that path, and the Lima user can't read mitmproxy-owned files,
    # so read them with sudo via vm_run.
    log_path = VMPaths.LOG_DIR / f"{cell_name}.jsonl"
    result = vm_run(["cat", str(log_path)], timeout=10, sudo=True)
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


def _cmd_network_from_otel(args: argparse.Namespace) -> int:
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

    # Walk forward (oldest → newest) and collect every match, then take the
    # last `tail`. A single batch line can hold more than `tail` records, so
    # breaking early would render the oldest of that batch, not the newest.
    matches: list[dict] = []
    for line in result.stdout.splitlines():
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
                        "tls_mode": attrs.get("tls_mode", ""),
                        "bytes_in": attrs.get("bytes_in", 0),
                        "bytes_out": attrs.get("bytes_out", 0),
                    })

    for entry in matches[-tail:]:
        _print_network_line(entry)
    return 0


# C0 controls + DEL + C1 controls. Stripped from cell-controlled fields before
# they reach the operator's terminal (ANSI/CR log-line forgery defense).
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(value: object) -> str:
    return _CONTROL_CHARS_RE.sub("", str(value))


def _print_network_line(entry: dict) -> None:
    ts = entry.get("ts") or entry.get("timestamp", "")
    # host/path/method/reason are cell-controlled and stored raw in the JSONL
    # (and _redact_path runs unquote, which DECODES %1b→ESC / %0d→CR). Strip
    # C0/C1 control bytes before printing so a cell can't inject ANSI escapes
    # or CRs to forge/erase lines in the operator's terminal — mirrors the
    # sanitize enforce.py applies before logging.
    method = _clean(entry.get("method", ""))
    host = _clean(entry.get("host", ""))
    path = _clean(entry.get("path", ""))
    status = entry.get("status", entry.get("status_code", ""))
    blocked = entry.get("blocked")
    tag = " [BLOCKED]" if blocked else ""
    reason = f" ({_clean(entry.get('block_reason', ''))})" if blocked else ""
    # Invariant 11: passthrough flows have no method/path/status — only
    # SNI (host) + bytes. Render distinctly so operators can grep them
    # from MITM lines.
    if entry.get("tls_mode") == "passthrough":
        bytes_in = entry.get("bytes_in", 0)
        bytes_out = entry.get("bytes_out", 0)
        output(
            f"{ts} PASSTHROUGH: {host} "
            f"({bytes_in}B in / {bytes_out}B out){tag}{reason}"
        )
        return
    ingress_route = entry.get("ingress_route")
    if ingress_route:
        ingress_src = _clean(entry.get("ingress_src_ip", entry.get("src_ip", "?")))
        output(
            f"{ts} INGRESS: {ingress_src} -> {method} {host}{path} "
            f"-> {status} (route={_clean(ingress_route)}){tag}{reason}"
        )
    else:
        output(f"{ts} OUT: {method} {host}{path} -> {status}{tag}{reason}")


def _attrs_to_dict(attrs: list[dict]) -> dict:
    out: dict = {}
    for a in attrs:
        if not isinstance(a, dict):
            continue
        key = a.get("key")
        if not isinstance(key, str):
            continue
        val = a.get("value", {})
        if not isinstance(val, dict):
            continue
        for typ in ("stringValue", "intValue", "doubleValue", "boolValue"):
            if typ in val:
                out[key] = val[typ]
                break
    return out


def cmd_events(args: argparse.Namespace) -> int:
    """Handle `brig cell events` — print lifecycle events.

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
