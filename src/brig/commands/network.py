"""Network commands: network, events."""

import json
import subprocess
import sys

from brig.commands._helpers import (
    CONTAINER_PREFIX,
    cell_exists,
    container_name,
    error_cell_not_found,
    info,
    output,
    run,
    validate_cell_name,
)
from pathlib import Path


def cmd_network(args) -> int:
    """View cell network activity logs."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    # Network logs are stored at /var/log/brig/network/{cell}.jsonl.
    log_file = Path(f"/var/log/brig/network/{cell_name}.jsonl")

    if not log_file.exists():
        info(f"No network activity logged for {cell_name}")
        return 0

    if args.follow:
        # Follow mode - use tail -f.
        if args.blocked:
            # Filter blocked requests in follow mode.
            proc = subprocess.Popen(
                ["tail", "-f", str(log_file)],
                stdout=subprocess.PIPE, text=True
            )
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if not entry.get("blocked"):
                            continue
                    except json.JSONDecodeError:
                        continue
                    if args.json:
                        print(line, flush=True)
                    else:
                        ts = entry.get("ts", "")[:19]
                        method = entry.get("method", "")
                        host = entry.get("host", "")
                        path = entry.get("path", "/")[:50]
                        status = entry.get("status", "")
                        print(f"{ts} {method:6} {host}{path} -> {status} [BLOCKED]", flush=True)
            except KeyboardInterrupt:
                pass
            finally:
                proc.terminate()
                proc.wait()
        else:
            cmd = ["tail", "-f", str(log_file)]
            try:
                run(cmd, check=False)
            except KeyboardInterrupt:
                pass
    else:
        # Read last N lines.
        cmd = ["tail", "-n", str(args.tail), str(log_file)]
        result = run(cmd, check=False, capture=True)

        if args.json:
            # Raw JSONL output.
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                if args.blocked:
                    try:
                        entry = json.loads(line)
                        if not entry.get("blocked"):
                            continue
                    except json.JSONDecodeError:
                        continue
                print(line)
        else:
            # Formatted output.
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if args.blocked and not entry.get("blocked"):
                        continue
                    ts = entry.get("ts", "")[:19]  # Truncate to seconds.
                    method = entry.get("method", "")
                    host = entry.get("host", "")
                    path = entry.get("path", "/")[:50]
                    status = entry.get("status", "")
                    blocked = " [BLOCKED]" if entry.get("blocked") else ""
                    print(f"{ts} {method:6} {host}{path} -> {status}{blocked}")
                except json.JSONDecodeError:
                    print(line)

    return 0


def cmd_events(args) -> int:
    """Stream cell lifecycle events as JSON."""
    cell_name = getattr(args, "name", None)

    # Use podman events to stream container lifecycle events.
    cmd = ["podman", "events", "--format", "json"]
    if cell_name:
        validate_cell_name(cell_name)
        if not cell_exists(cell_name):
            error_cell_not_found(cell_name)
        cmd.extend(["--filter", f"container={container_name(cell_name)}"])
    else:
        # Filter to only brig containers.
        cmd.extend(["--filter", f"container={CONTAINER_PREFIX}"])

    # Event type filter.
    cmd.extend(["--filter", "type=container"])

    if getattr(args, "since", None):
        cmd.extend(["--since", args.since])

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                # Enrich with cell name.
                actor_name = event.get("Actor", {}).get("Attributes", {}).get("name", "")
                if actor_name.startswith(CONTAINER_PREFIX):
                    event["cell"] = actor_name[len(CONTAINER_PREFIX):]

                if getattr(args, "output", "json") == "json":
                    output(json.dumps(event))
                    sys.stdout.flush()
                else:
                    # Human-readable format.
                    cell = event.get("cell", actor_name)
                    action = event.get("Action", event.get("Status", "unknown"))
                    ts = event.get("time", event.get("Time", ""))
                    output(f"{ts} {cell}: {action}")
                    sys.stdout.flush()
            except json.JSONDecodeError:
                output(line)
        proc.wait()
        return proc.returncode
    except KeyboardInterrupt:
        return 0
