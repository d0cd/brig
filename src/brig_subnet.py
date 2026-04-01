#!/usr/bin/env python3
"""
Brig Subnet Allocator

Manages subnet allocation for cell networks. Each cell gets a unique /24 subnet
from the range 10.60.1.0/24 through 10.60.254.0/24 (max 254 cells).

Usage:
    brig-subnet allocate <cell-name>      Allocate subnet, print to stdout
    brig-subnet free <cell-name>          Free allocated subnet
    brig-subnet get <cell-name>           Get subnet for cell
    brig-subnet list                      List all allocated subnets
    brig-subnet create-network <cell>     Create podman network for cell
    brig-subnet remove-network <cell>     Remove podman network for cell
    brig-subnet validate-index <index>    Check if index is valid (1-254)

Files:
    /state/system/subnets.json       Persistent allocation state
    /var/run/brig/subnet-map.json    Runtime mapping for warden

Exit codes:
    0 - Success
    1 - Error (message on stderr)
"""

import argparse
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Constants
SUBNETS_FILE = Path("/state/system/subnets.json")
SUBNET_MAP_FILE = Path("/var/run/brig/subnet-map.json")
LOCK_FILE = Path("/var/run/brig/allocator.lock")
SUBNET_PREFIX = "10.60"
MIN_INDEX = 1
MAX_INDEX = 254

# Cell name pattern imported from shared config.
from brig.config import CELL_NAME_PATTERN


def validate_cell_name(name: str) -> None:
    """Validate cell name or exit with error."""
    if not CELL_NAME_PATTERN.match(name):
        error(f"Invalid cell name '{name}': must match {CELL_NAME_PATTERN.pattern}")


def error(msg: str) -> None:
    """Print error message and exit."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def load_state() -> dict:
    """Load subnet allocation state from file."""
    default = {"next_index": 1, "allocated": {}, "freed": []}
    if not SUBNETS_FILE.exists():
        return default

    try:
        with open(SUBNETS_FILE, "r") as f:
            state = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        error(f"Failed to load {SUBNETS_FILE}: {e}")

    # Validate state schema and apply defaults for missing keys.
    if not isinstance(state, dict):
        error(f"Corrupted state file: expected JSON object, got {type(state).__name__}")
    for key in ("next_index", "allocated", "freed"):
        if key not in state:
            state[key] = default[key]
    if not isinstance(state["next_index"], int) or state["next_index"] < MIN_INDEX:
        state["next_index"] = default["next_index"]
    if not isinstance(state["allocated"], dict):
        state["allocated"] = default["allocated"]
    if not isinstance(state["freed"], list):
        state["freed"] = default["freed"]
    # Filter out invalid freed indices.
    state["freed"] = [i for i in state["freed"] if isinstance(i, int) and validate_index(i)]
    return state


def save_state(state: dict) -> None:
    """Save state atomically (write to temp, rename)."""
    SUBNETS_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Write to temp file first
    fd, tmp_path = tempfile.mkstemp(dir=SUBNETS_FILE.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp_path, SUBNETS_FILE)
    except Exception as e:
        os.unlink(tmp_path)
        error(f"Failed to save state: {e}")


def update_subnet_map(state: dict) -> None:
    """Update the subnet map file for proxy hot-reload."""
    SUBNET_MAP_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Build mapping: subnet -> cell name
    mapping = {}
    for cell_name, info in state["allocated"].items():
        subnet = index_to_subnet(info["index"])
        mapping[subnet] = cell_name

    # Write atomically
    fd, tmp_path = tempfile.mkstemp(dir=SUBNET_MAP_FILE.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(mapping, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp_path, SUBNET_MAP_FILE)
    except Exception as e:
        os.unlink(tmp_path)
        error(f"Failed to update subnet map: {e}")


def index_to_subnet(index: int) -> str:
    """Convert index to subnet string."""
    return f"{SUBNET_PREFIX}.{index}.0/24"


def validate_index(index: int) -> bool:
    """Check if index is in valid range (1-254)."""
    return MIN_INDEX <= index <= MAX_INDEX


def with_lock(func):
    """Decorator to run function with exclusive file lock."""
    def wrapper(*args, **kwargs):
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOCK_FILE, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                return func(*args, **kwargs)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
    return wrapper


@with_lock
def cmd_allocate(cell_name: str) -> None:
    """Allocate a subnet for a cell."""
    validate_cell_name(cell_name)
    state = load_state()

    # Check if cell already has allocation
    if cell_name in state["allocated"]:
        error(f"Cell '{cell_name}' already has subnet allocated")

    # Get next index (prefer freed, then next_index).
    if state["freed"]:
        index = state["freed"].pop(0)
        if not validate_index(index):
            error(f"Corrupted state: freed index {index} out of range")
    else:
        index = state["next_index"]
        if not validate_index(index):
            error(f"No more subnets available (max {MAX_INDEX} cells)")
        state["next_index"] = index + 1

    # Record allocation
    state["allocated"][cell_name] = {
        "index": index,
        "allocated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }

    save_state(state)
    update_subnet_map(state)

    # Output subnet to stdout
    print(index_to_subnet(index))


@with_lock
def cmd_free(cell_name: str) -> None:
    """Free a cell's subnet allocation."""
    validate_cell_name(cell_name)
    state = load_state()

    if cell_name not in state["allocated"]:
        error(f"Cell '{cell_name}' has no subnet allocated")

    # Get index and add to freed list
    index = state["allocated"][cell_name]["index"]
    del state["allocated"][cell_name]

    # Add to freed list (sorted for predictable reuse)
    if index not in state["freed"]:
        state["freed"].append(index)
        state["freed"].sort()

    save_state(state)
    update_subnet_map(state)


@with_lock
def cmd_get(cell_name: str) -> None:
    """Get subnet for a cell."""
    validate_cell_name(cell_name)
    state = load_state()

    if cell_name not in state["allocated"]:
        error(f"Cell '{cell_name}' has no subnet allocated")

    index = state["allocated"][cell_name]["index"]
    print(index_to_subnet(index))


@with_lock
def cmd_list() -> None:
    """List all allocated subnets."""
    state = load_state()

    if not state["allocated"]:
        print("No subnets allocated")
        return

    # Sort by index for consistent output
    items = sorted(
        state["allocated"].items(),
        key=lambda x: x[1]["index"]
    )

    for cell_name, info in items:
        subnet = index_to_subnet(info["index"])
        print(f"{cell_name}\t{subnet}\t{info['allocated_at']}")


def cmd_validate_index(index: int) -> None:
    """Validate if an index is in valid range."""
    if validate_index(index):
        sys.exit(0)
    else:
        sys.exit(1)


@with_lock
def cmd_create_network(cell_name: str) -> None:
    """Create a podman network for a cell."""
    validate_cell_name(cell_name)
    state = load_state()

    if cell_name not in state["allocated"]:
        error(f"Cell '{cell_name}' has no subnet allocated. Run 'allocate' first.")

    subnet = index_to_subnet(state["allocated"][cell_name]["index"])
    network_name = f"brig-{cell_name}"

    # Check if network already exists
    result = subprocess.run(
        ["podman", "network", "exists", network_name],
        capture_output=True
    )
    if result.returncode == 0:
        error(f"Network '{network_name}' already exists")

    # Create internal network with specific subnet
    result = subprocess.run(
        [
            "podman", "network", "create",
            "--internal",
            "--subnet", subnet,
            network_name
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        error(f"Failed to create network: {result.stderr}")

    print(network_name)


@with_lock
def cmd_remove_network(cell_name: str) -> None:
    """Remove a cell's podman network and free subnet."""
    validate_cell_name(cell_name)
    state = load_state()
    network_name = f"brig-{cell_name}"

    # Remove network if it exists
    result = subprocess.run(
        ["podman", "network", "exists", network_name],
        capture_output=True
    )
    if result.returncode == 0:
        result = subprocess.run(
            ["podman", "network", "rm", network_name],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            error(f"Failed to remove network: {result.stderr}")

    # Free the subnet allocation
    if cell_name in state["allocated"]:
        index = state["allocated"][cell_name]["index"]
        del state["allocated"][cell_name]
        if index not in state["freed"]:
            state["freed"].append(index)
            state["freed"].sort()
        save_state(state)
        update_subnet_map(state)


def main():
    parser = argparse.ArgumentParser(
        description="Brig subnet allocator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # allocate
    p_alloc = subparsers.add_parser("allocate", help="Allocate subnet for cell")
    p_alloc.add_argument("cell_name", help="Name of the cell")

    # free
    p_free = subparsers.add_parser("free", help="Free cell's subnet")
    p_free.add_argument("cell_name", help="Name of the cell")

    # get
    p_get = subparsers.add_parser("get", help="Get subnet for cell")
    p_get.add_argument("cell_name", help="Name of the cell")

    # list
    subparsers.add_parser("list", help="List allocated subnets")

    # validate-index
    p_val = subparsers.add_parser("validate-index", help="Check if index is valid")
    p_val.add_argument("index", type=int, help="Index to validate")

    # create-network
    p_create = subparsers.add_parser("create-network", help="Create podman network")
    p_create.add_argument("cell_name", help="Name of the cell")

    # remove-network
    p_remove = subparsers.add_parser("remove-network", help="Remove podman network")
    p_remove.add_argument("cell_name", help="Name of the cell")

    args = parser.parse_args()

    if args.command == "allocate":
        cmd_allocate(args.cell_name)
    elif args.command == "free":
        cmd_free(args.cell_name)
    elif args.command == "get":
        cmd_get(args.cell_name)
    elif args.command == "list":
        cmd_list()
    elif args.command == "validate-index":
        cmd_validate_index(args.index)
    elif args.command == "create-network":
        cmd_create_network(args.cell_name)
    elif args.command == "remove-network":
        cmd_remove_network(args.cell_name)


if __name__ == "__main__":
    main()
