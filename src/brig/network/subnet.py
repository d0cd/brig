"""
Embedded subnet allocator for cell networks.

Each cell gets a unique /24 subnet from 10.60.1.0/24 through 10.60.254.0/24
(max 254 cells). Uses a single state file with file locking for atomicity.

Replaces the standalone brig-subnet binary.
"""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from brig.config import ALLOCATOR_LOCK_FILE, CELL_NAME_PATTERN, SUBNET_MAP_FILE, SUBNET_STATE_FILE
from brig.ops.atomic import atomic_write_json

SUBNET_PREFIX = "10.60"
MIN_INDEX = 1
MAX_INDEX = 254


@dataclass
class SubnetInfo:
    """Allocated subnet information."""
    cell_name: str
    index: int
    subnet: str
    allocated_at: str


def index_to_subnet(index: int) -> str:
    """Convert index to subnet CIDR string."""
    return f"{SUBNET_PREFIX}.{index}.0/24"


def validate_index(index: int) -> bool:
    """Check if index is in valid range (1-254)."""
    return MIN_INDEX <= index <= MAX_INDEX


def _load_state(state_file: Path = SUBNET_STATE_FILE) -> dict:
    """Load subnet allocation state from file.

    UNLOCKED — caller must hold the allocator file lock (fcntl.LOCK_SH or
    LOCK_EX on ALLOCATOR_LOCK_FILE). Direct reads without the lock can
    observe a torn file in the rename window. All callers in this module
    (allocate/free/get/list_all/get_subnet_map) wrap _load_state in a lock;
    if you add a new caller, do the same.
    """
    default: dict = {"next_index": 1, "allocated": {}, "freed": []}
    if not state_file.exists():
        return default

    try:
        with open(state_file) as f:
            state = json.load(f)
    except (json.JSONDecodeError, IOError):
        return default

    if not isinstance(state, dict):
        return default

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


def _save_state(state: dict, state_file: Path = SUBNET_STATE_FILE) -> None:
    """Save state atomically (write to temp, fsync, rename)."""
    # State dir must be 0700 — holds the subnet allocator + audit logs.
    # atomic_write_json does mkdir(parents=True) but doesn't force 0700,
    # so re-chmod after to tighten if the dir already existed looser.
    state_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(state_file.parent, 0o700)
    except OSError:
        pass
    atomic_write_json(state_file, state)


def _build_subnet_map(state: dict) -> dict[str, str]:
    """Build subnet -> cell_name mapping from state."""
    mapping: dict[str, str] = {}
    for cell_name, info in state["allocated"].items():
        subnet = index_to_subnet(info["index"])
        mapping[subnet] = cell_name
    return mapping


def _write_subnet_map(state: dict, map_file: Path = SUBNET_MAP_FILE) -> None:
    """Write subnet-map.json atomically for enforce.py consumption.

    Must be called under the allocator lock.
    """
    atomic_write_json(map_file, _build_subnet_map(state))


def allocate(
    cell_name: str,
    state_file: Path = SUBNET_STATE_FILE,
    lock_file: Path = ALLOCATOR_LOCK_FILE,
) -> SubnetInfo:
    """Allocate a /24 subnet for a cell.

    Thread/process-safe via file locking. Raises ValueError on failure.
    """
    if not CELL_NAME_PATTERN.match(cell_name):
        raise ValueError(f"Invalid cell name '{cell_name}'")

    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_file, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            state = _load_state(state_file)

            if cell_name in state["allocated"]:
                raise ValueError(f"Cell '{cell_name}' already has subnet allocated")

            # Prefer freed indices, then next_index.
            if state["freed"]:
                index = state["freed"].pop(0)
                if not validate_index(index):
                    raise ValueError(f"Corrupted state: freed index {index} out of range")
            else:
                index = state["next_index"]
                if not validate_index(index):
                    raise ValueError(f"No more subnets available (max {MAX_INDEX} cells)")
                state["next_index"] = index + 1

            allocated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            state["allocated"][cell_name] = {
                "index": index,
                "allocated_at": allocated_at,
            }

            _save_state(state, state_file)
            _write_subnet_map(state)

            return SubnetInfo(
                cell_name=cell_name,
                index=index,
                subnet=index_to_subnet(index),
                allocated_at=allocated_at,
            )
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def free(
    cell_name: str,
    state_file: Path = SUBNET_STATE_FILE,
    lock_file: Path = ALLOCATOR_LOCK_FILE,
) -> None:
    """Free a cell's subnet allocation."""
    if not CELL_NAME_PATTERN.match(cell_name):
        raise ValueError(f"Invalid cell name '{cell_name}'")

    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_file, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            state = _load_state(state_file)

            if cell_name not in state["allocated"]:
                raise ValueError(f"Cell '{cell_name}' has no subnet allocated")

            index = state["allocated"][cell_name]["index"]
            del state["allocated"][cell_name]

            if index not in state["freed"]:
                state["freed"].append(index)
                state["freed"].sort()

            _save_state(state, state_file)
            _write_subnet_map(state)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def get(
    cell_name: str,
    state_file: Path = SUBNET_STATE_FILE,
    lock_file: Path = ALLOCATOR_LOCK_FILE,
) -> SubnetInfo | None:
    """Get subnet info for a cell. Returns None if not allocated."""
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_file, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        try:
            state = _load_state(state_file)
            if cell_name not in state["allocated"]:
                return None
            info = state["allocated"][cell_name]
            return SubnetInfo(
                cell_name=cell_name,
                index=info["index"],
                subnet=index_to_subnet(info["index"]),
                allocated_at=info["allocated_at"],
            )
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def list_all(
    state_file: Path = SUBNET_STATE_FILE,
    lock_file: Path = ALLOCATOR_LOCK_FILE,
) -> list[SubnetInfo]:
    """List all allocated subnets, sorted by index."""
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_file, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        try:
            state = _load_state(state_file)
            result = []
            for cell_name, info in sorted(
                state["allocated"].items(), key=lambda x: x[1]["index"]
            ):
                result.append(SubnetInfo(
                    cell_name=cell_name,
                    index=info["index"],
                    subnet=index_to_subnet(info["index"]),
                    allocated_at=info["allocated_at"],
                ))
            return result
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def get_subnet_map(
    state_file: Path = SUBNET_STATE_FILE,
    lock_file: Path = ALLOCATOR_LOCK_FILE,
) -> dict[str, str]:
    """Get the subnet -> cell_name mapping (for enforce.py consumption)."""
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_file, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        try:
            state = _load_state(state_file)
            return _build_subnet_map(state)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
