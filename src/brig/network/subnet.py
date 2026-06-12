"""
Embedded subnet allocator for cell networks.

Each cell gets a unique /24 subnet from 10.60.1.0/24 through 10.60.254.0/24
(max 254 cells). Uses a single state file with file locking for atomicity.

Replaces the standalone brig-subnet binary.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from brig.config import ALLOCATOR_LOCK_FILE, CELL_NAME_PATTERN, SUBNET_STATE_FILE
from brig.ops.atomic import atomic_write_json
from brig.ops.locking import locked_file

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
    (allocate/free/get/list_all) wrap _load_state in a lock;
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

    # Validate allocated indices too (subnets.json is untrusted, invariant 4):
    # drop entries whose index is non-int / out-of-range / colliding with an
    # already-seen index. An unchecked index flows into index_to_subnet and
    # would yield a malformed CIDR or two cells sharing a /24.
    seen_indices: set[int] = set()
    clean_allocated: dict = {}
    for cell_name, info in state["allocated"].items():
        if not isinstance(info, dict):
            continue
        idx = info.get("index")
        if not isinstance(idx, int) or not validate_index(idx) or idx in seen_indices:
            continue
        # get()/list_all() read info["allocated_at"]; a tampered entry missing
        # it (or with a non-str value) would KeyError out of unwrapped callers
        # (brig system metrics/prune/sweep). Normalize to "" so reads degrade
        # gracefully rather than crash (invariant 4: state dir is untrusted).
        if not isinstance(info.get("allocated_at"), str):
            info = {**info, "allocated_at": ""}
        seen_indices.add(idx)
        clean_allocated[cell_name] = info
    state["allocated"] = clean_allocated

    # Enforce disjointness across allocated / freed / next_index — a tampered
    # file could otherwise hand out an in-use /24 (two cells, one subnet):
    #   - drop freed indices that collide with an allocated one (allocate()
    #     pops freed first and would re-issue the live index), and dedup freed
    #     so the same index can't be popped for two cells;
    #   - clamp next_index above every allocated/freed index so the sequential
    #     path can't issue an index already in use.
    deduped_freed: list[int] = []
    freed_seen: set[int] = set()
    for i in state["freed"]:
        if i in seen_indices or i in freed_seen:
            continue
        freed_seen.add(i)
        deduped_freed.append(i)
    state["freed"] = deduped_freed

    used = seen_indices | freed_seen
    if used:
        state["next_index"] = max(state["next_index"], max(used) + 1)
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


def _write_subnet_map(state: dict, *, map_file: Path) -> None:
    """Write subnet-map.json atomically for enforce.py consumption.

    Must be called under the allocator lock. `map_file` is keyword-only with
    no default — a silent default here once let pytest clobber the user's
    real subnet-map.json when tests overrode only state_file.
    """
    atomic_write_json(map_file, _build_subnet_map(state))


def allocate(
    cell_name: str,
    state_file: Path = SUBNET_STATE_FILE,
    lock_file: Path = ALLOCATOR_LOCK_FILE,
) -> SubnetInfo:
    """Allocate a /24 subnet for a cell.

    Thread/process-safe via file locking. Raises ValueError on failure.

    Idempotent per cell name: a subnet is keyed by cell name, so re-allocating
    for a name that already holds one returns the existing allocation rather
    than failing. This lets `brig run` reclaim a same-named orphan (e.g. after
    a VM restart leaves the host-side allocation but drops the podman network)
    instead of erroring with "already has subnet allocated".
    """
    if not CELL_NAME_PATTERN.match(cell_name):
        raise ValueError(f"Invalid cell name '{cell_name}'")

    with locked_file(lock_file):
        state = _load_state(state_file)

        existing = state["allocated"].get(cell_name)
        if existing is not None:
            index = existing["index"]
            return SubnetInfo(
                cell_name=cell_name,
                index=index,
                subnet=index_to_subnet(index),
                allocated_at=existing["allocated_at"],
            )

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
        _write_subnet_map(state, map_file=state_file.parent / "subnet-map.json")

        return SubnetInfo(
            cell_name=cell_name,
            index=index,
            subnet=index_to_subnet(index),
            allocated_at=allocated_at,
        )


def free(
    cell_name: str,
    state_file: Path = SUBNET_STATE_FILE,
    lock_file: Path = ALLOCATOR_LOCK_FILE,
) -> None:
    """Free a cell's subnet allocation."""
    if not CELL_NAME_PATTERN.match(cell_name):
        raise ValueError(f"Invalid cell name '{cell_name}'")

    with locked_file(lock_file):
        state = _load_state(state_file)

        if cell_name not in state["allocated"]:
            raise ValueError(f"Cell '{cell_name}' has no subnet allocated")

        index = state["allocated"][cell_name]["index"]
        del state["allocated"][cell_name]

        if index not in state["freed"]:
            state["freed"].append(index)
            state["freed"].sort()

        _save_state(state, state_file)
        _write_subnet_map(state, map_file=state_file.parent / "subnet-map.json")


def get(
    cell_name: str,
    state_file: Path = SUBNET_STATE_FILE,
    lock_file: Path = ALLOCATOR_LOCK_FILE,
) -> SubnetInfo | None:
    """Get subnet info for a cell. Returns None if not allocated."""
    with locked_file(lock_file, exclusive=False):
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


def list_all(
    state_file: Path = SUBNET_STATE_FILE,
    lock_file: Path = ALLOCATOR_LOCK_FILE,
) -> list[SubnetInfo]:
    """List all allocated subnets, sorted by index."""
    with locked_file(lock_file, exclusive=False):
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


def reclaim_orphan_subnets() -> list[str]:
    """Free subnet allocations whose podman network no longer exists.

    Returns the freed cell names. Self-heals leaks from a raw `podman` kill or a
    crash mid-`rm` that left the /24 allocated after the network/container were
    gone — otherwise the bounded 254-subnet space (and stale ingress routes)
    accumulate until a manual `brig system prune`. Fails safe: if the network
    list can't be read, nothing is freed (a live subnet must never be reclaimed
    just because enumeration failed).
    """
    from brig.config import CONTAINER_PREFIX
    from brig.vm.shell import vm_run
    result = vm_run(["podman", "network", "ls", "--format", "{{.Name}}"])
    if result.returncode != 0:
        return []
    existing = set(result.stdout.strip().split("\n"))
    freed: list[str] = []
    for info in list_all():
        if f"{CONTAINER_PREFIX}{info.cell_name}" not in existing:
            try:
                free(info.cell_name)
                freed.append(info.cell_name)
            except ValueError:
                pass
    return freed
