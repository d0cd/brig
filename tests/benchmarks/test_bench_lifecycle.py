"""Benchmarks for cell lifecycle operations.

Tests build_run_command, subnet allocation, and state loading performance.
"""

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from brig.cell.reconciler import build_run_command
from brig.cell.spec import CellSpec
from brig.network.subnet import allocate, free, _load_state


# ---------------------------------------------------------------------------
# build_run_command benchmarks
# ---------------------------------------------------------------------------

@pytest.mark.bench
def test_bench_build_run_command_full(benchmark):
    """Build podman run command with all options."""
    spec = CellSpec(
        name="bench-cell",
        image="alpine:latest",
        command=["echo", "hello"],
        memory="2g",
        cpus="2",
        pids_limit=512,
        env=[f"VAR_{i}=value_{i}" for i in range(20)],
        labels=["team=bench", "tier=test"],
        detach=True,
        rm=True,
    )

    benchmark(build_run_command, spec, "10.60.1.2")


# ---------------------------------------------------------------------------
# Subnet allocator benchmarks
# ---------------------------------------------------------------------------

@pytest.fixture
def subnet_temp():
    """Create temp directory for subnet state."""
    tmpdir = Path(tempfile.mkdtemp())
    yield tmpdir
    shutil.rmtree(tmpdir)


@pytest.mark.bench
def test_bench_subnet_allocate(benchmark, subnet_temp):
    """Allocate a single subnet from empty state."""
    state_file = subnet_temp / "subnets.json"
    lock_file = subnet_temp / "allocator.lock"
    counter = [0]

    def do_allocate():
        counter[0] += 1
        state_file.unlink(missing_ok=True)
        allocate(f"bench-{counter[0]}", state_file, lock_file)

    benchmark(do_allocate)


@pytest.mark.bench
def test_bench_subnet_allocate_at_scale(benchmark, subnet_temp):
    """Allocate from a state with 200 existing allocations."""
    state_file = subnet_temp / "subnets.json"
    lock_file = subnet_temp / "allocator.lock"
    counter = [0]

    def build_state():
        state = {"next_index": 201, "allocated": {}, "freed": []}
        for i in range(1, 201):
            state["allocated"][f"cell-{i}"] = {
                "index": i, "allocated_at": "2026-01-01T00:00:00Z",
            }
        state_file.write_text(json.dumps(state))

    build_state()

    def do_allocate():
        counter[0] += 1
        build_state()
        allocate(f"scale-{counter[0]}", state_file, lock_file)

    benchmark(do_allocate)


@pytest.mark.bench
def test_bench_subnet_free(benchmark, subnet_temp):
    """Free a subnet from a state with 100 allocations."""
    state_file = subnet_temp / "subnets.json"
    lock_file = subnet_temp / "allocator.lock"

    def build_state():
        state = {"next_index": 101, "allocated": {}, "freed": []}
        for i in range(1, 101):
            state["allocated"][f"cell-{i}"] = {
                "index": i, "allocated_at": "2026-01-01T00:00:00Z",
            }
        state_file.write_text(json.dumps(state))

    def do_free():
        build_state()
        free("cell-50", state_file, lock_file)

    benchmark(do_free)


@pytest.mark.bench
def test_bench_subnet_load_state(benchmark, subnet_temp):
    """Load subnet state file with 200 entries."""
    state_file = subnet_temp / "subnets.json"
    state = {"next_index": 201, "allocated": {}, "freed": list(range(1, 11))}
    for i in range(1, 201):
        state["allocated"][f"cell-{i}"] = {
            "index": i, "allocated_at": "2026-01-01T00:00:00Z",
        }
    state_file.write_text(json.dumps(state))

    benchmark(_load_state, state_file)
