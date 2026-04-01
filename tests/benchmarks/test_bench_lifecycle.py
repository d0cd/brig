"""Cell lifecycle benchmarks.

Measures performance of cell creation, command building, subnet allocation,
and cleanup operations. Uses mocked subprocess calls since these benchmarks
run in CI without a real VM.
"""

import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

SRC_DIR = Path(__file__).parent.parent.parent / "src"


@pytest.fixture(scope="session")
def brig_mod():
    """Import brig.py module."""
    spec = importlib.util.spec_from_file_location("brig_main", SRC_DIR / "brig.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def subnet_mod():
    """Import brig_subnet.py module."""
    spec = importlib.util.spec_from_file_location("brig_subnet", SRC_DIR / "brig_subnet.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def brig_temp(brig_mod):
    """Patch STATE_DIR to a temp directory for _build_run_command."""
    tmpdir = Path(tempfile.mkdtemp())
    orig = brig_mod.STATE_DIR
    brig_mod.STATE_DIR = tmpdir
    yield tmpdir
    brig_mod.STATE_DIR = orig
    shutil.rmtree(tmpdir)


def _make_run_args(**overrides):
    """Build a minimal args namespace for _build_run_command."""
    defaults = dict(
        image="alpine:latest",
        container_cmd=["echo", "hello"],
        memory="2g",
        cpus="2",
        pids_limit=512,
        detach=False,
        rm=False,
        env=None,
        secret=None,
        label=None,
        seccomp_profile=None,
        workdir=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# _build_run_command benchmarks
# ---------------------------------------------------------------------------

@pytest.mark.bench
def test_bench_build_run_command_minimal(benchmark, brig_mod, brig_temp):
    """Build podman run command with minimal args."""
    args = _make_run_args()

    def build():
        return brig_mod._build_run_command(
            args, "bench-cell", False, "brig-bench-cell",
            "10.60.1.2", 0, lambda *a: None,
        )

    benchmark(build)


@pytest.mark.bench
def test_bench_build_run_command_full(benchmark, brig_mod, brig_temp):
    """Build podman run command with env, labels, timeout, detach."""
    args = _make_run_args(
        env=[f"VAR_{i}=value_{i}" for i in range(20)],
        label=["team=bench", "tier=test"],
        detach=True,
        rm=True,
    )

    def build():
        return brig_mod._build_run_command(
            args, "bench-cell", False, "brig-bench-cell",
            "10.60.1.2", 3600, lambda *a: None,
        )

    benchmark(build)


@pytest.mark.bench
def test_bench_build_run_command_airgapped(benchmark, brig_mod, brig_temp):
    """Build podman run command in air-gapped mode."""
    args = _make_run_args()

    def build():
        return brig_mod._build_run_command(
            args, "bench-cell", True, "brig-bench-cell",
            "", 0, lambda *a: None,
        )

    benchmark(build)


# ---------------------------------------------------------------------------
# Subnet allocator benchmarks
# ---------------------------------------------------------------------------

@pytest.fixture
def subnet_temp(subnet_mod):
    """Create temp directory and patch subnet module paths."""
    tmpdir = tempfile.mkdtemp()
    orig_subnets = subnet_mod.SUBNETS_FILE
    orig_map = subnet_mod.SUBNET_MAP_FILE
    orig_lock = subnet_mod.LOCK_FILE

    subnet_mod.SUBNETS_FILE = Path(tmpdir) / "subnets.json"
    subnet_mod.SUBNET_MAP_FILE = Path(tmpdir) / "subnet-map.json"
    subnet_mod.LOCK_FILE = Path(tmpdir) / "allocator.lock"

    yield tmpdir

    subnet_mod.SUBNETS_FILE = orig_subnets
    subnet_mod.SUBNET_MAP_FILE = orig_map
    subnet_mod.LOCK_FILE = orig_lock
    shutil.rmtree(tmpdir)


@pytest.mark.bench
def test_bench_subnet_allocate(benchmark, subnet_mod, subnet_temp):
    """Allocate a single subnet from empty state."""
    counter = [0]

    def allocate():
        counter[0] += 1
        # Reset state each time to measure cold allocation.
        subnet_mod.SUBNETS_FILE.unlink(missing_ok=True)
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            subnet_mod.cmd_allocate(f"bench-{counter[0]}")

    benchmark(allocate)


@pytest.mark.bench
def test_bench_subnet_allocate_at_scale(benchmark, subnet_mod, subnet_temp):
    """Allocate from a state with 200 existing allocations."""
    counter = [0]

    def _build_state_200():
        """Reset to 200 allocations with room to grow."""
        state = {"next_index": 201, "allocated": {}, "freed": []}
        for i in range(1, 201):
            state["allocated"][f"cell-{i}"] = {
                "index": i,
                "allocated_at": "2026-01-01T00:00:00Z",
            }
        with open(subnet_mod.SUBNETS_FILE, "w") as fp:
            json.dump(state, fp)

    _build_state_200()

    def allocate():
        counter[0] += 1
        # Reset state before each iteration to prevent exhaustion.
        _build_state_200()
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            subnet_mod.cmd_allocate(f"scale-{counter[0]}")

    benchmark(allocate)


@pytest.mark.bench
def test_bench_subnet_free(benchmark, subnet_mod, subnet_temp):
    """Free a subnet from a state with 100 allocations."""

    def _build_state_100():
        state = {"next_index": 101, "allocated": {}, "freed": []}
        for i in range(1, 101):
            state["allocated"][f"cell-{i}"] = {
                "index": i,
                "allocated_at": "2026-01-01T00:00:00Z",
            }
        with open(subnet_mod.SUBNETS_FILE, "w") as fp:
            json.dump(state, fp)

    def setup_and_free():
        _build_state_100()
        subnet_mod.cmd_free("cell-50")

    benchmark(setup_and_free)


@pytest.mark.bench
def test_bench_subnet_load_state(benchmark, subnet_mod, subnet_temp):
    """Load subnet state file with 200 entries."""
    state = {"next_index": 201, "allocated": {}, "freed": list(range(1, 11))}
    for i in range(1, 201):
        state["allocated"][f"cell-{i}"] = {
            "index": i,
            "allocated_at": "2026-01-01T00:00:00Z",
        }
    with open(subnet_mod.SUBNETS_FILE, "w") as fp:
        json.dump(state, fp)

    benchmark(subnet_mod.load_state)


# ---------------------------------------------------------------------------
# Network name generation
# ---------------------------------------------------------------------------

@pytest.mark.bench
def test_bench_network_name(benchmark, brig_mod):
    """network_name() string construction."""
    benchmark(brig_mod.network_name, "my-benchmark-cell")
