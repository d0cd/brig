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
        no_seccomp=True,
        workdir=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# _build_run_command benchmarks
# ---------------------------------------------------------------------------

@pytest.mark.bench
def test_bench_build_run_command_full(benchmark, brig_mod, brig_temp):
    """Build podman run command with all options (env, labels, timeout).

    Measures the CLI-side command construction — the part between
    argument parsing and the podman subprocess call.
    """
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
# Cell lifecycle command benchmarks
# ---------------------------------------------------------------------------

def _make_cmd_run_args(**overrides):
    """Build a full args namespace for cmd_run."""
    defaults = dict(
        name="bench-cell",
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
        no_seccomp=True,
        workdir=None,
        file=None,
        profile=None,
        network="default",
        timeout=None,
        verify_image=False,
        tor=False,
        policy_allow=None,
        policy_deny=None,
        dry_run=False,
        canary=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_stop_args(name="bench-cell"):
    """Build args namespace for cmd_stop."""
    return SimpleNamespace(name=name)


def _make_rm_args(name="bench-cell", force=True, purge=False):
    """Build args namespace for cmd_rm."""
    return SimpleNamespace(name=name, force=force, purge=purge)


def _mock_run_success(*args, **kwargs):
    """Return a successful subprocess result."""
    return SimpleNamespace(returncode=0, stdout="", stderr="")


def _patch_lifecycle(monkeypatch, patches: dict):
    """Patch names in both _helpers and lifecycle modules.

    Since lifecycle.py does `from _helpers import proxy_running, ...`,
    we must patch the name in the lifecycle module's namespace.
    """
    import brig.commands._helpers as _helpers
    import brig.commands.lifecycle as _lifecycle

    for name, val in patches.items():
        for mod in (_helpers, _lifecycle):
            if hasattr(mod, name):
                monkeypatch.setattr(mod, name, val)


def _patch_lifecycle_for_run(monkeypatch):
    """Patch functions for cmd_run benchmark."""
    _patch_lifecycle(monkeypatch, {
        "proxy_running": lambda: True,
        "cell_exists": lambda name: False,
        "check_rate_limit": lambda: True,
        "get_proxy_ip": lambda net: "10.60.1.1",
        "run": _mock_run_success,
        "invalidate_cell_cache": lambda name: None,
        "log_operation": lambda *a, **kw: None,
        "log_lifecycle": lambda *a, **kw: None,
        "save_cell_policy": lambda *a, **kw: True,
        "load_cell_policy": lambda *a, **kw: {},
        "allocate_subnet": lambda name: ("10.60.1.0/24", 1),
    })


def _patch_lifecycle_for_stop(monkeypatch):
    """Patch functions for cmd_stop benchmark."""
    _patch_lifecycle(monkeypatch, {
        "cell_exists": lambda name: True,
        "cell_running": lambda name: True,
        "run": _mock_run_success,
        "invalidate_cell_cache": lambda name: None,
        "log_operation": lambda *a, **kw: None,
        "log_lifecycle": lambda *a, **kw: None,
    })


def _patch_lifecycle_for_rm(monkeypatch):
    """Patch functions for cmd_rm benchmark."""
    _patch_lifecycle(monkeypatch, {
        "cell_exists": lambda name: True,
        "cell_running": lambda name: False,
        "run": _mock_run_success,
        "invalidate_cell_cache": lambda name: None,
        "delete_cell_policy": lambda name: None,
        "log_operation": lambda *a, **kw: None,
        "log_lifecycle": lambda *a, **kw: None,
    })


@pytest.mark.bench
def test_bench_cmd_run(benchmark, brig_mod, brig_temp, monkeypatch):
    """Cell creation time — mock the full cmd_run flow."""
    _patch_lifecycle_for_run(monkeypatch)
    counter = [0]

    def run_cell():
        counter[0] += 1
        args = _make_cmd_run_args(name=f"bench-cell-{counter[0]}")
        brig_mod.cmd_run(args)

    benchmark(run_cell)


@pytest.mark.bench
def test_bench_cmd_stop(benchmark, brig_mod, brig_temp, monkeypatch):
    """Cell stop time — mock cmd_stop flow."""
    _patch_lifecycle_for_stop(monkeypatch)

    def stop_cell():
        args = _make_stop_args("bench-cell")
        brig_mod.cmd_stop(args)

    benchmark(stop_cell)


@pytest.mark.bench
def test_bench_cmd_rm(benchmark, brig_mod, brig_temp, monkeypatch):
    """Cell removal time including network cleanup."""
    _patch_lifecycle_for_rm(monkeypatch)

    def rm_cell():
        args = _make_rm_args("bench-cell")
        brig_mod.cmd_rm(args)

    benchmark(rm_cell)


# ---------------------------------------------------------------------------
# Concurrent cell creation benchmarks
# ---------------------------------------------------------------------------

def _run_concurrent_creation(brig_mod, n_cells):
    """Create n_cells concurrently using ThreadPoolExecutor."""
    from concurrent.futures import ThreadPoolExecutor

    def create_cell(i):
        args = _make_cmd_run_args(name=f"concurrent-cell-{i}")
        return brig_mod.cmd_run(args)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(create_cell, range(n_cells)))


@pytest.mark.bench
def test_bench_concurrent_creation_10(benchmark, brig_mod, brig_temp, monkeypatch):
    """10 cells created concurrently — baseline for parallelism."""
    _patch_lifecycle_for_run(monkeypatch)

    def create_10():
        _run_concurrent_creation(brig_mod, 10)

    benchmark(create_10)


@pytest.mark.bench
def test_bench_concurrent_creation_100(benchmark, brig_mod, brig_temp, monkeypatch):
    """100 cells created concurrently — measures scaling and GIL contention."""
    _patch_lifecycle_for_run(monkeypatch)

    def create_100():
        _run_concurrent_creation(brig_mod, 100)

    benchmark(create_100)


# ---------------------------------------------------------------------------
# Subnet allocator concurrent allocation benchmark
# ---------------------------------------------------------------------------

@pytest.mark.bench
def test_bench_subnet_concurrent_allocate(benchmark, subnet_mod, subnet_temp):
    """Concurrent subnet allocation — measures lock contention."""
    from concurrent.futures import ThreadPoolExecutor

    counter = [0]

    def allocate_batch():
        # Reset state for each benchmark iteration.
        subnet_mod.SUBNETS_FILE.unlink(missing_ok=True)
        counter[0] += 1
        base = counter[0] * 1000

        def allocate_one(i):
            f = io.StringIO()
            with contextlib.redirect_stdout(f):
                subnet_mod.cmd_allocate(f"concurrent-{base}-{i}")

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(allocate_one, range(20)))

    benchmark(allocate_batch)
