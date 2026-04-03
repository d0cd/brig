"""CLI and cache benchmarks.

Measures brig cache operations and cell definition validation throughput.
"""

import pytest


@pytest.mark.bench
def test_bench_cache_hit(benchmark, brig_module):
    """_cached() with valid (non-expired) entry."""
    brig_module._set_cache("bench_key", {"data": "value"})

    def cache_hit():
        return brig_module._cached("bench_key")

    benchmark(cache_hit)


@pytest.mark.bench
def test_bench_cache_miss(benchmark, brig_module):
    """_cached() with absent key."""
    def cache_miss():
        return brig_module._cached("nonexistent_key")

    benchmark(cache_miss)


@pytest.mark.bench
def test_bench_cache_set(benchmark, brig_module):
    """_set_cache() throughput — overwrites same key to avoid unbounded growth."""
    benchmark(brig_module._set_cache, "bench_set_key", {"data": "value"})


@pytest.mark.bench
def test_bench_validate_cell_definition(benchmark, brig_module):
    """Typical cell definition validation."""
    cell_def = {
        "name": "test-cell",
        "image": "python:3.12-slim",
        "command": ["python", "-c", "print('hello')"],
        "env": {"FOO": "bar", "BAZ": "qux"},
        "memory": "512m",
        "cpus": "1.0",
        "secrets": ["api-key"],
    }
    benchmark(brig_module.validate_cell_definition, cell_def)


@pytest.mark.bench
def test_bench_validate_cell_definition_large(benchmark, brig_module):
    """Large cell definition: 1000 env vars, 100 secrets."""
    cell_def = {
        "name": "large-cell",
        "image": "python:3.12-slim",
        "env": {f"VAR_{i}": f"value_{i}" for i in range(1000)},
        "secrets": [f"secret-{i}" for i in range(100)],
        "memory": "2g",
        "cpus": "4",
    }
    benchmark(brig_module.validate_cell_definition, cell_def)
