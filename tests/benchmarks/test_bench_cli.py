"""CLI benchmarks.

Measures cell definition validation — the only non-trivial CLI-side
computation that runs on every `brig run -f`.
"""

import pytest


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
    """Large cell definition: 1000 env vars, 100 secrets.

    Regression guard — validation iterates all env vars and secrets
    for security checks (injection, traversal). Must stay under 1ms.
    """
    cell_def = {
        "name": "large-cell",
        "image": "python:3.12-slim",
        "env": {f"VAR_{i}": f"value_{i}" for i in range(1000)},
        "secrets": [f"secret-{i}" for i in range(100)],
        "memory": "2g",
        "cpus": "4",
    }
    benchmark(brig_module.validate_cell_definition, cell_def)
