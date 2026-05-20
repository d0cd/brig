"""Shared fixtures for benchmark tests.

Provides pre-configured addon classes and test data generators.
Uses mitmproxy mocking pattern from test_addons_unit.py.
"""

import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Mock mitmproxy before importing addons.
for mod in ("mitmproxy", "mitmproxy.http", "mitmproxy.ctx", "mitmproxy.connection"):
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

# Add src/addons to path.
ADDONS_DIR = Path(__file__).parent.parent.parent / "src" / "addons"
if str(ADDONS_DIR) not in sys.path:
    sys.path.insert(0, str(ADDONS_DIR))

# Add src/ to path.
SRC_DIR = Path(__file__).parent.parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def pytest_benchmark_update_machine_info(config, machine_info):
    """Annotate the pytest-benchmark JSON with the OTel endpoint we
    forwarded to, so the static JSON record carries the same
    correlation operators see in Grafana."""
    import os
    endpoint = os.environ.get("BRIG_BENCH_OTEL_ENDPOINT", "")
    if endpoint:
        machine_info.setdefault("brig", {})["otel_endpoint"] = endpoint


@pytest.fixture(autouse=True)
def _brig_bench_otel_emit(request):
    """After each benchmark test, forward its stats into the OTel
    collector. No-op when pytest-benchmark wasn't used in the test
    or BRIG_BENCH_OTEL_ENDPOINT is unset."""
    yield
    bench = request.node.funcargs.get("benchmark")
    if bench is None:
        return
    try:
        from tests.benchmarks.otel_emit import emit
        emit(bench)
    except Exception:
        # Never fail a benchmark because of telemetry export.
        pass


@pytest.fixture(scope="session")
def policy_class():
    """Policy class from enforce.py."""
    from enforce import Policy
    return Policy


@pytest.fixture(scope="session")
def policy_rule_class():
    """PolicyRule class from enforce.py."""
    from enforce import PolicyRule
    return PolicyRule


@pytest.fixture(scope="session")
def policy_enforcer_class():
    """PolicyEnforcer class from enforce.py."""
    from enforce import PolicyEnforcer
    return PolicyEnforcer


@pytest.fixture(scope="session")
def token_bucket_class():
    """TokenBucket class from ops.py."""
    from ops import TokenBucket
    return TokenBucket


@pytest.fixture(scope="session")
def cell_metrics_class():
    """CellMetrics class from ops.py."""
    from ops import CellMetrics
    return CellMetrics


@pytest.fixture(scope="session")
def ops_addon_class():
    """OpsAddon class from ops.py (replaces MetricsCollector)."""
    from ops import OpsAddon
    return OpsAddon


@pytest.fixture(scope="session")
def log_filter_class():
    """LogFilter class from logger.py."""
    from logger import LogFilter
    return LogFilter


@pytest.fixture(scope="session")
def brig_module():
    """Import brig domain modules."""
    import brig.cell.spec as spec_mod
    return spec_mod


@pytest.fixture
def subnet_map_small():
    """10-entry subnet map for benchmarking."""
    return {f"10.60.{i}.0/24": f"cell-{i}" for i in range(1, 11)}


@pytest.fixture
def subnet_map_large():
    """200-entry subnet map for benchmarking."""
    return {f"10.60.{i}.0/24": f"cell-{i}" for i in range(1, 201)}


@pytest.fixture
def policy_10_rules(policy_class):
    """Policy with 10 allow rules."""
    domains = [f"service-{i}.example.com" for i in range(10)]
    return policy_class(allow=domains)


@pytest.fixture
def policy_100_rules(policy_class):
    """Policy with 100 allow rules."""
    domains = [f"service-{i}.example.com" for i in range(100)]
    return policy_class(allow=domains)


@pytest.fixture
def policy_1000_rules(policy_class):
    """Policy with 1000 allow rules."""
    domains = [f"service-{i}.example.com" for i in range(1000)]
    return policy_class(allow=domains)
