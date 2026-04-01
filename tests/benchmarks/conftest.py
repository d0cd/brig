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
    """TokenBucket class from ratelimit.py."""
    from ratelimit import TokenBucket
    return TokenBucket


@pytest.fixture(scope="session")
def histogram_class():
    """HistogramLatencyBuffer class from metrics.py."""
    from metrics import HistogramLatencyBuffer
    return HistogramLatencyBuffer


@pytest.fixture(scope="session")
def cell_metrics_class():
    """CellMetrics class from metrics.py."""
    from metrics import CellMetrics
    return CellMetrics


@pytest.fixture(scope="session")
def metrics_collector_class():
    """MetricsCollector class from metrics.py."""
    from metrics import MetricsCollector
    return MetricsCollector


@pytest.fixture(scope="session")
def log_filter_class():
    """LogFilter class from logger.py."""
    from logger import LogFilter
    return LogFilter


@pytest.fixture(scope="session")
def brig_module():
    """Import brig.py via importlib (requires mocking subprocess)."""
    spec = importlib.util.spec_from_file_location("brig_main", SRC_DIR / "brig.py")
    mod = importlib.util.module_from_spec(spec)
    # Brig imports brig.config which needs the brig package on path.
    spec.loader.exec_module(mod)
    return mod


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
