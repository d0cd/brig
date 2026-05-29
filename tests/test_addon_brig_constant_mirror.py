"""Cross-module constant mirror tests.

Some constants must be identical between `brig.config` (host-side) and the
addon module that owns them (`enforce.py`, `ingress.py`). The addons can't
import `brig.*` because they run inside the warden container, so duplication
is unavoidable. This test fails loudly if they drift.

Add a row here whenever a new mirrored constant pair is introduced.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

# Stub mitmproxy so the addon modules can be imported in the test env.
_mock = MagicMock()
sys.modules.setdefault("mitmproxy", _mock)
sys.modules.setdefault("mitmproxy.ctx", _mock.ctx)
sys.modules.setdefault("mitmproxy.http", _mock.http)

_ADDONS_DIR = str(Path(__file__).parent.parent / "src" / "addons")
if _ADDONS_DIR not in sys.path:
    sys.path.insert(0, _ADDONS_DIR)


def test_host_service_suffix_matches():
    """brig.config.HOST_SERVICE_DOMAIN_SUFFIX (if/when reintroduced) and
    enforce.py:HOST_SERVICE_SUFFIX must agree on '.host.brig'."""
    from enforce import HOST_SERVICE_SUFFIX
    # brig.config doesn't currently export this — but the value is fixed
    # at the wire-protocol layer. If config ever re-adds it, assert match.
    assert HOST_SERVICE_SUFFIX == ".host.brig"


def test_ingress_port_matches():
    """ingress.py:INGRESS_PORT and brig.config.INGRESS_PORT must agree."""
    from brig.config import INGRESS_PORT as host_port
    from ingress import INGRESS_PORT as addon_port
    assert host_port == addon_port, (
        f"INGRESS_PORT mismatch: brig.config={host_port}, ingress.py={addon_port}"
    )


def test_max_ingress_per_cell_implied_by_validator():
    """The MAX_INGRESS_PER_CELL cap in brig.config is the spec-side limit;
    the addon doesn't enforce a separate cap but trusts the host-validated
    routes file. Just verify the host-side value is sensible.
    """
    from brig.config import MAX_INGRESS_PER_CELL
    assert 1 <= MAX_INGRESS_PER_CELL <= 64


def test_blocked_networks_single_source():
    """BLOCKED_NETWORKS lives only in _common.py now (post-audit).
    enforce.py and notifier.py both import from _common — verify they
    reference the same object."""
    from _common import BLOCKED_NETWORKS as common_blocked
    from enforce import BLOCKED_NETWORKS as enforce_blocked
    from notifier import BLOCKED_NETWORKS as notifier_blocked
    assert enforce_blocked is common_blocked
    assert notifier_blocked is common_blocked
