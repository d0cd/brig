"""Cross-module constant mirror tests.

Some constants must be identical between `brig.config` (host-side) and the
addon module that owns them (`enforce.py`, `ingress.py`). The addons can't
import `brig.*` because they run inside the warden container, so duplication
is unavoidable. This test fails loudly if they drift.

Add a row here whenever a new mirrored constant pair is introduced.
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("mitmproxy", reason="install dev extras: uv pip install -e '.[dev]'")

_ADDONS_DIR = str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons")
if _ADDONS_DIR not in sys.path:
    sys.path.insert(0, _ADDONS_DIR)


def test_host_service_suffix_value_pinned():
    """Pin enforce.py:HOST_SERVICE_SUFFIX to the wire-protocol value '.host.brig'.

    This is a value check, not a cross-module mirror: brig.config has no
    counterpart (host_services are read from per-cell policy, not a global
    registry). If brig.config ever exports the suffix, make this an equality
    assertion between the two.
    """
    from enforce import HOST_SERVICE_SUFFIX
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


def test_warden_reserved_ports_match():
    """_policy.py hardcodes WARDEN_RESERVED_PORTS as a literal {8080, 8443}
    because addons can't import warden.* — guard it against drift by tying it to
    brig.config's PROXY_PORT/INGRESS_PORT (the source warden.proxy derives from).
    """
    from _policy import WARDEN_RESERVED_PORTS as addon_ports
    from brig.config import INGRESS_PORT, PROXY_PORT
    assert addon_ports == frozenset({PROXY_PORT, INGRESS_PORT}), (
        f"WARDEN_RESERVED_PORTS drift: _policy={addon_ports}, "
        f"brig.config={{{PROXY_PORT}, {INGRESS_PORT}}}"
    )


def test_blocked_networks_single_source():
    """BLOCKED_NETWORKS lives only in _common.py now (post-audit).
    enforce.py and notifier.py both import from _common — verify they
    reference the same object."""
    from _common import BLOCKED_NETWORKS as common_blocked
    from enforce import BLOCKED_NETWORKS as enforce_blocked
    from notifier import BLOCKED_NETWORKS as notifier_blocked
    assert enforce_blocked is common_blocked
    assert notifier_blocked is common_blocked
