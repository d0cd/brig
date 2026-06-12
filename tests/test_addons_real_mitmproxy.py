"""Smoke tests that import the addon classes against the real mitmproxy.

A mitmproxy API drift (renamed hook, new required arg, removed type)
surfaces here as a unit-CI failure rather than silently in E2E. Skipped
if mitmproxy is unavailable.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytest.importorskip("mitmproxy", reason="install dev extras: uv pip install -e '.[dev]'")

import mitmproxy.ctx  # noqa: E402
if not hasattr(mitmproxy.ctx, "log"):
    mitmproxy.ctx.log = MagicMock()

_ADDONS_DIR = str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons")
if _ADDONS_DIR not in sys.path:
    sys.path.insert(0, _ADDONS_DIR)


def test_real_mitmproxy_has_addon_api_shape():
    """Sanity-check the mitmproxy API surface every addon depends on."""
    import mitmproxy.ctx  # noqa: F401
    import mitmproxy.http
    # Response.make is used by enforce._block; signature must accept
    # (status, body, headers).
    assert callable(getattr(mitmproxy.http.Response, "make", None))


def test_enforce_addon_loads_against_real_mitmproxy():
    """The PolicyEnforcer addon class instantiates and exposes its hooks
    when imported with the real mitmproxy module in sys.modules."""
    import enforce  # type: ignore[import-not-found]
    addon = enforce.PolicyEnforcer()
    for hook in ("load", "configure", "request", "http_connect",
                 "tls_clienthello", "responseheaders", "tcp_start",
                 "websocket_message"):
        assert callable(getattr(addon, hook, None)), f"missing hook: {hook}"


def test_ops_addon_loads_against_real_mitmproxy():
    import ops  # type: ignore[import-not-found]
    addon = ops.OpsAddon()
    for hook in ("load", "done", "configure", "request", "response", "error"):
        assert callable(getattr(addon, hook, None)), f"missing hook: {hook}"


def test_ingress_addon_loads_against_real_mitmproxy():
    import ingress  # type: ignore[import-not-found]
    addons_list = getattr(ingress, "addons", None)
    assert isinstance(addons_list, list) and addons_list, \
        "ingress.addons must be a non-empty list (mitmproxy entry point)"


def test_logger_addon_loads_against_real_mitmproxy():
    import logger  # type: ignore[import-not-found]
    addons_list = getattr(logger, "addons", None)
    assert isinstance(addons_list, list) and addons_list, \
        "logger.addons must be a non-empty list"
