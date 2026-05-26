"""Smoke tests that import the *real* mitmproxy module.

The existing addon tests stub `sys.modules["mitmproxy"] = MagicMock()`
before importing enforce/ingress/etc., which lets the test exercise the
addon's own logic without dragging in mitmproxy's runtime. The cost is
that a mitmproxy API drift (renamed hook, new required arg, removed
type) only surfaces in E2E.

This file does the opposite: it imports mitmproxy as the production code
will see it and instantiates each addon's main class. If mitmproxy
removes or renames the symbols the addons reference, these tests fail
loudly in unit-CI rather than silently in E2E.

Skipped if mitmproxy is unavailable (e.g. older dev envs that haven't
re-synced after the dev-extras bump).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

def _real_mitmproxy_findable() -> bool:
    """Detect whether mitmproxy is installed without disturbing sys.modules.

    We can't use importlib.util.find_spec here when earlier tests have
    stubbed sys.modules["mitmproxy"] with a MagicMock — find_spec uses
    the cached module entry which then lacks `__spec__`. Instead probe
    the real filesystem via importlib.machinery.PathFinder.
    """
    import importlib.machinery
    try:
        return importlib.machinery.PathFinder.find_spec("mitmproxy") is not None
    except (ValueError, ModuleNotFoundError):
        return False


_HAS_MITMPROXY = _real_mitmproxy_findable()
pytestmark = pytest.mark.skipif(
    not _HAS_MITMPROXY,
    reason="mitmproxy not installed; run `uv pip install -e '.[dev]'`",
)


@pytest.fixture
def real_mitmproxy_modules():
    """Swap MagicMock stubs for real mitmproxy modules, restoring on teardown.

    Pytest doesn't isolate sys.modules between tests, so earlier
    test_addons_security et al. install MagicMock stubs at import time
    that this test needs to bypass — without leaving the bypass in place
    afterward, which would break the stub-dependent tests that follow.
    """
    addons = str(Path(__file__).parent.parent / "src" / "addons")
    sys_path_added = addons not in sys.path
    if sys_path_added:
        sys.path.insert(0, addons)

    # Snapshot the entries we're about to mutate so teardown can restore.
    mutated_keys = (
        "mitmproxy", "mitmproxy.ctx", "mitmproxy.http",
        "_common", "_policy", "enforce", "ingress", "logger",
        "ops", "notifier", "otel_export",
    )
    saved = {k: sys.modules.get(k) for k in mutated_keys}

    # Drop the MagicMock stubs and any cached addon imports built on top
    # of them so the addon modules re-import against the real mitmproxy.
    for mod in mutated_keys:
        existing = sys.modules.get(mod)
        if existing is None:
            continue
        if mod.startswith("mitmproxy") and not getattr(existing, "__file__", None):
            del sys.modules[mod]
        elif not mod.startswith("mitmproxy"):
            sys.modules.pop(mod, None)

    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
        if sys_path_added and addons in sys.path:
            sys.path.remove(addons)


def test_real_mitmproxy_has_addon_api_shape(real_mitmproxy_modules):
    """Sanity-check the mitmproxy API surface every addon depends on."""
    import mitmproxy.ctx  # noqa: F401
    import mitmproxy.http
    # Response.make is used by enforce._block; signature must accept
    # (status, body, headers).
    assert callable(getattr(mitmproxy.http.Response, "make", None))


def test_enforce_addon_loads_against_real_mitmproxy(real_mitmproxy_modules):
    """The PolicyEnforcer addon class instantiates and exposes its hooks
    when imported with the real mitmproxy module in sys.modules."""
    import enforce  # type: ignore[import-not-found]
    addon = enforce.PolicyEnforcer()
    for hook in ("load", "configure", "request", "http_connect",
                 "tls_clienthello", "responseheaders", "tcp_start",
                 "websocket_message"):
        assert callable(getattr(addon, hook, None)), f"missing hook: {hook}"


def test_ops_addon_loads_against_real_mitmproxy(real_mitmproxy_modules):
    import ops  # type: ignore[import-not-found]
    addon = ops.OpsAddon()
    for hook in ("load", "done", "configure", "request", "response", "error"):
        assert callable(getattr(addon, hook, None)), f"missing hook: {hook}"


def test_ingress_addon_loads_against_real_mitmproxy(real_mitmproxy_modules):
    import ingress  # type: ignore[import-not-found]
    addons_list = getattr(ingress, "addons", None)
    assert isinstance(addons_list, list) and addons_list, \
        "ingress.addons must be a non-empty list (mitmproxy entry point)"


def test_logger_addon_loads_against_real_mitmproxy(real_mitmproxy_modules):
    import logger  # type: ignore[import-not-found]
    addons_list = getattr(logger, "addons", None)
    assert isinstance(addons_list, list) and addons_list, \
        "logger.addons must be a non-empty list"
