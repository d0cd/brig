"""Micro-benchmarks for the addon hooks we added in the recent
aitelier-driven work. Pin the per-flow cost so future refactors
catch regressions on warden's hot path.

  - Ingress SSE detection (responseheaders) — fires on every ingress
    response; was added for SA's streaming agent output.
  - tls_clienthello invariant-11 decision — fires on every TLS
    egress (every HTTPS request from a cell goes through this).
  - tcp_start access-control for TCP host_services — fires once per
    raw TCP connection to a host_service listener.
  - Policy.is_passthrough — invariant-11 defense-in-depth check.

If any of these regress to milliseconds, warden's per-request
overhead becomes user-visible (aitelier already flagged warden as
slow for large-blob downloads; we don't want to add to that cost).
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

# Real mitmproxy is imported by the benchmarks conftest (importorskip), so the
# addons import cleanly against it. We deliberately do NOT install a module-level
# mitmproxy mock here — that previously leaked a non-package mock into the shared
# session. MagicMock below is only used to build fake per-flow objects.


@pytest.fixture(scope="module")
def ingress_router():
    sys.path.insert(0, "src/brig/warden_addons")
    try:
        from ingress import IngressRouter
    finally:
        sys.path.pop(0)
    return IngressRouter()


@pytest.fixture(scope="module")
def policy_enforcer():
    sys.path.insert(0, "src/brig/warden_addons")
    try:
        from enforce import PolicyEnforcer
        from _policy import Policy
    finally:
        sys.path.pop(0)
    enf = PolicyEnforcer()
    enf.cell_policies["alice"] = Policy(
        allow=["api.anthropic.com", "*.openai.com"],
        tls_passthrough=["chatgpt.com"],
        host_services=[
            {"name": "db", "port": 5432, "protocol": "tcp"},
        ],
    )
    enf.subnets = type("S", (), {
        "get_cell_name": staticmethod(lambda ip: "alice"),
    })()
    return enf


def _sse_flow():
    flow = MagicMock()
    flow.metadata = {"ingress_route": "api", "cell": "alice"}
    flow.response = MagicMock()
    flow.response.headers = {"Content-Type": "text/event-stream"}
    flow.response.stream = False
    return flow


def _non_sse_flow():
    flow = MagicMock()
    flow.metadata = {"ingress_route": "api", "cell": "alice"}
    flow.response = MagicMock()
    flow.response.headers = {"Content-Type": "application/json"}
    flow.response.stream = False
    return flow


@pytest.mark.bench
@pytest.mark.benchmark(group="recent_hooks", max_time=0.5, min_rounds=5)
def test_bench_ingress_sse_detection_match(benchmark, ingress_router):
    """The hot path: every ingress response gets responseheaders'd.
    SSE-positive case (sets stream=True)."""
    benchmark(ingress_router.responseheaders, _sse_flow())


@pytest.mark.bench
@pytest.mark.benchmark(group="recent_hooks", max_time=0.5, min_rounds=5)
def test_bench_ingress_sse_detection_negative(benchmark, ingress_router):
    """SSE-negative case (most ingress flows). Must not be slower
    than the positive path."""
    benchmark(ingress_router.responseheaders, _non_sse_flow())


def _tls_clienthello_data(sni):
    from types import SimpleNamespace
    client = MagicMock()
    client.peername = ("10.60.1.5", 54321)
    client.metadata = {}
    client.tls_passthrough = False
    server = SimpleNamespace(address=(sni, 443))
    context = SimpleNamespace(client=client, server=server)
    hello = SimpleNamespace(sni=sni)
    return SimpleNamespace(client_hello=hello, context=context)


@pytest.mark.bench
@pytest.mark.benchmark(group="recent_hooks", max_time=0.5, min_rounds=5)
def test_bench_tls_clienthello_passthrough_match(benchmark, policy_enforcer):
    """Cell has chatgpt.com in both allow + tls_passthrough. Hook
    flips client_conn.tls_passthrough. Fires on every TLS egress."""
    benchmark(policy_enforcer.tls_clienthello, _tls_clienthello_data("chatgpt.com"))


@pytest.mark.bench
@pytest.mark.benchmark(group="recent_hooks", max_time=0.5, min_rounds=5)
def test_bench_tls_clienthello_no_passthrough(benchmark, policy_enforcer):
    """SNI not in passthrough list — common path for MITM flows."""
    benchmark(policy_enforcer.tls_clienthello, _tls_clienthello_data("api.anthropic.com"))


def _tcp_flow(port):
    flow = MagicMock()
    flow.client_conn.peername = ("10.60.1.5", 54321)
    flow.client_conn.metadata = {}
    flow.server_conn.address = ("host.lima.internal", port)
    flow.metadata = {}
    return flow


@pytest.mark.bench
@pytest.mark.benchmark(group="recent_hooks", max_time=0.5, min_rounds=5)
def test_bench_tcp_start_allow(benchmark, policy_enforcer):
    """TCP host_service permitted-port path. Per-connection cost for
    every cell that uses TCP host_services."""
    benchmark(policy_enforcer.tcp_start, _tcp_flow(5432))


@pytest.mark.bench
@pytest.mark.benchmark(group="recent_hooks", max_time=0.5, min_rounds=5)
def test_bench_tcp_start_deny(benchmark, policy_enforcer):
    """TCP host_service blocked-port path. Fail-closed must still be
    fast — DoS resilience."""
    # Use a fresh flow each call so kill() side-effects don't poison
    # subsequent iterations.
    def _call():
        policy_enforcer.tcp_start(_tcp_flow(9999))
    benchmark(_call)


@pytest.mark.bench
@pytest.mark.benchmark(group="recent_hooks", max_time=0.5, min_rounds=5)
def test_bench_policy_is_passthrough_match(benchmark):
    """Invariant 11 defense-in-depth check. Runs at every
    tls_clienthello and gates the passthrough flip — must be µs."""
    sys.path.insert(0, "src/brig/warden_addons")
    try:
        from _policy import Policy
    finally:
        sys.path.pop(0)
    p = Policy(
        allow=["chatgpt.com", "*.openai.com", "api.anthropic.com"],
        tls_passthrough=["chatgpt.com", "auth.openai.com"],
    )
    benchmark(p.is_passthrough, "chatgpt.com")


@pytest.mark.bench
@pytest.mark.benchmark(group="recent_hooks", max_time=0.5, min_rounds=5)
def test_bench_policy_is_passthrough_no_match(benchmark):
    """Negative path — host not in passthrough list. Hot for every
    TLS connection that ISN'T passthrough (the majority)."""
    sys.path.insert(0, "src/brig/warden_addons")
    try:
        from _policy import Policy
    finally:
        sys.path.pop(0)
    p = Policy(
        allow=["api.anthropic.com", "*.example.com"],
        tls_passthrough=["chatgpt.com"],
    )
    benchmark(p.is_passthrough, "api.anthropic.com")
