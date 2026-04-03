"""Proxy hot-path benchmarks.

Measures the per-request cost of the addon chain that runs inside
mitmproxy for every cell HTTP request. Organized by subsystem.

Design principles:
- Each benchmark measures ONE non-trivial operation.
- Scaling benchmarks vary input size to prove algorithmic complexity.
- No benchmarks for trivial stdlib operations (dict lookup, string concat).
- Fresh objects per benchmark — no mutation of shared fixtures.
"""

import json
import pytest


# =========================================================================
# Policy evaluation — the critical path for every request
# =========================================================================

@pytest.mark.bench
def test_bench_policy_allow_10_rules(benchmark, policy_class):
    """Policy allow hit with 10 rules. Proves trie O(k) baseline."""
    rules = [f"svc-{i}.example.com" for i in range(9)] + ["target.example.com"]
    policy = policy_class(allow=rules)
    benchmark(policy.is_allowed, "target.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_allow_1000_rules(benchmark, policy_class):
    """Policy allow hit with 1000 rules. Must match 10-rule time (trie is O(k))."""
    rules = [f"svc-{i}.example.com" for i in range(999)] + ["target.example.com"]
    policy = policy_class(allow=rules)
    benchmark(policy.is_allowed, "target.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_deny_hit(benchmark, policy_class):
    """Deny rule match — deny trie is checked before allow trie."""
    policy = policy_class(
        allow=[f"allow-{i}.example.com" for i in range(100)],
        deny=["evil.com"],
    )
    benchmark(policy.is_allowed, "evil.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_default_deny(benchmark, policy_class):
    """No match in either trie — falls through to default deny."""
    policy = policy_class(
        allow=[f"allow-{i}.example.com" for i in range(100)],
        deny=[f"deny-{i}.example.com" for i in range(10)],
    )
    benchmark(policy.is_allowed, "nomatch.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_wildcard(benchmark, policy_class):
    """Wildcard match — trie walks to *.example.com node."""
    policy = policy_class(allow=["*.example.com"])
    benchmark(policy.is_allowed, "deep.sub.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_path_method(benchmark, policy_class):
    """Rule with path glob + method restriction — full match pipeline."""
    rules = [
        {"domain": "api.example.com", "paths": ["/v1/*", "/v2/*"], "methods": ["GET", "POST"]},
    ]
    policy = policy_class(allow=rules)
    benchmark(policy.is_allowed, "api.example.com", "/v1/users", "GET")


# =========================================================================
# IDN normalization — only non-trivial for punycode domains
# =========================================================================

@pytest.mark.bench
def test_bench_domain_normalization_idn(benchmark, policy_rule_class):
    """IDN domain → punycode encoding. Regression guard for the slow path."""
    benchmark(policy_rule_class._normalize_domain, "\u00fc\u00f6\u00e4.example.com")


# =========================================================================
# Subnet lookup — cell attribution from source IP
# =========================================================================

@pytest.mark.bench
def test_bench_subnet_lookup_200(benchmark, policy_enforcer_class, subnet_map_large):
    """Cell attribution from IP with 200 subnets — proves O(1) dict lookup."""
    enforcer = policy_enforcer_class()
    enforcer.subnet_map = subnet_map_large
    enforcer._build_subnet_index()
    benchmark(enforcer._get_cell_name, "10.60.200.5")


# =========================================================================
# Rate limiting — token bucket per request
# =========================================================================

@pytest.mark.bench
def test_bench_token_bucket_consume(benchmark, token_bucket_class):
    """TokenBucket.consume() — called once per request."""
    bucket = token_bucket_class(rate=1000, burst=10000)
    benchmark(bucket.consume)


# =========================================================================
# Metrics recording — per-request accounting
# =========================================================================

@pytest.mark.bench
def test_bench_histogram_add(benchmark, histogram_class):
    """HistogramLatencyBuffer.add() — O(1) latency recording."""
    histogram = histogram_class()
    counter = [0]

    def add_latency():
        counter[0] += 1
        histogram.add(float(counter[0] % 1000))

    benchmark(add_latency)


@pytest.mark.bench
def test_bench_metrics_record(benchmark, metrics_collector_class):
    """Record a request: get_or_create cell metrics + update counters."""
    collector = metrics_collector_class()

    def record():
        m = collector._get_or_create_metrics("bench-cell")
        m.total_requests += 1
        m.bytes_sent += 1234

    benchmark(record)


@pytest.mark.bench
def test_bench_lru_eviction(benchmark, metrics_collector_class):
    """Eviction cost at capacity — worst case for _get_or_create_metrics."""
    collector = metrics_collector_class()
    for i in range(1000):
        with collector.metrics_lock:
            from metrics import CellMetrics
            collector.metrics[f"cell-{i}"] = CellMetrics()
            collector.metrics[f"cell-{i}"].last_request_ts = float(i)

    counter = [0]

    def create_new_cell():
        counter[0] += 1
        collector._get_or_create_metrics(f"new-cell-{counter[0]}")

    benchmark(create_new_cell)


# =========================================================================
# Log filtering — decides whether to write a log entry
# =========================================================================

@pytest.mark.bench
def test_bench_log_filter(benchmark, log_filter_class):
    """LogFilter.should_log() with exclusion rules."""
    log_filter = log_filter_class({
        "exclude_hosts": ["*.internal.corp", "health.check.local"],
        "exclude_paths": ["/healthz", "/readyz", "/metrics"],
        "min_status": 0,
        "sample_rate": 1.0,
    })
    benchmark(log_filter.should_log, "api.example.com", "/v1/data", 200)


# =========================================================================
# Throughput — measures GIL contention under concurrent load
# =========================================================================

@pytest.mark.bench
def test_bench_throughput_serial(benchmark, policy_class):
    """100 policy evals serial — baseline ops/sec."""
    policy = policy_class(
        allow=[f"svc-{i}.example.com" for i in range(100)],
        deny=["evil.com", "*.malware.net"],
    )
    domains = [f"svc-{i}.example.com" for i in range(100)]

    def serial_batch():
        for d in domains:
            policy.is_allowed(d, "/api/v1", "GET")

    benchmark(serial_batch)


@pytest.mark.bench
def test_bench_throughput_concurrent(benchmark, policy_class):
    """100 policy evals across 10 threads — measures GIL impact."""
    from concurrent.futures import ThreadPoolExecutor

    policy = policy_class(
        allow=[f"svc-{i}.example.com" for i in range(100)],
        deny=["evil.com", "*.malware.net"],
    )
    domains = [f"svc-{i}.example.com" for i in range(100)]

    def concurrent_batch():
        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(lambda d: policy.is_allowed(d, "/api/v1", "GET"), domains))

    benchmark(concurrent_batch)


# =========================================================================
# Full addon chain — end-to-end per-request cost
# =========================================================================

@pytest.mark.bench
def test_bench_full_addon_chain(benchmark, policy_class, token_bucket_class,
                                 metrics_collector_class, log_filter_class):
    """Simulated full addon chain: enforce + ratelimit + log + metrics.

    This is the most important benchmark — it measures the total CPU cost
    added to every HTTP request that flows through the proxy.
    """
    policy = policy_class(
        allow=["api.example.com", "*.github.com"],
        deny=["evil.com"],
    )
    bucket = token_bucket_class(rate=10000, burst=50000)
    collector = metrics_collector_class()
    log_filter = log_filter_class({
        "exclude_hosts": [],
        "exclude_paths": ["/healthz"],
        "sample_rate": 1.0,
    })

    def full_chain():
        host = "api.example.com"
        path = "/v1/data"

        # 1. Policy check (trie lookup + path/method).
        policy.is_allowed(host, path, "GET")

        # 2. Rate limit (token bucket).
        bucket.consume()

        # 3. Log filter + JSON format.
        if log_filter.should_log(host, path, 200):
            json.dumps({"host": host, "path": path, "status": 200})

        # 4. Metrics update.
        m = collector._get_or_create_metrics("bench-cell")
        m.total_requests += 1

    benchmark(full_chain)


# =========================================================================
# Log filter scaling — the most expensive addon (47% of chain)
# =========================================================================

@pytest.mark.bench
def test_bench_log_filter_50_patterns(benchmark, log_filter_class):
    """LogFilter with 50 exclusion patterns — worst-case scaling.

    fnmatch is O(n) per pattern. This catches regressions in the
    most expensive addon under realistic enterprise configs.
    """
    log_filter = log_filter_class({
        "exclude_hosts": [f"*.internal-{i}.corp" for i in range(25)],
        "exclude_paths": [f"/internal/{i}/*" for i in range(25)],
        "sample_rate": 1.0,
    })
    # Non-matching host/path forces full scan of all patterns.
    benchmark(log_filter.should_log, "api.external.com", "/v1/data", 200)


# =========================================================================
# Policy rebuild — cost of SIGHUP reload
# =========================================================================

@pytest.mark.bench
def test_bench_policy_rebuild_1000(benchmark, policy_class):
    """Rebuild Policy with 1000 rules — SIGHUP reload cost.

    During reload, in-flight requests use the old policy. This
    measures how long the rebuild blocks the reload handler.
    """
    rules = [f"svc-{i}.example.com" for i in range(1000)]
    deny = [f"deny-{i}.evil.com" for i in range(100)]

    benchmark(policy_class, allow=rules, deny=deny)
