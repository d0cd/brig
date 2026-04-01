"""Proxy addon benchmarks.

Measures hot-path performance for policy enforcement, subnet lookup,
rate limiting, metrics collection, and log filtering.
"""

import pytest

# -- Policy.is_allowed() scaling --


@pytest.mark.bench
def test_bench_policy_is_allowed_10_rules(benchmark, policy_10_rules):
    """Policy.is_allowed() worst-case match with 10 rules."""
    # Last rule matches — forces full scan.
    policy_10_rules.allow_rules[-1].domain_exact = "target.example.com"
    benchmark(policy_10_rules.is_allowed, "target.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_is_allowed_100_rules(benchmark, policy_100_rules):
    """Policy.is_allowed() worst-case match with 100 rules."""
    policy_100_rules.allow_rules[-1].domain_exact = "target.example.com"
    benchmark(policy_100_rules.is_allowed, "target.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_is_allowed_1000_rules(benchmark, policy_1000_rules):
    """Policy.is_allowed() worst-case match with 1000 rules."""
    policy_1000_rules.allow_rules[-1].domain_exact = "target.example.com"
    benchmark(policy_1000_rules.is_allowed, "target.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_deny_check(benchmark, policy_class):
    """Policy deny matched early (best case)."""
    policy = policy_class(
        allow=[f"allow-{i}.example.com" for i in range(100)],
        deny=["evil.com"],
    )
    benchmark(policy.is_allowed, "evil.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_default_deny(benchmark, policy_class):
    """Policy default deny — no match, full scan of allow and deny."""
    policy = policy_class(
        allow=[f"allow-{i}.example.com" for i in range(100)],
        deny=[f"deny-{i}.example.com" for i in range(10)],
    )
    benchmark(policy.is_allowed, "nomatch.example.com", "/", "GET")


# -- Domain normalization --


@pytest.mark.bench
def test_bench_domain_normalization_ascii(benchmark, policy_rule_class):
    """_normalize_domain() with ASCII domain."""
    benchmark(policy_rule_class._normalize_domain, "api.example.com")


@pytest.mark.bench
def test_bench_domain_normalization_idn(benchmark, policy_rule_class):
    """_normalize_domain() with IDN domain (punycode encoding)."""
    benchmark(policy_rule_class._normalize_domain, "\u00fc\u00f6\u00e4.example.com")


# -- Subnet lookup --


@pytest.mark.bench
def test_bench_subnet_lookup_10(benchmark, policy_enforcer_class, subnet_map_small):
    """_get_cell_name() with 10 subnets."""
    enforcer = policy_enforcer_class()
    enforcer.subnet_map = subnet_map_small
    enforcer._build_subnet_index()
    # Look up last subnet (worst case for linear scan).
    benchmark(enforcer._get_cell_name, "10.60.10.5")


@pytest.mark.bench
def test_bench_subnet_lookup_200(benchmark, policy_enforcer_class, subnet_map_large):
    """_get_cell_name() with 200 subnets — proves O(n) vs O(1)."""
    enforcer = policy_enforcer_class()
    enforcer.subnet_map = subnet_map_large
    enforcer._build_subnet_index()
    # Look up last subnet.
    benchmark(enforcer._get_cell_name, "10.60.200.5")


# -- Token bucket --


@pytest.mark.bench
def test_bench_token_bucket_consume(benchmark, token_bucket_class):
    """TokenBucket.consume() throughput."""
    bucket = token_bucket_class(rate=1000, burst=10000)
    benchmark(bucket.consume)


# -- Histogram --


@pytest.mark.bench
def test_bench_histogram_add(benchmark, histogram_class):
    """HistogramLatencyBuffer.add() — should be O(1)."""
    histogram = histogram_class()
    counter = [0]

    def add_latency():
        counter[0] += 1
        histogram.add(float(counter[0] % 1000))

    benchmark(add_latency)


@pytest.mark.bench
def test_bench_histogram_percentile(benchmark, histogram_class):
    """HistogramLatencyBuffer.percentile() after 10k samples."""
    histogram = histogram_class()
    for i in range(10000):
        histogram.add(float(i % 1000))
    benchmark(histogram.percentile, 95.0)


# -- Log filter --


@pytest.mark.bench
def test_bench_log_filter(benchmark, log_filter_class):
    """LogFilter.should_log() baseline."""
    log_filter = log_filter_class({
        "exclude_hosts": ["*.internal.corp", "health.check.local"],
        "exclude_paths": ["/healthz", "/readyz", "/metrics"],
        "min_status": 0,
        "sample_rate": 1.0,
    })
    benchmark(log_filter.should_log, "api.example.com", "/v1/data", 200)


# -- LRU eviction --


@pytest.mark.bench
def test_bench_lru_eviction(benchmark, metrics_collector_class):
    """_get_or_create_metrics() at capacity — measures eviction cost."""
    collector = metrics_collector_class()
    # Fill to capacity.
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
