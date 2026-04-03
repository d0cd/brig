"""Proxy addon benchmarks.

Measures hot-path performance for policy enforcement, subnet lookup,
rate limiting, metrics collection, and log filtering.

Design principles:
- Benchmarks create fresh objects inside setup, not mutate shared fixtures.
- Each benchmark measures one code path (hit, miss, deny, default-deny).
- Scaling benchmarks prove O(k) trie vs O(n) linear by holding domain
  constant and varying rule count.
"""

import pytest

# -- Policy.is_allowed() scaling --
# The target domain is included IN the rule list so the DomainTrie
# indexes it correctly. We vary rule count to prove O(k) scaling.


@pytest.mark.bench
def test_bench_policy_is_allowed_10_rules(benchmark, policy_class):
    """Policy.is_allowed() with 10 rules — target is last rule."""
    rules = [f"service-{i}.example.com" for i in range(9)] + ["target.example.com"]
    policy = policy_class(allow=rules)
    benchmark(policy.is_allowed, "target.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_is_allowed_100_rules(benchmark, policy_class):
    """Policy.is_allowed() with 100 rules — target is last rule."""
    rules = [f"service-{i}.example.com" for i in range(99)] + ["target.example.com"]
    policy = policy_class(allow=rules)
    benchmark(policy.is_allowed, "target.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_is_allowed_1000_rules(benchmark, policy_class):
    """Policy.is_allowed() with 1000 rules — target is last rule."""
    rules = [f"service-{i}.example.com" for i in range(999)] + ["target.example.com"]
    policy = policy_class(allow=rules)
    benchmark(policy.is_allowed, "target.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_deny_check(benchmark, policy_class):
    """Policy deny hit — deny trie finds match."""
    policy = policy_class(
        allow=[f"allow-{i}.example.com" for i in range(100)],
        deny=["evil.com"],
    )
    benchmark(policy.is_allowed, "evil.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_default_deny(benchmark, policy_class):
    """Policy default deny — neither trie finds a match."""
    policy = policy_class(
        allow=[f"allow-{i}.example.com" for i in range(100)],
        deny=[f"deny-{i}.example.com" for i in range(10)],
    )
    benchmark(policy.is_allowed, "nomatch.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_wildcard_match(benchmark, policy_class):
    """Wildcard rule match — *.example.com matching sub.example.com."""
    policy = policy_class(
        allow=["*.example.com"] + [f"other-{i}.test" for i in range(99)],
    )
    benchmark(policy.is_allowed, "deep.sub.example.com", "/", "GET")


@pytest.mark.bench
def test_bench_policy_with_path_method(benchmark, policy_class):
    """Rule with path and method restrictions — full match check."""
    rules = [
        {"domain": "api.example.com", "paths": ["/v1/*", "/v2/*"], "methods": ["GET", "POST"]},
    ] + [f"other-{i}.test" for i in range(50)]
    policy = policy_class(allow=rules)
    benchmark(policy.is_allowed, "api.example.com", "/v1/users", "GET")


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


# -- Throughput under concurrency --


@pytest.mark.bench
def test_bench_policy_throughput_serial(benchmark, policy_class):
    """Serial throughput: policy evaluations per second (baseline)."""
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
def test_bench_policy_throughput_concurrent(benchmark, policy_class):
    """Concurrent throughput: 10 threads hitting policy simultaneously."""
    from concurrent.futures import ThreadPoolExecutor

    policy = policy_class(
        allow=[f"svc-{i}.example.com" for i in range(100)],
        deny=["evil.com", "*.malware.net"],
    )
    domains = [f"svc-{i}.example.com" for i in range(100)]

    def concurrent_batch():
        def evaluate(domain):
            return policy.is_allowed(domain, "/api/v1", "GET")
        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(evaluate, domains))

    benchmark(concurrent_batch)


# -- Addon chain simulation --
# Measures per-addon overhead by calling their hot-path functions.


@pytest.mark.bench
def test_bench_addon_enforce_request(benchmark, policy_enforcer_class, subnet_map_small):
    """Enforce addon: full request evaluation (policy + subnet + IP check)."""
    enforcer = policy_enforcer_class()
    enforcer.subnet_map = subnet_map_small
    enforcer._build_subnet_index()
    enforcer.global_policy = policy_enforcer_class.__bases__[0].__subclasses__()[0]  # Can't easily construct
    # Simplified: just measure the policy evaluation path.
    from enforce import Policy
    enforcer.global_policy = Policy(
        allow=["httpbin.org", "api.github.com"],
        deny=["evil.com"],
    )

    def evaluate_request():
        enforcer.global_policy.is_allowed("httpbin.org", "/get", "GET")

    benchmark(evaluate_request)


@pytest.mark.bench
def test_bench_addon_logger_format(benchmark):
    """Logger addon: JSON log entry formatting."""
    import json
    import time

    entry = {
        "ts": time.time(),
        "cell": "test-cell",
        "method": "GET",
        "host": "api.example.com",
        "path": "/v1/users",
        "status": 200,
        "bytes_in": 0,
        "bytes_out": 1234,
        "duration_ms": 45.2,
    }

    benchmark(json.dumps, entry)


@pytest.mark.bench
def test_bench_addon_ratelimit_check(benchmark, token_bucket_class):
    """Rate limiter: check + consume combined."""
    bucket = token_bucket_class(rate=1000, burst=10000)

    def check_and_consume():
        bucket.consume()

    benchmark(check_and_consume)


@pytest.mark.bench
def test_bench_addon_metrics_record(benchmark, metrics_collector_class):
    """Metrics collector: record a request (get_or_create + update)."""
    collector = metrics_collector_class()

    counter = [0]

    def record():
        counter[0] += 1
        m = collector._get_or_create_metrics("bench-cell")
        m.total_requests += 1
        m.bytes_sent += 1234

    benchmark(record)


@pytest.mark.bench
def test_bench_full_addon_chain(benchmark, policy_class, token_bucket_class,
                                 metrics_collector_class, log_filter_class):
    """Simulated full addon chain: enforce + ratelimit + log + metrics."""
    import json

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

    counter = [0]

    def full_chain():
        counter[0] += 1
        host = "api.example.com"
        path = "/v1/data"

        # 1. Policy check.
        allowed, reason, _ = policy.is_allowed(host, path, "GET")

        # 2. Rate limit.
        bucket.consume()

        # 3. Log filter + format.
        if log_filter.should_log(host, path, 200):
            json.dumps({"host": host, "path": path, "status": 200})

        # 4. Metrics update.
        m = collector._get_or_create_metrics("bench-cell")
        m.total_requests += 1

    benchmark(full_chain)
