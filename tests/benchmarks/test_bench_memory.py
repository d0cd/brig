"""Memory profiling benchmarks.

Uses tracemalloc (stdlib) to measure memory consumption.
These are not time benchmarks — they verify memory bounds.
"""

import tracemalloc

import pytest

# The histogram / metrics-collector tests below target the old
# `metrics.py` addon module that was removed when warden was rewired
# through the OTel collector. The fixtures (`histogram_class`,
# `metrics_collector_class`) were never re-introduced after the
# rewrite. Skip them until equivalent benchmarks for the collector
# pipeline are written.
_METRICS_GONE = pytest.mark.skip(
    reason="metrics.py was replaced by the OTel collector; "
           "equivalent benchmarks pending",
)


def test_memory_policy_1000_rules(policy_class):
    """1000-rule Policy should use less than 1MB."""
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]

    policy = policy_class(
        allow=[f"service-{i}.example.com" for i in range(1000)]
    )

    after = tracemalloc.get_traced_memory()[0]
    tracemalloc.stop()

    delta_bytes = after - before
    delta_kb = delta_bytes / 1024
    # Verify the policy was created.
    assert len(policy.allow_rules) == 1000
    # Must be under 1MB.
    assert delta_bytes < 1_000_000, f"Policy uses {delta_kb:.1f}KB, expected <1000KB"


@_METRICS_GONE
def test_memory_histogram_10k(histogram_class):
    """Histogram after 10k samples should use less than 10KB."""
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]

    histogram = histogram_class()
    for i in range(10000):
        histogram.add(float(i % 5000))

    after = tracemalloc.get_traced_memory()[0]
    tracemalloc.stop()

    delta_bytes = after - before
    # Fixed bucket count means bounded memory regardless of sample count.
    assert delta_bytes < 10_000, f"Histogram uses {delta_bytes}B, expected <10KB"


def test_memory_metrics_100_cells(cell_metrics_class):
    """100 CellMetrics objects — baseline measurement."""
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]

    cells = {}
    for i in range(100):
        cells[f"cell-{i}"] = cell_metrics_class()

    after = tracemalloc.get_traced_memory()[0]
    tracemalloc.stop()

    delta_bytes = after - before
    per_cell = delta_bytes / 100
    # Log the per-cell cost for baseline.
    assert len(cells) == 100
    # Sanity check: each cell should be under 200KB.
    assert per_cell < 200_000, f"Per-cell cost {per_cell:.0f}B is too high"


@_METRICS_GONE
def test_memory_lru_bounded(metrics_collector_class):
    """Fill MetricsCollector to MAX+100, verify eviction bounds count."""
    from metrics import MAX_TRACKED_CELLS

    collector = metrics_collector_class()
    total = MAX_TRACKED_CELLS + 100

    for i in range(total):
        collector._get_or_create_metrics(f"cell-{i}")

    # Must not exceed MAX_TRACKED_CELLS.
    assert len(collector.metrics) <= MAX_TRACKED_CELLS, (
        f"Metrics count {len(collector.metrics)} exceeds max {MAX_TRACKED_CELLS}"
    )


@_METRICS_GONE
def test_memory_steady_state_50k_requests(policy_class, metrics_collector_class,
                                           log_filter_class):
    """Simulate 50k requests in 5 batches, verify memory stabilizes.

    Checks two things:
    1. Total growth stays under 500KB (no large leak).
    2. Per-batch growth converges to near-zero (no slow leak).
    """
    import json

    policy = policy_class(
        allow=[f"svc-{i}.example.com" for i in range(100)],
        deny=["evil.com"],
    )
    collector = metrics_collector_class()
    log_filter = log_filter_class({
        "exclude_hosts": ["*.internal.corp"],
        "exclude_paths": ["/healthz"],
        "sample_rate": 1.0,
    })

    hosts = [f"svc-{i % 100}.example.com" for i in range(50)]

    # Warmup — let initial allocations settle.
    for host in hosts[:10]:
        policy.is_allowed(host, "/api", "GET")
        collector._get_or_create_metrics("warmup-cell")

    tracemalloc.start()
    baseline = tracemalloc.get_traced_memory()[0]
    prev = baseline
    batch_deltas = []

    for batch in range(5):
        for i in range(10000):
            h = hosts[i % len(hosts)]
            policy.is_allowed(h, f"/api/v{i % 5}", "GET")
            m = collector._get_or_create_metrics(f"cell-{i % 20}")
            m.total_requests += 1
            if log_filter.should_log(h, "/api", 200):
                json.dumps({"host": h, "status": 200})

        current = tracemalloc.get_traced_memory()[0]
        batch_deltas.append(current - prev)
        prev = current

    tracemalloc.stop()

    total_growth = prev - baseline

    # Total growth must be under 500KB.
    assert total_growth < 512_000, (
        f"Memory grew by {total_growth / 1024:.1f}KB after 50k requests. "
        f"Possible leak in hot path."
    )

    # Last 3 batches should each grow less than 5KB (convergence).
    for i, delta in enumerate(batch_deltas[2:], start=3):
        assert delta < 5120, (
            f"Batch {i} grew by {delta}B (expected <5KB). "
            f"Slow leak detected in hot path."
        )


def test_memory_policy_trie_vs_rules(policy_class):
    """Verify DomainTrie doesn't use excessive memory vs flat rule list."""
    # Measure just the rules (no trie).
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]
    from enforce import PolicyRule
    rules = [PolicyRule(f"svc-{i}.example.com") for i in range(1000)]  # noqa: F841 — held for tracemalloc
    rules_mem = tracemalloc.get_traced_memory()[0] - before
    tracemalloc.stop()

    # Measure policy (rules + trie).
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]
    policy = policy_class(allow=[f"svc-{i}.example.com" for i in range(1000)])  # noqa: F841 — held for tracemalloc
    policy_mem = tracemalloc.get_traced_memory()[0] - before
    tracemalloc.stop()

    trie_overhead = policy_mem - rules_mem
    # Trie adds node objects for each domain label. At 1000 rules with
    # ~3 labels each, expect ~3000 trie nodes. Each node is ~100 bytes
    # (dict + two lists). Total trie overhead should be under 3x raw rules.
    assert trie_overhead < rules_mem * 3, (
        f"Trie overhead ({trie_overhead}B) exceeds 3x raw rules ({rules_mem}B). "
        f"DomainTrie is using too much memory."
    )
