"""Memory profiling benchmarks.

Uses tracemalloc (stdlib) to measure memory consumption.
These are not time benchmarks — they verify memory bounds.
"""

import tracemalloc


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


def test_memory_lru_bounded(metrics_collector_class):
    """Fill MetricsCollector to MAX+100, verify eviction bounds count."""
    from metrics import MAX_TRACKED_CELLS, CellMetrics

    collector = metrics_collector_class()
    total = MAX_TRACKED_CELLS + 100

    for i in range(total):
        collector._get_or_create_metrics(f"cell-{i}")

    # Must not exceed MAX_TRACKED_CELLS.
    assert len(collector.metrics) <= MAX_TRACKED_CELLS, (
        f"Metrics count {len(collector.metrics)} exceeds max {MAX_TRACKED_CELLS}"
    )
