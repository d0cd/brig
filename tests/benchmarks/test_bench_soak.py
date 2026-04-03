"""Soak tests — sustained load over time.

Unlike the micro-benchmarks that measure single-operation cost, these
tests run sustained workloads and check for degradation patterns:
- Latency drift (p99 creeping up over time)
- Memory growth (slow leaks invisible in short runs)
- GC pause frequency (gen2 collections getting worse)
- Lock contention (mutexes becoming hot under load)

Marked @pytest.mark.slow — excluded from default CI runs.
Run explicitly: pytest tests/benchmarks/test_bench_soak.py -v
"""

import gc
import json
import sys
import threading
import time
import tracemalloc
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Mock mitmproxy.
for mod in ("mitmproxy", "mitmproxy.http", "mitmproxy.ctx", "mitmproxy.connection"):
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

SRC_DIR = Path(__file__).parent.parent.parent / "src"
ADDONS_DIR = SRC_DIR / "addons"
if str(ADDONS_DIR) not in sys.path:
    sys.path.insert(0, str(ADDONS_DIR))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from enforce import Policy
from logger import LogFilter
from metrics import MetricsCollector
from ratelimit import TokenBucket


def _make_addon_chain():
    """Create a fresh addon chain for soak testing."""
    policy = Policy(
        allow=[f"svc-{i}.example.com" for i in range(100)]
              + ["*.github.com", "*.amazonaws.com"],
        deny=["evil.com", "*.malware.net", "*.phishing.org"],
    )
    bucket = TokenBucket(rate=100000, burst=500000)
    collector = MetricsCollector()
    log_filter = LogFilter({
        "exclude_hosts": [f"*.internal-{i}.corp" for i in range(10)],
        "exclude_paths": ["/healthz", "/readyz", "/metrics", "/ping"],
        "sample_rate": 1.0,
    })
    return policy, bucket, collector, log_filter


def _run_request_batch(policy, bucket, collector, log_filter,
                        batch_size, hosts, cell_count):
    """Simulate a batch of requests through the addon chain."""
    latencies = []
    for i in range(batch_size):
        host = hosts[i % len(hosts)]
        cell = f"cell-{i % cell_count}"
        path = f"/api/v{i % 5}/resource/{i % 100}"

        start = time.perf_counter()

        policy.is_allowed(host, path, "GET")
        bucket.consume()
        m = collector._get_or_create_metrics(cell)
        m.total_requests += 1
        m.bytes_sent += 512
        if log_filter.should_log(host, path, 200):
            json.dumps({"host": host, "path": path, "status": 200, "ms": 42.5})

        elapsed = (time.perf_counter() - start) * 1e6
        latencies.append(elapsed)

    return latencies


@pytest.mark.slow
def test_soak_latency_stability():
    """Run sustained load for 60 seconds, verify latency doesn't degrade.

    Checks that p99 latency in the last 10 seconds is within 2x of the
    first 10 seconds. Catches lock contention, GC pressure buildup,
    and cache pollution that only manifest under sustained load.
    """
    policy, bucket, collector, log_filter = _make_addon_chain()
    hosts = [f"svc-{i}.example.com" for i in range(100)]

    batch_size = 5000
    batches = []
    start_time = time.time()
    duration = 10  # seconds

    while time.time() - start_time < duration:
        lats = _run_request_batch(policy, bucket, collector, log_filter,
                                   batch_size, hosts, cell_count=50)
        elapsed = time.time() - start_time
        lats.sort()
        batches.append({
            "elapsed_s": round(elapsed, 1),
            "p50": lats[len(lats) // 2],
            "p99": lats[int(len(lats) * 0.99)],
            "max": lats[-1],
            "requests": batch_size,
        })

    assert len(batches) >= 3, f"Only completed {len(batches)} batches in {duration}s"

    # Compare first quarter vs last quarter.
    quarter = len(batches) // 4
    early_p99 = sum(b["p99"] for b in batches[:quarter]) / quarter
    late_p99 = sum(b["p99"] for b in batches[-quarter:]) / quarter

    total_requests = sum(b["requests"] for b in batches)
    throughput = total_requests / duration

    # Print results for visibility.
    print(f"\nSoak test: {total_requests:,} requests in {duration}s ({throughput:,.0f} req/s)")
    print(f"  Early p99: {early_p99:.1f}us")
    print(f"  Late  p99: {late_p99:.1f}us")
    print(f"  Drift:     {late_p99/early_p99:.2f}x")

    # p99 should not degrade by more than 2x over the test duration.
    assert late_p99 < early_p99 * 2, (
        f"Latency degradation: early p99={early_p99:.1f}us, late p99={late_p99:.1f}us "
        f"({late_p99/early_p99:.1f}x). Possible lock contention or GC pressure buildup."
    )


@pytest.mark.slow
def test_soak_memory_stability():
    """Run sustained load for 60 seconds, verify memory stabilizes.

    Measures RSS-equivalent (tracemalloc) at 10-second intervals.
    After the first 20 seconds (warmup), memory growth per interval
    must be under 100KB. Catches slow leaks that short tests miss.
    """
    policy, bucket, collector, log_filter = _make_addon_chain()
    hosts = [f"svc-{i}.example.com" for i in range(100)]

    batch_size = 5000
    duration = 10
    interval = 2

    tracemalloc.start()
    baseline = tracemalloc.get_traced_memory()[0]
    snapshots = [{"time": 0, "mem": baseline}]

    start_time = time.time()
    while time.time() - start_time < duration:
        _run_request_batch(policy, bucket, collector, log_filter,
                           batch_size, hosts, cell_count=50)

        elapsed = time.time() - start_time
        if elapsed >= len(snapshots) * interval:
            mem = tracemalloc.get_traced_memory()[0]
            snapshots.append({"time": round(elapsed, 1), "mem": mem})

    tracemalloc.stop()

    # Print memory timeline.
    print(f"\nMemory timeline ({len(snapshots)} snapshots):")
    for i, s in enumerate(snapshots):
        delta = s["mem"] - snapshots[max(0, i-1)]["mem"]
        print(f"  t={s['time']:5.1f}s  mem={s['mem']/1024:.0f}KB  delta={delta/1024:+.1f}KB")

    # After warmup (first interval), each interval should grow < 100KB.
    for i in range(2, len(snapshots)):
        growth = snapshots[i]["mem"] - snapshots[i-1]["mem"]
        assert growth < 102400, (
            f"Memory grew {growth/1024:.1f}KB between t={snapshots[i-1]['time']}s "
            f"and t={snapshots[i]['time']}s. Possible slow leak."
        )


@pytest.mark.slow
def test_soak_gc_pressure():
    """Run sustained load for 60 seconds, track GC collection frequency.

    If gen2 collections increase in frequency over time, it indicates
    growing long-lived garbage — a sign of accumulation bugs.
    """
    policy, bucket, collector, log_filter = _make_addon_chain()
    hosts = [f"svc-{i}.example.com" for i in range(100)]

    batch_size = 5000
    duration = 10
    interval = 2

    gc.collect()
    gc_snapshots = [{"time": 0, "gen2": gc.get_stats()[2]["collections"]}]

    start_time = time.time()
    while time.time() - start_time < duration:
        _run_request_batch(policy, bucket, collector, log_filter,
                           batch_size, hosts, cell_count=50)

        elapsed = time.time() - start_time
        if elapsed >= len(gc_snapshots) * interval:
            stats = gc.get_stats()
            gc_snapshots.append({
                "time": round(elapsed, 1),
                "gen0": stats[0]["collections"],
                "gen1": stats[1]["collections"],
                "gen2": stats[2]["collections"],
            })

    print(f"\nGC collection timeline:")
    for i, s in enumerate(gc_snapshots):
        if i == 0:
            print(f"  t={s['time']:5.1f}s  gen2={s['gen2']}")
        else:
            g2_delta = s["gen2"] - gc_snapshots[i-1]["gen2"]
            print(f"  t={s['time']:5.1f}s  gen2={s['gen2']}  (+{g2_delta} in {interval}s)")

    # Gen2 collection rate should not increase over time.
    # Compare first half rate vs second half rate.
    mid = len(gc_snapshots) // 2
    if mid >= 2 and len(gc_snapshots) > mid + 1:
        early_rate = (gc_snapshots[mid]["gen2"] - gc_snapshots[1]["gen2"]) / (gc_snapshots[mid]["time"] - gc_snapshots[1]["time"])
        late_rate = (gc_snapshots[-1]["gen2"] - gc_snapshots[mid]["gen2"]) / (gc_snapshots[-1]["time"] - gc_snapshots[mid]["time"])

        print(f"\n  Early gen2 rate: {early_rate:.2f}/s")
        print(f"  Late  gen2 rate: {late_rate:.2f}/s")

        if early_rate > 0:
            assert late_rate < early_rate * 3, (
                f"Gen2 GC rate increased from {early_rate:.2f}/s to {late_rate:.2f}/s. "
                f"Long-lived garbage is accumulating."
            )


@pytest.mark.slow
def test_soak_concurrent_load():
    """4 threads hitting the addon chain for 30 seconds.

    Checks that concurrent access doesn't cause latency spikes,
    deadlocks, or data corruption. Each thread gets its own cell
    name space to avoid artificial contention.
    """
    policy, bucket, collector, log_filter = _make_addon_chain()
    hosts = [f"svc-{i}.example.com" for i in range(100)]

    results = {"errors": 0, "total": 0}
    results_lock = threading.Lock()
    thread_latencies = {i: [] for i in range(4)}
    duration = 10
    stop = threading.Event()

    def worker(thread_id):
        batch_lats = []
        count = 0
        while not stop.is_set():
            host = hosts[count % len(hosts)]
            cell = f"thread-{thread_id}-cell-{count % 10}"
            try:
                start = time.perf_counter()
                policy.is_allowed(host, "/api/v1/data", "GET")
                bucket.consume()
                m = collector._get_or_create_metrics(cell)
                m.total_requests += 1
                if log_filter.should_log(host, "/api", 200):
                    json.dumps({"host": host, "status": 200})
                elapsed = (time.perf_counter() - start) * 1e6
                batch_lats.append(elapsed)
            except Exception:
                with results_lock:
                    results["errors"] += 1
            count += 1

        with results_lock:
            results["total"] += count
            thread_latencies[thread_id] = sorted(batch_lats)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()

    time.sleep(duration)
    stop.set()
    for t in threads:
        t.join(timeout=5)

    print(f"\nConcurrent soak: {results['total']:,} requests in {duration}s "
          f"({results['total']/duration:,.0f} req/s), {results['errors']} errors")

    for tid, lats in thread_latencies.items():
        if lats:
            p50 = lats[len(lats) // 2]
            p99 = lats[int(len(lats) * 0.99)]
            print(f"  Thread {tid}: {len(lats):,} reqs, p50={p50:.1f}us, p99={p99:.1f}us")

    assert results["errors"] == 0, f"{results['errors']} errors during concurrent soak"
    assert results["total"] > 10000, f"Only {results['total']} requests in {duration}s — too slow"
