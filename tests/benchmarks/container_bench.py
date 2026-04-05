"""Benchmark suite that runs inside a container.
Measures syscall, compute, I/O, and sustained load."""

import json
import os
import resource
import sys
import time

def syscall_bench(n=5000):
    """Open+read+close /proc/self/status N times."""
    lats = []
    for _ in range(n):
        s = time.perf_counter()
        with open("/proc/self/status") as f:
            f.read()
        lats.append((time.perf_counter() - s) * 1e6)
    lats.sort()
    return {"p50": lats[len(lats)//2], "p99": lats[int(len(lats)*0.99)], "max": lats[-1], "ops": n}

def compute_bench(n=500000):
    """Pure compute — no syscalls."""
    s = time.perf_counter()
    x = 0
    for i in range(n):
        x += i * i
    elapsed = (time.perf_counter() - s) * 1000
    return {"ms": elapsed, "ops": n}

def file_io_bench(size_kb=1024, count=100):
    """Write+read+delete files."""
    data = b"x" * (size_kb * 1024)
    lats = []
    for i in range(count):
        path = f"/tmp/bench_{i}.dat"
        s = time.perf_counter()
        with open(path, "wb") as f:
            f.write(data)
        with open(path, "rb") as f:
            f.read()
        os.unlink(path)
        lats.append((time.perf_counter() - s) * 1000)
    lats.sort()
    return {"p50": lats[len(lats)//2], "p99": lats[int(len(lats)*0.99)], "ops": count, "size_kb": size_kb}

def soak_bench(duration_s=10):
    """Sustained mixed workload — syscalls + compute + memory."""
    interval = 2
    snapshots = []
    start = time.time()
    batch = 0
    while time.time() - start < duration_s:
        batch += 1
        # Mixed workload per batch.
        sc = syscall_bench(1000)
        comp = compute_bench(50000)
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        elapsed = time.time() - start
        snapshots.append({
            "t": round(elapsed, 1),
            "sc_p50": round(sc["p50"], 1),
            "sc_p99": round(sc["p99"], 1),
            "comp_ms": round(comp["ms"], 1),
            "rss_kb": rss,
        })
    return {"batches": batch, "snapshots": snapshots}

def main():
    results = {}

    print("Running syscall benchmark...", file=sys.stderr)
    results["syscall"] = syscall_bench(5000)

    print("Running compute benchmark...", file=sys.stderr)
    results["compute"] = compute_bench(500000)

    print("Running file I/O benchmark...", file=sys.stderr)
    results["file_io"] = file_io_bench(size_kb=100, count=50)

    print("Running soak test (10s)...", file=sys.stderr)
    results["soak"] = soak_bench(10)

    results["rss_kb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    json.dump(results, sys.stdout, indent=2)

if __name__ == "__main__":
    main()
