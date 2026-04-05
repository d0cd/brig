# Brig Performance Benchmarks

Measured overhead at each layer of the isolation stack. All numbers are steady-state (container already running), averaged across 3 runs with coefficient of variation (CV) reported for repeatability.

## Test Environment

- **Host**: Apple Silicon Mac (aarch64)
- **VM**: Lima 2.0.3, VZ framework, 4 vCPU, 8GB RAM
- **Guest OS**: Ubuntu 24.04
- **Container runtime**: Podman 4.9.3
- **gVisor**: runsc release-20260126.0 (systrap platform)
- **Python**: 3.12.3 (VM), 3.12 (containers)

## Stack Overhead by Layer

```
macOS host
  └── Lima VM (Apple VZ, hardware virtualization)
       └── Container (crun, namespaces, cgroups, seccomp)
            └── gVisor (runsc, userspace syscall interception)
```

### Syscall Performance (open + read + close /proc/self/status)

| Layer | p50 | p99 | CV |
|-------|-----|-----|-----|
| VM native | **5.0us** | 9.0us | 4.4% |
| + Container (crun) | 6.0us (1.2x) | 9.5us (1.1x) | 2.1% |
| + gVisor (runsc) | 18.7us (3.7x) | 32.4us (3.6x) | 1.2% |

### Compute Performance (500k iterations, pure CPU)

| Layer | Time | Overhead | CV |
|-------|------|----------|-----|
| VM native | **12.4ms** | baseline | 2.1% |
| + Container | 12.4ms | 1.0x | 4.1% |
| + gVisor | 12.2ms | **1.0x (none)** | 3.0% |

### Throughput (mixed syscall + compute batches over 10s)

| Layer | Batches/10s | Relative | CV |
|-------|-------------|----------|-----|
| VM native | **1,494** | baseline | 1.0% |
| + Container | 1,343 | 0.9x | 0.4% |
| + gVisor | 471 | 0.3x | 0.4% |

### Per-Request Proxy Overhead (addon chain)

| Component | Cost | % of total |
|-----------|------|-----------|
| Policy evaluation (trie) | 0.9us | 34% |
| Log filter (pre-compiled regex) | 0.5us | 19% |
| JSON log formatting | 0.9us | 33% |
| Metrics recording | 0.2us | 8% |
| Rate limiting | 0.2us | 7% |
| **Total per request** | **2.7us** | |

At 1000 requests/sec: 0.27% of one CPU core.

### Sustained Load (soak tests, 10 seconds)

| Metric | Result |
|--------|--------|
| Throughput | 230,000 req/s (serial), 254,000 req/s (4 threads) |
| Latency drift (p99 early vs late) | 0.96x (no degradation) |
| Memory growth | +0.1KB per 10k-request interval (no leak) |
| GC pressure | Zero gen2 collections |
| Errors under concurrent load | 0 |

### Cell Lifecycle

| Operation | Time |
|-----------|------|
| Cell startup (full brig run) | ~165ms |
| Cell startup (pre-pulled image) | ~111ms |
| Cell stop (graceful) | ~50ms |
| Cell remove (with network cleanup) | ~80ms |
| Proxy overhead per HTTP request | ~0ms (network latency dominates) |

## Key Takeaways

1. **Containers are free.** crun adds 1.2x syscall overhead and zero compute overhead. There is no performance reason to avoid containerization.

2. **gVisor costs 3.7x per syscall, zero for compute.** The overhead is entirely in syscall interception. CPU-bound workloads (ML training, data processing) run at native speed.

3. **The proxy is invisible.** At 2.7us per request, the Warden addon chain uses 0.27% of a CPU core at 1000 req/s. Network latency (~200ms) is 75,000x larger.

4. **No degradation over time.** Latency, memory, and GC pressure are all stable across sustained 10-second soak tests.

5. **Measurements are repeatable.** CV under 5% for syscall and compute metrics across 3 independent runs.

## Reproducing

### Unit benchmarks (no VM needed)

```bash
pytest tests/benchmarks/ -m bench --benchmark-enable -v
```

### Soak tests (no VM needed)

```bash
pytest tests/benchmarks/test_bench_soak.py -v -s
```

### Container runtime comparison (requires VM)

```bash
# Start VM and warden.
limactl start cell
brig vm shell -- warden start

# Run the comparison (copies container_bench.py into VM).
./tests/test_overhead.sh
```

### Full overhead suite (requires VM)

```bash
CELL_VM_NAME=cell ./tests/test_overhead.sh --json
```
