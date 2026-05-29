"""Push benchmark results into the same OTel pipeline warden uses.

After each benchmark, pytest-benchmark records mean/stddev/min/max.
This module forwards those into the OTel collector as histograms +
gauges, using metric names parallel to warden's runtime emissions
(brig_bench_*). Operators can then compare bench results vs prod
data on the same Grafana board.

Activation: set BRIG_BENCH_OTEL_ENDPOINT to an OTLP gRPC endpoint
(e.g. http://127.0.0.1:4317 from inside the brig VM). When unset,
this module is a no-op.
"""

from __future__ import annotations

import os
from typing import Any

_emitter: Any = None


def _get_emitter():
    """Lazily build the OTel meter + instruments. Returns None when
    the SDK isn't installed or the endpoint isn't configured."""
    global _emitter
    if _emitter is not None:
        return _emitter

    endpoint = os.environ.get("BRIG_BENCH_OTEL_ENDPOINT", "").strip()
    if not endpoint:
        return None

    try:
        from opentelemetry import metrics
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
            OTLPMetricExporter,
        )
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import (
            PeriodicExportingMetricReader,
        )
        from opentelemetry.sdk.resources import Resource
    except ImportError:
        return None

    resource = Resource.create({
        "service.name": "brig-bench",
        "service.namespace": "brig",
        "brig.version": os.environ.get("BRIG_VERSION", "dev"),
    })
    reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=endpoint, insecure=True),
        export_interval_millis=1000,
    )
    metrics.set_meter_provider(MeterProvider(
        resource=resource, metric_readers=[reader],
    ))
    meter = metrics.get_meter("brig.bench")

    _emitter = {
        "duration_ms": meter.create_histogram(
            "brig_bench_duration_ms",
            description="Per-benchmark wall-clock duration in milliseconds",
            unit="ms",
        ),
        "iterations": meter.create_counter(
            "brig_bench_iterations_total",
            description="Total benchmark iterations executed",
        ),
        "outliers": meter.create_counter(
            "brig_bench_outliers_total",
            description="pytest-benchmark outlier count",
        ),
    }
    return _emitter


def emit(benchmark) -> None:
    """Forward one pytest-benchmark result into the OTel collector.

    benchmark is the pytest-benchmark fixture instance after .stats
    has been populated. No-op if the emitter isn't configured.
    """
    em = _get_emitter()
    if em is None:
        return
    name = getattr(benchmark, "name", None) or "unknown"
    group = getattr(benchmark, "group", None) or ""
    stats = getattr(benchmark, "stats", None)
    if stats is None:
        return
    # pytest-benchmark stores Stats objects with mean, stddev, min, max,
    # rounds, iterations, outliers as attributes.
    labels = {"bench": name, "group": group}
    # Convert each sample (rounds) into a histogram observation.
    # stats.data is the list of per-round seconds.
    data = getattr(stats, "data", None)
    if data:
        for seconds in data:
            em["duration_ms"].record(float(seconds) * 1000.0, attributes=labels)
    em["iterations"].add(
        int(getattr(stats, "rounds", 0) or 0), attributes=labels,
    )
    outliers = getattr(stats, "outliers", "")
    if isinstance(outliers, str) and ";" in outliers:
        # pytest-benchmark formats outliers like "1;3" → low;high.
        low, _, high = outliers.partition(";")
        total = 0
        try:
            total = int(low) + int(high)
        except ValueError:
            total = 0
        if total:
            em["outliers"].add(total, attributes=labels)
