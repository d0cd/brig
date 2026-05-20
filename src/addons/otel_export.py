"""OpenTelemetry instrumentation for warden.

Exports per-request metrics to the OTel collector running as a
sibling container. Loaded as a mitmproxy addon alongside enforce.py
and logger.py. No-op if the OTel SDK isn't installed in the image
(bare mitmproxy fallback path).

Metric cardinality is bounded — labels include cell name, decision,
and method, never host or path. Per-host attribution lives in
traces, not metrics, to keep series count manageable.
"""

from __future__ import annotations

import os
import time

from mitmproxy import ctx, http

try:
    from opentelemetry import metrics, trace
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
        OTLPMetricExporter,
    )
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


_REQUEST_START_KEY = "otel_request_start"


class OtelExporter:
    """mitmproxy addon: emit request metrics + spans to OTLP."""

    def __init__(self) -> None:
        self.meter = None
        self.tracer = None
        self.requests_total = None
        self.request_duration_ms = None
        self.blocked_total = None
        self.bytes_in_total = None
        self.bytes_out_total = None

    def load(self, loader) -> None:
        if not _OTEL_AVAILABLE:
            ctx.log.warn("OtelExporter: opentelemetry SDK not installed; no metrics will be exported")
            return

        endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
        if not endpoint:
            ctx.log.warn("OtelExporter: OTEL_EXPORTER_OTLP_ENDPOINT unset; no metrics will be exported")
            return

        resource = Resource.create({
            "service.name": os.environ.get("OTEL_SERVICE_NAME", "warden"),
            "service.namespace": "brig",
        })

        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=endpoint, insecure=True),
            export_interval_millis=5000,
        )
        metrics.set_meter_provider(MeterProvider(
            resource=resource, metric_readers=[metric_reader],
        ))
        self.meter = metrics.get_meter("brig.warden")

        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(BatchSpanProcessor(
            OTLPSpanExporter(endpoint=endpoint, insecure=True),
        ))
        trace.set_tracer_provider(tracer_provider)
        self.tracer = trace.get_tracer("brig.warden")

        self.requests_total = self.meter.create_counter(
            "warden_requests_total",
            description="Number of HTTP requests through warden, by cell + decision + method",
        )
        self.request_duration_ms = self.meter.create_histogram(
            "warden_request_duration_ms",
            description="Request duration in milliseconds, by cell",
            unit="ms",
        )
        self.blocked_total = self.meter.create_counter(
            "warden_blocked_total",
            description="Number of HTTP requests blocked by warden, by cell + reason",
        )
        self.bytes_in_total = self.meter.create_counter(
            "warden_bytes_in_total",
            description="Request body bytes received from cells, by cell",
            unit="By",
        )
        self.bytes_out_total = self.meter.create_counter(
            "warden_bytes_out_total",
            description="Response body bytes sent to cells, by cell",
            unit="By",
        )

        ctx.log.info(f"OtelExporter: emitting to {endpoint}")

    def request(self, flow: http.HTTPFlow) -> None:
        flow.metadata[_REQUEST_START_KEY] = time.monotonic()

    def response(self, flow: http.HTTPFlow) -> None:
        if self.requests_total is None:
            return  # OTel not initialized.

        start = flow.metadata.get(_REQUEST_START_KEY)
        duration_ms = (time.monotonic() - start) * 1000.0 if start else 0.0
        cell = flow.metadata.get("cell") or "unknown"
        method = flow.request.method
        blocked = bool(flow.metadata.get("blocked"))
        decision = "blocked" if blocked else "allowed"

        labels = {"cell": cell, "decision": decision, "method": method}
        self.requests_total.add(1, attributes=labels)
        self.request_duration_ms.record(
            duration_ms, attributes={"cell": cell},
        )

        if blocked:
            reason = flow.metadata.get("block_reason") or "unknown"
            self.blocked_total.add(
                1, attributes={"cell": cell, "reason": reason},
            )

        req_bytes = len(flow.request.content) if flow.request.content else 0
        resp_bytes = len(flow.response.content) if flow.response and flow.response.content else 0
        if req_bytes:
            self.bytes_in_total.add(req_bytes, attributes={"cell": cell})
        if resp_bytes:
            self.bytes_out_total.add(resp_bytes, attributes={"cell": cell})


addons = [OtelExporter()]
