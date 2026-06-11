"""OpenTelemetry instrumentation for warden.

Exports per-request metrics and structured log records to the OTel
collector running as a sibling container. Loaded as a mitmproxy addon
alongside enforce.py and logger.py. No-op if the OTel SDK isn't
installed in the image (bare mitmproxy fallback path).

Metric cardinality is bounded — labels include cell name, decision,
and method, never host or path. Per-host/per-request detail lives in
the log records (`brig cell network --otel`), not metrics, to keep
series count manageable.
"""

from __future__ import annotations

import os
import time

from mitmproxy import ctx, http

# Same query-string secret redaction the JSONL sink applies, so both audit
# sinks scrub `?api_key=...` consistently. Warden logs request paths by design
# (egress must be observable, invariant 3); redaction strips known secret
# params while keeping the endpoint for audit.
from _log_writer import _redact_path

try:
    from opentelemetry import _logs, metrics
    from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
        OTLPLogExporter,
    )
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
        OTLPMetricExporter,
    )
    from opentelemetry.sdk._logs import LoggerProvider, LogRecord
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


_REQUEST_START_KEY = "otel_request_start"
_PASSTHROUGH_START_KEY = "otel_passthrough_start"
_PASSTHROUGH_BYTES_IN_KEY = "otel_passthrough_bytes_in"
_PASSTHROUGH_BYTES_OUT_KEY = "otel_passthrough_bytes_out"


class OtelExporter:
    """mitmproxy addon: emit request metrics + structured log records to OTLP.

    HTTP flows (default MITM mode) emit the full per-request shape:
    method, host, path, status, bytes, duration. Passthrough flows
    (invariant 11) tunnel raw TCP via `data.ignore_connection`, which
    leaves no flow object — so the tcp_start/tcp_message/tcp_end hooks
    (and the warden_passthrough_* counters they would feed) do not fire
    today; passthrough's only audit trail is the connection-level log
    line in enforce.py. See the NOTE on tcp_end.
    """

    def __init__(self) -> None:
        self.meter = None
        self.logger = None
        self.requests_total = None
        self.request_duration_ms = None
        self.blocked_total = None
        self.bytes_in_total = None
        self.bytes_out_total = None
        self.passthrough_connections_total = None
        self.passthrough_bytes_total = None
        self.passthrough_duration_ms = None

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

        logger_provider = LoggerProvider(resource=resource)
        logger_provider.add_log_record_processor(BatchLogRecordProcessor(
            OTLPLogExporter(endpoint=endpoint, insecure=True),
        ))
        _logs.set_logger_provider(logger_provider)
        self.logger = _logs.get_logger("brig.warden")

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
        self.passthrough_connections_total = self.meter.create_counter(
            "warden_passthrough_connections_total",
            description="TLS passthrough connections (un-MITM'd), by cell + host",
        )
        self.passthrough_bytes_total = self.meter.create_counter(
            "warden_passthrough_bytes_total",
            description="Bytes through passthrough connections, by cell + host + direction",
            unit="By",
        )
        self.passthrough_duration_ms = self.meter.create_histogram(
            "warden_passthrough_duration_ms",
            description="Passthrough connection duration in milliseconds, by cell + host",
            unit="ms",
        )

        ctx.log.info(f"OtelExporter: emitting to {endpoint}")

    def request(self, flow: http.HTTPFlow) -> None:
        flow.metadata[_REQUEST_START_KEY] = time.monotonic()

    def tcp_start(self, flow) -> None:
        """Snapshot start time + byte counters for a passthrough TCP flow.

        NOTE: enforce.py engages passthrough via `data.ignore_connection =
        True`, which makes mitmproxy build an *ignored* TCP layer with no flow
        object — so this hook (and tcp_message / tcp_end) never fires for real
        passthrough today, and the `passthrough_*` metrics stay empty by
        design. Kept for a possible future flow-bearing relay; see
        docs/INVARIANTS.md invariant 11 and tcp_end's note.
        """
        if self.passthrough_connections_total is None:
            return
        client = getattr(flow, "client_conn", None)
        metadata = getattr(client, "metadata", None)
        if not isinstance(metadata, dict) or metadata.get("tls_mode") != "passthrough":
            return
        flow.metadata[_PASSTHROUGH_START_KEY] = time.monotonic()
        flow.metadata[_PASSTHROUGH_BYTES_IN_KEY] = 0
        flow.metadata[_PASSTHROUGH_BYTES_OUT_KEY] = 0

    def tcp_message(self, flow) -> None:
        """Accumulate per-direction bytes for passthrough audits."""
        if _PASSTHROUGH_START_KEY not in flow.metadata:
            return
        try:
            msg = flow.messages[-1]
            # mitmproxy: from_client True = cell→host, False = host→cell.
            key = (_PASSTHROUGH_BYTES_IN_KEY if msg.from_client
                   else _PASSTHROUGH_BYTES_OUT_KEY)
            flow.metadata[key] = (
                flow.metadata.get(key, 0) + len(msg.content or b"")
            )
        except (AttributeError, IndexError):
            pass

    def tcp_end(self, flow) -> None:
        """Emit one audit record per passthrough connection at teardown."""
        start = flow.metadata.get(_PASSTHROUGH_START_KEY)
        if start is None or self.passthrough_connections_total is None:
            return
        duration_ms = (time.monotonic() - start) * 1000.0
        client = getattr(flow, "client_conn", None)
        metadata = getattr(client, "metadata", {}) or {}
        sni = metadata.get("passthrough_sni") or "unknown"
        # NOTE: with passthrough engaged via ignore_connection, mitmproxy
        # builds an ignored TCPLayer (flow=None) and never fires tcp_start/
        # tcp_message/tcp_end — so this hook does not run for real passthrough
        # flows. Kept for any future flow-bearing relay; see INVARIANTS inv 11.
        cell = flow.metadata.get("cell") or "unknown"
        bytes_in = flow.metadata.get(_PASSTHROUGH_BYTES_IN_KEY, 0)
        bytes_out = flow.metadata.get(_PASSTHROUGH_BYTES_OUT_KEY, 0)

        labels = {"cell": cell, "host": sni}
        self.passthrough_connections_total.add(1, attributes=labels)
        self.passthrough_duration_ms.record(duration_ms, attributes=labels)
        if bytes_in:
            self.passthrough_bytes_total.add(
                bytes_in,
                attributes={"cell": cell, "host": sni, "direction": "in"},
            )
        if bytes_out:
            self.passthrough_bytes_total.add(
                bytes_out,
                attributes={"cell": cell, "host": sni, "direction": "out"},
            )

        if self.logger is not None:
            self.logger.emit(LogRecord(
                timestamp=time.time_ns(),
                # Emitted outside any span; pass zero ids (not None) so the OTLP
                # encoder's _encode_span_id/_encode_trace_id get ints, not None.
                trace_id=0, span_id=0, trace_flags=0,
                severity_text="INFO",
                body=f"PASSTHROUGH {sni}",
                attributes={
                    "cell": cell,
                    "decision": "allowed",
                    "tls_mode": "passthrough",
                    "host": sni,
                    "duration_ms": duration_ms,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    # method/path/status absent BY CONSTRUCTION — warden
                    # never saw the cleartext. Operators reading the
                    # log must rely on host (SNI) + bytes for audit.
                },
            ))

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

        # Emit a structured log record per request so brig cell network
        # can read the same shape it gets from JSONL files today.
        # OTel logs records carry both severity + a body, plus
        # arbitrary attributes for downstream filtering. tls_mode=mitm
        # is the default for HTTP flows; passthrough flows emit through
        # tcp_end and have tls_mode=passthrough.
        if self.logger is not None:
            safe_path = _redact_path(flow.request.path)
            self.logger.emit(LogRecord(
                timestamp=time.time_ns(),
                # Span-less record — zero ids so the OTLP encoder gets ints.
                trace_id=0, span_id=0, trace_flags=0,
                severity_text="WARN" if blocked else "INFO",
                body=f"{method} {flow.request.host}{safe_path}",
                attributes={
                    "cell": cell,
                    "src_ip": flow.metadata.get("client_ip", ""),
                    "decision": decision,
                    "tls_mode": "mitm",
                    "method": method,
                    "host": flow.request.host,
                    "path": safe_path,
                    "status": flow.response.status_code if flow.response else 0,
                    "duration_ms": duration_ms,
                    "bytes_in": req_bytes,
                    "bytes_out": resp_bytes,
                    "block_reason": flow.metadata.get("block_reason", "") if blocked else "",
                    "ingress_route": flow.metadata.get("ingress_route", ""),
                },
            ))


addons = [OtelExporter()]
