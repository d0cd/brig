"""brig cell trace — read OTel spans from the collector's trace file.

The collector writes JSONL traces to /var/lib/otel/traces.jsonl
inside the VM. Each line is one ResourceSpans batch (the OTLP
default). We grep by trace_id, then pretty-print the span tree
sorted by start time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from brig.errors import BrigError
from brig.ops.logging import output
from brig.vm.shell import vm_run

TRACES_PATH = "/var/lib/otel/traces.jsonl"


@dataclass
class Span:
    trace_id: str
    span_id: str
    parent_span_id: str
    name: str
    start_ns: int
    end_ns: int
    attributes: dict[str, Any] = field(default_factory=dict)
    status_code: int = 0
    cell: str = ""

    @property
    def duration_ms(self) -> float:
        return (self.end_ns - self.start_ns) / 1_000_000


def fetch_trace_file() -> str:
    """Read the collector's trace file via vm_run."""
    result = vm_run(["cat", TRACES_PATH], timeout=10)
    if result.returncode != 0:
        raise BrigError(
            f"could not read {TRACES_PATH}",
            suggestion="Is the collector running and has it seen traffic yet?",
        )
    return result.stdout


def parse_spans(jsonl: str) -> list[Span]:
    """Flatten the nested OTLP ResourceSpans format into plain Spans."""
    spans: list[Span] = []
    for line in jsonl.splitlines():
        if not line.strip():
            continue
        try:
            batch = json.loads(line)
        except json.JSONDecodeError:
            continue
        for rs in batch.get("resourceSpans", []):
            resource_attrs = _attrs_to_dict(
                rs.get("resource", {}).get("attributes", []),
            )
            for ss in rs.get("scopeSpans", []):
                for raw in ss.get("spans", []):
                    sp_attrs = _attrs_to_dict(raw.get("attributes", []))
                    spans.append(Span(
                        trace_id=raw.get("traceId", ""),
                        span_id=raw.get("spanId", ""),
                        parent_span_id=raw.get("parentSpanId", ""),
                        name=raw.get("name", ""),
                        start_ns=int(raw.get("startTimeUnixNano", 0)),
                        end_ns=int(raw.get("endTimeUnixNano", 0)),
                        attributes=sp_attrs,
                        status_code=raw.get("status", {}).get("code", 0),
                        cell=sp_attrs.get("cell") or resource_attrs.get("cell", ""),
                    ))
    return spans


def _attrs_to_dict(attrs: list[dict]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for a in attrs:
        key = a.get("key")
        if not isinstance(key, str):
            continue
        val = a.get("value", {})
        # OTel attribute values are tagged: stringValue, intValue, etc.
        for typ in ("stringValue", "intValue", "doubleValue", "boolValue"):
            if typ in val:
                out[key] = val[typ]
                break
    return out


def render_trace(spans: list[Span]) -> str:
    """Print a tree view of one trace's spans, sorted by start_ns."""
    if not spans:
        return "(no spans for that trace_id)"

    by_id = {s.span_id: s for s in spans}
    children: dict[str, list[Span]] = {}
    roots: list[Span] = []
    for s in spans:
        parent = by_id.get(s.parent_span_id)
        if parent is None:
            roots.append(s)
        else:
            children.setdefault(s.parent_span_id, []).append(s)
    for kids in children.values():
        kids.sort(key=lambda s: s.start_ns)
    roots.sort(key=lambda s: s.start_ns)

    lines: list[str] = []
    lines.append(f"TRACE {spans[0].trace_id}")

    def _walk(s: Span, depth: int) -> None:
        bar = "  " * depth + ("└─ " if depth else "")
        attrs = ""
        if s.cell:
            attrs += f" cell={s.cell}"
        for k in ("http.method", "http.host", "http.target", "http.status_code"):
            if k in s.attributes:
                attrs += f" {k.split('.')[-1]}={s.attributes[k]}"
        status_marker = " [error]" if s.status_code == 2 else ""
        lines.append(
            f"{bar}{s.name}  ({s.duration_ms:.1f}ms){attrs}{status_marker}"
        )
        for kid in children.get(s.span_id, []):
            _walk(kid, depth + 1)

    for r in roots:
        _walk(r, 0)
    return "\n".join(lines)


def cmd_trace(args) -> int:
    """Handle `brig cell trace <trace_id>`."""
    body = fetch_trace_file()
    all_spans = parse_spans(body)
    matching = [s for s in all_spans if s.trace_id == args.trace_id]
    if not matching:
        # Allow prefix match for ergonomics.
        prefix = args.trace_id
        matching = [s for s in all_spans if s.trace_id.startswith(prefix)]
    output(render_trace(matching))
    return 0 if matching else 1
