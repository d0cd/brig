"""brig system stats — read warden metrics from the OTel collector
and render a per-cell summary.

The collector's Prometheus exporter is at
http://127.0.0.1:9464/metrics inside the brig VM. We query through
limactl shell because the host doesn't have a route to the VM-side
port without Lima's explicit forward (and we don't want to depend
on that being configured).
"""

from __future__ import annotations

import collections
from dataclasses import dataclass

from brig.config import COLLECTOR_PROMETHEUS_PORT
from brig.errors import BrigError
from brig.observability.promql import Histogram, Sample, parse
from brig.ops.logging import output
from brig.vm.shell import vm_run

# The collector adds the "brig" namespace prefix; the addon names
# everything with a "warden_" prefix. Final names look like:
#   brig_warden_requests_total
#   brig_warden_blocked_total
#   brig_warden_request_duration_ms_milliseconds  (suffix added by SDK)
COUNTER_REQUESTS = "brig_warden_requests_total"
COUNTER_BLOCKED = "brig_warden_blocked_total"
COUNTER_BYTES_IN = "brig_warden_bytes_in_total"
COUNTER_BYTES_OUT = "brig_warden_bytes_out_total"
HISTOGRAM_DURATION = "brig_warden_request_duration_ms_milliseconds"


@dataclass
class CellStats:
    cell: str
    requests: int = 0
    blocked: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0


def fetch_metrics() -> str:
    """Scrape the collector's Prometheus exporter from inside the VM."""
    result = vm_run(
        ["curl", "-s", "--max-time", "5",
         f"http://127.0.0.1:{COLLECTOR_PROMETHEUS_PORT}/metrics"],
        timeout=10,
    )
    if result.returncode != 0:
        raise BrigError(
            "could not reach OTel collector at "
            f"127.0.0.1:{COLLECTOR_PROMETHEUS_PORT}",
            suggestion="Is the collector running? brig system doctor",
        )
    return result.stdout


def aggregate(scalars: dict[str, list[Sample]],
              histos: dict[str, list[Histogram]]) -> dict[str, CellStats]:
    """Pivot raw exposition into per-cell summary records."""
    cells: dict[str, CellStats] = collections.defaultdict(
        lambda: CellStats(cell="")
    )

    def _bump(name: str, attr: str) -> None:
        for s in scalars.get(name, []):
            cell = s.labels.get("cell", "unknown")
            cs = cells.setdefault(cell, CellStats(cell=cell))
            cs.cell = cell
            setattr(cs, attr, int(getattr(cs, attr) + s.value))

    _bump(COUNTER_REQUESTS, "requests")
    _bump(COUNTER_BLOCKED, "blocked")
    _bump(COUNTER_BYTES_IN, "bytes_in")
    _bump(COUNTER_BYTES_OUT, "bytes_out")

    for h in histos.get(HISTOGRAM_DURATION, []):
        cell = h.labels.get("cell", "unknown")
        cs = cells.setdefault(cell, CellStats(cell=cell))
        cs.cell = cell
        cs.p50_ms = round(h.quantile(0.50), 2)
        cs.p95_ms = round(h.quantile(0.95), 2)
        cs.p99_ms = round(h.quantile(0.99), 2)

    return dict(cells)


def render_text(by_cell: dict[str, CellStats]) -> str:
    """Render a compact table summary."""
    lines: list[str] = []
    lines.append("CELLS")
    if not by_cell:
        lines.append("  (no metrics yet — drive some traffic, then re-run)")
        return "\n".join(lines)

    header = f"  {'CELL':<20} {'REQ':>6} {'BLOCKED':>8} {'IN':>10} {'OUT':>10} {'p50ms':>8} {'p95ms':>8} {'p99ms':>8}"
    lines.append(header)
    for cell in sorted(by_cell):
        c = by_cell[cell]
        blocked_pct = (c.blocked / c.requests * 100) if c.requests else 0.0
        blocked_cell = f"{c.blocked} ({blocked_pct:.1f}%)" if c.blocked else "0"
        lines.append(
            f"  {c.cell:<20} {c.requests:>6} {blocked_cell:>8} "
            f"{_human_bytes(c.bytes_in):>10} {_human_bytes(c.bytes_out):>10} "
            f"{c.p50_ms:>8.1f} {c.p95_ms:>8.1f} {c.p99_ms:>8.1f}"
        )
    return "\n".join(lines)


def _human_bytes(n: int) -> str:
    for suffix in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n}{suffix}"
        n //= 1024
    return f"{n}T"


def cmd_stats(args) -> int:
    """Handle `brig system stats`."""
    body = fetch_metrics()
    scalars, histos = parse(body)
    by_cell = aggregate(scalars, histos)
    output(render_text(by_cell))
    return 0
