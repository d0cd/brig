"""Minimal Prometheus text-format parser.

Reads the body of /metrics (text/plain version 0.0.4) and returns
a structured view the CLI can pivot for display. Handles the three
shapes brig actually emits: counters, gauges, and histograms.

No regex anchored against complex escapes — keep it readable, the
input shape is bounded by what warden's OTel SDK produces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class Sample:
    name: str
    labels: dict[str, str]
    value: float


@dataclass
class Histogram:
    """A single labelled histogram series (one (labels) → buckets+sum+count)."""
    labels: dict[str, str]
    buckets: list[tuple[float, float]] = field(default_factory=list)  # (le, cumulative_count)
    sum: float = 0.0
    count: float = 0.0

    def quantile(self, q: float) -> float:
        """Linear-interpolation quantile estimate over the histogram
        buckets. Returns 0 for empty histograms."""
        if self.count <= 0 or not self.buckets:
            return 0.0
        target = q * self.count
        prev_le, prev_count = 0.0, 0.0
        for le, cum in self.buckets:
            if cum >= target:
                if cum == prev_count:
                    return le
                # Linear interpolation within the bucket.
                frac = (target - prev_count) / (cum - prev_count)
                return prev_le + frac * (le - prev_le)
            prev_le, prev_count = le, cum
        return self.buckets[-1][0]  # fell past +Inf bucket cap


def parse(text: str) -> tuple[dict[str, list[Sample]], dict[str, list[Histogram]]]:
    """Parse a Prometheus exposition body.

    Returns (counters_and_gauges, histograms):
      counters_and_gauges: metric_name → [Sample, ...]
      histograms:           metric_name → [Histogram, ...]
    """
    scalars: dict[str, list[Sample]] = {}
    histos: dict[str, dict[tuple, Histogram]] = {}

    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, labels, value = _parse_line(line)
        if name is None:
            continue
        if name.endswith("_bucket"):
            base = name[: -len("_bucket")]
            le = labels.pop("le", None)
            if le is None:
                continue
            key = tuple(sorted(labels.items()))
            histos.setdefault(base, {})
            h = histos[base].setdefault(key, Histogram(labels=dict(labels)))
            try:
                h.buckets.append((float(le), value))
            except ValueError:
                pass
        elif name.endswith("_sum"):
            base = name[: -len("_sum")]
            key = tuple(sorted(labels.items()))
            histos.setdefault(base, {})
            h = histos[base].setdefault(key, Histogram(labels=dict(labels)))
            h.sum = value
        elif name.endswith("_count"):
            base = name[: -len("_count")]
            key = tuple(sorted(labels.items()))
            histos.setdefault(base, {})
            h = histos[base].setdefault(key, Histogram(labels=dict(labels)))
            h.count = value
        else:
            scalars.setdefault(name, []).append(Sample(name, labels, value))

    histos_out: dict[str, list[Histogram]] = {}
    for base, by_key in histos.items():
        # Sort each histogram's buckets by le.
        for h in by_key.values():
            h.buckets.sort(key=lambda b: b[0])
        histos_out[base] = list(by_key.values())

    return scalars, histos_out


def _parse_line(line: str) -> tuple[str | None, dict[str, str], float]:
    """Split one exposition line into (name, labels, value).

    Returns (None, {}, 0.0) on malformed input.
    """
    try:
        # Find label braces if any.
        brace = line.find("{")
        if brace == -1:
            name, _, rest = line.partition(" ")
            return name, {}, _parse_value(rest)
        name = line[:brace]
        close = line.rfind("}")
        if close == -1 or close < brace:
            return None, {}, 0.0
        label_str = line[brace + 1: close]
        rest = line[close + 1:].lstrip()
        return name, _parse_labels(label_str), _parse_value(rest)
    except (ValueError, IndexError):
        return None, {}, 0.0


def _parse_labels(s: str) -> dict[str, str]:
    """Parse `key="val",key2="val2"`. Values are quoted; commas inside
    quotes are tolerated."""
    out: dict[str, str] = {}
    i, n = 0, len(s)
    while i < n:
        eq = s.find("=", i)
        if eq == -1:
            break
        key = s[i:eq].strip()
        # Value must start with a quote.
        if eq + 1 >= n or s[eq + 1] != '"':
            break
        end = eq + 2
        while end < n:
            if s[end] == "\\" and end + 1 < n:
                end += 2
                continue
            if s[end] == '"':
                break
            end += 1
        val = s[eq + 2: end].replace('\\"', '"').replace("\\\\", "\\")
        out[key] = val
        i = end + 1
        # Skip the trailing comma + optional whitespace.
        while i < n and s[i] in ", \t":
            i += 1
    return out


def _parse_value(rest: str) -> float:
    """First whitespace-separated token of `rest` as a float.
    Trailing timestamp (Prometheus exposition's optional ms) is ignored."""
    tok = rest.strip().split()[0]
    return float(tok)
