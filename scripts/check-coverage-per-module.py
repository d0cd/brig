#!/usr/bin/env python3
"""B6 from docs/plans/0.3-validation-plan.md: per-package coverage gates.

Global 65% floor isn't enough for security-critical modules — a regression
that drops src/brig/security/ from 95% to 70% would pass the global gate.
This script reads coverage.xml (produced by pytest-cov) and asserts
per-package thresholds.

Usage:
    pytest --cov=src --cov-report=xml ...
    python scripts/check-coverage-per-module.py coverage.xml

Exit codes:
    0  all gates passed
    1  at least one gate failed
    2  invalid input / coverage.xml missing
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Package-glob → minimum coverage percentage. Globs are matched against the
# `filename` attribute of <class> elements in coverage.xml (which is the
# file path relative to the source root).
# Filenames in coverage.xml are relative to the [tool.coverage.run] source,
# which is "src" — so paths drop the leading "src/".
#
# Thresholds are a ratchet: set to current actual minus a small buffer,
# so PRs can't *regress* coverage on the modules that matter most. As we
# add tests (B-phase of the 0.3 plan), bump these toward the audit goal
# (commented in the right column).
#
# Path                            current   →   gate    audit goal
# brig/warden_addons/enforce.py    ~58%         55.0%   90%
# brig/security/                   ~83%         80.0%   90%
# brig/cell/reconciler.py          ~81%         78.0%   85%
#
# Gates run below the current actuals so a small refactor passes without
# an immediate test-write demand. The security gate stays at 80 because
# the slow-marked tests skewed local coverage above what CI sees.
THRESHOLDS: list[tuple[str, float]] = [
    ("brig/warden_addons/enforce.py", 55.0),
    ("brig/security/", 80.0),
    ("brig/cell/reconciler.py", 78.0),
]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} coverage.xml", file=sys.stderr)
        return 2

    xml_path = Path(argv[1])
    if not xml_path.is_file():
        print(f"FAIL: {xml_path} not found", file=sys.stderr)
        return 2

    tree = ET.parse(xml_path)
    root = tree.getroot()

    failures: list[str] = []
    matched_classes: set[str] = set()

    for prefix, threshold in THRESHOLDS:
        lines_covered = 0
        lines_total = 0
        files: list[str] = []
        for cls in root.iter("class"):
            fname = cls.get("filename", "")
            if fname.startswith(prefix) or fname == prefix:
                matched_classes.add(fname)
                files.append(fname)
                # coverage.xml emits `line-rate` per class as a float 0..1
                # but the line-by-line truth is in <lines>; sum those for
                # an aggregate.
                lines = cls.find("lines")
                if lines is None:
                    continue
                for line in lines.findall("line"):
                    lines_total += 1
                    if int(line.get("hits", "0")) > 0:
                        lines_covered += 1

        if not files:
            print(f"WARN: no files matched threshold prefix '{prefix}' "
                  f"— stale config?", file=sys.stderr)
            continue

        pct = (lines_covered / lines_total * 100.0) if lines_total else 100.0
        ok = pct >= threshold
        status = "OK" if ok else "FAIL"
        print(f"  {status:4} {prefix:40} {pct:5.1f}% "
              f"(threshold {threshold:.0f}%, "
              f"{lines_covered}/{lines_total} lines, {len(files)} files)")
        if not ok:
            failures.append(
                f"{prefix}: {pct:.1f}% < {threshold:.0f}%"
            )

    if failures:
        print(file=sys.stderr)
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1

    print()
    print("All per-package coverage gates passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
