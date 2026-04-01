#!/usr/bin/env python3
"""Benchmark trend analysis.

Collects pytest-benchmark JSON results and reports trends over time.
Stores results in tests/benchmarks/results/ (gitignored).

Usage:
    # Save current run as a data point.
    python tests/benchmarks/bench_trend.py save results.json

    # Show trend report (last N runs).
    python tests/benchmarks/bench_trend.py report [--last 10]

    # Generate a new baseline from the latest run.
    python tests/benchmarks/bench_trend.py baseline results.json

    # Show regressions vs baseline.
    python tests/benchmarks/bench_trend.py check results.json [--threshold 10]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"
BASELINE_FILE = Path(__file__).parent / "baseline.json"


def cmd_save(args):
    """Save benchmark results as a timestamped data point."""
    source = Path(args.file)
    if not source.exists():
        print(f"File not found: {source}", file=sys.stderr)
        return 1

    try:
        data = json.loads(source.read_text())
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in {source}: {e}", file=sys.stderr)
        return 1

    if "benchmarks" not in data:
        print(f"Not a pytest-benchmark file (missing 'benchmarks' key): {source}", file=sys.stderr)
        return 1

    # Add metadata.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    data["_trend_metadata"] = {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "label": args.label or timestamp,
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    dest = RESULTS_DIR / f"bench-{timestamp}.json"
    dest.write_text(json.dumps(data, indent=2))
    print(f"Saved: {dest.name}")
    return 0


def _load_results(last_n=None):
    """Load saved results sorted by timestamp."""
    files = sorted(RESULTS_DIR.glob("bench-*.json"))
    if last_n:
        files = files[-last_n:]

    results = []
    for f in files:
        try:
            data = json.loads(f.read_text())
            results.append((f.name, data))
        except (json.JSONDecodeError, IOError):
            continue
    return results


def _extract_benchmarks(data):
    """Extract benchmark name -> mean time mapping from pytest-benchmark JSON."""
    benchmarks = {}
    for bench in data.get("benchmarks", []):
        name = bench.get("name", bench.get("fullname", "unknown"))
        stats = bench.get("stats", {})
        benchmarks[name] = {
            "mean": stats.get("mean", 0),
            "stddev": stats.get("stddev", 0),
            "rounds": stats.get("rounds", 0),
            "min": stats.get("min", 0),
            "max": stats.get("max", 0),
        }
    return benchmarks


def cmd_report(args):
    """Show trend report across saved runs."""
    results = _load_results(args.last)
    if not results:
        print("No saved results found. Run: bench_trend.py save results.json")
        return 1

    # Collect all benchmark names.
    all_names = set()
    for _, data in results:
        all_names.update(_extract_benchmarks(data).keys())

    # Print header.
    print(f"Benchmark Trends ({len(results)} runs)")
    print("=" * 80)

    for name in sorted(all_names):
        means = []
        for filename, data in results:
            benchmarks = _extract_benchmarks(data)
            if name in benchmarks:
                means.append(benchmarks[name]["mean"])

        if len(means) < 2:
            continue

        latest = means[-1]
        first = means[0]
        change_pct = ((latest - first) / first) * 100 if first > 0 else 0
        direction = "+" if change_pct > 0 else ""

        # Simple sparkline.
        if means:
            min_v, max_v = min(means), max(means)
            span = max_v - min_v if max_v != min_v else 1
            blocks = " _.-~*"
            spark = "".join(blocks[min(5, int((v - min_v) / span * 5))] for v in means)
        else:
            spark = ""

        # Format the mean time.
        if latest < 0.001:
            time_str = f"{latest * 1_000_000:.1f}us"
        elif latest < 1:
            time_str = f"{latest * 1_000:.2f}ms"
        else:
            time_str = f"{latest:.3f}s"

        short_name = name.split("::")[-1] if "::" in name else name
        print(f"  {short_name:<45} {time_str:>10}  {direction}{change_pct:.1f}%  {spark}")

    print()
    return 0


def cmd_baseline(args):
    """Generate a new baseline from a results file."""
    source = Path(args.file)
    if not source.exists():
        print(f"File not found: {source}", file=sys.stderr)
        return 1

    data = json.loads(source.read_text())
    BASELINE_FILE.write_text(json.dumps(data, indent=2))
    benchmarks = _extract_benchmarks(data)
    print(f"Baseline updated: {len(benchmarks)} benchmarks")
    return 0


def cmd_check(args):
    """Check for regressions against baseline."""
    source = Path(args.file)
    if not source.exists():
        print(f"File not found: {source}", file=sys.stderr)
        return 1
    if not BASELINE_FILE.exists():
        print("No baseline found. Generate one: bench_trend.py baseline results.json")
        return 1

    try:
        current = _extract_benchmarks(json.loads(source.read_text()))
        baseline = _extract_benchmarks(json.loads(BASELINE_FILE.read_text()))
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}", file=sys.stderr)
        return 1

    if not baseline:
        print("Warning: baseline has no benchmarks, skipping check")
        return 0

    threshold = args.threshold / 100.0

    regressions = []
    for name, cur in current.items():
        if name in baseline:
            base_mean = baseline[name]["mean"]
            if base_mean > 0 and (cur["mean"] - base_mean) / base_mean > threshold:
                pct = ((cur["mean"] - base_mean) / base_mean) * 100
                regressions.append((name, base_mean, cur["mean"], pct))

    if regressions:
        print(f"REGRESSIONS (>{args.threshold}% slower):")
        for name, base, cur, pct in sorted(regressions, key=lambda x: -x[3]):
            short = name.split("::")[-1] if "::" in name else name
            print(f"  {short}: {base*1000:.2f}ms -> {cur*1000:.2f}ms (+{pct:.1f}%)")
        return 1
    else:
        print(f"No regressions detected (threshold: {args.threshold}%)")
        return 0


def main():
    parser = argparse.ArgumentParser(description="Benchmark trend analysis")
    sub = parser.add_subparsers(dest="command")

    p_save = sub.add_parser("save", help="Save results as data point")
    p_save.add_argument("file", help="pytest-benchmark JSON file")
    p_save.add_argument("--label", help="Label for this run")

    p_report = sub.add_parser("report", help="Show trend report")
    p_report.add_argument("--last", type=int, default=10, help="Number of runs (default: 10)")

    p_baseline = sub.add_parser("baseline", help="Generate baseline from results")
    p_baseline.add_argument("file", help="pytest-benchmark JSON file")

    p_check = sub.add_parser("check", help="Check for regressions")
    p_check.add_argument("file", help="pytest-benchmark JSON file")
    p_check.add_argument("--threshold", type=float, default=10, help="Regression threshold %% (default: 10)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    dispatch = {"save": cmd_save, "report": cmd_report, "baseline": cmd_baseline, "check": cmd_check}
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
