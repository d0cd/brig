#!/usr/bin/env python3
"""Format benchmark results as GitHub-flavored markdown.

Reads pytest-benchmark JSON and outputs a markdown summary suitable for
GitHub Actions job summaries ($GITHUB_STEP_SUMMARY) or PR comments.

Usage:
    python format_results.py results.json                    # Summary only
    python format_results.py results.json --baseline base.json  # With comparison
    python format_results.py results.json --format badge     # Shield.io badge JSON
"""

import argparse
import json
import sys
from pathlib import Path


def _extract(data):
    """Extract benchmark name -> stats from pytest-benchmark JSON."""
    out = {}
    for b in data.get("benchmarks", []):
        name = b["name"].split("::")[-1]
        s = b["stats"]
        out[name] = {
            "mean": s["mean"],
            "stddev": s["stddev"],
            "min": s["min"],
            "max": s["max"],
            "rounds": s["rounds"],
        }
    return out


def _fmt_time(seconds):
    """Format seconds as human-readable."""
    if seconds < 1e-6:
        return f"{seconds * 1e9:.0f}ns"
    if seconds < 1e-3:
        return f"{seconds * 1e6:.1f}us"
    if seconds < 1:
        return f"{seconds * 1e3:.2f}ms"
    return f"{seconds:.2f}s"


def _categorize(benchmarks):
    """Group benchmarks by category."""
    categories = {
        "Policy Evaluation": [],
        "Addon Chain": [],
        "Data Structures": [],
        "Cell Lifecycle": [],
        "Throughput": [],
    }
    for name, stats in sorted(benchmarks.items()):
        if "policy" in name and "rebuild" not in name:
            categories["Policy Evaluation"].append((name, stats))
        elif "addon" in name or "full_addon" in name or "log_filter" in name:
            categories["Addon Chain"].append((name, stats))
        elif "throughput" in name or "concurrent" in name:
            categories["Throughput"].append((name, stats))
        elif "cmd_" in name or "build_run" in name or "subnet" in name:
            categories["Cell Lifecycle"].append((name, stats))
        else:
            categories["Data Structures"].append((name, stats))
    return {k: v for k, v in categories.items() if v}


def format_summary(benchmarks, baseline=None):
    """Generate markdown summary."""
    lines = []
    lines.append("## Benchmark Results\n")

    # Key metrics callout.
    chain = benchmarks.get("test_bench_full_addon_chain", {})
    p10 = benchmarks.get("test_bench_policy_allow_10_rules", {})
    p1k = benchmarks.get("test_bench_policy_allow_1000_rules", {})

    if chain:
        lines.append(f"**Per-request cost:** {_fmt_time(chain['mean'])} "
                      f"| **Policy (10 rules):** {_fmt_time(p10['mean']) if p10 else 'N/A'} "
                      f"| **Policy (1000 rules):** {_fmt_time(p1k['mean']) if p1k else 'N/A'}")
        if p10 and p1k:
            ratio = p1k["mean"] / p10["mean"] if p10["mean"] > 0 else 0
            scaling = "O(k) confirmed" if ratio < 1.3 else f"WARNING: {ratio:.1f}x scaling"
            lines.append(f"| **Trie scaling:** {scaling}\n")
        lines.append("")

    # Regression table.
    if baseline:
        regressions = []
        improvements = []
        for name, cur in benchmarks.items():
            if name in baseline:
                base_mean = baseline[name]["mean"]
                if base_mean > 0:
                    change = (cur["mean"] - base_mean) / base_mean * 100
                    if change > 10:
                        regressions.append((name, base_mean, cur["mean"], change))
                    elif change < -10:
                        improvements.append((name, base_mean, cur["mean"], change))

        if regressions:
            lines.append("### Regressions (>10% slower)\n")
            lines.append("| Benchmark | Before | After | Change |")
            lines.append("|-----------|--------|-------|--------|")
            for name, before, after, pct in sorted(regressions, key=lambda x: -x[3]):
                short = name.replace("test_bench_", "")
                lines.append(f"| `{short}` | {_fmt_time(before)} | {_fmt_time(after)} | +{pct:.0f}% |")
            lines.append("")

        if improvements:
            lines.append("### Improvements (>10% faster)\n")
            lines.append("| Benchmark | Before | After | Change |")
            lines.append("|-----------|--------|-------|--------|")
            for name, before, after, pct in sorted(improvements, key=lambda x: x[3]):
                short = name.replace("test_bench_", "")
                lines.append(f"| `{short}` | {_fmt_time(before)} | {_fmt_time(after)} | {pct:.0f}% |")
            lines.append("")

        if not regressions and not improvements:
            lines.append("No regressions or improvements detected (within 10% threshold).\n")

    # Full results by category.
    categories = _categorize(benchmarks)
    lines.append("<details><summary>Full results</summary>\n")
    for cat_name, items in categories.items():
        lines.append(f"### {cat_name}\n")
        lines.append("| Benchmark | Mean | Stddev | Min | Rounds |")
        lines.append("|-----------|------|--------|-----|--------|")
        for name, stats in items:
            short = name.replace("test_bench_", "")
            lines.append(
                f"| `{short}` | {_fmt_time(stats['mean'])} "
                f"| {_fmt_time(stats['stddev'])} "
                f"| {_fmt_time(stats['min'])} "
                f"| {stats['rounds']} |"
            )
        lines.append("")
    lines.append("</details>")

    return "\n".join(lines)


def format_badge(benchmarks):
    """Generate shields.io endpoint JSON."""
    chain = benchmarks.get("test_bench_full_addon_chain", {})
    if chain:
        label = "per-request"
        message = _fmt_time(chain["mean"])
        color = "brightgreen" if chain["mean"] < 5e-6 else "yellow" if chain["mean"] < 20e-6 else "red"
    else:
        label = "benchmarks"
        message = f"{len(benchmarks)} tests"
        color = "blue"

    return json.dumps({
        "schemaVersion": 1,
        "label": label,
        "message": message,
        "color": color,
    }, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Format benchmark results")
    parser.add_argument("file", help="pytest-benchmark JSON results")
    parser.add_argument("--baseline", help="Baseline JSON for comparison")
    parser.add_argument("--format", choices=["markdown", "badge"], default="markdown")
    args = parser.parse_args()

    data = json.loads(Path(args.file).read_text())
    benchmarks = _extract(data)

    baseline = None
    if args.baseline and Path(args.baseline).exists():
        baseline = _extract(json.loads(Path(args.baseline).read_text()))

    if args.format == "badge":
        print(format_badge(benchmarks))
    else:
        print(format_summary(benchmarks, baseline))


if __name__ == "__main__":
    main()
