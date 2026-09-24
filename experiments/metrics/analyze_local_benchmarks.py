#!/usr/bin/env python3
"""Compute reproducible summary statistics for TASK-11 local benchmarks.

Input is the raw CSV emitted by run_local_benchmarks.sh. Output is a machine
readable CSV and, optionally, a short Markdown summary. Percentiles use the
nearest-rank method so the result is deterministic without third-party
dependencies.
"""
import csv
import math
import statistics
import sys
from collections import defaultdict


def percentile_nearest_rank(values, percentile):
    ordered_values = sorted(values)
    rank = math.ceil((percentile / 100.0) * len(ordered_values))
    return ordered_values[max(0, min(rank - 1, len(ordered_values) - 1))]


def summarize_group(rows):
    elapsed_values = [float(row["elapsed_ms"]) for row in rows]
    sample_count = len(elapsed_values)
    return {
        "count": sample_count,
        "pass_count": sum(1 for row in rows if row["outcome"] == "pass"),
        "fail_count": sum(1 for row in rows if row["outcome"] != "pass"),
        "mean_ms": statistics.mean(elapsed_values),
        "stdev_ms": statistics.stdev(elapsed_values) if sample_count > 1 else 0.0,
        "median_ms": statistics.median(elapsed_values),
        "min_ms": min(elapsed_values),
        "max_ms": max(elapsed_values),
        "p95_ms": percentile_nearest_rank(elapsed_values, 95),
        "p99_ms": percentile_nearest_rank(elapsed_values, 99),
    }


def format_number(value):
    return f"{value:.3f}" if isinstance(value, float) else str(value)


def read_rows(raw_csv_path):
    with open(raw_csv_path, newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))
    if not rows:
        raise ValueError(f"{raw_csv_path} contains no benchmark rows")
    required_columns = {
        "benchmark",
        "iteration",
        "started_at_utc",
        "elapsed_ms",
        "exit_code",
        "expected_exit_code",
        "outcome",
        "detail",
    }
    missing_columns = required_columns - set(rows[0].keys())
    if missing_columns:
        raise ValueError(f"{raw_csv_path} missing columns: {sorted(missing_columns)}")
    return rows


def write_stats_csv(stats_csv_path, grouped_rows):
    fieldnames = [
        "benchmark",
        "expected_exit_code",
        "count",
        "pass_count",
        "fail_count",
        "mean_ms",
        "stdev_ms",
        "median_ms",
        "min_ms",
        "max_ms",
        "p95_ms",
        "p99_ms",
    ]
    total_failures = 0
    with open(stats_csv_path, "w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for (benchmark_name, expected_exit_code), rows in sorted(grouped_rows.items()):
            summary = summarize_group(rows)
            total_failures += summary["fail_count"]
            output_row = {
                "benchmark": benchmark_name,
                "expected_exit_code": expected_exit_code,
                **summary,
            }
            writer.writerow({key: format_number(output_row[key]) for key in fieldnames})
    return total_failures


def write_markdown(markdown_path, grouped_rows):
    lines = [
        "# TASK-11 Local Benchmark Statistics",
        "",
        "Percentiles use deterministic nearest-rank calculation. These local CLI timings do not infer H100 performance.",
        "",
        "| Benchmark | n | Pass | Fail | Mean ms | Stddev ms | Median ms | p95 ms | p99 ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for (benchmark_name, _expected_exit_code), rows in sorted(grouped_rows.items()):
        summary = summarize_group(rows)
        lines.append(
            "| {benchmark} | {count} | {pass_count} | {fail_count} | {mean_ms:.3f} | "
            "{stdev_ms:.3f} | {median_ms:.3f} | {p95_ms:.3f} | {p99_ms:.3f} |".format(
                benchmark=benchmark_name,
                **summary,
            )
        )
    with open(markdown_path, "w") as markdown_file:
        markdown_file.write("\n".join(lines) + "\n")


def main():
    if len(sys.argv) not in (3, 4):
        print(
            "usage: analyze_local_benchmarks.py <raw-csv> <stats-csv> [summary-md]",
            file=sys.stderr,
        )
        sys.exit(2)

    raw_csv_path = sys.argv[1]
    stats_csv_path = sys.argv[2]
    markdown_path = sys.argv[3] if len(sys.argv) == 4 else None

    try:
        rows = read_rows(raw_csv_path)
    except Exception as error:
        print(f"read benchmark rows: {error}", file=sys.stderr)
        sys.exit(2)

    grouped_rows = defaultdict(list)
    for row in rows:
        grouped_rows[(row["benchmark"], row["expected_exit_code"])].append(row)

    total_failures = write_stats_csv(stats_csv_path, grouped_rows)
    if markdown_path:
        write_markdown(markdown_path, grouped_rows)

    print(f"wrote_stats_csv={stats_csv_path}")
    if markdown_path:
        print(f"wrote_summary_md={markdown_path}")
    print(f"benchmark_groups={len(grouped_rows)} total_failures={total_failures}")
    sys.exit(0 if total_failures == 0 else 1)


if __name__ == "__main__":
    main()
