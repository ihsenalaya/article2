#!/usr/bin/env python3
"""Computes summary statistics (n, min, max, mean, stddev) from the raw CSV
files produced by measure_propagation.sh / measure_revocation.sh /
measure_agent_footprint.sh. Takes only raw data as input, prints computed
figures — per the project rule that no number appears in RESULTS.md without
a traceable script that produced it from raw, unedited data.
"""
import csv
import math
import statistics
import sys


def welch_ci(vals1, vals2, label1, label2, confidence=0.95):
    """95% CI on the difference of means (vals1 - vals2) via Welch's t-test
    (unequal variances, unequal n) -- appropriate here since neither
    assumption is guaranteed between with/without-agent samples. Uses
    scipy's exact t-distribution quantile at the Welch-Satterthwaite degrees
    of freedom when scipy is available, falling back to a documented normal
    approximation (z=1.96) otherwise so this script has no hard dependency."""
    n1, n2 = len(vals1), len(vals2)
    if n1 < 2 or n2 < 2:
        return None
    m1, m2 = statistics.mean(vals1), statistics.mean(vals2)
    v1, v2 = statistics.variance(vals1), statistics.variance(vals2)
    se = math.sqrt(v1 / n1 + v2 / n2)
    if se == 0:
        return None
    diff = m1 - m2
    df = (v1 / n1 + v2 / n2) ** 2 / (
        (v1 / n1) ** 2 / (n1 - 1) + (v2 / n2) ** 2 / (n2 - 1)
    )
    try:
        from scipy import stats as scipy_stats
        t_crit = scipy_stats.t.ppf(1 - (1 - confidence) / 2, df)
        exact = True
    except ImportError:
        t_crit = 1.96
        exact = False
    margin = t_crit * se
    return {
        "label1": label1, "label2": label2, "n1": n1, "n2": n2,
        "mean1": m1, "mean2": m2, "diff": diff, "df": df,
        "ci_low": diff - margin, "ci_high": diff + margin,
        "confidence": confidence, "exact_t": exact,
    }


def quartiles(vals):
    """Simple inclusive-median method IQR -- documented here rather than
    silently picking one of several conventions, since Q1/Q3 definitions
    genuinely differ across libraries and this must be reproducible."""
    s = sorted(vals)
    n = len(s)
    med = statistics.median(s)
    lower = s[: n // 2]
    upper = s[(n + 1) // 2 :]
    q1 = statistics.median(lower) if lower else med
    q3 = statistics.median(upper) if upper else med
    return med, q1, q3


def summarize(path, value_col, label):
    vals = []
    with open(path) as f:
        for row in csv.DictReader(f):
            v = row.get(value_col, "")
            if v not in ("", "NA", "NOTFOUND"):
                vals.append(float(v))
    n = len(vals)
    if n == 0:
        print(f"{label}: n=0 (no valid samples)")
        return
    mean = statistics.mean(vals)
    stdev = statistics.stdev(vals) if n > 1 else 0.0
    med, q1, q3 = quartiles(vals)
    print(f"{label}: n={n} min={min(vals):.3f} max={max(vals):.3f} mean={mean:.3f} stdev={stdev:.3f} "
          f"median={med:.3f} IQR=[{q1:.3f},{q3:.3f}]")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: analyze_metrics.py <csv-file> [<csv-file> ...]", file=sys.stderr)
        sys.exit(1)
    benchmark_data = {}  # condition -> metric_name -> [vals]
    for path in sys.argv[1:]:
        if "propagation" in path:
            summarize(path, "propagation_seconds", f"propagation ({path})")
        elif "revocation" in path:
            summarize(path, "revocation_seconds", f"revocation ({path})")
        elif "hook_latency" in path:
            with open(path) as f:
                rows = list(csv.DictReader(f))
            for hook in ("execve", "openat", "connect"):
                by_condition = {}
                for present in ("true", "false"):
                    vals = [
                        float(r["usecs_per_call"])
                        for r in rows
                        if r["syscall"] == hook and r["agent_present"] == present and r["usecs_per_call"] not in ("", "NA")
                    ]
                    by_condition[present] = vals
                    if vals:
                        n = len(vals)
                        mean = statistics.mean(vals)
                        stdev = statistics.stdev(vals) if n > 1 else 0.0
                        label = "with agent" if present == "true" else "without agent (baseline)"
                        print(f"{hook} usecs/call, {label}: n={n} min={min(vals):.1f} max={max(vals):.1f} mean={mean:.1f} stdev={stdev:.1f}")
                if by_condition.get("true") and by_condition.get("false"):
                    delta = statistics.mean(by_condition["true"]) - statistics.mean(by_condition["false"])
                    pct = 100.0 * delta / statistics.mean(by_condition["false"])
                    print(f"{hook} added overhead (mean with-agent - mean baseline): {delta:.1f} usecs/call ({pct:.1f}%)")
        elif "benchmark_" in path:
            with open(path) as f:
                rows = list(csv.DictReader(f))
            condition = rows[0]["condition"] if rows else path
            for metric_col, metric_name in (("tokens_per_second", "tokens/s"), ("latency_seconds", "latency (s)")):
                vals = [float(r[metric_col]) for r in rows if r.get(metric_col, "") not in ("", "NA")]
                if not vals:
                    continue
                n = len(vals)
                mean = statistics.mean(vals)
                stdev = statistics.stdev(vals) if n > 1 else 0.0
                med, q1, q3 = quartiles(vals)
                p95 = sorted(vals)[max(0, int(round(0.95 * (n - 1))))]
                p99 = sorted(vals)[max(0, int(round(0.99 * (n - 1))))]
                print(f"{condition} {metric_name}: n={n} mean={mean:.3f} stdev={stdev:.3f} "
                      f"median={med:.3f} IQR=[{q1:.3f},{q3:.3f}] p95={p95:.3f} p99={p99:.3f}")
                benchmark_data.setdefault(condition, {}).setdefault(metric_name, []).extend(vals)
        elif "footprint" in path:
            with open(path) as f:
                rows = list(csv.DictReader(f))
            for node in sorted(set(r["node"] for r in rows)):
                cpu = [int(r["cpu_usage_nanocores"]) / 1e6 for r in rows if r["node"] == node and r["cpu_usage_nanocores"]]
                mem = [int(r["memory_working_set_bytes"]) / (1024 * 1024) for r in rows if r["node"] == node and r["memory_working_set_bytes"]]
                if cpu:
                    print(f"{node} CPU (millicores): n={len(cpu)} min={min(cpu):.2f} max={max(cpu):.2f} mean={statistics.mean(cpu):.2f}")
                if mem:
                    print(f"{node} memory working set (MiB): n={len(mem)} min={min(mem):.2f} max={max(mem):.2f} mean={statistics.mean(mem):.2f}")
        else:
            print(f"skipping unrecognized file: {path}", file=sys.stderr)

    if "with_agent" in benchmark_data and "without_agent" in benchmark_data:
        print("\n=== 95% CI on (with agent - without agent) difference, Welch's t-test ===")
        for metric_name in ("tokens/s", "latency (s)"):
            v1 = benchmark_data["with_agent"].get(metric_name)
            v2 = benchmark_data["without_agent"].get(metric_name)
            if not v1 or not v2:
                continue
            r = welch_ci(v1, v2, "with_agent", "without_agent")
            if r is None:
                continue
            method = "exact t" if r["exact_t"] else "normal approx z=1.96 (scipy unavailable)"
            significant = not (r["ci_low"] <= 0 <= r["ci_high"])
            print(f"{metric_name}: diff(with-without)={r['diff']:.4f} "
                  f"95% CI=[{r['ci_low']:.4f}, {r['ci_high']:.4f}] (df={r['df']:.1f}, {method}) "
                  f"-> {'SIGNIFICANT (CI excludes 0)' if significant else 'not significant (CI includes 0)'}")
