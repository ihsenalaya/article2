#!/usr/bin/env python3
"""Generates paired_results.csv and summary.csv from raw_results.jsonl for the
BPF-LSM enforcement-path microbenchmark (reviewer concern: isolate the
incremental cost of the BPF-LSM enforcement path, separately from the
existing observation/audit-path numbers in
artifacts/experiments/performance/).

No hard-coded result values: every number here is derived from
raw_results.jsonl, produced by scripts/run_benchmark.py.

Statistics -- same methodology as the existing F1-F3 experiment
(artifacts/experiments/performance/scripts/analyze.py), reused rather than a
new statistical framework, per the protocol's own instruction:
- Paired design: each block pairs C0/C1/C2/C3 measurements of the SAME
  operation, close together in time.
- Primary interval: nonparametric bootstrap 95% CI on the mean paired
  difference (10000 resamples, fixed seed for reproducibility).
- Effect size: Hedges' g for paired/repeated-measures designs (d_z =
  mean_diff/sd_diff, small-sample-corrected by J), not independent-sample
  Cohen's d.
- No p-value is computed, for the same reason F1's analyze.py states one:
  interpreting p > 0.05 as "no overhead" is a real misreading risk this
  design deliberately avoids by reporting a bootstrap CI instead.

Primary deltas (experiment protocol PRIMARY DERIVED METRICS):
  Δ_hook        = C1 - C0   (cost of entering + dispatching the bare hook)
  Δ_map         = C2 - C1   (incremental cost of the policy-map lookup)
  Δ_enforcement = C3 - C0   (full authorization-derived enforcement path)
  Δ_full_vs_map = C3 - C2   (optional: remaining RuntimeGuard-specific cost
                              beyond hook+lookup -- e.g. evidence emission)
"""
import csv
import json
import os
import random
import statistics

BASE = os.path.dirname(os.path.abspath(__file__))
RAW_PATH = os.path.join(BASE, "raw_results.jsonl")
PAIRED_PATH = os.path.join(BASE, "paired_results.csv")
SUMMARY_PATH = os.path.join(BASE, "summary.csv")

random.seed(20260817)

METRIC = "usec_per_op_cpu_total"


def load_rows():
    if not os.path.exists(RAW_PATH):
        return []
    with open(RAW_PATH) as f:
        return [json.loads(line) for line in f if line.strip()]


def bootstrap_ci_mean(values, n_resamples=10000, alpha=0.05):
    if not values:
        return None, None
    n = len(values)
    means = []
    for _ in range(n_resamples):
        sample = [values[random.randrange(n)] for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    lo_idx = int((alpha / 2) * n_resamples)
    hi_idx = int((1 - alpha / 2) * n_resamples) - 1
    return means[lo_idx], means[hi_idx]


def hedges_g_paired(diffs):
    n = len(diffs)
    if n < 2:
        return None
    mean_diff = statistics.mean(diffs)
    sd_diff = statistics.stdev(diffs)
    if sd_diff == 0:
        return None
    d_z = mean_diff / sd_diff
    j = 1 - 3 / (4 * (n - 1) - 1)
    return d_z * j


def write_csv(path, rows, fields):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def main():
    rows = load_rows()

    # Group by (operation_class, block_id) -> {condition: row}
    blocks = {}
    for r in rows:
        key = (r["operation_class"], r["block_id"])
        blocks.setdefault(key, {})[r["condition"]] = r

    paired_rows = []
    for (op, block_id), by_cond in sorted(blocks.items()):
        conds_present = set(by_cond.keys())
        if conds_present != {"C0", "C1", "C2", "C3"}:
            continue  # incomplete block (e.g. still running), skip until complete
        any_excluded = any(by_cond[c]["excluded"] for c in ("C0", "C1", "C2", "C3"))
        row = {
            "operation": op,
            "block_id": block_id,
            "excluded": any_excluded,
            "exclusion_reason": "; ".join(
                by_cond[c]["exclusion_reason"] for c in ("C0", "C1", "C2", "C3") if by_cond[c]["exclusion_reason"]
            ),
        }
        for c in ("C0", "C1", "C2", "C3"):
            row[f"{c.lower()}_usec_per_op"] = by_cond[c][METRIC]
        if not any_excluded:
            c0, c1, c2, c3 = (by_cond[c][METRIC] for c in ("C0", "C1", "C2", "C3"))
            row["delta_hook_usec"] = c1 - c0
            row["delta_map_usec"] = c2 - c1
            row["delta_enforcement_usec"] = c3 - c0
            row["delta_full_vs_map_usec"] = c3 - c2
        else:
            row["delta_hook_usec"] = row["delta_map_usec"] = None
            row["delta_enforcement_usec"] = row["delta_full_vs_map_usec"] = None
        paired_rows.append(row)

    fields = [
        "operation", "block_id", "excluded", "exclusion_reason",
        "c0_usec_per_op", "c1_usec_per_op", "c2_usec_per_op", "c3_usec_per_op",
        "delta_hook_usec", "delta_map_usec", "delta_enforcement_usec", "delta_full_vs_map_usec",
    ]
    write_csv(PAIRED_PATH, paired_rows, fields)

    comparisons = [
        ("hook", "delta_hook_usec"),
        ("map", "delta_map_usec"),
        ("enforcement", "delta_enforcement_usec"),
        ("full_vs_map", "delta_full_vs_map_usec"),
    ]
    summary_rows = []
    for op in ["exec", "file", "network"]:
        op_blocks = [r for r in paired_rows if r["operation"] == op and not r["excluded"]]
        for comparison, field in comparisons:
            diffs = [r[field] for r in op_blocks if r[field] is not None]
            n = len(diffs)
            if n == 0:
                summary_rows.append({
                    "operation": op, "comparison": comparison, "n": 0,
                    "mean_delta_us": None, "median_delta_us": None,
                    "ci95_low_us": None, "ci95_high_us": None, "paired_hedges_g": None,
                })
                continue
            mean_d = statistics.mean(diffs)
            median_d = statistics.median(diffs)
            ci_lo, ci_hi = bootstrap_ci_mean(diffs)
            g = hedges_g_paired(diffs)
            summary_rows.append({
                "operation": op, "comparison": comparison, "n": n,
                "mean_delta_us": round(mean_d, 4),
                "median_delta_us": round(median_d, 4),
                "ci95_low_us": round(ci_lo, 4) if ci_lo is not None else None,
                "ci95_high_us": round(ci_hi, 4) if ci_hi is not None else None,
                "paired_hedges_g": round(g, 4) if g is not None else None,
            })
    write_csv(
        SUMMARY_PATH, summary_rows,
        ["operation", "comparison", "n", "mean_delta_us", "median_delta_us", "ci95_low_us", "ci95_high_us", "paired_hedges_g"],
    )

    print(f"wrote {PAIRED_PATH} ({len(paired_rows)} blocks)")
    print(f"wrote {SUMMARY_PATH} ({len(summary_rows)} rows)")
    for r in summary_rows:
        print(" ", r)


if __name__ == "__main__":
    main()
