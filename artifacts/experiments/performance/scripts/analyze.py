#!/usr/bin/env python3
"""Generates processed CSVs and figures for Experiment F (Task 09) from raw/*.jsonl.

Statistics notes (experiment protocol section 11, F5):
- This is a paired design (each block pairs an ON run and an OFF run),
  so paired-differences statistics are used throughout -- never an
  independent-samples formula.
- The primary interval estimate is a nonparametric bootstrap 95% CI on
  the mean paired difference (10000 resamples), not a normal/t-distribution
  assumption -- avoids needing an external stats dependency and makes no
  distributional assumption about the differences.
- Effect size is Hedges' g for paired/repeated-measures designs:
  d_z = mean_diff / sd_diff, g = d_z * J, J = 1 - 3/(4*(n-1)-1)
  (the standard small-sample bias correction), NOT the independent-
  samples pooled-SD Cohen's d.
- No p-value/significance test is computed or reported. This is a
  deliberate choice, not an omission: the experiment protocol explicitly warns
  against interpreting p > 0.05 as "no overhead," and reporting a mean
  difference with a bootstrap CI plus a stated minimum-detectable-effect
  (sensitivity) already answers the same question without that
  misinterpretation risk.
"""
import json
import csv
import os
import random
import statistics

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(BASE, "raw")
PROCESSED = os.path.join(BASE, "processed")
FIGURES = os.path.join(BASE, "figures")
os.makedirs(PROCESSED, exist_ok=True)
os.makedirs(FIGURES, exist_ok=True)

random.seed(20260814)


def load(name):
    path = os.path.join(RAW, name)
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


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


def min_detectable_effect(n, alpha=0.05, power=0.8):
    # d_z = (z_{alpha/2} + z_{power}) / sqrt(n), two-sided.
    z_alpha = 1.959964
    z_power = 0.841621
    if n < 2:
        return None
    return (z_alpha + z_power) / (n ** 0.5)


def write_csv(path, rows):
    if not rows:
        return
    fields = list(rows[0].keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


# --- F1-F3: paired ON/OFF blocks ---
f1 = load("f1-paired-blocks.jsonl")
f1_summary = []
f1_by_op = {}
for r in f1:
    if r.get("outcome") != "success":
        continue
    f1_by_op.setdefault(r["op"], []).append(r)

for op, rows in sorted(f1_by_op.items()):
    diffs = [r["diff_usec_per_op"] for r in rows]
    on_vals = [r["on_usec_per_op"] for r in rows]
    off_vals = [r["off_usec_per_op"] for r in rows]
    n = len(diffs)
    mean_diff = statistics.mean(diffs)
    sd_diff = statistics.stdev(diffs) if n > 1 else 0.0
    ci_lo, ci_hi = bootstrap_ci_mean(diffs)
    g = hedges_g_paired(diffs)
    mde = min_detectable_effect(n)
    f1_summary.append({
        "op": op, "n_blocks": n,
        "on_mean_usec_per_op": round(statistics.mean(on_vals), 4),
        "off_mean_usec_per_op": round(statistics.mean(off_vals), 4),
        "mean_diff_usec_per_op": round(mean_diff, 4),
        "sd_diff_usec_per_op": round(sd_diff, 4),
        "ci95_lo": round(ci_lo, 4) if ci_lo is not None else None,
        "ci95_hi": round(ci_hi, 4) if ci_hi is not None else None,
        "ci_excludes_zero": (ci_lo is not None and ci_lo > 0) or (ci_hi is not None and ci_hi < 0),
        "hedges_g_paired": round(g, 4) if g is not None else None,
        "min_detectable_dz_at_80pct_power": round(mde, 4) if mde is not None else None,
    })
write_csv(os.path.join(PROCESSED, "f1-paired-summary.csv"), f1_summary)
write_csv(os.path.join(PROCESSED, "f1-paired-raw.csv"), f1)

# --- F3: event/drop count check ---
f3 = load("f3-event-drop-check.jsonl")
write_csv(os.path.join(PROCESSED, "f3-event-drop-check.csv"), f3)

# --- F4: event-rate curve ---
f4 = load("f4-rate-curve.jsonl")
f4_by_c = {}
for r in f4:
    if r.get("outcome") != "success":
        continue
    f4_by_c.setdefault(r["concurrency"], []).append(r)
f4_summary = []
for c in sorted(f4_by_c.keys()):
    rows = f4_by_c[c]
    rates = [r["agg_ops_per_second"] for r in rows if r.get("agg_ops_per_second")]
    cpus = [r["cpu_total_seconds"] for r in rows if r.get("cpu_total_seconds") is not None]
    drops = [r["events_dropped_since_last_evidence"] or 0 for r in rows]
    incorporated = [r["incorporated_count"] or 0 for r in rows]
    total_ops = [r["total_ops"] for r in rows if r.get("total_ops") is not None]
    f4_summary.append({
        "concurrency": c, "n_reps": len(rows),
        "mean_ops_per_second": round(statistics.mean(rates), 2) if rates else None,
        "mean_cpu_total_seconds": round(statistics.mean(cpus), 4) if cpus else None,
        "mean_total_ops": round(statistics.mean(total_ops), 1) if total_ops else None,
        "mean_incorporated_count": round(statistics.mean(incorporated), 1) if incorporated else None,
        "mean_events_dropped": round(statistics.mean(drops), 2),
        "any_drops_observed": any(d > 0 for d in drops),
    })
write_csv(os.path.join(PROCESSED, "f4-rate-curve-summary.csv"), f4_summary)
write_csv(os.path.join(PROCESSED, "f4-rate-curve-raw.csv"), f4)

print("F1-F3 paired ON/OFF summary (usec/op CPU total):")
for r in f1_summary:
    print(" ", r)
print("F3 event/drop check:")
for r in f3:
    print(" ", r)
print("F4 rate curve summary:")
for r in f4_summary:
    print(" ", r)

# --- Figures ---
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    if f1_summary:
        ops = [r["op"] for r in f1_summary]
        means = [r["mean_diff_usec_per_op"] for r in f1_summary]
        los = [r["ci95_lo"] for r in f1_summary]
        his = [r["ci95_hi"] for r in f1_summary]
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.errorbar(range(len(ops)), means,
                    yerr=[[m - lo for m, lo in zip(means, los)], [hi - m for m, hi in zip(means, his)]],
                    fmt='o', capsize=6, color='tab:blue')
        ax.axhline(0, color='gray', linestyle='--', linewidth=0.8)
        ax.set_xticks(range(len(ops)))
        ax.set_xticklabels(ops)
        ax.set_ylabel("mean paired diff (ON - OFF), usec/op CPU total")
        ax.set_title("F1-F3: RuntimeGuard incremental cost per event\n(error bars: bootstrap 95% CI on paired mean)")
        fig.tight_layout()
        fig.savefig(os.path.join(FIGURES, "f1-paired-diff-by-op.png"), dpi=150)
        print("wrote f1-paired-diff-by-op.png")

        fig, axes = plt.subplots(1, len(f1_by_op), figsize=(4 * len(f1_by_op), 4), squeeze=False)
        for i, (op, rows) in enumerate(sorted(f1_by_op.items())):
            ax = axes[0][i]
            diffs = sorted(r["diff_usec_per_op"] for r in rows)
            ax.hist(diffs, bins=min(15, max(5, len(diffs) // 2)), color='tab:orange', edgecolor='black')
            ax.axvline(0, color='gray', linestyle='--')
            ax.set_title(f"{op} (n={len(diffs)})")
            ax.set_xlabel("paired diff usec/op")
        fig.suptitle("F1-F3: distribution of paired ON-OFF differences per block")
        fig.tight_layout()
        fig.savefig(os.path.join(FIGURES, "f1-paired-diff-distributions.png"), dpi=150)
        print("wrote f1-paired-diff-distributions.png")

    if f4_summary:
        cs = [r["concurrency"] for r in f4_summary]
        rates = [r["mean_ops_per_second"] or 0 for r in f4_summary]
        cpus = [r["mean_cpu_total_seconds"] or 0 for r in f4_summary]
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        ax1.plot(cs, rates, 'o-', color='tab:green')
        ax1.set_xlabel("concurrent workers")
        ax1.set_ylabel("achieved aggregate ops/second")
        ax1.set_title("F4: achieved exec rate vs concurrency")
        ax2.plot(cs, cpus, 's-', color='tab:red')
        ax2.set_xlabel("concurrent workers")
        ax2.set_ylabel("total CPU seconds (all workers)")
        ax2.set_title("F4: aggregate CPU cost vs concurrency")
        fig.tight_layout()
        fig.savefig(os.path.join(FIGURES, "f4-rate-curve.png"), dpi=150)
        print("wrote f4-rate-curve.png")
except ImportError:
    print("matplotlib not available, skipping figures")
