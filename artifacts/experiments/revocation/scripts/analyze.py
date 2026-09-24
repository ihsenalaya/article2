#!/usr/bin/env python3
"""Generates processed CSVs and figures for Experiment C (Task 06) from raw/*.jsonl."""
import json
import csv
import os
import statistics

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(BASE, "raw")
PROCESSED = os.path.join(BASE, "processed")
FIGURES = os.path.join(BASE, "figures")
os.makedirs(PROCESSED, exist_ok=True)
os.makedirs(FIGURES, exist_ok=True)


def load(name):
    path = os.path.join(RAW, name)
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p / 100
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def summarize_group(rows, key_field, value_field):
    groups = {}
    for r in rows:
        groups.setdefault(r[key_field], []).append(r)
    out = []
    for key, grp in sorted(groups.items()):
        vals = [r[value_field] for r in grp if r.get(value_field) is not None]
        n_total = len(grp)
        n_success = len(vals)
        row = {
            key_field: key,
            "n_total": n_total,
            "n_success": n_success,
            "n_failed": n_total - n_success,
        }
        if vals:
            row.update({
                "mean": round(statistics.mean(vals), 4),
                "median": round(statistics.median(vals), 4),
                "sd": round(statistics.stdev(vals), 4) if len(vals) > 1 else 0.0,
                "min": round(min(vals), 4),
                "max": round(max(vals), 4),
                "p5": round(pct(vals, 5), 4),
                "p25": round(pct(vals, 25), 4),
                "p75": round(pct(vals, 75), 4),
                "p95": round(pct(vals, 95), 4),
            })
        else:
            row.update({k: None for k in ("mean", "median", "sd", "min", "max", "p5", "p25", "p75", "p95")})
        out.append(row)
    return out


def write_csv(path, rows):
    if not rows:
        return
    fields = list(rows[0].keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


# C1: Delta_detect by poll_interval
c1_detect = load("c1-detect-latency.jsonl")
c1_detect_summary = summarize_group(c1_detect, "poll_interval", "delta_detect_seconds")
write_csv(os.path.join(PROCESSED, "c1-detect-latency-summary.csv"), c1_detect_summary)

# C1: Delta_evidence by poll_interval
c1_evidence = load("c1-evidence-latency.jsonl")
c1_evidence_summary = summarize_group(c1_evidence, "poll_interval", "delta_evidence_seconds")
write_csv(os.path.join(PROCESSED, "c1-evidence-latency-summary.csv"), c1_evidence_summary)

# C2: watch vs poll
c2 = load("c2-watch-vs-poll.jsonl")
c2_summary = summarize_group(c2, "condition", "delta_detect_seconds")
write_csv(os.path.join(PROCESSED, "c2-watch-vs-poll-summary.csv"), c2_summary)

# C3: pass-through (already a single summary record, small n)
c3 = load("c3-stale-evidence.jsonl")
write_csv(os.path.join(PROCESSED, "c3-stale-evidence-summary.csv"), c3)

print("C1 detect latency by poll_interval:")
for r in c1_detect_summary:
    print(" ", r)
print("C1 evidence latency by poll_interval:")
for r in c1_evidence_summary:
    print(" ", r)
print("C2 watch vs poll:")
for r in c2_summary:
    print(" ", r)
print("C3:")
for r in c3:
    print(" ", r)

# Figures
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    if c1_detect_summary:
        intervals = [r["poll_interval"] for r in c1_detect_summary]
        means = [r["mean"] for r in c1_detect_summary]
        p5s = [r["p5"] for r in c1_detect_summary]
        p95s = [r["p95"] for r in c1_detect_summary]
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.errorbar(range(len(intervals)), means,
                    yerr=[[m - p5 for m, p5 in zip(means, p5s)], [p95 - m for m, p95 in zip(means, p95s)]],
                    fmt='o-', capsize=4, color='tab:blue')
        ax.set_xticks(range(len(intervals)))
        ax.set_xticklabels(intervals)
        ax.set_xlabel("--poll-interval")
        ax.set_ylabel("Delta_detect (seconds)")
        ax.set_title("C1: revocation detection latency vs poll interval\n(error bars: P5-P95)")
        fig.tight_layout()
        fig.savefig(os.path.join(FIGURES, "c1-detect-latency-vs-poll-interval.png"), dpi=150)
        print("wrote c1-detect-latency-vs-poll-interval.png")

    if c1_evidence_summary:
        intervals = [r["poll_interval"] for r in c1_evidence_summary]
        means = [r["mean"] for r in c1_evidence_summary]
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.plot(range(len(intervals)), means, 'o-', color='tab:orange')
        ax.set_xticks(range(len(intervals)))
        ax.set_xticklabels(intervals)
        ax.set_xlabel("--poll-interval")
        ax.set_ylabel("Delta_evidence (seconds)")
        ax.set_title("C1: t_rev to first revoked-evidence latency vs poll interval\n(bottlenecked by fixed 30s evidence tick, not poll interval)")
        ax.axhline(30, color='gray', linestyle='--', linewidth=0.8, label='evidence-interval (30s)')
        ax.legend()
        fig.tight_layout()
        fig.savefig(os.path.join(FIGURES, "c1-evidence-latency-vs-poll-interval.png"), dpi=150)
        print("wrote c1-evidence-latency-vs-poll-interval.png")

    if c2_summary:
        labels = [r["condition"] for r in c2_summary]
        means = [r["mean"] or 0 for r in c2_summary]
        fig, ax = plt.subplots(figsize=(5, 4))
        bars = ax.bar(labels, means, color=['tab:red', 'tab:green'])
        ax.set_ylabel("Delta_detect (seconds)")
        ax.set_title("C2: watch vs poll-only revocation detection\n(poll-interval fixed at 10s)")
        for b, m in zip(bars, means):
            ax.annotate(f'{m:.2f}s', (b.get_x() + b.get_width() / 2, m), textcoords="offset points", xytext=(0, 3), ha='center')
        fig.tight_layout()
        fig.savefig(os.path.join(FIGURES, "c2-watch-vs-poll.png"), dpi=150)
        print("wrote c2-watch-vs-poll.png")
except ImportError:
    print("matplotlib not available, skipping figures")
