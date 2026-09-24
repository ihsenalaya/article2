#!/usr/bin/env python3
"""Generates processed CSVs and figures for Experiment E (Task 08) from raw/*.jsonl."""
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

    def sort_key(k):
        return k if isinstance(k, (int, float)) else str(k)

    out = []
    for key in sorted(groups.keys(), key=sort_key):
        grp = groups[key]
        vals = [r[value_field] for r in grp if r.get(value_field) is not None]
        row = {key_field: key, "n_reps": len(grp)}
        if vals:
            row.update({
                "mean": round(statistics.mean(vals), 4),
                "median": round(statistics.median(vals), 4),
                "sd": round(statistics.stdev(vals), 4) if len(vals) > 1 else 0.0,
                "min": round(min(vals), 4),
                "max": round(max(vals), 4),
                "p5": round(pct(vals, 5), 4),
                "p95": round(pct(vals, 95), 4),
            })
        else:
            row.update({k: None for k in ("mean", "median", "sd", "min", "max", "p5", "p95")})
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


# --- E1: steady-state scale ---
e1 = load("e1-steady-state.jsonl")
e1_summary = summarize_group(e1, "n", "ready_time_mean")
write_csv(os.path.join(PROCESSED, "e1-steady-state-summary.csv"), e1_summary)
write_csv(os.path.join(PROCESSED, "e1-steady-state-raw.csv"), e1)

# --- E2: submission concurrency (pooled per-decision records, not per-run means) ---
e2_runs = load("e2-concurrency.jsonl")
e2_pooled = {}
for run in e2_runs:
    if run.get("outcome") != "success":
        continue
    c = run["concurrency"]
    e2_pooled.setdefault(c, {"accepted": [], "policy_created": [], "ready": []})
    for r in run.get("records", []):
        if r.get("submit_to_accepted_seconds"):
            e2_pooled[c]["accepted"].append(r["submit_to_accepted_seconds"])
        if r.get("submit_to_policy_created_seconds"):
            e2_pooled[c]["policy_created"].append(r["submit_to_policy_created_seconds"])
        if r.get("submit_to_ready_seconds"):
            e2_pooled[c]["ready"].append(r["submit_to_ready_seconds"])

e2_summary = []
for c in sorted(e2_pooled.keys()):
    row = {"concurrency": c}
    for stage in ("accepted", "policy_created", "ready"):
        vals = e2_pooled[c][stage]
        row[f"{stage}_n"] = len(vals)
        row[f"{stage}_p50"] = round(pct(vals, 50), 4) if vals else None
        row[f"{stage}_p95"] = round(pct(vals, 95), 4) if vals else None
        row[f"{stage}_p99"] = round(pct(vals, 99), 4) if vals else None
    e2_summary.append(row)
write_csv(os.path.join(PROCESSED, "e2-concurrency-summary.csv"), e2_summary)

# --- E3: 500-policy case ---
e3 = load("e3-500-policy.jsonl")
write_csv(os.path.join(PROCESSED, "e3-500-policy-raw.csv"), [
    {k: v for k, v in r.items() if k not in ("outcome_breakdown",)} | {
        "outcome_breakdown": json.dumps(r.get("outcome_breakdown", {}))
    } for r in e3
])

# --- E4: event integrity under scale ---
e4 = load("e4-event-integrity.jsonl")
write_csv(os.path.join(PROCESSED, "e4-event-integrity-raw.csv"), [
    {k: v for k, v in r.items() if k not in ("conformance_breakdown", "behavior_sum")} | {
        "conformance_breakdown": json.dumps(r.get("conformance_breakdown", {})),
        "behavior_sum": json.dumps(r.get("behavior_sum", {})),
    } for r in e4
])

print("E1 steady-state (ready_time_mean by N):")
for r in e1_summary:
    print(" ", r)
print("E2 concurrency (pooled per-decision percentiles):")
for r in e2_summary:
    print(" ", r)
print("E3 500-policy runs:")
for r in e3:
    print(" ", {k: v for k, v in r.items() if k != "rca_path"})
print("E4 event integrity:")
for r in e4:
    print(" ", r)

# --- Figures ---
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    if e1_summary:
        ns = [r["n"] for r in e1_summary]
        means = [r["mean"] for r in e1_summary]
        p5s = [r["p5"] for r in e1_summary]
        p95s = [r["p95"] for r in e1_summary]
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.errorbar(range(len(ns)), means,
                    yerr=[[m - p5 for m, p5 in zip(means, p5s)], [p95 - m for m, p95 in zip(means, p95s)]],
                    fmt='o-', capsize=4, color='tab:blue')
        ax.set_xticks(range(len(ns)))
        ax.set_xticklabels(ns)
        ax.set_xlabel("N (concurrent decisions)")
        ax.set_ylabel("mean submit-to-ready seconds (per-run mean)")
        ax.set_title("E1: steady-state convergence time vs N\n(error bars: P5-P95 across reps)")
        fig.tight_layout()
        fig.savefig(os.path.join(FIGURES, "e1-ready-time-vs-n.png"), dpi=150)
        print("wrote e1-ready-time-vs-n.png")

    if e2_summary:
        cs = [r["concurrency"] for r in e2_summary]
        p50 = [r["ready_p50"] for r in e2_summary]
        p95 = [r["ready_p95"] for r in e2_summary]
        p99 = [r["ready_p99"] for r in e2_summary]
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.plot(range(len(cs)), p50, 'o-', label='p50')
        ax.plot(range(len(cs)), p95, 's-', label='p95')
        ax.plot(range(len(cs)), p99, '^-', label='p99')
        ax.set_xticks(range(len(cs)))
        ax.set_xticklabels(cs)
        ax.set_xlabel("concurrency (in-flight submissions)")
        ax.set_ylabel("submit-to-ready seconds")
        ax.set_title("E2: submit-to-ready latency distribution vs concurrency\n(N=50 fixed)")
        ax.legend()
        fig.tight_layout()
        fig.savefig(os.path.join(FIGURES, "e2-ready-latency-vs-concurrency.png"), dpi=150)
        print("wrote e2-ready-latency-vs-concurrency.png")

    if e3:
        reps = [f"rep{r['rep']}" for r in e3]
        rates = [r.get("convergence_rate", 0) or 0 for r in e3]
        fig, ax = plt.subplots(figsize=(5, 4))
        bars = ax.bar(reps, rates, color='tab:red')
        ax.set_ylabel("convergence_rate (converged / 500)")
        ax.set_ylim(0, 1)
        ax.set_title("E3: 500-policy convergence rate\n(single 110-max-pod worker node)")
        for b, r in zip(bars, rates):
            ax.annotate(f'{r:.1%}', (b.get_x() + b.get_width() / 2, r), textcoords="offset points", xytext=(0, 3), ha='center')
        fig.tight_layout()
        fig.savefig(os.path.join(FIGURES, "e3-convergence-rate.png"), dpi=150)
        print("wrote e3-convergence-rate.png")

    if e4:
        reps = [f"rep{r['rep']}" for r in e4]
        coverage = [r.get("evidence_coverage", 0) or 0 for r in e4]
        drops = [r.get("events_dropped_since_last_evidence_nonzero_count", 0) or 0 for r in e4]
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9, 4))
        ax1.bar(reps, coverage, color='tab:blue')
        ax1.set_ylabel("evidence_coverage (evidence objs / N)")
        ax1.set_ylim(0, 1.05)
        ax1.set_title("E4: evidence coverage under N=100 load")
        ax2.bar(reps, drops, color='tab:red')
        ax2.set_ylabel("# evidence objs with nonzero drop delta")
        ax2.set_title("E4: event-drop incidence under N=100 load")
        fig.tight_layout()
        fig.savefig(os.path.join(FIGURES, "e4-event-integrity.png"), dpi=150)
        print("wrote e4-event-integrity.png")
except ImportError:
    print("matplotlib not available, skipping figures")
