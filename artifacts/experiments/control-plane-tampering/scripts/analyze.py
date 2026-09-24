#!/usr/bin/env python3
"""Generates processed CSVs and a figure for the control-plane-tampering
experiment (Task 11) from raw/results.jsonl."""
import json
import csv
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(BASE, "raw")
PROCESSED = os.path.join(BASE, "processed")
FIGURES = os.path.join(BASE, "figures")
os.makedirs(PROCESSED, exist_ok=True)
os.makedirs(FIGURES, exist_ok=True)

with open(os.path.join(RAW, "results.jsonl")) as f:
    rows = [json.loads(l) for l in f if l.strip()]

with open(os.path.join(PROCESSED, "results-raw.csv"), "w", newline="") as f:
    fields = ["condition", "rep", "pod", "baseline_verdict", "verdict", "expected"]
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in rows:
        row = {k: r.get(k, "") for k in fields}
        w.writerow(row)

summary = {}
for r in rows:
    cond = r["condition"]
    s = summary.setdefault(cond, {"n": 0, "n_as_expected": 0})
    s["n"] += 1
    actual = r["verdict"].split(":", 1)[0]
    expected = r["expected"]
    if actual == expected:
        s["n_as_expected"] += 1

rows_out = []
for cond, s in sorted(summary.items()):
    rows_out.append({
        "condition": cond, "n": s["n"], "n_as_expected": s["n_as_expected"],
        "rate_as_expected": round(s["n_as_expected"] / s["n"], 3),
    })
with open(os.path.join(PROCESSED, "summary.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
    w.writeheader()
    w.writerows(rows_out)

print("Control-plane-tampering summary:")
for r in rows_out:
    print(" ", r)

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = [r["condition"] for r in rows_out]
    rates = [r["rate_as_expected"] for r in rows_out]
    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(labels, rates, color=["tab:green", "tab:red"])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("fraction matching expected outcome")
    ax.set_title("Task 11: worker-side D->P validation\n(valid D + correct P -> accepted; valid D + tampered P -> rejected)")
    for b, r in zip(bars, rates):
        ax.annotate(f'{r:.0%}', (b.get_x() + b.get_width() / 2, r), textcoords="offset points", xytext=(0, 3), ha='center')
    fig.tight_layout()
    fig.savefig(os.path.join(FIGURES, "verdict-rates.png"), dpi=150)
    print("wrote verdict-rates.png")
except ImportError:
    print("matplotlib not available, skipping figure")
