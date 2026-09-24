#!/usr/bin/env python3
"""Generates processed CSVs and a figure for Experiment G (Task 10) from raw/g1-results.json."""
import json
import csv
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(BASE, "raw")
PROCESSED = os.path.join(BASE, "processed")
FIGURES = os.path.join(BASE, "figures")
os.makedirs(PROCESSED, exist_ok=True)
os.makedirs(FIGURES, exist_ok=True)

with open(os.path.join(RAW, "g1-results.json")) as f:
    results = json.load(f)

write_fields = ["op", "condition", "rep", "target", "success", "errno",
                 "errno_is_eperm", "side_effect_observed", "raw_error"]
with open(os.path.join(PROCESSED, "g1-results-raw.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=write_fields)
    w.writeheader()
    for r in results:
        w.writerow({k: r.get(k, "") for k in write_fields})

summary = {}
for r in results:
    key = (r["op"], r["condition"])
    s = summary.setdefault(key, {"n": 0, "n_success": 0, "n_eperm": 0, "n_side_effect": 0})
    s["n"] += 1
    if r["success"]:
        s["n_success"] += 1
    if r["errno_is_eperm"]:
        s["n_eperm"] += 1
    if r["side_effect_observed"]:
        s["n_side_effect"] += 1

rows = []
for (op, cond), s in sorted(summary.items()):
    rows.append({
        "op": op, "condition": cond, "n": s["n"],
        "n_success": s["n_success"], "success_rate": round(s["n_success"] / s["n"], 3),
        "n_eperm": s["n_eperm"], "eperm_rate": round(s["n_eperm"] / s["n"], 3),
        "n_side_effect_observed": s["n_side_effect"],
        "pre_effect_denial_demonstrated": (cond == "deny" and s["n_eperm"] == s["n"] and s["n_side_effect"] == 0),
    })
with open(os.path.join(PROCESSED, "g1-summary.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)

print("G1 summary by op/condition:")
for r in rows:
    print(" ", r)

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    ops = sorted(set(r["op"] for r in rows))
    fig, ax = plt.subplots(figsize=(7, 4))
    width = 0.35
    x = range(len(ops))
    allow_success = [next(r["success_rate"] for r in rows if r["op"] == op and r["condition"] == "allow") for op in ops]
    deny_eperm = [next(r["eperm_rate"] for r in rows if r["op"] == op and r["condition"] == "deny") for op in ops]
    ax.bar([i - width / 2 for i in x], allow_success, width, label="allow: success rate", color="tab:green")
    ax.bar([i + width / 2 for i in x], deny_eperm, width, label="deny: EPERM rate (pre-effect denial)", color="tab:red")
    ax.set_xticks(list(x))
    ax.set_xticklabels(ops)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("rate")
    ax.set_title("G1: BPF-LSM allow success vs. deny EPERM rate\n(deny bars near 0 = unresolved finding, see summary.md)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(FIGURES, "g1-allow-vs-deny.png"), dpi=150)
    print("wrote g1-allow-vs-deny.png")
except ImportError:
    print("matplotlib not available, skipping figure")
