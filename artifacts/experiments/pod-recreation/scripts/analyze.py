#!/usr/bin/env python3
"""Generates processed/d1-pod-recreation-summary.csv from raw/d1-pod-recreation.jsonl."""
import json
import csv
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(BASE, "raw", "d1-pod-recreation.jsonl")
PROCESSED = os.path.join(BASE, "processed")
os.makedirs(PROCESSED, exist_ok=True)

with open(RAW) as f:
    rows = [json.loads(l) for l in f if l.strip()]

n_total = len(rows)
n_uid_changed = sum(1 for r in rows if r["uid_changed"])
n_cgroups_unchanged = sum(1 for r in rows if r["applied_cgroups_unchanged"])
n_evidence_not_bound = sum(1 for r in rows if not r["evidence_incorrectly_bound_to_b"])
n_refusal_confirmed = sum(1 for r in rows if r["refusal_log_confirmed"])
n_pass = sum(1 for r in rows if r["policy_did_not_bind_to_b"])

summary = {
    "n_total": n_total,
    "n_uid_changed": n_uid_changed,
    "n_applied_cgroups_unchanged": n_cgroups_unchanged,
    "n_evidence_not_incorrectly_bound": n_evidence_not_bound,
    "n_refusal_log_confirmed": n_refusal_confirmed,
    "n_pass_policy_did_not_bind_to_b": n_pass,
    "pass_rate": n_pass / n_total if n_total else None,
}

with open(os.path.join(PROCESSED, "d1-pod-recreation-summary.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(summary.keys()))
    w.writeheader()
    w.writerow(summary)

print(json.dumps(summary, indent=2))

with open(os.path.join(PROCESSED, "d1-pod-recreation-per-rep.csv"), "w", newline="") as f:
    fields = ["pod_name", "uid_a", "uid_b", "uid_changed", "applied_cgroups_unchanged",
              "refusal_log_confirmed", "evidence_incorrectly_bound_to_b", "policy_did_not_bind_to_b"]
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k) for k in fields})
