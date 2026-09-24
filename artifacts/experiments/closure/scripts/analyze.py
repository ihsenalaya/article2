#!/usr/bin/env python3
"""Task 04 (Experiment A) analysis: computes distributions for Delta_PR and
Delta_RC per condition from raw JSONL trial records, programmatically -- no
manual editing of statistical results, per experiment protocol rule 26.
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

RAW_DIR = Path(__file__).resolve().parent.parent / "raw"
PROCESSED_DIR = Path(__file__).resolve().parent.parent / "processed"
FIGURES_DIR = Path(__file__).resolve().parent.parent / "figures"
PROCESSED_DIR.mkdir(exist_ok=True)
FIGURES_DIR.mkdir(exist_ok=True)


def load_jsonl(path):
    records = []
    if not path.exists():
        return records
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append({"_parse_error": True, "raw": line})
    return records


def stats_row(condition, values_ns, n_total):
    values_ns = [v for v in values_ns if v is not None]
    n = len(values_ns)
    row = {"condition": condition, "n_total_runs": n_total, "n_with_value": n}
    if n == 0:
        for k in ["mean_ms", "median_ms", "sd_ms", "min_ms", "max_ms", "p5_ms", "p25_ms", "p75_ms", "p95_ms"]:
            row[k] = None
        return row
    arr = np.array(values_ns, dtype=np.float64) / 1e6  # ns -> ms
    row["mean_ms"] = float(np.mean(arr))
    row["median_ms"] = float(np.median(arr))
    row["sd_ms"] = float(np.std(arr, ddof=1)) if n > 1 else 0.0
    row["min_ms"] = float(np.min(arr))
    row["max_ms"] = float(np.max(arr))
    row["p5_ms"] = float(np.percentile(arr, 5))
    row["p25_ms"] = float(np.percentile(arr, 25))
    row["p75_ms"] = float(np.percentile(arr, 75))
    row["p95_ms"] = float(np.percentile(arr, 95))
    return row


def analyze_closure_file(path, label_prefix=""):
    records = load_jsonl(path)
    if not records:
        return None, records
    df = pd.DataFrame(records)
    return df, records


def main():
    all_summary_rows = []
    combined_records = []

    for raw_file, exp_label in [
        (RAW_DIR / "a1-nominal.jsonl", "A1"),
        (RAW_DIR / "a2-readiness-stress.jsonl", "A2"),
        (RAW_DIR / "a3-concurrency.jsonl", "A3"),
    ]:
        df, records = analyze_closure_file(raw_file)
        if df is None:
            continue
        combined_records.extend(records)
        for condition, group in df.groupby("condition"):
            n_total = len(group)
            success = group[group["outcome"] == "success"] if "outcome" in group else group
            dpr = success["delta_pr_ns"].tolist() if "delta_pr_ns" in success else []
            drc = success["delta_rc_ns"].tolist() if "delta_rc_ns" in success else []
            row_pr = stats_row(f"{condition}__delta_pr", dpr, n_total)
            row_pr["experiment"] = exp_label
            row_pr["metric"] = "delta_pr"
            row_rc = stats_row(f"{condition}__delta_rc", drc, n_total)
            row_rc["experiment"] = exp_label
            row_rc["metric"] = "delta_rc"
            n_success = len(success)
            n_failed = n_total - n_success
            row_pr["n_success"] = n_success
            row_pr["n_failed"] = n_failed
            row_rc["n_success"] = n_success
            row_rc["n_failed"] = n_failed
            all_summary_rows.append(row_pr)
            all_summary_rows.append(row_rc)

    if not all_summary_rows:
        print("No raw data found yet.", file=sys.stderr)
        return

    summary_df = pd.DataFrame(all_summary_rows)
    summary_df.to_csv(PROCESSED_DIR / "closure-summary-stats.csv", index=False)
    print(summary_df.to_string(index=False))

    # Figures: Delta_PR and Delta_RC distributions per condition (A1+A2).
    for metric, ylabel in [("delta_pr_ns", "Delta_PR (t_r - t_p), ms"), ("delta_rc_ns", "Delta_RC (t_c - t_r), ms")]:
        fig, ax = plt.subplots(figsize=(10, 6))
        # Combined boxplot across all A1/A2 conditions for this metric.
        combined = []
        combined_labels = []
        for raw_file in [RAW_DIR / "a1-nominal.jsonl", RAW_DIR / "a2-readiness-stress.jsonl"]:
            df, _ = analyze_closure_file(raw_file)
            if df is None or metric not in df.columns:
                continue
            success = df[df["outcome"] == "success"] if "outcome" in df else df
            for c in sorted(success["condition"].dropna().unique()):
                vals = (success[success["condition"] == c][metric].dropna() / 1e6).tolist()
                if vals:
                    combined.append(vals)
                    combined_labels.append(c)
        if combined:
            ax.boxplot(combined, tick_labels=combined_labels, showmeans=True)
            ax.set_ylabel(ylabel)
            ax.set_title(f"{ylabel} by condition (Task 04, Experiment A)")
            ax.axhline(0, color="red", linewidth=0.8, linestyle="--")
            plt.xticks(rotation=30, ha="right")
            plt.tight_layout()
            plt.savefig(FIGURES_DIR / f"{metric}-by-condition.png", dpi=150)
        plt.close(fig)

    print(f"\nWrote {PROCESSED_DIR / 'closure-summary-stats.csv'}")
    print(f"Wrote figures to {FIGURES_DIR}")


if __name__ == "__main__":
    main()
