#!/usr/bin/env python3
"""Aggregate three fixed Phase4 v4 LOFO seeds with safety/abstention metrics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


SEEDS = (20260824, 20260825, 20260826)
HIGHER_IS_BETTER = (
    "d95_feasible_rate",
    "beats_single_baseline_rate",
    "family_macro_win_rate",
    "mean_fallback_gain_percent",
    "opportunity_capture_rate",
    "candidate_action_rate",
)
LOWER_IS_BETTER = (
    "mean_regret_percent",
    "max_regret_percent",
    "abstain_rate",
    "unsafe_combo_selection_rate",
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True, type=Path)
    args = parser.parse_args()
    parts = []
    for seed in SEEDS:
        path = args.run_root / f"seed_{seed}" / "lofo_summary.tsv"
        part = pd.read_csv(path, sep="\t")
        part.insert(0, "seed", seed)
        parts.append(part)
    per_seed = pd.concat(parts, ignore_index=True)
    per_seed.to_csv(args.run_root / "three_seed_per_model.tsv", sep="\t", index=False)

    rows = []
    for model, part in per_seed.groupby("model", sort=True):
        if len(part) != 3 or set(part.seed) != set(SEEDS):
            raise RuntimeError(f"Missing or duplicate fixed seed for {model}")
        row = {"model": model, "seed_count": len(part)}
        for metric in HIGHER_IS_BETTER:
            row[f"{metric}_mean"] = float(part[metric].mean())
            row[f"{metric}_std"] = float(part[metric].std(ddof=0))
            row[f"{metric}_worst"] = float(part[metric].min())
        for metric in LOWER_IS_BETTER:
            row[f"{metric}_mean"] = float(part[metric].mean())
            row[f"{metric}_std"] = float(part[metric].std(ddof=0))
            row[f"{metric}_worst"] = float(part[metric].max())
        safe = (
            row["d95_feasible_rate_worst"] == 1.0
            and row["unsafe_combo_selection_rate_worst"] == 0.0
        )
        signal = row["beats_single_baseline_rate_worst"] > 0.0
        row["safety_status"] = "PASS" if safe else "FAIL"
        row["practical_signal_status"] = (
            "PASS" if safe and signal else
            "SAFE_BUT_NO_PRACTICAL_SIGNAL" if safe else "FAIL"
        )
        rows.append(row)
    aggregate = pd.DataFrame(rows)
    aggregate.to_csv(args.run_root / "three_seed_aggregate.tsv", sep="\t", index=False)
    payload = {
        "status": "PASS",
        "seed_policy": list(SEEDS),
        "selection_policy": "all seeds included; no best-seed selection",
        "safety_gate": "every seed has D95 rate 1.0 and unsafe combo selection rate 0.0",
        "practical_signal_gate": "safety gate passes and every seed has at least one held-out win",
        "models": aggregate.to_dict(orient="records"),
    }
    (args.run_root / "three_seed_summary.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
