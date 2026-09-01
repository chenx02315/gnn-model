#!/usr/bin/env python3
"""Independently recompute and verify the fixed-three-seed Phase4 LOFO summary."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd


SEEDS = [20260824, 20260825, 20260826]
MODELS = {"graphsage", "xgboost_scalar"}
FIELDS = [
    "d95_feasible_rate",
    "beats_single_baseline_rate",
    "family_macro_win_rate",
    "mean_fallback_gain_percent",
    "opportunity_capture_rate",
    "candidate_action_rate",
    "abstain_rate",
    "unsafe_combo_selection_rate",
    "mean_regret_percent",
    "max_regret_percent",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True, type=Path)
    parser.add_argument("--family-map", required=True, type=Path)
    parser.add_argument("--candidate-table", required=True, type=Path)
    parser.add_argument("--graph-manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    family = pd.read_csv(args.family_map, sep="\t")[["circuit", "effective_family"]]
    if len(family) != 15 or family.circuit.duplicated().any():
        raise RuntimeError("Independent family-map hard gate failed")
    family_lookup = family.set_index("circuit").effective_family.to_dict()
    candidate_source = pd.read_csv(args.candidate_table, sep="\t")
    if candidate_source.candidate_uid.duplicated().any():
        raise RuntimeError("Candidate source UID is not unique")
    per_seed = []
    invalid_selections = []
    input_hashes = {}
    for seed in SEEDS:
        seed_dir = args.run_root / f"seed_{seed}"
        metrics_path = seed_dir / "lofo_circuit_metrics.tsv"
        summary_path = seed_dir / "run_summary.json"
        metrics = pd.read_csv(metrics_path, sep="\t")
        meta = json.loads(summary_path.read_text(encoding="utf-8"))
        if meta.get("status") != "PASS" or meta.get("seed") != seed:
            raise RuntimeError(f"Seed metadata hard gate failed: {seed}")
        if (
            meta.get("candidate_rows") != 11167
            or meta.get("circuits") != 15
            or meta.get("effective_families") != 12
            or meta.get("measured_infeasible_candidate_rows") != 1
        ):
            raise RuntimeError(f"Seed input cardinality drift: {seed}")
        if set(metrics.model) != MODELS or metrics.duplicated(["model", "test_circuit"]).any():
            raise RuntimeError(f"Seed result cardinality drift: {seed}")
        required_action = {
            "selection_action", "selection_reason", "selected_action_uid",
            "safe_anchor_uid", "unsafe_combo_selection",
        }
        if not required_action <= set(metrics.columns):
            raise RuntimeError(f"Missing v4 action columns: {seed}")
        abstained = metrics[metrics.selection_action == "single_baseline"]
        if not (abstained.selected_action_uid == abstained.safe_anchor_uid).all():
            raise RuntimeError(f"Abstention did not use the fixed safe anchor: {seed}")
        expected_single_class = metrics.test_family == "itc99_b14_connected"
        if not (
            (metrics.loc[expected_single_class, "selection_reason"] == "ABSTAIN_SINGLE_CLASS").all()
            and (metrics.loc[expected_single_class, "selection_action"] == "single_baseline").all()
        ):
            raise RuntimeError(f"Single-class family did not deterministically abstain: {seed}")
        if (metrics.selected_action_uid == "fixed:2e5149eb7ca519e4322efbd2").any():
            raise RuntimeError(f"Known failed b21 UID was selected: {seed}")
        source_check = metrics.merge(
            candidate_source,
            left_on="selected_action_uid",
            right_on="candidate_uid",
            how="left",
            validate="many_to_one",
            suffixes=("_metric", "_source"),
        )
        if source_check.candidate_uid.isna().any():
            raise RuntimeError(f"Selected action UID missing from source table: {seed}")
        if not (
            (source_check.predicted_best_actual_cycles == source_check.total_cycles)
            & (source_check.predicted_best_detected_faults == source_check.detected_faults)
            & (source_check.d95_metric == source_check.d95_source)
        ).all():
            raise RuntimeError(f"Selected action outcome does not match source table: {seed}")
        anchor_source = source_check[source_check.selection_action == "single_baseline"]
        if not (
            (anchor_source.scheme == "FullScan-F4")
            & (anchor_source.stage == "single_boundary")
            & (anchor_source.f_patterns == anchor_source.f_full_patterns)
            & (anchor_source.feasible_at_d95 == 1)
            & (anchor_source.detected_faults >= anchor_source.d95_source)
        ).all():
            raise RuntimeError(f"Safe-anchor source contract failed: {seed}")
        expected_family = metrics.test_circuit.map(family_lookup)
        if expected_family.isna().any() or not expected_family.equals(metrics.test_family):
            raise RuntimeError(f"Held-out family mapping mismatch: {seed}")
        recomputed_d95 = (metrics.predicted_best_detected_faults >= metrics.d95).astype(int)
        recomputed_win = (
            (recomputed_d95 == 1)
            & (metrics.predicted_best_actual_cycles < metrics.single_baseline_cycles)
        ).astype(int)
        if not np.array_equal(recomputed_d95, metrics.d95_feasible.astype(int)):
            raise RuntimeError(f"D95 selection metric mismatch: {seed}")
        if not np.array_equal(recomputed_win, metrics.beats_single_baseline.astype(int)):
            raise RuntimeError(f"Single-baseline metric mismatch: {seed}")
        for row in metrics[metrics.d95_feasible == 0].itertuples(index=False):
            invalid_selections.append({
                "seed": seed,
                "model": row.model,
                "circuit": row.test_circuit,
                "candidate_uid": row.predicted_best_uid,
                "detected_faults": int(row.predicted_best_detected_faults),
                "d95": int(row.d95),
            })
        for model, part in metrics.groupby("model", sort=True):
            if len(part) != 15 or part.test_family.nunique() != 12:
                raise RuntimeError(f"Incomplete LOFO rows: seed={seed} model={model}")
            family_macro = part.groupby("test_family").beats_single_baseline.mean().mean()
            opportunities = part[part.oracle_can_beat_single == 1]
            opportunity_capture = opportunities.beats_single_baseline.mean()
            per_seed.append({
                "seed": seed,
                "model": model,
                "circuits": len(part),
                "families": part.test_family.nunique(),
                "d95_feasible_rate": part.d95_feasible.mean(),
                "beats_single_baseline_rate": part.beats_single_baseline.mean(),
                "family_macro_win_rate": family_macro,
                "mean_fallback_gain_percent": part.fallback_gain_vs_single_percent.mean(),
                "opportunity_capture_rate": opportunity_capture,
                "candidate_action_rate": (part.selection_action == "candidate").mean(),
                "abstain_rate": (part.selection_action != "candidate").mean(),
                "unsafe_combo_selection_rate": part.unsafe_combo_selection.mean(),
                "mean_regret_percent": part.regret_percent.mean(),
                "max_regret_percent": part.regret_percent.max(),
            })
        input_hashes[str(metrics_path)] = sha256(metrics_path)
        input_hashes[str(summary_path)] = sha256(summary_path)

    per_seed_frame = pd.DataFrame(per_seed)
    aggregate_rows = []
    for model, part in per_seed_frame.groupby("model", sort=True):
        row = {"model": model, "seed_count": len(part)}
        for field in FIELDS:
            row[f"{field}_mean"] = part[field].mean()
            row[f"{field}_std"] = part[field].std(ddof=0)
            if field in {
                "mean_regret_percent", "max_regret_percent", "abstain_rate",
                "unsafe_combo_selection_rate",
            }:
                row[f"{field}_worst"] = part[field].max()
            else:
                row[f"{field}_worst"] = part[field].min()
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
        aggregate_rows.append(row)
    aggregate = pd.DataFrame(aggregate_rows)

    internal = pd.read_csv(args.run_root / "three_seed_aggregate.tsv", sep="\t")
    check = aggregate.merge(internal, on="model", suffixes=("_independent", "_internal"))
    for field in FIELDS:
        for suffix in ("mean", "std", "worst"):
            left = check[f"{field}_{suffix}_independent"].to_numpy(dtype=float)
            right = check[f"{field}_{suffix}_internal"].to_numpy(dtype=float)
            if not np.allclose(left, right, rtol=0, atol=1e-10, equal_nan=True):
                raise RuntimeError(f"Independent/internal mismatch: {field}_{suffix}")
    if not (
        check.practical_signal_status_independent
        == check.practical_signal_status_internal
    ).all():
        raise RuntimeError("Independent/internal practical signal mismatch")
    if not (check.safety_status_independent == check.safety_status_internal).all():
        raise RuntimeError("Independent/internal safety status mismatch")

    per_seed_frame.to_csv(
        args.output / "independent_per_seed.tsv", sep="\t", index=False, lineterminator="\n"
    )
    aggregate.to_csv(
        args.output / "independent_aggregate.tsv", sep="\t", index=False, lineterminator="\n"
    )
    pd.DataFrame(invalid_selections).to_csv(
        args.output / "independent_infeasible_selections.tsv",
        sep="\t",
        index=False,
        lineterminator="\n",
    )
    result = {
        "status": "PASS",
        "verification": "independent recomputation from all circuit-level rows",
        "fixed_seeds": SEEDS,
        "all_seeds_included": True,
        "circuits_per_model_seed": 15,
        "effective_families": 12,
        "internal_summary_numeric_match": True,
        "selected_actions_rejoined_to_candidate_source": True,
        "safe_anchor_source_contract": "PASS",
        "model_practical_signal": dict(
            zip(aggregate.model, aggregate.practical_signal_status)
        ),
        "model_safety_status": dict(zip(aggregate.model, aggregate.safety_status)),
        "infeasible_selected_rows": invalid_selections,
        "candidate_table_sha256": sha256(args.candidate_table),
        "family_map_sha256": sha256(args.family_map),
        "graph_manifest_sha256": sha256(args.graph_manifest),
        "input_result_hashes": input_hashes,
    }
    (args.output / "independent_summary.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    outputs = [
        args.output / "independent_per_seed.tsv",
        args.output / "independent_aggregate.tsv",
        args.output / "independent_infeasible_selections.tsv",
        args.output / "independent_summary.json",
    ]
    (args.output / "independent_outputs.sha256").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in outputs),
        encoding="utf-8",
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
