#!/usr/bin/env python3
"""Aggregate all three fixed seed predictions without selecting a seed."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from src.models.runtime_training_v2 import (
    TrainingV2Error, read_json, reject_protected_paths, replay_validation, sha256_file,
    validate_contract, validate_outcome_split, write_tsv,
)


PREDICTED = ("predicted_epsilon_hit_probability", "predicted_cycles", "predicted_runtime_s", "cost_aware_score")


def read_ranking(path: Path):
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def aggregate(contract_path: Path, package_root: Path, outcome_split: Path,
              seed_roots: list[Path], model: str, output: Path) -> dict:
    reject_protected_paths([contract_path, package_root, outcome_split, output, *seed_roots])
    contract = read_json(contract_path)
    validate_contract(contract)
    required = contract["determinism"]["seeds"]
    receipts, rankings = [], []
    for root in seed_roots:
        receipt = read_json(root / "seed_receipt.json")
        receipts.append(receipt)
        rankings.append(read_ranking(root / ("ranking_%s.tsv" % model)))
    seeds = [item["seed"] for item in receipts]
    if sorted(seeds) != sorted(required) or len(set(seeds)) != len(required):
        raise TrainingV2Error("EXACT_THREE_FIXED_SEEDS_REQUIRED")
    if any(item.get("status") != "PASS_FIXED_SEED_TRAINING" for item in receipts):
        raise TrainingV2Error("SEED_RECEIPT_STATUS")
    anchor_fields = (
        "git_commit", "contract_sha256", "dataset_manifest_sha256", "dependency_lock_sha256",
        "environment_preflight_sha256", "independent_review_sha256", "outcome_split_receipt_sha256",
    )
    for field in anchor_fields:
        values = {item.get(field) for item in receipts}
        if len(values) != 1 or None in values:
            raise TrainingV2Error("SEED_ANCHOR_MISMATCH:%s" % field)
    if receipts[0]["contract_sha256"] != sha256_file(contract_path):
        raise TrainingV2Error("ENSEMBLE_CONTRACT_BINDING")
    if receipts[0]["dataset_manifest_sha256"] != sha256_file(package_root / "runtime_training_package_manifest_v2.json"):
        raise TrainingV2Error("ENSEMBLE_DATASET_BINDING")
    if receipts[0]["outcome_split_receipt_sha256"] != sha256_file(outcome_split / "outcome_split_receipt_v2.json"):
        raise TrainingV2Error("ENSEMBLE_OUTCOME_SPLIT_BINDING")
    for root, receipt in zip(seed_roots, receipts):
        ranking_path = root / ("ranking_%s.tsv" % model)
        freeze_path = root / ("ranking_%s.freeze.json" % model)
        if receipt.get("artifact_sha256", {}).get(ranking_path.name) != sha256_file(ranking_path):
            raise TrainingV2Error("SEED_RANKING_ARTIFACT_SHA")
        if receipt.get("artifact_sha256", {}).get(freeze_path.name) != sha256_file(freeze_path):
            raise TrainingV2Error("SEED_FREEZE_ARTIFACT_SHA")
        freeze = read_json(freeze_path)
        if (freeze.get("model") != model
                or freeze.get("contract_sha256") != receipts[0]["contract_sha256"]
                or freeze.get("features_sha256") != contract["trust_anchors"]["features_sha256"]
                or freeze.get("ranking_sha256") != sha256_file(ranking_path)
                or freeze.get("validation_outcomes_read") is not False):
            raise TrainingV2Error("SEED_FREEZE_BINDING")
    base_uids = [row["action_uid"] for row in rankings[0]]
    if any([row["action_uid"] for row in rows] != base_uids for rows in rankings[1:]):
        raise TrainingV2Error("SEED_ACTION_ORDER")
    output_rows = []
    for index, base in enumerate(rankings[0]):
        row = dict(base)
        for field in PREDICTED[:3]:
            row[field] = "%.12g" % (sum(float(rows[index][field]) for rows in rankings) / len(rankings))
        row["cost_aware_score"] = "%.12g" % (
            float(row["predicted_epsilon_hit_probability"]) / max(float(row["predicted_runtime_s"]), 1e-9))
        output_rows.append(row)
    output.parent.mkdir(parents=True, exist_ok=False)
    fields = list(rankings[0][0])
    write_tsv(output, fields, output_rows)
    freeze = {
        "schema_version": "runtime-v2-ensemble-ranking-freeze",
        "model": model,
        "seeds": required,
        "seed_selection_used": False,
        "ranking_sha256": sha256_file(output),
        "contract_sha256": sha256_file(contract_path),
        "dataset_manifest_sha256": receipts[0]["dataset_manifest_sha256"],
        "validation_outcomes_read": False,
    }
    freeze_path = output.parent / "ensemble_ranking.freeze.json"
    freeze_path.write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Only the immutable ensemble ranking may unlock validation outcome access.
    validate_outcome_split(outcome_split, package_root, contract, validation_access_allowed=True)
    if sha256_file(output) != read_json(freeze_path)["ranking_sha256"]:
        raise TrainingV2Error("PERSISTED_ENSEMBLE_RANKING_DRIFT")
    persisted_rows = read_ranking(output)
    replay = replay_validation(persisted_rows, outcome_split / "validation_outcomes.tsv",
                               int(contract["ranking"]["top_k"]))
    replay_path = output.parent / "ensemble_validation_replay.json"
    replay_path.write_text(json.dumps(replay, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt = {
        "schema_version": "runtime-v2-three-seed-ensemble",
        "status": "PASS_THREE_FIXED_SEED_ENSEMBLE",
        "model": model,
        "seeds": required,
        "seed_selection_used": False,
        "aggregation": "arithmetic_mean_predictions",
        "contract_sha256": sha256_file(contract_path),
        "seed_receipt_sha256": dict((str(item["seed"]), sha256_file(root / "seed_receipt.json"))
                                    for item, root in zip(receipts, seed_roots)),
        "ranking_sha256": sha256_file(output),
        "ranking_freeze_sha256": sha256_file(freeze_path),
        "validation_replay_sha256": sha256_file(replay_path),
    }
    (output.parent / "ensemble_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--outcome-split", type=Path, required=True)
    parser.add_argument("--seed-root", type=Path, action="append", required=True)
    parser.add_argument("--model", choices=("graphsage", "xgboost"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = aggregate(args.contract, args.package, args.outcome_split,
                        args.seed_root, args.model, args.output)
    print("RUNTIME_V2_ENSEMBLE=" + receipt["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
