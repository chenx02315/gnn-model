#!/usr/bin/env python3
"""Create role-separated outcome files for ordered-access runtime-v2 training."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from src.models.runtime_training_v2 import (
    OUTCOME_COLUMNS, TrainingV2Error, read_tsv, reject_protected_paths,
    sha256_file, write_tsv,
)


def split(package_root: Path, output_root: Path) -> dict:
    reject_protected_paths((package_root, output_root))
    if output_root.exists():
        raise TrainingV2Error("OUTPUT_MUST_NOT_EXIST")
    features_path = package_root / "features.tsv"
    outcomes_path = package_root / "outcomes.tsv"
    role_by_uid = {row["action_uid"]: row["role"] for row in read_tsv(features_path)}
    if len(role_by_uid) != 2521 or set(role_by_uid.values()) != {"TRAIN", "VALIDATION"}:
        raise TrainingV2Error("FEATURE_ROLE_SET")
    rows = read_tsv(outcomes_path)
    if len(rows) != len(role_by_uid) or {row["action_uid"] for row in rows} != set(role_by_uid):
        raise TrainingV2Error("OUTCOME_ACTION_SET")
    train = [row for row in rows if role_by_uid[row["action_uid"]] == "TRAIN"]
    validation = [row for row in rows if role_by_uid[row["action_uid"]] == "VALIDATION"]
    if len(train) != 1706 or len(validation) != 815:
        raise TrainingV2Error("ROLE_COUNTS")
    output_root.mkdir(parents=True)
    train_path = output_root / "train_outcomes.tsv"
    validation_path = output_root / "validation_outcomes.tsv"
    write_tsv(train_path, OUTCOME_COLUMNS, train)
    write_tsv(validation_path, OUTCOME_COLUMNS, validation)
    receipt = {
        "schema_version": "runtime-v2-outcome-role-split",
        "status": "PASS_OUTCOME_ROLE_SPLIT",
        "source_features_sha256": sha256_file(features_path),
        "source_outcomes_sha256": sha256_file(outcomes_path),
        "train_outcomes_sha256": sha256_file(train_path),
        "validation_outcomes_sha256": sha256_file(validation_path),
        "train_count": len(train),
        "validation_count": len(validation),
        "ordering": "source_outcomes_order_preserved_within_each_role",
        "boundaries": {"blind_rows_read": False, "pilot_rows_read": False,
                       "raw_rows_in_git_allowed": False},
    }
    (output_root / "outcome_split_receipt_v2.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = split(args.package, args.output)
    print("RUNTIME_V2_OUTCOME_SPLIT=" + receipt["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
