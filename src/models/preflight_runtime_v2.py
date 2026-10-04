#!/usr/bin/env python3
"""Fail-closed environment and package preflight for runtime-v2 training."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
import sys
from pathlib import Path

from src.models.runtime_training_v2 import (
    TrainingV2Error, build_scalar_features, read_json, sha256_file,
    reject_protected_paths, validate_contract, validate_outcome_split, validate_package,
)


def parse_lock(path: Path) -> dict:
    versions = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise TrainingV2Error("UNPINNED_DEPENDENCY:%s" % line)
        name, version = line.split("==", 1)
        versions[name.lower().replace("_", "-")] = version
    required = {"numpy", "scikit-learn", "scipy", "torch", "xgboost"}
    if not required <= set(versions):
        raise TrainingV2Error("DEPENDENCY_LOCK_INCOMPLETE")
    return versions


def validate_installed_dependencies(requested: dict) -> dict:
    """Compare the full freeze using distribution versions, as pip freeze does."""
    installed = {}
    for name, expected_version in requested.items():
        actual = importlib.metadata.version(name)
        installed[name] = actual
        if actual != expected_version:
            raise TrainingV2Error("DEPENDENCY_VERSION:%s:%s!=%s" % (name, actual, expected_version))
    return installed


def run(args) -> dict:
    reject_protected_paths((args.contract, args.package, args.stage_seal,
                            args.outcome_split, args.dependency_lock, args.workspace, args.output))
    workspace_path = Path(args.workspace).resolve()
    expected_output = workspace_path / "evidence" / "environment_preflight.json"
    if args.output.resolve(strict=False) != expected_output:
        raise TrainingV2Error("PREFLIGHT_OUTPUT_PATH")
    contract = read_json(args.contract)
    validate_contract(contract)
    package = validate_package(args.package, contract, args.stage_seal)
    split_receipt = validate_outcome_split(args.outcome_split, args.package, contract,
                                           validation_access_allowed=False)
    names, _ = build_scalar_features(package.features)
    expected = contract["features"]["candidate"]
    if names != expected:
        raise TrainingV2Error("CONTRACT_FEATURE_DRIFT")
    resolved = workspace_path.as_posix()
    protected = contract["environment"]["protected_root_forbidden"]
    if resolved == protected or resolved.startswith(protected + "/"):
        raise TrainingV2Error("PROTECTED_ROOT")
    if not resolved.startswith("/ssd/cjc/gnn_model_runtime_v2_"):
        raise TrainingV2Error("WORKSPACE_ROOT")
    requested = parse_lock(args.dependency_lock)
    installed = validate_installed_dependencies(requested)
    import numpy as np
    from xgboost import XGBClassifier
    smoke_x = np.asarray([[0.0], [1.0], [2.0], [3.0]])
    smoke_y = np.asarray([0, 0, 1, 1])
    smoke = XGBClassifier(n_estimators=2, max_depth=1, n_jobs=1, random_state=20260824,
                          tree_method="hist", verbosity=0)
    smoke.fit(smoke_x, smoke_y)
    smoke_prediction = smoke.predict_proba(smoke_x)[:, 1]
    if smoke_prediction.shape != (4,) or not np.isfinite(smoke_prediction).all():
        raise TrainingV2Error("XGBOOST_SKLEARN_SMOKE")
    if "%s.%s" % sys.version_info[:2] != contract["environment"]["python_major_minor"]:
        raise TrainingV2Error("PYTHON_VERSION")
    receipt = {
        "schema_version": "runtime-v2-environment-preflight",
        "status": "PASS_ENVIRONMENT_PREFLIGHT",
        "workspace": resolved,
        "contract_sha256": sha256_file(args.contract),
        "dependency_lock_sha256": sha256_file(args.dependency_lock),
        "dataset_manifest_sha256": sha256_file(args.package / "runtime_training_package_manifest_v2.json"),
        "outcome_split_receipt_sha256": sha256_file(args.outcome_split / "outcome_split_receipt_v2.json"),
        "train_outcomes_sha256": split_receipt["train_outcomes_sha256"],
        "versions": installed,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "counts": package.manifest["counts"],
        "xgboost_sklearn_smoke": "PASS",
        "boundaries": {"blind_rows_read": False, "pilot_rows_read": False,
                       "training_executed": False, "lsf_or_tessent_executed": False},
    }
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--stage-seal", type=Path, required=True)
    parser.add_argument("--dependency-lock", type=Path, required=True)
    parser.add_argument("--outcome-split", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    receipt = run(parser.parse_args(argv))
    print("RUNTIME_V2_PREFLIGHT=" + receipt["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
