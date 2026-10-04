#!/usr/bin/env python3
"""Train one fixed runtime-v2 seed and freeze validation rankings before replay."""
from __future__ import annotations

import argparse
import json
import math
import platform
import subprocess
import sys
from pathlib import Path

from src.models.runtime_training_v2 import (
    FEATURE_COLUMNS, RANKING_FIELDS, TrainingV2Error, assert_feature_boundary,
    build_scalar_features, canonical_sha256, load_graph_tensor, make_graphsage_model,
    ranking_rows, read_json, read_training_outcomes_only, read_tsv, reject_protected_paths, replay_validation,
    seed_everything, sha256_file, standardizer, validate_contract, validate_package,
    validate_outcome_split, write_tsv,
)
from src.models.preflight_runtime_v2 import parse_lock, validate_installed_dependencies


def _imports():
    try:
        import numpy as np
        import torch
        import xgboost as xgb
    except ImportError as exc:
        raise TrainingV2Error("ML_DEPENDENCY_MISSING:%s" % exc) from exc
    return np, torch, xgb


def _git_commit(repo: Path) -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo), check=True,
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.strip()


def _targets(features, train_outcomes, np):
    hit, cycles, runtime = [], [], []
    for row in features:
        outcome = train_outcomes.get(row["action_uid"])
        if outcome is None:
            hit.append(float("nan")); cycles.append(float("nan")); runtime.append(float("nan"))
        else:
            hit.append(float(outcome["epsilon_hit"]))
            cycles.append(math.log1p(outcome["total_cycles"] / float(row["common_fault_count"])))
            runtime.append(math.log1p(outcome["policy_charged_runtime_s"]))
    return np.asarray(hit), np.asarray(cycles), np.asarray(runtime)


def _fit_graphsage(features, scalar_x, train_indices, targets, graphs, contract, seed, np, torch):
    seed_everything(seed, torch, np)
    x_norm, x_mean, x_std = standardizer(scalar_x, train_indices, np)
    hit, cycles, runtime = targets
    cycle_mean, cycle_std = cycles[train_indices].mean(), max(cycles[train_indices].std(), 1e-12)
    runtime_mean, runtime_std = runtime[train_indices].mean(), max(runtime[train_indices].std(), 1e-12)
    x_tensor = torch.tensor(x_norm, dtype=torch.float32)
    train_tensor = torch.tensor(train_indices, dtype=torch.long)
    y_hit = torch.tensor(hit[train_indices], dtype=torch.float32)
    y_cycles = torch.tensor((cycles[train_indices] - cycle_mean) / cycle_std, dtype=torch.float32)
    y_runtime = torch.tensor((runtime[train_indices] - runtime_mean) / runtime_std, dtype=torch.float32)
    model = make_graphsage_model(torch, next(iter(graphs.values()))[0].shape[1], x_tensor.shape[1], contract)
    cfg = contract["graphsage"]
    optimizer = torch.optim.Adam(model.parameters(), lr=cfg["learning_rate"], weight_decay=cfg["weight_decay"])
    positives = float(y_hit.sum().item())
    negatives = float(len(y_hit) - positives)
    if positives <= 0 or negatives <= 0:
        raise TrainingV2Error("EPSILON_HEAD_SINGLE_CLASS")
    hit_loss = torch.nn.BCEWithLogitsLoss(pos_weight=torch.tensor(negatives / positives))
    mse = torch.nn.MSELoss()
    train_circuits = [features[index]["graph_key"] for index in train_indices]
    train_graphs = dict((name, graphs[name]) for name in sorted(set(train_circuits)))
    model.train()
    final_loss = None
    for _ in range(int(cfg["epochs"])):
        optimizer.zero_grad()
        ph, pc, pr = model(train_graphs, train_circuits, x_tensor[train_tensor])
        loss = hit_loss(ph, y_hit) + mse(pc, y_cycles) + mse(pr, y_runtime)
        loss.backward()
        optimizer.step()
        final_loss = float(loss.detach().item())
    model.eval()
    with torch.no_grad():
        circuits = [row["graph_key"] for row in features]
        ph, pc, pr = model(graphs, circuits, x_tensor)
        probability = torch.sigmoid(ph).cpu().numpy()
        cycles_pred = np.expm1(pc.cpu().numpy() * cycle_std + cycle_mean) * np.asarray(
            [float(row["common_fault_count"]) for row in features])
        runtime_pred = np.expm1(pr.cpu().numpy() * runtime_std + runtime_mean)
    prediction = dict((row["action_uid"], {
        "predicted_epsilon_hit_probability": max(0.0, min(1.0, float(probability[index]))),
        "predicted_cycles": max(1e-9, float(cycles_pred[index])),
        "predicted_runtime_s": max(1e-9, float(runtime_pred[index])),
    }) for index, row in enumerate(features))
    preprocessing = {
        "feature_names": list(FEATURE_COLUMNS), "x_mean": x_mean.tolist(), "x_std": x_std.tolist(),
        "cycles_target_mean": float(cycle_mean), "cycles_target_std": float(cycle_std),
        "runtime_target_mean": float(runtime_mean), "runtime_target_std": float(runtime_std),
    }
    return model, prediction, preprocessing, final_loss


def _fit_xgboost(features, scalar_x, train_indices, targets, contract, seed, np, xgb):
    x_norm, x_mean, x_std = standardizer(scalar_x, train_indices, np)
    hit, cycles, runtime = targets
    cfg = contract["xgboost_baseline"]
    common = dict(n_estimators=cfg["n_estimators"], max_depth=cfg["max_depth"],
                  learning_rate=cfg["learning_rate"], subsample=cfg["subsample"],
                  colsample_bytree=cfg["colsample_bytree"], n_jobs=cfg["n_jobs"],
                  tree_method=cfg["tree_method"], random_state=seed, verbosity=0)
    train_x = x_norm[train_indices]
    y_hit = hit[train_indices]
    positives, negatives = y_hit.sum(), len(y_hit) - y_hit.sum()
    if positives <= 0 or negatives <= 0:
        raise TrainingV2Error("XGB_EPSILON_HEAD_SINGLE_CLASS")
    classifier = xgb.XGBClassifier(objective="binary:logistic", eval_metric="logloss",
                                   scale_pos_weight=float(negatives / positives), **common)
    cycle_model = xgb.XGBRegressor(objective="reg:squarederror", **common)
    runtime_model = xgb.XGBRegressor(objective="reg:squarederror", **common)
    classifier.fit(train_x, y_hit)
    cycle_model.fit(train_x, cycles[train_indices])
    runtime_model.fit(train_x, runtime[train_indices])
    probability = classifier.predict_proba(x_norm)[:, 1]
    cycle_norm = cycle_model.predict(x_norm)
    runtime_log = runtime_model.predict(x_norm)
    cycle_pred = np.expm1(cycle_norm) * np.asarray([float(row["common_fault_count"]) for row in features])
    runtime_pred = np.expm1(runtime_log)
    prediction = dict((row["action_uid"], {
        "predicted_epsilon_hit_probability": max(0.0, min(1.0, float(probability[index]))),
        "predicted_cycles": max(1e-9, float(cycle_pred[index])),
        "predicted_runtime_s": max(1e-9, float(runtime_pred[index])),
    }) for index, row in enumerate(features))
    preprocessing = {"feature_names": list(FEATURE_COLUMNS), "x_mean": x_mean.tolist(), "x_std": x_std.tolist()}
    return (classifier, cycle_model, runtime_model), prediction, preprocessing


def _freeze_and_replay(name, features, prediction, package_root, outcome_split, output_root, contract):
    rows = ranking_rows(features, prediction)
    ranking_path = output_root / ("ranking_%s.tsv" % name)
    write_tsv(ranking_path, RANKING_FIELDS, rows)
    freeze = {
        "schema_version": "runtime-v2-ranking-freeze",
        "model": name,
        "ranking_sha256": sha256_file(ranking_path),
        "contract_sha256": sha256_file(output_root / "runtime_training_v2.bound.json"),
        "features_sha256": sha256_file(package_root / "features.tsv"),
        "validation_outcomes_read": False,
        "ranking_rule": contract["ranking"],
    }
    freeze_path = output_root / ("ranking_%s.freeze.json" % name)
    freeze_path.write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Outcome access begins only after the immutable ranking and its receipt exist.
    validate_outcome_split(outcome_split, package_root, contract, validation_access_allowed=True)
    if sha256_file(ranking_path) != read_json(freeze_path)["ranking_sha256"]:
        raise TrainingV2Error("PERSISTED_RANKING_DRIFT")
    persisted_rows = read_tsv(ranking_path)
    replay = replay_validation(persisted_rows, outcome_split / "validation_outcomes.tsv",
                               int(contract["ranking"]["top_k"]))
    replay_path = output_root / ("validation_replay_%s.json" % name)
    replay_path.write_text(json.dumps(replay, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return ranking_path, freeze_path, replay_path


def train(args) -> dict:
    reject_protected_paths((args.contract, args.package, args.stage_seal, args.outcome_split,
                            args.dependency_lock, args.repo, args.output, args.preflight_receipt,
                            args.independent_review))
    np, torch, xgb = _imports()
    contract = read_json(args.contract)
    validate_contract(contract)
    preflight = read_json(args.preflight_receipt)
    review = read_json(args.independent_review)
    expected_implementation = {
        "src/models/runtime_training_v2.py": sha256_file(args.repo / "src/models/runtime_training_v2.py"),
        "src/models/train_runtime_v2.py": sha256_file(args.repo / "src/models/train_runtime_v2.py"),
        "src/models/preflight_runtime_v2.py": sha256_file(args.repo / "src/models/preflight_runtime_v2.py"),
        "src/models/aggregate_runtime_v2.py": sha256_file(args.repo / "src/models/aggregate_runtime_v2.py"),
    }
    if preflight.get("status") != "PASS_ENVIRONMENT_PREFLIGHT":
        raise TrainingV2Error("ENVIRONMENT_PREFLIGHT_STATUS")
    if preflight.get("contract_sha256") != sha256_file(args.contract):
        raise TrainingV2Error("ENVIRONMENT_CONTRACT_BINDING")
    if preflight.get("dependency_lock_sha256") != sha256_file(args.dependency_lock):
        raise TrainingV2Error("ENVIRONMENT_LOCK_BINDING")
    if review.get("status") != "PASS_TRAINER_CODE_GATE":
        raise TrainingV2Error("INDEPENDENT_REVIEW_STATUS")
    if review.get("contract_sha256") != sha256_file(args.contract):
        raise TrainingV2Error("REVIEW_CONTRACT_BINDING")
    if review.get("implementation_sha256") != expected_implementation:
        raise TrainingV2Error("REVIEW_IMPLEMENTATION_BINDING")
    workspace = Path(preflight["workspace"]).resolve()
    output_resolved = args.output.resolve()
    if workspace not in output_resolved.parents or output_resolved.parent.name != "runs":
        raise TrainingV2Error("OUTPUT_OUTSIDE_PREFLIGHT_WORKSPACE")
    requested = parse_lock(args.dependency_lock)
    validate_installed_dependencies(requested)
    if args.seed not in contract["determinism"]["seeds"]:
        raise TrainingV2Error("UNREGISTERED_SEED")
    if args.output.exists():
        raise TrainingV2Error("OUTPUT_MUST_NOT_EXIST")
    args.output.mkdir(parents=True)
    bound_contract = args.output / "runtime_training_v2.bound.json"
    bound_contract.write_bytes(args.contract.read_bytes())
    package = validate_package(args.package, contract, args.stage_seal)
    split_receipt = validate_outcome_split(args.outcome_split, args.package, contract,
                                           validation_access_allowed=False)
    if preflight.get("outcome_split_receipt_sha256") != sha256_file(args.outcome_split / "outcome_split_receipt_v2.json"):
        raise TrainingV2Error("ENVIRONMENT_OUTCOME_SPLIT_BINDING")
    names, scalar_values = build_scalar_features(package.features)
    assert_feature_boundary(names)
    scalar_x = np.asarray(scalar_values, dtype=np.float64)
    train_indices = np.asarray([i for i, row in enumerate(package.features) if row["role"] == "TRAIN"], dtype=np.int64)
    validation_indices = [i for i, row in enumerate(package.features) if row["role"] == "VALIDATION"]
    if not len(train_indices) or not validation_indices:
        raise TrainingV2Error("SPLIT_EMPTY")
    train_uids = {package.features[i]["action_uid"] for i in train_indices}
    train_outcomes = read_training_outcomes_only(args.outcome_split / "train_outcomes.tsv", train_uids)
    targets = _targets(package.features, train_outcomes, np)
    graphs = dict((name, load_graph_tensor(path, contract, torch)) for name, path in package.graphs.items())
    graph_model, graph_prediction, graph_pre, final_loss = _fit_graphsage(
        package.features, scalar_x, train_indices, targets, graphs, contract, args.seed, np, torch)
    xgb_models, xgb_prediction, xgb_pre = _fit_xgboost(
        package.features, scalar_x, train_indices, targets, contract, args.seed, np, xgb)
    checkpoint = args.output / "graphsage.pt"
    torch.save({"state_dict": graph_model.state_dict(), "preprocessing": graph_pre,
                "seed": args.seed, "contract_sha256": sha256_file(args.contract)}, checkpoint)
    for label, model in zip(("epsilon_hit", "cycles", "runtime"), xgb_models):
        model.save_model(args.output / ("xgboost_%s.json" % label))
    (args.output / "xgboost_preprocessing.json").write_text(
        json.dumps(xgb_pre, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    graph_files = _freeze_and_replay("graphsage", package.features, graph_prediction, args.package,
                                     args.outcome_split, args.output, contract)
    xgb_files = _freeze_and_replay("xgboost", package.features, xgb_prediction, args.package,
                                   args.outcome_split, args.output, contract)
    artifacts = [checkpoint, args.output / "xgboost_epsilon_hit.json", args.output / "xgboost_cycles.json",
                 args.output / "xgboost_runtime.json", args.output / "xgboost_preprocessing.json", *graph_files, *xgb_files]
    receipt = {
        "schema_version": "runtime-v2-seed-receipt",
        "status": "PASS_FIXED_SEED_TRAINING",
        "seed": args.seed,
        "git_commit": _git_commit(args.repo),
        "contract_sha256": sha256_file(args.contract),
        "dataset_manifest_sha256": sha256_file(args.package / "runtime_training_package_manifest_v2.json"),
        "dependency_lock_sha256": sha256_file(args.dependency_lock),
        "environment_preflight_sha256": sha256_file(args.preflight_receipt),
        "independent_review_sha256": sha256_file(args.independent_review),
        "outcome_split_receipt_sha256": sha256_file(args.outcome_split / "outcome_split_receipt_v2.json"),
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(),
                        "numpy": np.__version__, "torch": torch.__version__, "xgboost": xgb.__version__},
        "boundaries": {"d95_head_present": False, "blind_rows_read": False,
                       "pilot_rows_read": False, "validation_used_for_training_or_selection": False},
        "counts": {"train_actions": len(train_indices), "validation_actions": len(validation_indices)},
        "graphsage_final_train_loss": final_loss,
        "artifact_sha256": dict((path.name, sha256_file(path)) for path in artifacts),
    }
    receipt_path = args.output / "seed_receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--stage-seal", type=Path, required=True)
    parser.add_argument("--dependency-lock", type=Path, required=True)
    parser.add_argument("--outcome-split", type=Path, required=True)
    parser.add_argument("--preflight-receipt", type=Path, required=True)
    parser.add_argument("--independent-review", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    receipt = train(parse_args(argv))
    print("RUNTIME_V2_TRAINING=%s SEED=%s" % (receipt["status"], receipt["seed"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
