#!/usr/bin/env python3
"""Fail-closed accounting for frozen validation Top-k rankings.

This module does not train a model and never calls Tessent.  It consumes a
normalized, non-BLIND runtime-training dataset plus rankings that were frozen
before outcome access.  Costs are charged before an action's outcome is read.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(HERE, "..", "data"))
if DATA_DIR not in sys.path:
    sys.path.insert(0, DATA_DIR)
import validate_runtime_training_package_v1 as package_validator


DATASET_FIELDS = (
    "role", "family", "circuit", "action_uid", "action_scheme", "h_limit",
    "m_limit", "common_fault_count", "execution_status", "is_d95_feasible",
    "total_cycles", "graph_key", "policy_charged_runtime_s", "epsilon_hit",
)
RANKING_FIELDS = ("method", "circuit", "rank", "action_uid")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _value(row: Mapping[str, str], key: str) -> str:
    return str(row.get(key, "")).strip()


def _positive_float(value: str, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("%s must be numeric" % label) from exc
    if not math.isfinite(number) or number <= 0:
        raise ValueError("%s must be finite and positive" % label)
    return number


def _positive_int(value: str, label: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("%s must be an integer" % label) from exc
    if number <= 0:
        raise ValueError("%s must be positive" % label)
    return number


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _repo_root() -> Path:
    return Path(HERE).resolve().parents[1]


def _require_nonsymlink_path(path: Path, kind: str, label: str) -> Path:
    raw = Path(os.path.abspath(os.fspath(path)))
    cursor = raw
    while True:
        if cursor.is_symlink():
            raise ValueError("%s path or parent must not be a symlink" % label)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    if kind == "file" and not raw.is_file():
        raise ValueError("%s must be a regular file" % label)
    if kind == "dir" and not raw.is_dir():
        raise ValueError("%s must be a directory" % label)
    return raw


def _artifact_beside(manifest_path: Path, relative: str) -> Path:
    if not relative or Path(relative).is_absolute():
        raise ValueError("ranking freeze artifact path invalid")
    root = manifest_path.parent.resolve()
    raw_candidate = root / relative
    if raw_candidate.is_symlink():
        raise ValueError("ranking freeze artifact must be a regular non-symlink file")
    cursor = raw_candidate.parent
    while cursor != root:
        if cursor.is_symlink():
            raise ValueError("ranking freeze artifact parent must not be a symlink")
        if cursor.parent == cursor:
            raise ValueError("ranking freeze artifact path escapes root")
        cursor = cursor.parent
    candidate = raw_candidate.resolve()
    if root not in candidate.parents and candidate != root:
        raise ValueError("ranking freeze artifact path escapes root")
    if not candidate.is_file():
        raise ValueError("ranking freeze artifact must be a regular file")
    return candidate


def validate_ranking_freeze(features_path: Path, ranking_path: Path, manifest_path: Path, methods: Sequence[str]) -> dict:
    manifest_path = _require_nonsymlink_path(manifest_path, "file", "ranking freeze manifest")
    ranking_path = _require_nonsymlink_path(ranking_path, "file", "ranking")
    features_path = _require_nonsymlink_path(features_path, "file", "features")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = {
        "schema_version", "status", "features_sha256", "ranking_sha256",
        "training_contract_sha256", "split_contract_sha256", "ranking_generator_path",
        "ranking_generator_sha256", "preoutcome_receipt_path", "preoutcome_receipt_sha256",
        "methods", "ranking_frozen_before_outcome_access", "outcome_files_opened",
    }
    if set(manifest) != expected:
        raise ValueError("ranking freeze manifest schema mismatch")
    root = _repo_root()
    generator_path = _artifact_beside(manifest_path, str(manifest.get("ranking_generator_path", "")))
    receipt_path = _artifact_beside(manifest_path, str(manifest.get("preoutcome_receipt_path", "")))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_fields = {
        "schema_version", "status", "features_sha256", "ranking_sha256",
        "ranking_generator_path", "ranking_generator_sha256", "outcome_artifacts_present",
        "events",
    }
    if set(receipt) != receipt_fields:
        raise ValueError("preoutcome receipt schema mismatch")
    if (manifest["schema_version"] != "runtime-ranking-freeze-v1"
            or manifest["status"] != "FROZEN_BEFORE_OUTCOME_ACCESS"
            or manifest["ranking_frozen_before_outcome_access"] is not True
            or manifest["outcome_files_opened"] is not False
            or manifest["methods"] != list(methods)
            or manifest["features_sha256"] != sha256_file(features_path)
            or manifest["ranking_sha256"] != sha256_file(ranking_path)
            or manifest["training_contract_sha256"] != sha256_file(root / "contracts" / "runtime_training_v1.json")
            or manifest["split_contract_sha256"] != sha256_file(root / "contracts" / "data_split_v1.json")
            or manifest["ranking_generator_sha256"] != sha256_file(generator_path)
            or manifest["preoutcome_receipt_sha256"] != sha256_file(receipt_path)
            or receipt["schema_version"] != "runtime-ranking-preoutcome-receipt-v1"
            or receipt["status"] != "PASS_FROZEN_WITHOUT_OUTCOMES"
            or receipt["features_sha256"] != manifest["features_sha256"]
            or receipt["ranking_sha256"] != manifest["ranking_sha256"]
            or receipt["ranking_generator_path"] != manifest["ranking_generator_path"]
            or receipt["ranking_generator_sha256"] != manifest["ranking_generator_sha256"]
            or receipt["outcome_artifacts_present"] is not False
            or receipt["events"] != ["FEATURES_OPENED", "RANKING_WRITTEN", "RECEIPT_SEALED"]):
        raise ValueError("ranking freeze manifest binding mismatch")
    return manifest


def _append_access_event(path: Path, event: str, previous_sha256: str, binding_sha256: str) -> str:
    payload = {
        "schema_version": "runtime-outcome-access-event-v1",
        "event": event,
        "previous_event_sha256": previous_sha256,
        "binding_sha256": binding_sha256,
    }
    canonical = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    event_sha = hashlib.sha256(canonical).hexdigest()
    record = dict(payload, event_sha256=event_sha)
    mode = "x" if previous_sha256 == "0" * 64 else "a"
    with path.open(mode, encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return event_sha


def read_tsv(path: Path, exact_fields: Sequence[str]) -> List[Dict[str, str]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("input must be a regular non-symlink file: %s" % path)
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if tuple(reader.fieldnames or ()) != tuple(exact_fields):
            raise ValueError("unexpected columns in %s" % path)
        return [dict(row) for row in reader]


def validate_dataset(rows: Iterable[Mapping[str, str]]) -> Dict[str, Dict[str, str]]:
    actions: Dict[str, Dict[str, str]] = {}
    circuit_family: Dict[str, str] = {}
    circuit_oracle: Dict[str, int] = {}
    grouped: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for raw in rows:
        row = {field: _value(raw, field) for field in DATASET_FIELDS}
        if row["role"] != "VALIDATION":
            raise ValueError("replay accepts VALIDATION rows only")
        if not all(row.values()):
            raise ValueError("dataset row contains an empty required field")
        uid = row["action_uid"]
        if uid in actions:
            raise ValueError("duplicate action_uid: %s" % uid)
        _positive_int(row["common_fault_count"], "common_fault_count")
        _positive_float(row["policy_charged_runtime_s"], "policy_charged_runtime_s")
        if row["is_d95_feasible"] not in ("0", "1") or row["epsilon_hit"] not in ("0", "1"):
            raise ValueError("binary fields must be 0 or 1")
        if row["execution_status"] == "SUCCESS":
            _positive_int(row["total_cycles"], "total_cycles")
        elif row["total_cycles"] not in ("0", "NA"):
            raise ValueError("failed action total_cycles must be 0 or NA")
        if row["epsilon_hit"] == "1" and not (
            row["execution_status"] == "SUCCESS" and row["is_d95_feasible"] == "1"
        ):
            raise ValueError("epsilon hit must be successful and D95 feasible")
        circuit = row["circuit"]
        if circuit in circuit_family and circuit_family[circuit] != row["family"]:
            raise ValueError("circuit maps to multiple families")
        circuit_family[circuit] = row["family"]
        actions[uid] = row
        grouped[circuit].append(row)
    if not actions:
        raise ValueError("empty validation dataset")
    for circuit, part in grouped.items():
        feasible_cycles = [
            int(row["total_cycles"]) for row in part
            if row["execution_status"] == "SUCCESS" and row["is_d95_feasible"] == "1"
        ]
        if not feasible_cycles:
            raise ValueError("no successful D95-feasible action for %s" % circuit)
        oracle = min(feasible_cycles)
        circuit_oracle[circuit] = oracle
        for row in part:
            expected = (
                row["execution_status"] == "SUCCESS"
                and row["is_d95_feasible"] == "1"
                and int(row["total_cycles"]) <= oracle * 1.01 + 1e-12
            )
            if (row["epsilon_hit"] == "1") != expected:
                raise ValueError("epsilon_hit does not match measured oracle for %s" % circuit)
    return actions


def replay(
    dataset_rows: Iterable[Mapping[str, str]],
    ranking_rows: Iterable[Mapping[str, str]],
    methods: Sequence[str],
    top_k: int = 10,
) -> Dict[str, object]:
    if top_k != 10:
        raise ValueError("primary top_k must equal 10")
    actions = validate_dataset(dataset_rows)
    actions_by_circuit: Dict[str, set] = defaultdict(set)
    for uid, row in actions.items():
        actions_by_circuit[row["circuit"]].add(uid)
    method_set = tuple(methods)
    if len(method_set) != 3 or len(set(method_set)) != 3:
        raise ValueError("exactly three distinct preregistered methods are required")
    rankings: Dict[tuple, List[Dict[str, str]]] = defaultdict(list)
    seen_pairs = set()
    for raw in ranking_rows:
        row = {field: _value(raw, field) for field in RANKING_FIELDS}
        if not all(row.values()):
            raise ValueError("ranking row contains an empty required field")
        if row["method"] not in method_set:
            raise ValueError("unregistered method")
        if row["action_uid"] not in actions:
            raise ValueError("ranking references unknown action")
        if actions[row["action_uid"]]["circuit"] != row["circuit"]:
            raise ValueError("ranking circuit/action mismatch")
        pair = (row["method"], row["action_uid"])
        if pair in seen_pairs:
            raise ValueError("duplicate method/action ranking")
        seen_pairs.add(pair)
        rankings[(row["method"], row["circuit"])].append(row)
    per_circuit = []
    action_space_hashes: Dict[str, str] = {}
    for circuit, expected_actions in sorted(actions_by_circuit.items()):
        canonical = "\n".join(sorted(expected_actions)) + "\n"
        action_space_hashes[circuit] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        for method in method_set:
            part = rankings.get((method, circuit), [])
            if {row["action_uid"] for row in part} != expected_actions:
                raise ValueError("every method must rank the identical full action space")
            ordered = sorted(part, key=lambda row: int(row["rank"]))
            if [int(row["rank"]) for row in ordered] != list(range(1, len(ordered) + 1)):
                raise ValueError("ranks must be contiguous and one-based")
            charged = 0.0
            hit_rank = 0
            attempted = 0
            for rank_row in ordered[:top_k]:
                action = actions[rank_row["action_uid"]]
                charged += _positive_float(action["policy_charged_runtime_s"], "runtime")
                attempted += 1
                if action["epsilon_hit"] == "1":
                    hit_rank = attempted
                    break
            sample = actions[ordered[0]["action_uid"]]
            per_circuit.append({
                "method": method,
                "family": sample["family"],
                "circuit": circuit,
                "success_at_k": 1 if hit_rank else 0,
                "hit_rank": hit_rank,
                "attempted_actions": attempted,
                "cumulative_runtime_s": charged,
                "action_space_sha256": action_space_hashes[circuit],
            })
    aggregate = []
    for method in method_set:
        method_rows = [row for row in per_circuit if row["method"] == method]
        by_family: Dict[str, List[dict]] = defaultdict(list)
        for row in method_rows:
            by_family[row["family"]].append(row)
        family_rows = []
        for family, part in sorted(by_family.items()):
            family_rows.append({
                "family": family,
                "success_rate": sum(row["success_at_k"] for row in part) / len(part),
                "mean_cumulative_runtime_s": sum(row["cumulative_runtime_s"] for row in part) / len(part),
            })
        aggregate.append({
            "method": method,
            "family_count": len(family_rows),
            "family_macro_success_at_k": sum(row["success_rate"] for row in family_rows) / len(family_rows),
            "family_macro_cumulative_runtime_s": sum(row["mean_cumulative_runtime_s"] for row in family_rows) / len(family_rows),
        })
    return {
        "schema_version": "runtime-topk-replay-v1",
        "status": "PASS_VALIDATION_REPLAY",
        "top_k": top_k,
        "epsilon": 0.01,
        "cost_charged_before_outcome_access": True,
        "action_space_sha256_by_circuit": action_space_hashes,
        "per_circuit": per_circuit,
        "aggregate_family_macro": aggregate,
        "blind_rows_read": False,
    }


def _load_output_package(package_root: Path) -> tuple:
    package_validator.validate_output_package(str(package_root))
    features_path = package_root / "features.tsv"
    outcomes_path = package_root / "outcomes.tsv"
    feature_rows = read_tsv(features_path, package_validator.FEATURE_FIELDS)
    outcome_rows = read_tsv(outcomes_path, package_validator.OUTCOME_FIELDS)
    outcomes = {row["action_uid"]: row for row in outcome_rows}
    if len(outcomes) != len(outcome_rows):
        raise ValueError("duplicate outcome action")
    split = json.loads((_repo_root() / "contracts" / "data_split_v1.json").read_text(encoding="utf-8"))
    validation = {item["circuit"]: item["family"] for item in split["formal_runtime_membership"]["VALIDATION"]}
    combined = []
    for feature in feature_rows:
        if feature["role"] != "VALIDATION" or validation.get(feature["circuit"]) != feature["family"]:
            continue
        outcome = outcomes.get(feature["action_uid"])
        if outcome is None:
            raise ValueError("missing outcome action")
        row = dict(feature)
        row.update({key: value for key, value in outcome.items() if key != "action_uid"})
        combined.append(row)
    if not combined:
        raise ValueError("package contains no validation rows")
    return features_path, combined


def run_cli(package_root: Path, ranking_path: Path, ranking_freeze_path: Path, access_ledger_path: Path, output_path: Path, methods: Sequence[str]) -> None:
    if output_path.exists() or access_ledger_path.exists():
        raise ValueError("output or access ledger path already exists")
    package_root = _require_nonsymlink_path(package_root, "dir", "package root")
    ranking_path = _require_nonsymlink_path(ranking_path, "file", "ranking")
    ranking_freeze_path = _require_nonsymlink_path(ranking_freeze_path, "file", "ranking freeze manifest")
    features_path = Path(package_validator._under(str(package_root), "features.tsv"))
    if not features_path.is_file() or features_path.is_symlink():
        raise ValueError("features must be a regular non-symlink package file")
    validate_ranking_freeze(features_path, ranking_path, ranking_freeze_path, methods)
    rankings = read_tsv(ranking_path, RANKING_FIELDS)
    freeze_sha = sha256_file(ranking_freeze_path)
    first_sha = _append_access_event(
        access_ledger_path, "PREOUTCOME_RECEIPT_VERIFIED", "0" * 64, freeze_sha
    )
    features_path, dataset = _load_output_package(package_root)
    _append_access_event(
        access_ledger_path, "OUTCOMES_OPENED_AFTER_FREEZE", first_sha,
        sha256_file(package_root / "outcomes.tsv"),
    )
    result = replay(dataset, rankings, methods)
    result["package_manifest_sha256"] = sha256_file(package_root / "runtime_training_package_manifest_v1.json")
    result["features_sha256"] = sha256_file(features_path)
    result["ranking_sha256"] = sha256_file(ranking_path)
    result["ranking_freeze_sha256"] = sha256_file(ranking_freeze_path)
    result["outcome_access_ledger_sha256"] = sha256_file(access_ledger_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
