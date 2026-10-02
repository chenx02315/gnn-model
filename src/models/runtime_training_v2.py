#!/usr/bin/env python3
"""Fail-closed helpers for the safe-by-construction runtime-v2 trainer.

Heavy ML dependencies are imported only by the execution path.  Contract,
package, feature-boundary, and ranking tests therefore run in a clean Python
installation without accidentally weakening the dependency preflight.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple


IDENTIFIERS = ("action_uid", "circuit", "family", "role", "graph_key")
FEATURE_COLUMNS = (
    "scheme_hf", "scheme_hmf", "log1p_h_limit", "log1p_m_limit",
    "h_limit_fraction_of_circuit_max", "m_limit_fraction_of_circuit_max",
    "log1p_common_fault_count",
)
OUTCOME_COLUMNS = (
    "action_uid", "execution_status", "is_d95_feasible", "total_cycles",
    "policy_charged_runtime_s", "epsilon_hit",
)
FORBIDDEN_FEATURE_TOKENS = (
    "cycle", "runtime", "elapsed", "epsilon", "outcome", "status",
    "feasible", "detected", "faults_detected", "attempt", "retry",
)


class TrainingV2Error(RuntimeError):
    pass


PROTECTED_ROOT = "/ssd/cjc/multimode_ate_gnn_v1"


def reject_protected_paths(paths: Iterable[Path]) -> None:
    for path in paths:
        candidates = {path.as_posix(), path.resolve(strict=False).as_posix()}
        for resolved in candidates:
            if resolved == PROTECTED_ROOT or resolved.startswith(PROTECTED_ROOT + "/"):
                raise TrainingV2Error("PROTECTED_PATH:%s" % resolved)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_sha256(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TrainingV2Error("JSON_OBJECT_REQUIRED:%s" % path)
    return value


def read_tsv(path: Path) -> List[dict]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def write_tsv(path: Path, fields: Sequence[str], rows: Iterable[Mapping[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(fields), delimiter="\t", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(dict((field, row[field]) for field in fields))


def validate_contract(contract: Mapping[str, object]) -> None:
    require = lambda ok, code: None if ok else (_ for _ in ()).throw(TrainingV2Error(code))
    require(contract.get("schema_version") == "runtime-training-v2", "CONTRACT_SCHEMA")
    safety = contract.get("safety", {})
    require(safety.get("d95_head_present") is False, "D95_HEAD_MUST_BE_ABSENT")
    require(safety.get("all_actions_d95_safe_required") is True, "SAFE_CONSTRUCTION_REQUIRED")
    heads = contract.get("graphsage", {}).get("heads", [])
    require(heads == ["epsilon_hit_logit", "normalized_cycles", "runtime"], "MODEL_HEADS")
    require(contract.get("determinism", {}).get("seeds") == [20260824, 20260825, 20260826], "SEEDS")
    require(contract.get("determinism", {}).get("seed_selection_allowed") is False, "SEED_SELECTION")
    require(contract.get("scope", {}).get("forbidden_roles") == ["PILOT", "BLIND_TEST"], "FORBIDDEN_ROLES")
    require(contract.get("ranking", {}).get("cost_aware_score") ==
            "predicted_epsilon_hit_probability/max(predicted_runtime_s,1e-9)", "RANKING_RULE")


@dataclass(frozen=True)
class PackageData:
    features: List[dict]
    graphs: Dict[str, Path]
    manifest: dict


def validate_role_family_mapping(features: Sequence[Mapping[str, str]], contract: Mapping[str, object]) -> None:
    mapping = {}
    for row in features:
        key = (row["role"], row["circuit"])
        if key in mapping and mapping[key] != row["family"]:
            raise TrainingV2Error("FAMILY_DRIFT:%s" % row["circuit"])
        mapping[key] = row["family"]
    expected_mapping = contract["scope"]["exact_role_family_mapping"]
    actual_mapping = {}
    for (role, circuit), family in mapping.items():
        actual_mapping.setdefault(role, {})[circuit] = family
    if actual_mapping != expected_mapping:
        raise TrainingV2Error("EXACT_ROLE_FAMILY_MAPPING")
    if len(set(mapping.values())) != len(mapping):
        raise TrainingV2Error("FAMILY_ISOLATION")


def validate_package(package_root: Path, contract: Mapping[str, object], stage_seal_path: Path) -> PackageData:
    manifest_path = package_root / "runtime_training_package_manifest_v2.json"
    review_path = package_root / "independent_review_v2.json"
    manifest = read_json(manifest_path)
    review = read_json(review_path)
    anchors = contract["trust_anchors"]
    checks = {
        "DATASET_MANIFEST_SHA": sha256_file(manifest_path) == anchors["dataset_manifest_sha256"],
        "DATASET_REVIEW_SHA": sha256_file(review_path) == anchors["dataset_independent_review_sha256"],
        "STAGE_SEAL_SHA": sha256_file(stage_seal_path) == anchors["stage_seal_sha256"],
        "FEATURES_SHA": sha256_file(package_root / "features.tsv") == anchors["features_sha256"],
        "GRAPH_MANIFEST_SHA": sha256_file(package_root / "graph_manifest.tsv") == anchors["graph_manifest_sha256"],
        "PACKAGE_STATUS": manifest.get("status") == "PASS_PACKAGE_INDEPENDENT_REVIEW_PENDING",
        "REVIEW_STATUS": review.get("status") == "PASS_DATASET_PACKAGE_GATE",
        "ALL_D95_SAFE": manifest.get("gates", {}).get("all_actions_d95_safe") is True,
        "BLIND_NOT_READ": manifest.get("gates", {}).get("blind_rows_read") is False,
    }
    failed = sorted(code for code, ok in checks.items() if not ok)
    if failed:
        raise TrainingV2Error("PACKAGE_GATE:" + ",".join(failed))
    features = read_tsv(package_root / "features.tsv")
    if len(features) != manifest.get("counts", {}).get("action_count"):
        raise TrainingV2Error("FEATURE_COUNT")
    if len({row["action_uid"] for row in features}) != len(features):
        raise TrainingV2Error("ACTION_UID_UNIQUE")
    roles = {row["role"] for row in features}
    if not roles <= {"TRAIN", "VALIDATION"}:
        raise TrainingV2Error("FORBIDDEN_ROLE_PRESENT")
    validate_role_family_mapping(features, contract)
    if manifest.get("formal_runtime_membership_sha256") != anchors["formal_runtime_membership_sha256"]:
        raise TrainingV2Error("MEMBERSHIP_SHA")
    seal = read_json(stage_seal_path)
    if seal.get("status") != "PASS_DATASET_PACKAGE_GATE_TRAINER_PREFLIGHT_PENDING":
        raise TrainingV2Error("STAGE_SEAL_STATUS")
    if seal.get("package", {}).get("manifest_sha256") != anchors["dataset_manifest_sha256"]:
        raise TrainingV2Error("STAGE_SEAL_MANIFEST_BINDING")
    graph_rows = read_tsv(package_root / "graph_manifest.tsv")
    graphs = {}
    for row in graph_rows:
        graph_path = package_root / row["graph_path"]
        if sha256_file(graph_path) != row["graph_sha256"]:
            raise TrainingV2Error("GRAPH_SHA:%s" % row["circuit"])
        graphs[row["graph_key"]] = graph_path
    if {row["graph_key"] for row in features} != set(graphs):
        raise TrainingV2Error("GRAPH_KEY_SET")
    return PackageData(features=features, graphs=graphs, manifest=manifest)


def validate_outcome_split(split_root: Path, package_root: Path, contract: Mapping[str, object],
                           validation_access_allowed: bool = False) -> dict:
    if split_root.is_symlink() or not split_root.is_dir():
        raise TrainingV2Error("OUTCOME_SPLIT_ROOT")
    for name in ("outcome_split_receipt_v2.json", "train_outcomes.tsv", "validation_outcomes.tsv"):
        path = split_root / name
        if path.is_symlink() or not path.is_file():
            raise TrainingV2Error("OUTCOME_SPLIT_FILE:%s" % name)
    receipt = read_json(split_root / "outcome_split_receipt_v2.json")
    anchors = contract["trust_anchors"]
    checks = {
        "SPLIT_RECEIPT_SHA": sha256_file(split_root / "outcome_split_receipt_v2.json") == anchors["outcome_split_receipt_sha256"],
        "SPLIT_STATUS": receipt.get("status") == "PASS_OUTCOME_ROLE_SPLIT",
        "SOURCE_OUTCOMES_SHA": receipt.get("source_outcomes_sha256") == contract["trust_anchors"]["outcomes_sha256"],
        "SOURCE_FEATURES_SHA": receipt.get("source_features_sha256") == contract["trust_anchors"]["features_sha256"],
        "TRAIN_OUTCOMES_SHA": sha256_file(split_root / "train_outcomes.tsv") == receipt.get("train_outcomes_sha256") == anchors["train_outcomes_sha256"],
        "TRAIN_COUNT": receipt.get("train_count") == 1706,
        "VALIDATION_COUNT": receipt.get("validation_count") == 815,
    }
    if validation_access_allowed:
        checks["VALIDATION_OUTCOMES_SHA"] = (
            sha256_file(split_root / "validation_outcomes.tsv") == receipt.get("validation_outcomes_sha256") == anchors["validation_outcomes_sha256"])
    failed = sorted(code for code, ok in checks.items() if not ok)
    if failed:
        raise TrainingV2Error("OUTCOME_SPLIT_GATE:" + ",".join(failed))
    return receipt


def build_scalar_features(rows: Sequence[Mapping[str, str]]) -> Tuple[List[str], List[List[float]]]:
    """Build decision-time scalar features without reading any outcome table."""
    maxima: Dict[str, Tuple[int, int]] = {}
    for row in rows:
        h, m = int(row["h_limit"]), int(row["m_limit"])
        old = maxima.get(row["circuit"], (0, 0))
        maxima[row["circuit"]] = (max(old[0], h), max(old[1], m))
    values = []
    for row in rows:
        scheme = row["action_scheme"]
        if scheme not in ("HF", "HMF"):
            raise TrainingV2Error("ACTION_SCHEME:%s" % scheme)
        h, m = int(row["h_limit"]), int(row["m_limit"])
        hmax, mmax = maxima[row["circuit"]]
        values.append([
            1.0 if scheme == "HF" else 0.0,
            1.0 if scheme == "HMF" else 0.0,
            math.log1p(h), math.log1p(m),
            h / float(max(hmax, 1)), m / float(max(mmax, 1)),
            math.log1p(int(row["common_fault_count"])),
        ])
    return list(FEATURE_COLUMNS), values


def assert_feature_boundary(names: Sequence[str]) -> None:
    if list(names) != list(FEATURE_COLUMNS):
        raise TrainingV2Error("FEATURE_ALLOWLIST")
    lowered = [name.lower() for name in names]
    bad = [name for name in lowered if any(token in name for token in FORBIDDEN_FEATURE_TOKENS)]
    # common_fault_count is an allowed decision-time denominator; the generic
    # token check intentionally exempts its log transform.
    bad = [name for name in bad if name != "log1p_common_fault_count"]
    if bad:
        raise TrainingV2Error("FEATURE_LEAKAGE:" + ",".join(bad))


def read_training_outcomes_only(path: Path, train_action_uids: set[str]) -> Dict[str, dict]:
    """Materialize only TRAIN outcomes; skipped rows are not parsed beyond UID."""
    result = {}
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if tuple(reader.fieldnames or ()) != OUTCOME_COLUMNS:
            raise TrainingV2Error("OUTCOME_SCHEMA")
        for raw in reader:
            uid = raw["action_uid"]
            if uid not in train_action_uids:
                continue
            row = {
                "action_uid": uid,
                "execution_status": raw["execution_status"],
                "is_d95_feasible": int(raw["is_d95_feasible"]),
                "total_cycles": int(raw["total_cycles"]),
                "policy_charged_runtime_s": float(raw["policy_charged_runtime_s"]),
                "epsilon_hit": int(raw["epsilon_hit"]),
            }
            if row["execution_status"] != "SUCCESS" or row["is_d95_feasible"] != 1:
                raise TrainingV2Error("TRAIN_ACTION_NOT_SAFE_SUCCESS:%s" % uid)
            if row["total_cycles"] <= 0 or row["policy_charged_runtime_s"] <= 0:
                raise TrainingV2Error("TRAIN_TARGET_NONPOSITIVE:%s" % uid)
            result[uid] = row
    if set(result) != train_action_uids:
        raise TrainingV2Error("TRAIN_OUTCOME_COVERAGE")
    return result


def standardizer(matrix, train_indices, np):
    train = matrix[train_indices]
    mean = train.mean(axis=0)
    std = train.std(axis=0)
    std[std < 1e-12] = 1.0
    return (matrix - mean) / std, mean, std


def seed_everything(seed: int, torch, np) -> None:
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)


def _hash_bucket(value: str, buckets: int) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest(), 16) % buckets


def load_graph_tensor(path: Path, contract: Mapping[str, object], torch):
    raw = read_json(path)
    if raw.get("schema_version") != "runtime-graph-v1":
        raise TrainingV2Error("GRAPH_SCHEMA")
    nodes = raw.get("nodes")
    edges = raw.get("edge_index")
    if not isinstance(nodes, list) or not nodes:
        raise TrainingV2Error("GRAPH_NODES")
    cfg = contract["features"]
    nt_buckets, ct_buckets = cfg["node_type_buckets"], cfg["cell_type_hash_buckets"]
    dim = nt_buckets + ct_buckets + 1
    x = torch.zeros((len(nodes), dim), dtype=torch.float32)
    for index, node in enumerate(nodes):
        x[index, _hash_bucket(str(node["node_type"]), nt_buckets)] = 1.0
        x[index, nt_buckets + _hash_bucket(str(node["cell_type"]), ct_buckets)] = 1.0
        x[index, -1] = 1.0 if node["sequential_flag"] else 0.0
    if edges:
        edge = torch.tensor(edges, dtype=torch.long).t().contiguous()
        if edge.min().item() < 0 or edge.max().item() >= len(nodes):
            raise TrainingV2Error("GRAPH_EDGE_RANGE")
    else:
        edge = torch.empty((2, 0), dtype=torch.long)
    return x, edge


def make_graphsage_model(torch, node_dim: int, candidate_dim: int, contract: Mapping[str, object]):
    nn = torch.nn
    hidden = int(contract["graphsage"]["hidden_dim"])

    class MeanSAGE(nn.Module):
        def __init__(self, in_dim, out_dim):
            super().__init__()
            self.self_linear = nn.Linear(in_dim, out_dim)
            self.neighbor_linear = nn.Linear(in_dim, out_dim, bias=False)

        def forward(self, x, edge_index):
            src, dst = edge_index[0], edge_index[1]
            aggregate = torch.zeros_like(x)
            degree = torch.zeros((x.shape[0], 1), dtype=x.dtype, device=x.device)
            if src.numel():
                aggregate.index_add_(0, dst, x[src])
                degree.index_add_(0, dst, torch.ones((dst.numel(), 1), dtype=x.dtype, device=x.device))
            aggregate = aggregate / degree.clamp_min(1.0)
            return self.self_linear(x) + self.neighbor_linear(aggregate)

    class RuntimeV2Model(nn.Module):
        def __init__(self):
            super().__init__()
            self.sage1 = MeanSAGE(node_dim, hidden)
            self.sage2 = MeanSAGE(hidden, hidden)
            candidate_hidden = list(contract["graphsage"]["candidate_mlp_hidden"])
            fusion_hidden = list(contract["graphsage"]["fusion_mlp_hidden"])
            candidate_layers = []
            last = candidate_dim
            for width in candidate_hidden:
                candidate_layers.extend([nn.Linear(last, int(width)), nn.ReLU()])
                last = int(width)
            self.candidate_encoder = nn.Sequential(*candidate_layers)
            fusion_layers = []
            last = hidden + last
            for width in fusion_hidden:
                fusion_layers.extend([nn.Linear(last, int(width)), nn.ReLU()])
                last = int(width)
            self.shared = nn.Sequential(*fusion_layers)
            self.hit = nn.Linear(last, 1)
            self.cycles = nn.Linear(last, 1)
            self.runtime = nn.Linear(last, 1)

        def encode(self, graph):
            x, edge = graph
            x = torch.relu(self.sage1(x, edge))
            x = torch.relu(self.sage2(x, edge))
            return x.mean(dim=0)

        def forward(self, graphs, circuit_ids, candidate_x):
            embeddings = dict((name, self.encode(graph)) for name, graph in graphs.items())
            graph_x = torch.stack([embeddings[name] for name in circuit_ids])
            candidate_embedding = self.candidate_encoder(candidate_x)
            shared = self.shared(torch.cat([graph_x, candidate_embedding], dim=1))
            return self.hit(shared).squeeze(1), self.cycles(shared).squeeze(1), self.runtime(shared).squeeze(1)

    return RuntimeV2Model()


def ranking_rows(features: Sequence[Mapping[str, str]], predictions: Mapping[str, Mapping[str, float]]) -> List[dict]:
    rows = []
    for feature in features:
        pred = predictions[feature["action_uid"]]
        runtime = max(float(pred["predicted_runtime_s"]), 1e-9)
        rows.append({
            "role": feature["role"], "family": feature["family"], "circuit": feature["circuit"],
            "action_uid": feature["action_uid"], "action_scheme": feature["action_scheme"],
            "h_limit": int(feature["h_limit"]), "m_limit": int(feature["m_limit"]),
            "predicted_epsilon_hit_probability": "%.12g" % float(pred["predicted_epsilon_hit_probability"]),
            "predicted_cycles": "%.12g" % float(pred["predicted_cycles"]),
            "predicted_runtime_s": "%.12g" % runtime,
            "cost_aware_score": "%.12g" % (float(pred["predicted_epsilon_hit_probability"]) / runtime),
        })
    return rows


RANKING_FIELDS = (
    "role", "family", "circuit", "action_uid", "action_scheme", "h_limit", "m_limit",
    "predicted_epsilon_hit_probability", "predicted_cycles", "predicted_runtime_s", "cost_aware_score",
)


def ordered_actions(rows: Sequence[Mapping[str, str]], method: str) -> List[Mapping[str, str]]:
    if method == "fixed_heuristic":
        return sorted(rows, key=lambda r: (-int(r["action_scheme"] == "HMF"), -int(r["h_limit"]),
                                           -int(r["m_limit"]), r["action_uid"]))
    if method == "predicted_cycles":
        return sorted(rows, key=lambda r: (float(r["predicted_cycles"]), r["action_uid"]))
    if method == "cost_aware":
        return sorted(rows, key=lambda r: (-float(r["cost_aware_score"]),
                                           float(r["predicted_cycles"]), r["action_uid"]))
    raise TrainingV2Error("UNKNOWN_METHOD:%s" % method)


def replay_validation(ranking: Sequence[Mapping[str, str]], outcomes_path: Path, top_k: int = 10) -> dict:
    validation = [row for row in ranking if row["role"] == "VALIDATION"]
    allowed = {row["action_uid"] for row in validation}
    outcomes = {}
    for row in read_tsv(outcomes_path):
        if row["action_uid"] in allowed:
            outcomes[row["action_uid"]] = row
    if set(outcomes) != allowed:
        raise TrainingV2Error("VALIDATION_OUTCOME_COVERAGE")
    by_circuit: Dict[str, List[Mapping[str, str]]] = {}
    for row in validation:
        by_circuit.setdefault(row["circuit"], []).append(row)
    result = {"methods": {}, "top_k": top_k, "aggregation": "family_equal_macro_average"}
    for method in ("fixed_heuristic", "predicted_cycles", "cost_aware"):
        circuit_rows = []
        for circuit in sorted(by_circuit):
            cost, hit, attempts = 0.0, False, 0
            for row in ordered_actions(by_circuit[circuit], method)[:top_k]:
                outcome = outcomes[row["action_uid"]]
                cost += float(outcome["policy_charged_runtime_s"])
                attempts += 1
                if outcome["epsilon_hit"] == "1":
                    hit = True
                    break
            circuit_rows.append({"circuit": circuit, "family": by_circuit[circuit][0]["family"],
                                 "charged_runtime_s": cost, "epsilon_hit": hit, "attempts": attempts})
        result["methods"][method] = {
            "circuits": circuit_rows,
            "family_macro_mean_charged_runtime_s": sum(r["charged_runtime_s"] for r in circuit_rows) / len(circuit_rows),
            "family_macro_hit_rate": sum(1.0 for r in circuit_rows if r["epsilon_hit"]) / len(circuit_rows),
        }
    return result
