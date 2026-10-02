#!/usr/bin/env python3
"""Independent, exhaustive review of runtime training package v2."""
from __future__ import print_function

import argparse
import csv
import hashlib
import json
import math
import os


FEATURE_FIELDS = ("role", "family", "circuit", "action_uid", "action_scheme",
                  "h_limit", "m_limit", "common_fault_count", "graph_key")
OUTCOME_FIELDS = ("action_uid", "execution_status", "is_d95_feasible",
                  "total_cycles", "policy_charged_runtime_s", "epsilon_hit")
PROVENANCE_FIELDS = ("action_uid", "source_invocation_count", "attempt_session_count",
                     "success_session_count", "failed_session_count",
                     "aggregation_policy", "source_candidate_uids")


class AuditError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise AuditError(code)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path):
    require(os.path.isfile(path) and not os.path.islink(path), "JSON_MISSING_OR_LINK")
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def read_tsv(path, fields=None, code="TSV"):
    require(os.path.isfile(path) and not os.path.islink(path), code + "_MISSING_OR_LINK")
    with open(path, encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if fields is not None:
            require(tuple(reader.fieldnames or ()) == tuple(fields), code + "_FIELDS")
        rows = list(reader)
    require(rows, code + "_EMPTY")
    return rows


def unique(rows, field, code):
    answer = {}
    for row in rows:
        key = row.get(field, "")
        require(key and key not in answer, code)
        answer[key] = row
    return answer


def as_int(raw, code, positive=False):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise AuditError(code)
    require(str(value) == str(raw).strip() and (value > 0 if positive else value >= 0), code)
    return value


def as_float(raw, code):
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise AuditError(code)
    require(math.isfinite(value) and value > 0, code)
    return value


def audit(args):
    package_root = os.path.abspath(args.package_root)
    candidate_root = os.path.abspath(args.candidate_root)
    cost_root = os.path.abspath(args.cost_root)
    manifest_path = os.path.join(package_root, "runtime_training_package_manifest_v2.json")
    manifest = read_json(manifest_path)
    require(manifest.get("schema_version") == "runtime-training-package-v2" and
            manifest.get("status") == "PASS_PACKAGE_INDEPENDENT_REVIEW_PENDING" and
            manifest.get("training_execution_allowed") is False,
            "PACKAGE_MANIFEST_STATUS")

    paths = {
        "features.tsv": os.path.join(package_root, "features.tsv"),
        "outcomes.tsv": os.path.join(package_root, "outcomes.tsv"),
        "action_provenance.tsv": os.path.join(package_root, "action_provenance.tsv"),
        "graph_manifest.tsv": os.path.join(package_root, "graph_manifest.tsv"),
    }
    require(set(manifest.get("output_sha256", {})) == set(paths), "OUTPUT_HASH_SET")
    for name, path in paths.items():
        require(manifest["output_sha256"][name] == sha256_file(path), "OUTPUT_HASH_MISMATCH")

    features = unique(read_tsv(paths["features.tsv"], FEATURE_FIELDS, "FEATURES"),
                      "action_uid", "FEATURE_UID_DUPLICATE")
    outcomes = unique(read_tsv(paths["outcomes.tsv"], OUTCOME_FIELDS, "OUTCOMES"),
                      "action_uid", "OUTCOME_UID_DUPLICATE")
    provenance = unique(read_tsv(paths["action_provenance.tsv"], PROVENANCE_FIELDS,
                                "PROVENANCE"), "action_uid", "PROVENANCE_UID_DUPLICATE")
    require(set(features) == set(outcomes) == set(provenance), "PACKAGE_ACTION_SET")

    candidate_path = os.path.join(candidate_root, "candidate_space_v2.tsv")
    normalized_path = os.path.join(candidate_root, "formal_candidate_measurements_v2.tsv")
    cost_path = os.path.join(cost_root, "action_runtime_costs_v1.tsv")
    review_path = os.path.join(cost_root, "independent_review_v1.json")
    source_paths = {
        "candidate_space": candidate_path,
        "normalized_measurements": normalized_path,
        "candidate_receipt": os.path.join(candidate_root, "receipt_v2.json"),
        "action_runtime_costs": cost_path,
        "cost_receipt": os.path.join(cost_root, "receipt_v1.json"),
        "cost_independent_review": review_path,
        "denominator_receipt": args.denominator_receipt,
        "split_contract": args.split_contract,
        "graph_receipt": os.path.join(args.graph_root, "runtime_graphs_aggregate_receipt_v1.json"),
        "topology_parity_receipt": args.topology_parity_receipt,
    }
    require(set(manifest.get("source_sha256", {})) == set(source_paths), "SOURCE_HASH_SET")
    for name, path in source_paths.items():
        require(manifest["source_sha256"][name] == sha256_file(path), "SOURCE_HASH_MISMATCH")
    require(read_json(review_path).get("status") == "PASS_COST_LABEL_GATE", "COST_REVIEW")
    require(read_json(args.topology_parity_receipt).get("status") ==
            "PASS_TOPOLOGY_PARITY_DIGEST_ONLY", "TOPOLOGY_REVIEW")

    split = read_json(args.split_contract)
    expected, family_roles = {}, {}
    for role in ("TRAIN", "VALIDATION"):
        for item in split["formal_runtime_membership"][role]:
            require(item["family"] not in family_roles, "FAMILY_OVERLAP")
            expected[item["circuit"]] = (role, item["family"])
            family_roles[item["family"]] = role
    require(len(expected) == 8 and manifest.get("formal_runtime_membership_sha256") ==
            split.get("formal_runtime_membership_sha256"), "SPLIT_BINDING")

    denominator = read_json(args.denominator_receipt)
    require(denominator.get("status") == "PASS", "DENOMINATOR_STATUS")
    graph_rows = unique(read_tsv(paths["graph_manifest.tsv"], None, "GRAPHS"),
                        "circuit", "GRAPH_CIRCUIT_DUPLICATE")
    require(set(graph_rows) == set(expected), "GRAPH_ROSTER")
    for graph in graph_rows.values():
        graph_path = os.path.join(package_root, *graph["graph_path"].replace("\\", "/").split("/"))
        require(os.path.isfile(graph_path) and not os.path.islink(graph_path) and
                sha256_file(graph_path) == graph["graph_sha256"], "GRAPH_PAYLOAD")

    actions = unique(read_tsv(candidate_path), "action_uid", "SOURCE_ACTION_UID")
    normalized = unique(read_tsv(normalized_path), "candidate_uid", "SOURCE_CANDIDATE_UID")
    costs = unique(read_tsv(cost_path), "action_uid", "SOURCE_COST_UID")
    require(set(actions) == set(costs) == set(features), "SOURCE_PACKAGE_ACTION_SET")

    oracle = {}
    recalculated = {}
    repeat_count = 0
    for uid in sorted(actions):
        action, cost = actions[uid], costs[uid]
        sources = action["source_candidate_uids"].split("|")
        repeat_count += len(sources) > 1
        require(len(sources) == as_int(action["repeat_measurement_count"], "REPEAT_COUNT", True),
                "REPEAT_SOURCE_COUNT")
        rows = [normalized[source] for source in sources]
        require(all(row["result_status"] == "PASS" and row["eligible_regression"] == "1"
                    for row in rows), "SOURCE_STATUS")
        cycles = {as_int(row["total_cycles"], "TOTAL_CYCLES", True) for row in rows}
        detected = {as_int(row["detected_faults"], "DETECTED") for row in rows}
        require(len(cycles) == 1 and len(detected) == 1, "SOURCE_OUTCOME_CONFLICT")
        circuit = action["circuit"]
        total_cycles, detected_faults = next(iter(cycles)), next(iter(detected))
        denom = denominator["circuits"][circuit]
        require(detected_faults >= as_int(denom["d95"], "D95", True), "D95_UNSAFE")
        require(cost["aggregation_policy"] == "ARITHMETIC_MEAN_ALL_INVOCATIONS",
                "AGGREGATION_POLICY")
        runtime = as_float(cost["wall_time_mean_s"], "RUNTIME")
        recalculated[uid] = (circuit, total_cycles, runtime, sources, action, cost, denom)
        oracle[circuit] = min(oracle.get(circuit, total_cycles), total_cycles)

    epsilon_hits = 0
    roles_seen, families_seen = set(), set()
    for uid, item in recalculated.items():
        circuit, total_cycles, runtime, sources, action, cost, denom = item
        role, family = expected[circuit]
        feature, outcome, prov = features[uid], outcomes[uid], provenance[uid]
        require(feature == {
            "role": role, "family": family, "circuit": circuit, "action_uid": uid,
            "action_scheme": action["action_scheme"], "h_limit": action["h_patterns"],
            "m_limit": action["m_patterns"] or "0",
            "common_fault_count": str(denom["common_fault_count"]),
            "graph_key": graph_rows[circuit]["graph_key"],
        }, "FEATURE_RECALCULATION")
        hit = total_cycles <= oracle[circuit] * 1.01
        epsilon_hits += hit
        require(outcome == {
            "action_uid": uid, "execution_status": "SUCCESS", "is_d95_feasible": "1",
            "total_cycles": str(total_cycles), "policy_charged_runtime_s": "%.9f" % runtime,
            "epsilon_hit": "1" if hit else "0",
        }, "OUTCOME_RECALCULATION")
        require(prov == {
            "action_uid": uid, "source_invocation_count": cost["source_invocation_count"],
            "attempt_session_count": cost["attempt_session_count"],
            "success_session_count": cost["success_session_count"],
            "failed_session_count": cost["failed_session_count"],
            "aggregation_policy": cost["aggregation_policy"],
            "source_candidate_uids": action["source_candidate_uids"],
        }, "PROVENANCE_RECALCULATION")
        roles_seen.add(role); families_seen.add(family)

    require(manifest["circuit_oracle_cycles"] == dict(sorted(oracle.items())), "ORACLE_MANIFEST")
    require(manifest["counts"]["action_count"] == len(features) and
            manifest["counts"]["repeat_action_count"] == repeat_count and
            manifest["counts"]["epsilon_hit_action_count"] == epsilon_hits,
            "COUNT_MANIFEST")
    require(roles_seen == {"TRAIN", "VALIDATION"} and len(families_seen) == 8,
            "FAMILY_ISOLATION")

    receipt = {
        "schema_version": "runtime-training-package-v2-independent-review",
        "status": "PASS_DATASET_PACKAGE_GATE",
        "counts": {
            "action_count": len(features), "circuit_count": len(expected),
            "family_count": len(families_seen), "repeat_action_count": repeat_count,
            "epsilon_hit_action_count": epsilon_hits,
        },
        "gates": {
            "output_hashes_match": True, "source_hashes_match": True,
            "feature_recalculation_exhaustive": True,
            "outcome_recalculation_exhaustive": True,
            "runtime_recalculation_exhaustive": True,
            "epsilon_recalculation_exhaustive": True,
            "graph_payload_hashes_match": True,
            "family_isolated": True, "blind_rows_read": False,
            "fastest_success_selection_used": False,
            "missing_runtime_imputation_used": False,
        },
        "verified_sha256": {
            "package_manifest": sha256_file(manifest_path),
            "features": sha256_file(paths["features.tsv"]),
            "outcomes": sha256_file(paths["outcomes.tsv"]),
            "action_provenance": sha256_file(paths["action_provenance.tsv"]),
        },
        "training_execution_allowed": False,
        "next_gate": "TRAINER_AND_DEPENDENCY_PREFLIGHT",
    }
    require(not os.path.exists(args.output_receipt), "OUTPUT_RECEIPT_EXISTS")
    with open(args.output_receipt, "x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2); stream.write("\n")
    print(json.dumps(receipt, sort_keys=True))
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--candidate-root", required=True)
    parser.add_argument("--cost-root", required=True)
    parser.add_argument("--denominator-receipt", required=True)
    parser.add_argument("--split-contract", required=True)
    parser.add_argument("--graph-root", required=True)
    parser.add_argument("--topology-parity-receipt", required=True)
    parser.add_argument("--output-receipt", required=True)
    args = parser.parse_args(argv)
    try:
        audit(args); return 0
    except (AuditError, OSError, ValueError, KeyError) as exc:
        print("FAIL:%s" % exc); return 1


if __name__ == "__main__":
    raise SystemExit(main())
