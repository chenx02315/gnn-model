#!/usr/bin/env python3
"""Build the audited eight-circuit non-BLIND runtime training package v2."""
from __future__ import print_function

import argparse
import csv
import hashlib
import json
import math
import os
import shutil
import tempfile


FEATURE_FIELDS = (
    "role", "family", "circuit", "action_uid", "action_scheme", "h_limit",
    "m_limit", "common_fault_count", "graph_key",
)
OUTCOME_FIELDS = (
    "action_uid", "execution_status", "is_d95_feasible", "total_cycles",
    "policy_charged_runtime_s", "epsilon_hit",
)
PROVENANCE_FIELDS = (
    "action_uid", "source_invocation_count", "attempt_session_count",
    "success_session_count", "failed_session_count", "aggregation_policy",
    "source_candidate_uids",
)
ACTION_FIELDS = (
    "action_uid", "circuit", "action_scheme", "mode_stack", "h_patterns",
    "m_patterns", "repeat_measurement_count", "source_candidate_uids",
    "source_stages", "outcome_conflict", "outcome_conflict_fields",
)
COST_FIELDS = (
    "action_uid", "circuit", "action_scheme", "h_patterns", "m_patterns",
    "source_invocation_count", "attempt_session_count", "success_session_count",
    "failed_session_count", "wall_time_mean_s", "wall_time_population_stddev_s",
    "wall_time_min_invocation_s", "wall_time_max_invocation_s", "aggregation_policy",
)
GRAPH_FIELDS = ("graph_key", "circuit", "graph_path", "graph_sha256")


class BuildError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise BuildError(code)


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


def read_tsv(path, fields, code):
    require(os.path.isfile(path) and not os.path.islink(path), code + "_MISSING_OR_LINK")
    with open(path, encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        require(tuple(reader.fieldnames or ()) == tuple(fields), code + "_FIELDS")
        rows = list(reader)
    require(rows, code + "_EMPTY")
    return rows


def write_tsv(path, fields, rows):
    with open(path, "x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t",
                                lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def positive_int(raw, code):
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise BuildError(code)
    require(value > 0 and str(value) == str(raw).strip(), code)
    return value


def nonnegative_int(raw, code):
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise BuildError(code)
    require(value >= 0 and str(value) == str(raw).strip(), code)
    return value


def positive_float(raw, code):
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError):
        raise BuildError(code)
    require(math.isfinite(value) and value > 0, code)
    return value


def keyed(rows, key, code):
    answer = {}
    for row in rows:
        value = (row.get(key) or "").strip()
        require(value and value not in answer, code)
        answer[value] = row
    return answer


def split_membership(path):
    split = read_json(path)
    membership = split.get("formal_runtime_membership")
    canonical = json.dumps(membership, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    require(hashlib.sha256(canonical).hexdigest() ==
            split.get("formal_runtime_membership_sha256"), "SPLIT_DIGEST")
    result, families = {}, {}
    for role in ("TRAIN", "VALIDATION"):
        for item in membership.get(role, []):
            circuit, family = item.get("circuit"), item.get("family")
            require(circuit and family and circuit not in result, "SPLIT_MEMBERSHIP")
            require(family not in families, "SPLIT_FAMILY_OVERLAP")
            result[circuit] = (role, family)
            families[family] = role
    require(len(result) == 8 and len(families) == 8, "SPLIT_NONBLIND_ROSTER")
    return split, result


def verify_source_hash(receipt, section, name, path, code):
    expected = receipt.get(section, {}).get(name)
    require(expected and sha256_file(path) == expected, code)


def build(args):
    candidate_root = os.path.abspath(args.candidate_root)
    cost_root = os.path.abspath(args.cost_root)
    graph_root = os.path.abspath(args.graph_root)
    output_root = os.path.abspath(args.output_root)
    require(not os.path.exists(output_root), "OUTPUT_ROOT_EXISTS")
    require(os.path.isdir(os.path.dirname(output_root)), "OUTPUT_PARENT_MISSING")

    candidate_path = os.path.join(candidate_root, "candidate_space_v2.tsv")
    normalized_path = os.path.join(candidate_root, "formal_candidate_measurements_v2.tsv")
    candidate_receipt_path = os.path.join(candidate_root, "receipt_v2.json")
    candidate_receipt = read_json(candidate_receipt_path)
    require(candidate_receipt.get("status") == "PASS_BUILD_REPEAT_AGGREGATION_PENDING",
            "CANDIDATE_STATUS")
    verify_source_hash(candidate_receipt, "sha256", "candidate_space",
                       candidate_path, "CANDIDATE_SHA256")
    verify_source_hash(candidate_receipt, "sha256", "normalized_measurements",
                       normalized_path, "NORMALIZED_SHA256")

    cost_path = os.path.join(cost_root, "action_runtime_costs_v1.tsv")
    cost_receipt_path = os.path.join(cost_root, "receipt_v1.json")
    cost_review_path = os.path.join(cost_root, "independent_review_v1.json")
    cost_receipt = read_json(cost_receipt_path)
    cost_review = read_json(cost_review_path)
    require(cost_review.get("status") == "PASS_COST_LABEL_GATE", "COST_REVIEW_STATUS")
    require(cost_review.get("boundaries", {}).get("training_allowed") is False,
            "COST_REVIEW_BOUNDARY")
    require(cost_review.get("verified_sha256", {}).get("action_runtime_costs") ==
            sha256_file(cost_path), "COST_SHA256")
    require(cost_review.get("verified_sha256", {}).get("aggregation_receipt") ==
            sha256_file(cost_receipt_path), "COST_RECEIPT_SHA256")

    denominator = read_json(args.denominator_receipt)
    require(denominator.get("status") == "PASS" and
            denominator.get("candidate_or_outcome_data_read") is False,
            "DENOMINATOR_STATUS")
    topology = read_json(args.topology_parity_receipt)
    require(topology.get("status") == "PASS_TOPOLOGY_PARITY_DIGEST_ONLY" and
            topology.get("graph_count") == 8 and
            topology.get("raw_nodes_or_edges_persisted") is False,
            "TOPOLOGY_PARITY_STATUS")

    graph_manifest_path = os.path.join(graph_root, "graph_manifest.tsv")
    graph_receipt_path = os.path.join(graph_root, "runtime_graphs_aggregate_receipt_v1.json")
    require(topology.get("local_receipt_sha256") == sha256_file(graph_receipt_path),
            "TOPOLOGY_LOCAL_RECEIPT_SHA256")
    graph_receipt = read_json(graph_receipt_path)
    require(graph_receipt.get("graph_manifest_sha256") == sha256_file(graph_manifest_path),
            "GRAPH_MANIFEST_SHA256")
    graphs = read_tsv(graph_manifest_path, GRAPH_FIELDS, "GRAPH_MANIFEST")
    graph_by_circuit = keyed(graphs, "circuit", "GRAPH_CIRCUIT_DUPLICATE")
    require(len(graph_by_circuit) == 8, "GRAPH_COUNT")
    for graph in graphs:
        relative = graph["graph_path"].replace("\\", "/")
        require(relative and not os.path.isabs(relative) and ".." not in relative.split("/"),
                "GRAPH_PATH")
        graph_path = os.path.abspath(os.path.join(graph_root, *relative.split("/")))
        require(os.path.commonpath((graph_root, graph_path)) == graph_root and
                os.path.isfile(graph_path) and not os.path.islink(graph_path) and
                sha256_file(graph_path) == graph["graph_sha256"], "GRAPH_PAYLOAD")

    split, membership = split_membership(args.split_contract)
    require(set(membership) == set(graph_by_circuit), "GRAPH_SPLIT_ROSTER")
    denominator_circuits = denominator.get("circuits", {})
    require(set(denominator_circuits) == set(membership), "DENOMINATOR_ROSTER")

    actions = keyed(read_tsv(candidate_path, ACTION_FIELDS, "CANDIDATE"),
                    "action_uid", "ACTION_UID_DUPLICATE")
    costs = keyed(read_tsv(cost_path, COST_FIELDS, "COST"),
                  "action_uid", "COST_ACTION_UID_DUPLICATE")
    require(set(actions) == set(costs), "ACTION_COST_SET_MISMATCH")

    with open(normalized_path, encoding="utf-8", newline="") as stream:
        normalized_rows = list(csv.DictReader(stream, delimiter="\t"))
    normalized = keyed(normalized_rows, "candidate_uid", "SOURCE_UID_DUPLICATE")

    prepared, oracles = [], {}
    for uid in sorted(actions):
        action, cost = actions[uid], costs[uid]
        circuit = action["circuit"]
        require(circuit in membership and cost["circuit"] == circuit, "ACTION_CIRCUIT")
        require(action["outcome_conflict"] == "false" and
                not action["outcome_conflict_fields"], "ACTION_OUTCOME_CONFLICT")
        require(action["action_scheme"] in ("HF", "HMF") and
                cost["action_scheme"] == action["action_scheme"], "ACTION_SCHEME")
        source_uids = action["source_candidate_uids"].split("|")
        require(len(source_uids) == positive_int(action["repeat_measurement_count"],
                                                 "REPEAT_COUNT"), "SOURCE_UID_COUNT")
        source_rows = []
        for source_uid in source_uids:
            require(source_uid in normalized, "SOURCE_UID_MISSING")
            row = normalized[source_uid]
            require(row["circuit"] == circuit and row["result_status"] == "PASS" and
                    row["eligible_regression"] == "1", "SOURCE_ROW_STATUS")
            source_rows.append(row)
        cycles = {positive_int(row["total_cycles"], "TOTAL_CYCLES") for row in source_rows}
        detected = {nonnegative_int(row["detected_faults"], "DETECTED_FAULTS")
                    for row in source_rows}
        require(len(cycles) == 1 and len(detected) == 1, "SOURCE_OUTCOME_CONFLICT")
        total_cycles, detected_faults = next(iter(cycles)), next(iter(detected))
        denom = denominator_circuits[circuit]
        common_fault_count = positive_int(denom.get("common_fault_count"),
                                          "COMMON_FAULT_COUNT")
        d95 = positive_int(denom.get("d95"), "D95")
        safe = detected_faults >= d95
        require(safe, "NON_D95_ACTION_IN_FORMAL_SPACE")
        role, family = membership[circuit]
        require(denom.get("role") == role and denom.get("family") == family,
                "DENOMINATOR_SPLIT_MISMATCH")
        wall = positive_float(cost["wall_time_mean_s"], "RUNTIME_COST")
        require(cost["aggregation_policy"] == "ARITHMETIC_MEAN_ALL_INVOCATIONS" and
                positive_int(cost["source_invocation_count"], "INVOCATION_COUNT") ==
                len(source_uids), "RUNTIME_AGGREGATION_POLICY")
        prepared.append((uid, action, cost, role, family, common_fault_count,
                         total_cycles, wall, graph_by_circuit[circuit]))
        oracles[circuit] = min(oracles.get(circuit, total_cycles), total_cycles)

    feature_rows, outcome_rows, provenance_rows = [], [], []
    for (uid, action, cost, role, family, common_fault_count, total_cycles,
         wall, graph) in prepared:
        epsilon_hit = total_cycles <= oracles[action["circuit"]] * 1.01
        feature_rows.append({
            "role": role, "family": family, "circuit": action["circuit"],
            "action_uid": uid, "action_scheme": action["action_scheme"],
            "h_limit": action["h_patterns"], "m_limit": action["m_patterns"] or "0",
            "common_fault_count": str(common_fault_count), "graph_key": graph["graph_key"],
        })
        outcome_rows.append({
            "action_uid": uid, "execution_status": "SUCCESS",
            "is_d95_feasible": "1", "total_cycles": str(total_cycles),
            "policy_charged_runtime_s": "%.9f" % wall,
            "epsilon_hit": "1" if epsilon_hit else "0",
        })
        provenance_rows.append({field: value for field, value in {
            "action_uid": uid,
            "source_invocation_count": cost["source_invocation_count"],
            "attempt_session_count": cost["attempt_session_count"],
            "success_session_count": cost["success_session_count"],
            "failed_session_count": cost["failed_session_count"],
            "aggregation_policy": cost["aggregation_policy"],
            "source_candidate_uids": action["source_candidate_uids"],
        }.items()})

    temporary = tempfile.mkdtemp(prefix=os.path.basename(output_root) + ".tmp-",
                                 dir=os.path.dirname(output_root))
    try:
        write_tsv(os.path.join(temporary, "features.tsv"), FEATURE_FIELDS, feature_rows)
        write_tsv(os.path.join(temporary, "outcomes.tsv"), OUTCOME_FIELDS, outcome_rows)
        write_tsv(os.path.join(temporary, "action_provenance.tsv"), PROVENANCE_FIELDS,
                  provenance_rows)
        shutil.copyfile(graph_manifest_path, os.path.join(temporary, "graph_manifest.tsv"))
        os.mkdir(os.path.join(temporary, "graphs"))
        for graph in graphs:
            source = os.path.join(graph_root, *graph["graph_path"].replace("\\", "/").split("/"))
            shutil.copyfile(source, os.path.join(temporary, "graphs",
                                                os.path.basename(graph["graph_path"])))
        output_names = ("features.tsv", "outcomes.tsv", "action_provenance.tsv",
                        "graph_manifest.tsv")
        manifest = {
            "schema_version": "runtime-training-package-v2",
            "status": "PASS_PACKAGE_INDEPENDENT_REVIEW_PENDING",
            "counts": {
                "action_count": len(actions), "circuit_count": len(membership),
                "train_circuit_count": sum(1 for role, unused in membership.values()
                                           if role == "TRAIN"),
                "validation_circuit_count": sum(1 for role, unused in membership.values()
                                                if role == "VALIDATION"),
                "repeat_action_count": sum(1 for row in actions.values()
                                           if int(row["repeat_measurement_count"]) > 1),
                "epsilon_hit_action_count": sum(row["epsilon_hit"] == "1"
                                                for row in outcome_rows),
            },
            "circuit_oracle_cycles": dict(sorted(oracles.items())),
            "gates": {
                "family_isolated": True, "blind_rows_read": False,
                "candidate_cost_action_set_exact": True,
                "all_actions_d95_safe": True,
                "cost_independent_review_pass": True,
                "graph_topology_parity_pass": True,
                "missing_runtime_imputation_used": False,
                "fastest_success_selection_used": False,
            },
            "source_sha256": {
                "candidate_space": sha256_file(candidate_path),
                "normalized_measurements": sha256_file(normalized_path),
                "candidate_receipt": sha256_file(candidate_receipt_path),
                "action_runtime_costs": sha256_file(cost_path),
                "cost_receipt": sha256_file(cost_receipt_path),
                "cost_independent_review": sha256_file(cost_review_path),
                "denominator_receipt": sha256_file(args.denominator_receipt),
                "split_contract": sha256_file(args.split_contract),
                "graph_receipt": sha256_file(graph_receipt_path),
                "topology_parity_receipt": sha256_file(args.topology_parity_receipt),
            },
            "output_sha256": dict((name, sha256_file(os.path.join(temporary, name)))
                                  for name in output_names),
            "formal_runtime_membership_sha256": split["formal_runtime_membership_sha256"],
            "training_execution_allowed": False,
            "next_gate": "INDEPENDENT_PACKAGE_REVIEW",
        }
        with open(os.path.join(temporary, "runtime_training_package_manifest_v2.json"),
                  "x", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, sort_keys=True, indent=2)
            stream.write("\n")
        os.rename(temporary, output_root)
        print(json.dumps(manifest, sort_keys=True))
        return manifest
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", required=True)
    parser.add_argument("--cost-root", required=True)
    parser.add_argument("--denominator-receipt", required=True)
    parser.add_argument("--split-contract", required=True)
    parser.add_argument("--graph-root", required=True)
    parser.add_argument("--topology-parity-receipt", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args(argv)
    try:
        build(args)
        return 0
    except (BuildError, OSError, ValueError) as exc:
        print("FAIL:%s" % exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
