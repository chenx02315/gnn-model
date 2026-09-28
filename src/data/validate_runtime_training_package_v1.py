#!/usr/bin/env python3
"""Fail-closed validation for a non-BLIND runtime-training source package.

This module deliberately accepts a small, explicit TSV bundle only.  It is a
package validator, not a trainer: it never reads a BLIND row and never starts
Tessent or LSF work.
"""
from __future__ import print_function

import csv
import hashlib
import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from runtime_schema import MANIFEST_V2_FIELDS


SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_FILES = (
    "actions.tsv", "action_attempt_edges.tsv", "attempts.tsv", "graph_manifest.tsv",
    "source_attempt_inventory.tsv", "retry_completeness_evidence.json",
    "retry_completeness_review.json",
)
ACTION_FIELDS = (
    "role", "family", "circuit", "action_uid", "action_scheme", "h_limit", "m_limit",
    "common_fault_count", "execution_status", "is_d95_feasible", "total_cycles", "graph_key",
)
EDGE_FIELDS = ("action_uid", "invocation_order", "mode", "retry_group_id", "attempt_id", "prefix_key")
GRAPH_FIELDS = ("graph_key", "circuit", "graph_path", "graph_sha256")
SOURCE_INVENTORY_FIELDS = (
    "attempt_id", "circuit", "retry_group_id", "retry_order", "attempt_outcome_class",
)
FEATURE_FIELDS = (
    "role", "family", "circuit", "action_uid", "action_scheme", "h_limit",
    "m_limit", "common_fault_count", "graph_key",
)
OUTCOME_FIELDS = (
    "action_uid", "execution_status", "is_d95_feasible", "total_cycles",
    "policy_charged_runtime_s", "epsilon_hit",
)
TIMEOUT_VALUES = frozenset(("TIMEOUT", "TIMED_OUT", "TIMEOUT_KILLED"))
NO_TIMEOUT_VALUES = frozenset(("NO_TIMEOUT", "NOT_TIMEOUT"))
EXECUTION_STATUSES = frozenset(("SUCCESS", "FAILED", "TIMEOUT"))
TRUE_VALUES = frozenset(("true", "1", "yes"))
FALSE_VALUES = frozenset(("false", "0", "no"))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _fail(code):
    raise ValueError(code)


def _under(root, relative):
    if not isinstance(relative, str) or not relative or os.path.isabs(relative):
        _fail("PACKAGE_PATH_INVALID")
    candidate = os.path.abspath(os.path.join(root, *relative.replace("\\", "/").split("/")))
    real_root, real_candidate = os.path.realpath(root), os.path.realpath(candidate)
    if (os.path.commonpath((root, candidate)) != root
            or os.path.commonpath((real_root, real_candidate)) != real_root
            or os.path.islink(candidate)):
        _fail("PACKAGE_PATH_INVALID")
    cursor = candidate
    while cursor != root:
        if os.path.islink(cursor):
            _fail("PACKAGE_PATH_INVALID")
        parent = os.path.dirname(cursor)
        if parent == cursor:
            _fail("PACKAGE_PATH_INVALID")
        cursor = parent
    return candidate


def _read_tsv(path, fields, code):
    with open(path, encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if tuple(reader.fieldnames or ()) != tuple(fields):
            _fail(code + "_FIELDS")
        rows = list(reader)
    if not rows:
        _fail(code + "_EMPTY")
    return rows


def _number(raw, code, allow_zero=False):
    try:
        value = float(raw)
    except (TypeError, ValueError):
        _fail(code)
    if not math.isfinite(value) or value < 0 or (not allow_zero and value == 0):
        _fail(code)
    return value


def _positive_int(raw, code):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        _fail(code)
    if str(value) != str(raw).strip() or value < 1:
        _fail(code)
    return value


def _boolean(raw, code):
    value = str(raw).strip().lower()
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    _fail(code)


def _expected_membership(contract_root):
    split = _read_json(os.path.join(contract_root, "contracts", "data_split_v1.json"))
    membership = split.get("formal_runtime_membership")
    if not isinstance(membership, dict):
        _fail("SPLIT_INVALID")
    answer = {}
    for role in ("TRAIN", "VALIDATION", "PILOT", "BLIND_TEST"):
        for item in membership.get(role, []):
            circuit, family = item.get("circuit"), item.get("family")
            if not circuit or not family or circuit in answer:
                _fail("SPLIT_INVALID")
            answer[circuit] = (role, family)
    return answer


def _expected_authority(contract_root):
    files = {
        "runtime_training_contract_sha256": "contracts/runtime_training_v1.json",
        "feature_schema_sha256": "contracts/runtime_feature_schema_v1.json",
        "split_contract_sha256": "contracts/data_split_v1.json",
        "runtime_policy_sha256": "contracts/runtime_policy_v1.json",
    }
    return {key: sha256_file(os.path.join(contract_root, relative)) for key, relative in files.items()}


def _input_manifest(root):
    manifest_path = _under(root, "package_manifest.json")
    manifest = _read_json(manifest_path)
    required = ("schema_version", "files", "authority", "success_only_retry_completeness_proof", "prefix_reuse_effective")
    if set(manifest) != set(required) or manifest.get("schema_version") != "runtime-training-source-package-v1":
        _fail("PACKAGE_MANIFEST_SCHEMA")
    proof = manifest.get("success_only_retry_completeness_proof")
    if (not isinstance(proof, dict)
            or set(proof) != {"status", "evidence_path", "evidence_sha256", "circuits"}
            or proof.get("status") != "PASS_NO_OMITTED_FAILURE_OR_RETRY"
            or proof.get("evidence_path") != "retry_completeness_evidence.json"
            or not SHA256.match(str(proof.get("evidence_sha256", "")))
            or not isinstance(proof.get("circuits"), list)
            or not proof["circuits"]):
        _fail("SUCCESS_ONLY_COMPLETENESS_UNPROVEN")
    if manifest.get("prefix_reuse_effective") is not False:
        _fail("PREFIX_REUSE_NOT_DISABLED")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != set(REQUIRED_FILES):
        _fail("PACKAGE_MANIFEST_FILES")
    for name, digest in files.items():
        if not SHA256.match(str(digest)):
            _fail("PACKAGE_MANIFEST_SHA256")
        artifact_path = _under(root, name)
        if not os.path.isfile(artifact_path) or sha256_file(artifact_path) != digest:
            _fail("PACKAGE_FILE_SHA256_MISMATCH")
    evidence_path = _under(root, proof["evidence_path"])
    if sha256_file(evidence_path) != proof["evidence_sha256"]:
        _fail("SUCCESS_ONLY_COMPLETENESS_EVIDENCE_MISMATCH")
    return manifest, sha256_file(manifest_path)


def _validate_graph_payload(path, circuit, leakage_blacklist):
    payload = _read_json(path)
    if set(payload) != {"schema_version", "circuit", "nodes", "edge_index"}:
        _fail("GRAPH_PAYLOAD_SCHEMA")
    if payload.get("schema_version") != "runtime-graph-v1" or payload.get("circuit") != circuit:
        _fail("GRAPH_PAYLOAD_SCHEMA")
    nodes, edges = payload.get("nodes"), payload.get("edge_index")
    if not isinstance(nodes, list) or not nodes or not isinstance(edges, list):
        _fail("GRAPH_PAYLOAD_SCHEMA")
    allowed_node = {"node_type", "cell_type", "sequential_flag"}
    for node in nodes:
        if not isinstance(node, dict) or set(node) != allowed_node:
            _fail("GRAPH_FEATURE_NOT_ALLOWLISTED")
        if node["sequential_flag"] not in (0, 1, False, True):
            _fail("GRAPH_PAYLOAD_SCHEMA")
        if not isinstance(node["node_type"], str) or not isinstance(node["cell_type"], str):
            _fail("GRAPH_PAYLOAD_SCHEMA")
    for edge in edges:
        if (not isinstance(edge, list) or len(edge) != 2
                or any(not isinstance(index, int) or isinstance(index, bool) for index in edge)
                or any(index < 0 or index >= len(nodes) for index in edge)):
            _fail("GRAPH_PAYLOAD_SCHEMA")
    serialized_keys = set()
    def collect(value):
        if isinstance(value, dict):
            for key, child in value.items():
                serialized_keys.add(str(key))
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)
    collect(payload)
    if serialized_keys.intersection(leakage_blacklist):
        _fail("GRAPH_OUTCOME_LEAKAGE")


def validate_source_package(package_root, contract_root=None):
    """Return validated source rows and derived labels, or raise ValueError.

    ``package_root`` is an isolated, immutable candidate package.  All paths
    named by its manifest must be descendants of that directory and not links.
    """
    root = os.path.abspath(package_root)
    if not os.path.isdir(root) or os.path.islink(root):
        _fail("PACKAGE_ROOT_INVALID")
    if contract_root is None:
        contract_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    manifest, manifest_sha = _input_manifest(root)
    actions = _read_tsv(_under(root, "actions.tsv"), ACTION_FIELDS, "ACTIONS")
    edges = _read_tsv(_under(root, "action_attempt_edges.tsv"), EDGE_FIELDS, "EDGES")
    attempts = _read_tsv(_under(root, "attempts.tsv"), MANIFEST_V2_FIELDS, "ATTEMPTS")
    graphs = _read_tsv(_under(root, "graph_manifest.tsv"), GRAPH_FIELDS, "GRAPHS")
    membership = _expected_membership(contract_root)
    if manifest.get("authority") != _expected_authority(contract_root):
        _fail("PACKAGE_AUTHORITY_MISMATCH")

    feature_schema = _read_json(os.path.join(contract_root, "contracts", "runtime_feature_schema_v1.json"))
    leakage_blacklist = set(feature_schema.get("leakage_blacklist", []))
    if not leakage_blacklist:
        _fail("FEATURE_SCHEMA_INVALID")
    action_map = {}
    for action in actions:
        uid = action["action_uid"]
        if not uid or uid in action_map:
            _fail("ACTION_UID_NOT_UNIQUE")
        circuit = action["circuit"]
        if circuit not in membership:
            _fail("CIRCUIT_NOT_IN_FORMAL_SPLIT")
        role, family = membership[circuit]
        if role not in ("TRAIN", "VALIDATION") or action["role"] != role or action["family"] != family:
            _fail("ROLE_OR_FAMILY_FORBIDDEN")
        if action["action_scheme"] not in ("HF", "HMF") or action["execution_status"] not in EXECUTION_STATUSES:
            _fail("ACTION_STATUS_INVALID")
        feasible = _boolean(action["is_d95_feasible"], "D95_BOOLEAN_INVALID")
        _number(action["h_limit"], "ACTION_NUMERIC_INVALID", allow_zero=True)
        _number(action["m_limit"], "ACTION_NUMERIC_INVALID", allow_zero=True)
        _number(action["common_fault_count"], "ACTION_NUMERIC_INVALID")
        if action["action_scheme"] == "HF" and _number(action["m_limit"], "ACTION_NUMERIC_INVALID", allow_zero=True) != 0:
            _fail("HF_M_LIMIT_NONZERO")
        if action["execution_status"] == "SUCCESS":
            _number(action["total_cycles"], "ACTION_NUMERIC_INVALID")
        elif action["total_cycles"] not in ("0", "NA") or feasible:
            _fail("FAILED_ACTION_OUTCOME_INVALID")
        if not action["graph_key"]:
            _fail("ACTION_GRAPH_KEY_MISSING")
        action_map[uid] = action
    action_circuits = {action["circuit"] for action in action_map.values()}
    proof_circuits = manifest["success_only_retry_completeness_proof"]["circuits"]
    if len(proof_circuits) != len(set(proof_circuits)) or set(proof_circuits) != action_circuits:
        _fail("SUCCESS_ONLY_COMPLETENESS_SCOPE_MISMATCH")

    graph_map = {}
    for graph in graphs:
        key = graph["graph_key"]
        if not key or key in graph_map or not SHA256.match(graph["graph_sha256"]):
            _fail("GRAPH_MANIFEST_INVALID")
        graph_path = _under(root, graph["graph_path"])
        if not os.path.isfile(graph_path) or sha256_file(graph_path) != graph["graph_sha256"]:
            _fail("GRAPH_SHA256_MISMATCH")
        _validate_graph_payload(graph_path, graph["circuit"], leakage_blacklist)
        graph_map[key] = graph
    if set(graph_map) != {action["graph_key"] for action in action_map.values()}:
        _fail("GRAPH_SET_MISMATCH")
    for action in action_map.values():
        graph = graph_map.get(action["graph_key"])
        if graph is None or graph["circuit"] != action["circuit"]:
            _fail("ACTION_GRAPH_FOREIGN_KEY")

    attempt_map = {}
    for attempt in attempts:
        attempt_id = attempt["attempt_id"]
        if not attempt_id or attempt_id in attempt_map:
            _fail("ATTEMPT_ID_NOT_UNIQUE")
        circuit = attempt["circuit"]
        if circuit not in membership:
            _fail("ATTEMPT_CIRCUIT_INVALID")
        role, family = membership[circuit]
        if role not in ("TRAIN", "VALIDATION") or attempt["role"] != role or attempt["family"] != family:
            _fail("ATTEMPT_ROLE_OR_FAMILY_FORBIDDEN")
        if attempt["retry_order_status"] != "KNOWN_ORDER":
            _fail("UNKNOWN_RETRY_ORDER")
        _positive_int(attempt["retry_order"], "RETRY_ORDER_INVALID")
        if not attempt["retry_group_id"]:
            _fail("RETRY_GROUP_MISSING")
        timeout_status = attempt["timeout_status"].strip().upper()
        if timeout_status not in TIMEOUT_VALUES | NO_TIMEOUT_VALUES:
            _fail("TIMEOUT_STATUS_UNKNOWN")
        timeout = timeout_status in TIMEOUT_VALUES
        wall_raw = attempt["wall_s"].strip()
        if wall_raw:
            attempt["_charged_wall_s"] = _number(wall_raw, "WALL_TIME_INVALID")
        elif timeout:
            timeout_by_mode = {"H": 60.0, "M": 30.0, "F": 30.0}
            if attempt["mode"] not in timeout_by_mode:
                _fail("TIMEOUT_MODE_INVALID")
            attempt["_charged_wall_s"] = timeout_by_mode[attempt["mode"]]
        else:
            _fail("MISSING_WALL_TIME")
        attempt["_is_timeout"] = timeout
        outcome = attempt["attempt_outcome_class"].strip().upper()
        if outcome not in ("SUCCESS", "FAILURE", "TIMEOUT"):
            _fail("ATTEMPT_OUTCOME_UNKNOWN")
        if timeout != (outcome == "TIMEOUT"):
            _fail("ATTEMPT_TIMEOUT_OUTCOME_MISMATCH")
        attempt["_normalized_outcome"] = outcome
        attempt_map[attempt_id] = attempt

    edge_pairs = set()
    edge_by_action = {}
    for edge in edges:
        uid, attempt_id = edge["action_uid"], edge["attempt_id"]
        pair = (uid, attempt_id)
        if uid not in action_map or attempt_id not in attempt_map:
            _fail("EDGE_FOREIGN_KEY")
        if pair in edge_pairs:
            _fail("EDGE_PAIR_NOT_UNIQUE")
        edge_pairs.add(pair)
        _positive_int(edge["invocation_order"], "INVOCATION_ORDER_INVALID")
        if edge["mode"] not in ("H", "M", "F"):
            _fail("EDGE_MODE_INVALID")
        attempt = attempt_map[attempt_id]
        action = action_map[uid]
        if (attempt["mode"] != edge["mode"] or attempt["circuit"] != action["circuit"]
                or attempt["role"] != action["role"] or attempt["family"] != action["family"]):
            _fail("EDGE_ATTEMPT_ACTION_MISMATCH")
        if edge["retry_group_id"] != attempt_map[attempt_id]["retry_group_id"]:
            _fail("EDGE_RETRY_GROUP_MISMATCH")
        if edge["prefix_key"].strip() not in ("", "NONE", "DISABLED"):
            _fail("PREFIX_REUSE_NOT_DISABLED")
        edge_by_action.setdefault(uid, []).append(edge)
    if set(edge_by_action) != set(action_map):
        _fail("ACTION_WITHOUT_CHARGED_ATTEMPT")
    if {edge["attempt_id"] for edge in edges} != set(attempt_map):
        _fail("UNREFERENCED_ATTEMPT")

    source_inventory_path = _under(root, "source_attempt_inventory.tsv")
    source_inventory = _read_tsv(
        source_inventory_path, SOURCE_INVENTORY_FIELDS, "SOURCE_ATTEMPT_INVENTORY"
    )
    source_by_id = {}
    for row in source_inventory:
        attempt_id = row["attempt_id"].strip()
        if not attempt_id or attempt_id in source_by_id:
            _fail("SOURCE_ATTEMPT_INVENTORY_DUPLICATE")
        source_by_id[attempt_id] = row
    if set(source_by_id) != set(attempt_map):
        _fail("SOURCE_ATTEMPT_INVENTORY_SET_MISMATCH")
    for attempt_id, source_row in source_by_id.items():
        attempt = attempt_map[attempt_id]
        for field in ("circuit", "retry_group_id", "retry_order", "attempt_outcome_class"):
            if source_row[field].strip() != attempt[field].strip():
                _fail("SOURCE_ATTEMPT_INVENTORY_VALUE_MISMATCH")

    evidence = _read_json(_under(root, "retry_completeness_evidence.json"))
    if set(evidence) != {"schema_version", "status", "circuits", "independent_review"}:
        _fail("SUCCESS_ONLY_COMPLETENESS_EVIDENCE_SCHEMA")
    if (evidence.get("schema_version") != "runtime-retry-completeness-evidence-v1"
            or evidence.get("status") != "PASS_NO_OMITTED_FAILURE_OR_RETRY"
            or evidence.get("independent_review") != "PASS"):
        _fail("SUCCESS_ONLY_COMPLETENESS_EVIDENCE_STATUS")
    circuit_evidence = evidence.get("circuits")
    if not isinstance(circuit_evidence, dict) or set(circuit_evidence) != action_circuits:
        _fail("SUCCESS_ONLY_COMPLETENESS_SCOPE_MISMATCH")
    attempt_counts = {}
    for attempt in attempt_map.values():
        attempt_counts[attempt["circuit"]] = attempt_counts.get(attempt["circuit"], 0) + 1
    for circuit, item in circuit_evidence.items():
        required_keys = {
            "source_inventory_path", "source_inventory_sha256",
            "independent_review_receipt_path", "independent_review_receipt_sha256",
            "source_attempt_count", "packaged_attempt_count", "omitted_failure_count",
            "omitted_retry_count", "retry_order_known",
        }
        if not isinstance(item, dict) or set(item) != required_keys:
            _fail("SUCCESS_ONLY_COMPLETENESS_EVIDENCE_SCHEMA")
        if (item["source_inventory_path"] != "source_attempt_inventory.tsv"
                or item["source_inventory_sha256"] != sha256_file(source_inventory_path)
                or item["independent_review_receipt_path"] != "retry_completeness_review.json"
                or not SHA256.match(str(item["independent_review_receipt_sha256"]))):
            _fail("SUCCESS_ONLY_COMPLETENESS_EVIDENCE_SCHEMA")
        source_count = sum(1 for row in source_inventory if row["circuit"] == circuit)
        if (item["source_attempt_count"] != item["packaged_attempt_count"]
                or item["source_attempt_count"] != source_count
                or item["packaged_attempt_count"] != attempt_counts.get(circuit, 0)
                or item["omitted_failure_count"] != 0 or item["omitted_retry_count"] != 0
                or item["retry_order_known"] is not True):
            _fail("SUCCESS_ONLY_COMPLETENESS_UNPROVEN")

    review_path = _under(root, "retry_completeness_review.json")
    review = _read_json(review_path)
    review_keys = {
        "schema_version", "status", "reviewer_role", "review_scope",
        "source_inventory_path", "source_inventory_sha256", "attempts_path",
        "attempts_sha256", "circuits",
    }
    if set(review) != review_keys:
        _fail("COMPLETENESS_REVIEW_SCHEMA")
    if (review["schema_version"] != "runtime-retry-completeness-review-v1"
            or review["status"] != "PASS"
            or review["reviewer_role"] != "independent_read_only_reviewer"
            or review["review_scope"] != "SOURCE_INVENTORY_TO_PACKAGED_ATTEMPTS"
            or review["source_inventory_path"] != "source_attempt_inventory.tsv"
            or review["source_inventory_sha256"] != sha256_file(source_inventory_path)
            or review["attempts_path"] != "attempts.tsv"
            or review["attempts_sha256"] != sha256_file(_under(root, "attempts.tsv"))
            or review["circuits"] != dict(sorted(attempt_counts.items()))):
        _fail("COMPLETENESS_REVIEW_BINDING")
    for item in circuit_evidence.values():
        if item["independent_review_receipt_sha256"] != sha256_file(review_path):
            _fail("COMPLETENESS_REVIEW_BINDING")

    policy_cost = {}
    for uid, action_edges in edge_by_action.items():
        orders = set()
        groups = {}
        seen_attempts = set()
        total = 0.0
        for edge in action_edges:
            order = _positive_int(edge["invocation_order"], "INVOCATION_ORDER_INVALID")
            if order in orders:
                _fail("INVOCATION_ORDER_NOT_UNIQUE")
            orders.add(order)
            attempt = attempt_map[edge["attempt_id"]]
            groups.setdefault(edge["retry_group_id"], []).append((order, attempt))
            if attempt["attempt_id"] not in seen_attempts:
                seen_attempts.add(attempt["attempt_id"])
                total += attempt["_charged_wall_s"]
        if orders != set(range(1, len(action_edges) + 1)):
            _fail("INVOCATION_ORDER_NOT_CONTIGUOUS")
        for group in groups.values():
            group.sort(key=lambda item: item[0])
            if len({item[1]["mode"] for item in group}) != 1:
                _fail("RETRY_GROUP_MODE_MISMATCH")
            retry_orders = [int(item[1]["retry_order"]) for item in group]
            if len(retry_orders) != len(set(retry_orders)):
                _fail("RETRY_ORDER_NOT_UNIQUE")
            if len(retry_orders) > 2:
                _fail("MAX_RETRY_EXCEEDED")
            if sorted(retry_orders) != list(range(1, len(retry_orders) + 1)):
                _fail("RETRY_ORDER_NOT_CONTIGUOUS")
            for index, (_, attempt) in enumerate(group[:-1]):
                if attempt["_is_timeout"]:
                    _fail("TIMEOUT_RETRY_FORBIDDEN")
        ordered_edges = sorted(action_edges, key=lambda edge: int(edge["invocation_order"]))
        compressed_modes = []
        for edge in ordered_edges:
            if not compressed_modes or compressed_modes[-1] != edge["mode"]:
                compressed_modes.append(edge["mode"])
        expected_modes = ["H", "F"] if action_map[uid]["action_scheme"] == "HF" else ["H", "M", "F"]
        if compressed_modes != expected_modes[:len(compressed_modes)]:
            _fail("ACTION_MODE_ORDER_INVALID")
        final_attempt = attempt_map[ordered_edges[-1]["attempt_id"]]
        expected_outcome = {"SUCCESS": "SUCCESS", "FAILED": "FAILURE", "TIMEOUT": "TIMEOUT"}[action_map[uid]["execution_status"]]
        if final_attempt["_normalized_outcome"] != expected_outcome:
            _fail("ACTION_ATTEMPT_OUTCOME_MISMATCH")
        if action_map[uid]["execution_status"] == "SUCCESS" and compressed_modes != expected_modes:
            _fail("SUCCESS_ACTION_MODE_STACK_INCOMPLETE")
        if total <= 0:
            _fail("ZERO_COST_ACTION")
        policy_cost[uid] = total

    circuit_actions = {}
    for action in action_map.values():
        circuit_actions.setdefault(action["circuit"], []).append(action)
    derived = {}
    for circuit, rows in circuit_actions.items():
        feasible = [row for row in rows if row["execution_status"] == "SUCCESS" and _boolean(row["is_d95_feasible"], "D95_BOOLEAN_INVALID")]
        if not feasible:
            _fail("CIRCUIT_WITHOUT_FEASIBLE_ACTION")
        ranked = sorted(feasible, key=lambda row: (_number(row["total_cycles"], "ACTION_NUMERIC_INVALID"), row["action_uid"]))
        oracle_cycles = _number(ranked[0]["total_cycles"], "ACTION_NUMERIC_INVALID")
        ranks = {row["action_uid"]: index + 1 for index, row in enumerate(ranked)}
        for row in rows:
            cycles = (_number(row["total_cycles"], "ACTION_NUMERIC_INVALID")
                      if row["execution_status"] == "SUCCESS" else float("inf"))
            derived[row["action_uid"]] = {
                "policy_charged_runtime_s": policy_cost[row["action_uid"]],
                "epsilon_hit": row["action_uid"] in ranks and cycles <= oracle_cycles * 1.01,
                "oracle_cycles": oracle_cycles,
            }
    return {
        "input_manifest": manifest,
        "input_manifest_sha256": manifest_sha,
        "actions": action_map,
        "derived": derived,
        "circuit_count": len(circuit_actions),
        "action_count": len(action_map),
        "attempt_count": len(attempt_map),
        "edge_count": len(edge_pairs),
        "graph_count": len(graph_map),
        "graphs": list(graphs),
    }


def validate_output_package(output_root):
    root = os.path.abspath(output_root)
    manifest_path = _under(root, "runtime_training_package_manifest_v1.json")
    manifest = _read_json(manifest_path)
    required = ("schema_version", "status", "files", "counts", "circuit_oracles", "input_manifest_sha256", "authority", "training_execution_allowed")
    if set(manifest) != set(required) or manifest["schema_version"] != "runtime-training-package-v1" or manifest["status"] != "PASS":
        _fail("OUTPUT_MANIFEST_SCHEMA")
    if manifest["training_execution_allowed"] is not False or not SHA256.match(manifest["input_manifest_sha256"]):
        _fail("OUTPUT_MANIFEST_AUTHORITY")
    if manifest.get("authority") != _expected_authority(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))):
        _fail("OUTPUT_MANIFEST_AUTHORITY")
    expected_files = {"features.tsv", "outcomes.tsv", "package_manifest.json"} | set(REQUIRED_FILES)
    if set(manifest["files"]) != expected_files or any(not SHA256.match(value) for value in manifest["files"].values()):
        _fail("OUTPUT_MANIFEST_FILES")
    for name, digest in manifest["files"].items():
        artifact = _under(root, name)
        if not os.path.isfile(artifact) or sha256_file(artifact) != digest:
            _fail("OUTPUT_DATASET_SHA256")
    features = _under(root, "features.tsv")
    outcomes = _under(root, "outcomes.tsv")
    feature_rows = _read_tsv(features, FEATURE_FIELDS, "OUTPUT_FEATURES")
    outcome_rows = _read_tsv(outcomes, OUTCOME_FIELDS, "OUTPUT_OUTCOMES")
    forbidden = ("attempt_id", "source_log_path", "source_artifact", "source_artifact_sha256")
    if any(any(value in row for value in forbidden) for row in feature_rows + outcome_rows):
        _fail("OUTPUT_DISCLOSURE")
    if any(row["role"] not in ("TRAIN", "VALIDATION") for row in feature_rows):
        _fail("OUTPUT_ROLE_FORBIDDEN")
    feature_ids = [row["action_uid"] for row in feature_rows]
    outcome_ids = [row["action_uid"] for row in outcome_rows]
    if len(feature_ids) != len(set(feature_ids)) or len(outcome_ids) != len(set(outcome_ids)) or set(feature_ids) != set(outcome_ids):
        _fail("OUTPUT_ACTION_SET_MISMATCH")
    validate_source_package(root)
    return manifest


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("package_root")
    parser.add_argument("--output", action="store_true")
    args = parser.parse_args(argv)
    if args.output:
        validate_output_package(args.package_root)
    else:
        validate_source_package(args.package_root)
    print("RUNTIME_TRAINING_PACKAGE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
