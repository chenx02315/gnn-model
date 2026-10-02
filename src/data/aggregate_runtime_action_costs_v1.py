#!/usr/bin/env python3
"""Aggregate audited runtime sessions without fastest-repeat selection."""
from __future__ import print_function

import argparse
import csv
import decimal
import hashlib
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from audit_runtime_action_attempt_mapping_v1 import ACTION_FIELDS, EDGE_FIELDS
from runtime_schema import MANIFEST_V2_FIELDS


INVOCATION_FIELDS = (
    "action_uid", "source_candidate_uid", "circuit", "action_scheme",
    "h_patterns", "m_patterns", "attempt_session_count",
    "distinct_retry_group_count", "success_session_count", "failed_session_count",
    "wall_time_sum_s", "wall_time_min_s", "wall_time_max_s",
)
ACTION_COST_FIELDS = (
    "action_uid", "circuit", "action_scheme", "h_patterns", "m_patterns",
    "source_invocation_count", "attempt_session_count", "success_session_count",
    "failed_session_count", "wall_time_mean_s", "wall_time_population_stddev_s",
    "wall_time_min_invocation_s", "wall_time_max_invocation_s",
    "aggregation_policy",
)


class AggregationError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise AggregationError(code)


def value(row, key):
    return (row.get(key) or "").strip()


def digest(path):
    answer = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            answer.update(block)
    return answer.hexdigest()


def read_tsv(path, expected, label):
    require(os.path.isfile(path) and not os.path.islink(path), label + "_MISSING")
    with open(path, "r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        require(tuple(reader.fieldnames or ()) == tuple(expected), label + "_FIELDS")
        rows = list(reader)
    require(rows, label + "_EMPTY")
    return rows


def write_tsv(path, fields, rows):
    with open(path, "w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)


def decimal_wall(row):
    text = value(row, "wall_s")
    try:
        answer = decimal.Decimal(text)
    except decimal.InvalidOperation:
        raise AggregationError("WALL_TIME_INVALID")
    require(answer.is_finite() and answer >= 0, "WALL_TIME_INVALID")
    return answer


def formatted(number):
    return format(number.quantize(decimal.Decimal("0.000000001")), "f")


def aggregate(candidate_space, edges_path, mapping_receipt_path, manifest_root, output_root):
    require(not os.path.exists(output_root), "OUTPUT_ROOT_EXISTS")
    with open(mapping_receipt_path, "r", encoding="utf-8") as stream:
        mapping = json.load(stream)
    require(mapping.get("status") == "PASS_MAPPING_REPEAT_AGGREGATION_PENDING",
            "MAPPING_STATUS_NOT_PASS")
    require(mapping.get("candidate_space_sha256") == digest(candidate_space),
            "CANDIDATE_HASH_MISMATCH")
    require(mapping.get("output_sha256", {}).get("invocation_attempt_edges_v1.tsv") ==
            digest(edges_path), "EDGE_HASH_MISMATCH")

    actions = read_tsv(candidate_space, ACTION_FIELDS, "CANDIDATE_SPACE")
    action_map = {}
    expected_sources = set()
    for action in actions:
        uid = value(action, "action_uid")
        require(uid and uid not in action_map, "ACTION_UID_NOT_UNIQUE")
        sources = value(action, "source_candidate_uids").split("|")
        require(len(sources) == int(value(action, "repeat_measurement_count")),
                "ACTION_REPEAT_COUNT_MISMATCH")
        require(not expected_sources.intersection(sources), "SOURCE_UID_NOT_UNIQUE")
        expected_sources.update(sources)
        action_map[uid] = action

    attempts = {}
    for circuit, expected_hash in sorted(mapping.get("manifest_sha256", {}).items()):
        path = os.path.join(manifest_root, circuit + "_attempt_manifest_v2_remediated.tsv")
        require(digest(path) == expected_hash, "MANIFEST_HASH_MISMATCH")
        for row in read_tsv(path, MANIFEST_V2_FIELDS, "ATTEMPT_MANIFEST"):
            attempt_id = value(row, "attempt_id")
            require(attempt_id and attempt_id not in attempts, "ATTEMPT_ID_NOT_UNIQUE")
            attempts[attempt_id] = row

    edges = read_tsv(edges_path, EDGE_FIELDS, "MAPPING_EDGES")
    by_source, edge_keys = {}, set()
    for edge in edges:
        source_uid, attempt_id = value(edge, "source_candidate_uid"), value(edge, "attempt_id")
        key = (source_uid, attempt_id)
        require(key not in edge_keys, "EDGE_NOT_UNIQUE")
        edge_keys.add(key)
        require(source_uid in expected_sources, "EDGE_SOURCE_UNKNOWN")
        require(value(edge, "action_uid") in action_map, "EDGE_ACTION_UNKNOWN")
        require(attempt_id in attempts, "EDGE_ATTEMPT_UNKNOWN")
        require(value(attempts[attempt_id], "circuit") == value(edge, "circuit"),
                "EDGE_ATTEMPT_CIRCUIT_MISMATCH")
        by_source.setdefault(source_uid, []).append((edge, attempts[attempt_id]))
    require(set(by_source) == expected_sources, "SOURCE_INVOCATION_COVERAGE_MISMATCH")

    invocation_rows, invocations_by_action = [], {}
    for source_uid in sorted(by_source):
        pairs = by_source[source_uid]
        action_uid = value(pairs[0][0], "action_uid")
        require(all(value(edge, "action_uid") == action_uid for edge, unused in pairs),
                "SOURCE_ACTION_MISMATCH")
        walls = [decimal_wall(attempt) for unused, attempt in pairs]
        success = sum(value(attempt, "attempt_outcome_class") == "SUCCESS"
                      for unused, attempt in pairs)
        failed = len(pairs) - success
        action = action_map[action_uid]
        row = {
            "action_uid": action_uid, "source_candidate_uid": source_uid,
            "circuit": value(action, "circuit"),
            "action_scheme": value(action, "action_scheme"),
            "h_patterns": value(action, "h_patterns"),
            "m_patterns": value(action, "m_patterns"),
            "attempt_session_count": str(len(pairs)),
            "distinct_retry_group_count": str(len(set(
                value(attempt, "retry_group_id") for unused, attempt in pairs))),
            "success_session_count": str(success), "failed_session_count": str(failed),
            "wall_time_sum_s": formatted(sum(walls, decimal.Decimal("0"))),
            "wall_time_min_s": formatted(min(walls)),
            "wall_time_max_s": formatted(max(walls)),
        }
        invocation_rows.append(row)
        invocations_by_action.setdefault(action_uid, []).append(row)

    require(set(invocations_by_action) == set(action_map), "ACTION_COVERAGE_MISMATCH")
    action_rows = []
    for action_uid in sorted(action_map):
        action = action_map[action_uid]
        items = invocations_by_action[action_uid]
        require(len(items) == int(value(action, "repeat_measurement_count")),
                "ACTION_INVOCATION_COUNT_MISMATCH")
        costs = [decimal.Decimal(item["wall_time_sum_s"]) for item in items]
        mean = sum(costs, decimal.Decimal("0")) / decimal.Decimal(len(costs))
        variance = sum((cost - mean) ** 2 for cost in costs) / decimal.Decimal(len(costs))
        stddev = variance.sqrt()
        action_rows.append({
            "action_uid": action_uid, "circuit": value(action, "circuit"),
            "action_scheme": value(action, "action_scheme"),
            "h_patterns": value(action, "h_patterns"), "m_patterns": value(action, "m_patterns"),
            "source_invocation_count": str(len(items)),
            "attempt_session_count": str(sum(int(item["attempt_session_count"]) for item in items)),
            "success_session_count": str(sum(int(item["success_session_count"]) for item in items)),
            "failed_session_count": str(sum(int(item["failed_session_count"]) for item in items)),
            "wall_time_mean_s": formatted(mean),
            "wall_time_population_stddev_s": formatted(stddev),
            "wall_time_min_invocation_s": formatted(min(costs)),
            "wall_time_max_invocation_s": formatted(max(costs)),
            "aggregation_policy": "ARITHMETIC_MEAN_ALL_INVOCATIONS",
        })

    parent = os.path.dirname(os.path.abspath(output_root))
    require(os.path.isdir(parent), "OUTPUT_PARENT_MISSING")
    temporary = tempfile.mkdtemp(prefix=os.path.basename(output_root) + ".tmp-", dir=parent)
    try:
        invocation_path = os.path.join(temporary, "invocation_runtime_costs_v1.tsv")
        action_path = os.path.join(temporary, "action_runtime_costs_v1.tsv")
        write_tsv(invocation_path, INVOCATION_FIELDS, invocation_rows)
        write_tsv(action_path, ACTION_COST_FIELDS, action_rows)
        receipt = {
            "schema_version": "runtime-action-cost-aggregation-receipt-v1",
            "status": "PASS_AGGREGATION_INDEPENDENT_REVIEW_PENDING",
            "policy": "ARITHMETIC_MEAN_ALL_INVOCATIONS",
            "counts": {
                "action_count": len(action_rows),
                "source_invocation_count": len(invocation_rows),
                "repeat_action_count": sum(int(row["source_invocation_count"]) > 1 for row in action_rows),
                "edge_count": len(edges),
                "distinct_attempt_count": len(set(value(edge, "attempt_id") for edge in edges)),
                "failed_session_edge_count": sum(int(row["failed_session_count"]) for row in invocation_rows),
            },
            "inputs_sha256": {"candidate_space": digest(candidate_space),
                               "mapping_edges": digest(edges_path),
                               "mapping_receipt": digest(mapping_receipt_path)},
            "outputs_sha256": {"invocation_runtime_costs_v1.tsv": digest(invocation_path),
                                "action_runtime_costs_v1.tsv": digest(action_path)},
            "gates": {"all_source_invocations_have_cost": True,
                      "all_actions_have_cost": True, "repeat_count_match": True,
                      "wall_time_missing_or_invalid": 0, "fastest_selection_used": False,
                      "failed_or_retry_session_drop": False},
            "boundaries": {"training_allowed": False, "blind_rows_read": False,
                           "lsf_or_tessent_submitted": False,
                           "independent_review_pending": True},
        }
        receipt_path = os.path.join(temporary, "receipt_v1.json")
        with open(receipt_path, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(receipt, stream, sort_keys=True, indent=2); stream.write("\n")
        os.rename(temporary, output_root)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-space", required=True)
    parser.add_argument("--mapping-edges", required=True)
    parser.add_argument("--mapping-receipt", required=True)
    parser.add_argument("--manifest-root", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args(argv)
    try:
        return aggregate(os.path.abspath(args.candidate_space), os.path.abspath(args.mapping_edges),
                         os.path.abspath(args.mapping_receipt), os.path.abspath(args.manifest_root),
                         os.path.abspath(args.output_root))
    except (AggregationError, OSError, ValueError, decimal.InvalidOperation) as exc:
        print("FAIL:%s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
