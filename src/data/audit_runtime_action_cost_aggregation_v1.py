#!/usr/bin/env python3
"""Independent exhaustive verifier for runtime action cost aggregation."""
from __future__ import print_function

import argparse
import csv
import decimal
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from aggregate_runtime_action_costs_v1 import (
    ACTION_COST_FIELDS, INVOCATION_FIELDS, formatted,
)
from audit_runtime_action_attempt_mapping_v1 import ACTION_FIELDS, EDGE_FIELDS
from runtime_schema import MANIFEST_V2_FIELDS


class ReviewError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise ReviewError(code)


def value(row, key):
    return (row.get(key) or "").strip()


def digest(path):
    answer = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            answer.update(block)
    return answer.hexdigest()


def read_tsv(path, fields, label):
    with open(path, "r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        require(tuple(reader.fieldnames or ()) == tuple(fields), label + "_FIELDS")
        rows = list(reader)
    require(rows, label + "_EMPTY")
    return rows


def review(candidate_space, edges_path, manifest_root, aggregation_root, output_receipt):
    require(not os.path.exists(output_receipt), "OUTPUT_EXISTS")
    actions = read_tsv(candidate_space, ACTION_FIELDS, "CANDIDATE_SPACE")
    edges = read_tsv(edges_path, EDGE_FIELDS, "EDGES")
    invocation_path = os.path.join(aggregation_root, "invocation_runtime_costs_v1.tsv")
    action_path = os.path.join(aggregation_root, "action_runtime_costs_v1.tsv")
    aggregate_receipt_path = os.path.join(aggregation_root, "receipt_v1.json")
    invocation_rows = read_tsv(invocation_path, INVOCATION_FIELDS, "INVOCATION_COSTS")
    action_rows = read_tsv(action_path, ACTION_COST_FIELDS, "ACTION_COSTS")
    with open(aggregate_receipt_path, "r", encoding="utf-8") as stream:
        aggregate_receipt = json.load(stream)
    require(aggregate_receipt.get("status") == "PASS_AGGREGATION_INDEPENDENT_REVIEW_PENDING",
            "AGGREGATION_STATUS_INVALID")
    require(aggregate_receipt.get("outputs_sha256", {}).get("invocation_runtime_costs_v1.tsv") ==
            digest(invocation_path), "INVOCATION_OUTPUT_HASH_MISMATCH")
    require(aggregate_receipt.get("outputs_sha256", {}).get("action_runtime_costs_v1.tsv") ==
            digest(action_path), "ACTION_OUTPUT_HASH_MISMATCH")

    attempts = {}
    for path in sorted(os.path.join(manifest_root, name) for name in os.listdir(manifest_root)
                       if name.endswith("_attempt_manifest_v2_remediated.tsv")):
        for row in read_tsv(path, MANIFEST_V2_FIELDS, "ATTEMPT_MANIFEST"):
            attempt_id = value(row, "attempt_id")
            require(attempt_id not in attempts, "ATTEMPT_ID_DUPLICATE")
            attempts[attempt_id] = row

    by_source = {}
    for edge in edges:
        attempt_id = value(edge, "attempt_id")
        require(attempt_id in attempts, "ATTEMPT_MISSING")
        by_source.setdefault(value(edge, "source_candidate_uid"), []).append(attempt_id)
    invocation_map = {}
    for row in invocation_rows:
        source = value(row, "source_candidate_uid")
        require(source not in invocation_map and source in by_source, "INVOCATION_UID_INVALID")
        invocation_map[source] = row
        ids = by_source[source]
        walls = [decimal.Decimal(value(attempts[attempt_id], "wall_s")) for attempt_id in ids]
        expected_sum = sum(walls, decimal.Decimal("0"))
        expected_success = sum(value(attempts[attempt_id], "attempt_outcome_class") == "SUCCESS"
                               for attempt_id in ids)
        require(value(row, "wall_time_sum_s") == formatted(expected_sum),
                "INVOCATION_SUM_MISMATCH")
        require(int(value(row, "attempt_session_count")) == len(ids),
                "INVOCATION_SESSION_COUNT_MISMATCH")
        require(int(value(row, "success_session_count")) == expected_success,
                "INVOCATION_SUCCESS_COUNT_MISMATCH")
        require(int(value(row, "failed_session_count")) == len(ids) - expected_success,
                "INVOCATION_FAILURE_COUNT_MISMATCH")
    require(set(invocation_map) == set(by_source), "INVOCATION_COVERAGE_MISMATCH")

    action_output = dict((value(row, "action_uid"), row) for row in action_rows)
    require(len(action_output) == len(action_rows), "ACTION_OUTPUT_UID_DUPLICATE")
    fastest_difference_count = 0
    for action in actions:
        uid = value(action, "action_uid")
        require(uid in action_output, "ACTION_OUTPUT_MISSING")
        sources = value(action, "source_candidate_uids").split("|")
        require(all(source in invocation_map for source in sources), "ACTION_SOURCE_MISSING")
        costs = [decimal.Decimal(value(invocation_map[source], "wall_time_sum_s"))
                 for source in sources]
        mean = sum(costs, decimal.Decimal("0")) / decimal.Decimal(len(costs))
        output = action_output[uid]
        require(value(output, "wall_time_mean_s") == formatted(mean),
                "ACTION_MEAN_MISMATCH")
        require(value(output, "aggregation_policy") == "ARITHMETIC_MEAN_ALL_INVOCATIONS",
                "ACTION_POLICY_MISMATCH")
        require(int(value(output, "source_invocation_count")) == len(sources),
                "ACTION_REPEAT_COUNT_MISMATCH")
        if len(costs) > 1 and mean != min(costs):
            fastest_difference_count += 1
    require(set(action_output) == set(value(row, "action_uid") for row in actions),
            "ACTION_COVERAGE_MISMATCH")

    receipt = {
        "schema_version": "runtime-action-cost-independent-review-v1",
        "status": "PASS_COST_LABEL_GATE",
        "counts": {"action_count": len(actions),
                   "source_invocation_count": len(invocation_rows),
                   "edge_count": len(edges),
                   "repeat_action_count": sum(int(value(row, "source_invocation_count")) > 1
                                              for row in action_rows),
                   "repeat_mean_differs_from_fastest_count": fastest_difference_count},
        "verified_sha256": {"candidate_space": digest(candidate_space),
                            "mapping_edges": digest(edges_path),
                            "invocation_runtime_costs": digest(invocation_path),
                            "action_runtime_costs": digest(action_path),
                            "aggregation_receipt": digest(aggregate_receipt_path)},
        "gates": {"exhaustive_invocation_recalculation": True,
                  "exhaustive_action_mean_recalculation": True,
                  "fastest_repeat_selection_used": False,
                  "missing_action_or_invocation": 0},
        "boundaries": {"training_allowed": False, "blind_rows_read": False,
                       "lsf_or_tessent_submitted": False,
                       "next_gate": "FAMILY_ISOLATED_PACKAGE_AND_SPLIT"},
    }
    with open(output_receipt, "x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2); stream.write("\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-space", required=True)
    parser.add_argument("--mapping-edges", required=True)
    parser.add_argument("--manifest-root", required=True)
    parser.add_argument("--aggregation-root", required=True)
    parser.add_argument("--output-receipt", required=True)
    args = parser.parse_args(argv)
    try:
        return review(os.path.abspath(args.candidate_space), os.path.abspath(args.mapping_edges),
                      os.path.abspath(args.manifest_root), os.path.abspath(args.aggregation_root),
                      os.path.abspath(args.output_receipt))
    except (ReviewError, OSError, ValueError, decimal.InvalidOperation) as exc:
        print("FAIL:%s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
