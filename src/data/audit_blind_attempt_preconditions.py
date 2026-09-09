#!/usr/bin/env python3
"""Aggregate-only R04/R05/R11 audit for a sealed BLIND log cohort.

The parser operates in memory.  Output intentionally excludes paths, run IDs,
timing values, candidate identifiers, and per-attempt records.
"""
from __future__ import print_function

import argparse
import collections
import json
import os

from recover_runtime_attempts import gnu_rows


def count(rows, field, predicate=lambda value: bool(value)):
    return sum(1 for row in rows if predicate(row.get(field, "")))


def audit(input_path, evidence_root, meta, inventory_sha256):
    rows = gnu_rows(input_path, evidence_root, meta, [])
    attempt_ids = [row.get("attempt_id", "") for row in rows]
    parse_statuses = [row.get("parse_status", "") for row in rows]
    retry_statuses = collections.Counter(row.get("retry_order_status", "") for row in rows)
    result = {
        "schema_version": "blind-attempt-precondition-aggregate-v1",
        "circuit": meta["circuit"],
        "family": meta["family"],
        "role": meta["role"],
        "phase": meta["phase"],
        "cohort": meta["cohort"],
        "environment_cohort": meta["environment_cohort"],
        "source_inventory_manifest_sha256": inventory_sha256,
        "field_policy": "aggregate counts and gate booleans only; no paths, run IDs, timing values, candidates, patterns, cycles, or outcomes",
        "counts": {
            "discovered_log_count": len(rows),
            "recovered_attempt_count": len(rows),
            "unique_attempt_id_count": len(set(attempt_ids)),
            "classified_parse_status_count": sum(1 for value in parse_statuses if value),
            "unclassified_parse_status_count": sum(1 for value in parse_statuses if not value),
            "unknown_retry_order_count": retry_statuses.get("UNKNOWN_ORDER", 0),
            "nonempty_source_artifact_sha256_count": count(rows, "source_artifact_sha256"),
            "nonempty_inventory_binding_count": count(rows, "inventory_manifest_sha256"),
            "nonempty_phase_count": count(rows, "phase"),
            "nonempty_cohort_count": count(rows, "cohort"),
            "nonempty_environment_cohort_count": count(rows, "environment_cohort"),
        },
    }
    counts = result["counts"]
    row_count = counts["recovered_attempt_count"]
    result["validation"] = {
        "all_discovered_logs_retained": counts["discovered_log_count"] == row_count,
        "all_attempt_ids_unique": counts["unique_attempt_id_count"] == row_count,
        "all_attempts_have_parse_status": counts["classified_parse_status_count"] == row_count,
        "all_attempts_have_source_digest": counts["nonempty_source_artifact_sha256_count"] == row_count,
        "all_attempts_bind_inventory": counts["nonempty_inventory_binding_count"] == row_count,
        "all_attempts_record_phase": counts["nonempty_phase_count"] == row_count,
        "all_attempts_record_cohort": counts["nonempty_cohort_count"] == row_count,
        "all_attempts_record_environment_cohort": counts["nonempty_environment_cohort_count"] == row_count,
        "retry_order_not_imputed": counts["unknown_retry_order_count"] == row_count,
        "fastest_success_selection_performed": False,
        "candidate_join_performed": False,
        "blind_row_level_data_released": False,
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--circuit", required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--cohort", required=True)
    parser.add_argument("--environment-cohort", required=True)
    parser.add_argument("--inventory-manifest-sha256", required=True)
    args = parser.parse_args()
    meta = {
        "circuit": args.circuit,
        "family": args.family,
        "role": args.role,
        "phase": args.phase,
        "cohort": args.cohort,
        "environment_cohort": args.environment_cohort,
        "inventory_manifest_sha256": args.inventory_manifest_sha256,
    }
    result = audit(args.input, args.evidence_root, meta,
                   args.inventory_manifest_sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
