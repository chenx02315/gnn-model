#!/usr/bin/env python3
"""Verify the three recovered historical Phase2 runtime manifests.

The manifests remain outside Git.  This tool emits only aggregate provenance
needed to close R03: digests, sizes, row counts, and schema/status checks.
"""
from __future__ import print_function

import argparse
import csv
import hashlib
import json
import os
import re


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_FIELDS = {
    "candidate", "candidate_uid", "patterns", "h_patterns", "m_patterns",
    "f_patterns", "cycles", "total_cycles", "detected_faults", "d95",
    "feasible_at_d95", "outcome_rank",
}
HISTORICAL_FIELDS = (
    "attempt_id", "adapter", "circuit", "family", "role", "cohort",
    "environment_cohort", "phase", "stage", "mode", "run_id",
    "run_id_source", "wall_s", "user_s", "system_s", "rss_kb",
    "exit_status", "timeout_status", "retry_order", "retry_order_status",
    "parse_status", "attempt_outcome_class", "semantics_status",
    "semantics_contract", "elapsed_source", "elapsed_semantics",
    "retry_group_id", "source_artifact", "source_artifact_sha256",
    "source_row_number", "source_log_path", "source_log_sha256",
    "inventory_manifest_sha256",
)
SPECS = (
    {
        "circuit": "b18", "family": "itc99_b14_connected", "role": "PILOT",
        "logical_id": "phase2.b18.manifest", "rows": 2057,
        "manifest_sha256": "e251e482f070e2e80a6535ff1621a064cfb56e4c04b041c8d219c2505b6253e8",
        "source_sha256": "681943ab7d379169542a3c81956c79b124e17f7ee5fe718cf78400dc4eb89c71",
    },
    {
        "circuit": "s35932", "family": "iscas89_s35932", "role": "TRAIN",
        "logical_id": "phase2.s35932.manifest", "rows": 841,
        "manifest_sha256": "9eeb437f12598ddc08d5539800e0faaeab2508a0285e15d49b33f348538fe45f",
        "source_sha256": "63ed68527f1f5fedf60d5d1f08fdefff6b814e74de58e7c6a1754dbb3fbc62ee",
    },
    {
        "circuit": "s38417", "family": "iscas89_s38417", "role": "TRAIN",
        "logical_id": "phase2.s38417.manifest", "rows": 1711,
        "manifest_sha256": "416dfdbddee67964ebfbd93618d6cf63d8645553d7050804122b7b63f34f749c",
        "source_sha256": "ec169a9db102cd74e0856c2536fd7ae5fee0ec4a0f6927d1f4515eb2d28f58b6",
    },
)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def audit_file(input_dir, spec):
    name = "%s_attempt_manifest_v2.tsv" % spec["circuit"]
    path = os.path.join(input_dir, name)
    if not os.path.isfile(path):
        raise ValueError("missing historical manifest: %s" % name)
    observed_sha256 = sha256_file(path)
    if observed_sha256 != spec["manifest_sha256"]:
        raise ValueError("historical manifest digest mismatch: %s" % name)

    attempt_ids = set()
    source_rows = set()
    row_count = 0
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != HISTORICAL_FIELDS:
            raise ValueError("historical manifest schema mismatch: %s" % name)
        if FORBIDDEN_FIELDS.intersection(reader.fieldnames or ()):
            raise ValueError("forbidden outcome field in manifest: %s" % name)
        for row in reader:
            row_count += 1
            expected = {
                "adapter": "phase2_csv", "circuit": spec["circuit"],
                "family": spec["family"], "role": spec["role"],
                "cohort": "phase2_csv",
                "environment_cohort": "phase2_20260808_A_legacy_unverified",
                "phase": "phase2", "run_id_source": "csv_run_id",
                "parse_status": "PASS",
                "attempt_outcome_class": "COLLECTED_SUCCESS_ONLY",
                "semantics_status": "CONTRACT_VERIFIED",
                "semantics_contract": "tessent_process_wall_seconds",
                "elapsed_source": "phase2_csv.wall_time",
                "elapsed_semantics": "tessent_process_wall_seconds",
                "source_artifact_sha256": spec["source_sha256"],
            }
            if any(row[key] != value for key, value in expected.items()):
                raise ValueError("historical manifest metadata mismatch: %s row %d" %
                                 (name, row_count + 1))
            if not row["attempt_id"] or row["attempt_id"] in attempt_ids:
                raise ValueError("missing or duplicate attempt ID: %s" % name)
            if not row["wall_s"]:
                raise ValueError("missing wall time: %s row %d" % (name, row_count + 1))
            if row["source_log_path"] or row["source_log_sha256"]:
                raise ValueError("unexpected log-level provenance: %s" % name)
            try:
                source_row = int(row["source_row_number"])
            except ValueError:
                raise ValueError("invalid source row number: %s" % name)
            attempt_ids.add(row["attempt_id"])
            source_rows.add(source_row)

    if row_count != spec["rows"]:
        raise ValueError("historical manifest row count mismatch: %s" % name)
    if source_rows != set(range(2, spec["rows"] + 2)):
        raise ValueError("historical manifest source rows are incomplete: %s" % name)
    return {
        "byte_count": os.path.getsize(path),
        "data_row_count": row_count,
        "manifest_sha256": observed_sha256,
        "source_table_sha256": spec["source_sha256"],
        "unique_attempt_id_count": len(attempt_ids),
    }


def build_receipt(input_dir):
    artifacts = {}
    total_rows = 0
    total_bytes = 0
    for spec in SPECS:
        result = audit_file(input_dir, spec)
        artifacts[spec["logical_id"]] = result
        total_rows += result["data_row_count"]
        total_bytes += result["byte_count"]
    return {
        "schema_version": "phase2-historical-manifest-recovery-receipt-v1",
        "receipt_version": "r03-phase2-three-v1",
        "scope": "three non-BLIND historical Phase2 outcome-free runtime manifests",
        "source_boundary": "external local recovery directory; manifests are not checked into Git",
        "field_policy": "logical IDs, SHA-256 values, byte counts, row counts, and aggregate validation status only",
        "artifacts": artifacts,
        "counts": {
            "artifact_count": len(artifacts),
            "data_row_count": total_rows,
            "byte_count": total_bytes,
        },
        "validation": {
            "all_target_digests_match": True,
            "all_source_table_digests_match": True,
            "all_attempt_ids_unique_per_manifest": True,
            "all_rows_have_wall_time": True,
            "all_rows_collected_success_only": True,
            "all_forbidden_outcome_fields_absent": True,
            "blind_data_accessed": False,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    receipt = build_receipt(args.input_dir)
    with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(receipt, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("artifacts=%d rows=%d" %
          (receipt["counts"]["artifact_count"], receipt["counts"]["data_row_count"]))


if __name__ == "__main__":
    main()
