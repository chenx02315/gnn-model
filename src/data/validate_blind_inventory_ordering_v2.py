#!/usr/bin/env python3
"""Validate the versioned reconciliation of the v11 inventory false positive."""

import argparse
import json
import os
import sys


CIRCUITS = ("s9234", "s38584", "wb_dma")


def load(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def require(condition, code):
    if not condition:
        raise ValueError(code)


def validate(repo_root):
    v1 = load(os.path.join(repo_root, "data", "manifests", "blind_input_inventory_freeze_v1.json"))
    v2 = load(os.path.join(repo_root, "data", "manifests", "blind_input_inventory_freeze_v2.json"))
    failure = load(os.path.join(repo_root, "data", "manifests", "blind_runtime_unseal_v11_failure_20260923.json"))
    provenance = load(os.path.join(repo_root, "data", "manifests", "blind_inventory_drift_provenance_v1.json"))
    ordering = load(os.path.join(repo_root, "contracts", "blind_inventory_ordering_v2.json"))

    require(v2["schema_version"] == "blind-input-inventory-freeze-v2", "V2_SCHEMA")
    require(provenance["status"] == "V11_FALSE_POSITIVE_CONFIRMED", "PROVENANCE_STATUS")
    require(ordering["execution_authorized"] is False, "EXECUTION_AUTHORITY")
    require(ordering["training_allowed"] is False, "TRAINING_AUTHORITY")
    require(set(v2["circuits"]) == set(CIRCUITS), "V2_CIRCUITS")
    require(set(failure["inventory_diagnosis"]["circuits"]) == set(CIRCUITS), "FAILURE_CIRCUITS")

    for circuit in CIRCUITS:
        old = v1["circuits"][circuit]
        new = v2["circuits"][circuit]
        observed = failure["inventory_diagnosis"]["circuits"][circuit]
        finding = provenance["circuit_findings"][circuit]
        require(new["historical_locale_ordered_sha256"] == old["driver_log_file_set_sha256"], "HISTORICAL_DIGEST_" + circuit)
        require(new["bytewise_ordered_sha256"] == observed["current_driver_log_file_set_sha256"], "BYTEWISE_DIGEST_" + circuit)
        require(new["driver_log_count"] == old["driver_log_count"] == observed["driver_log_count"], "LOG_COUNT_" + circuit)
        require(new["measurement_file_set_sha256"] == old["measurement_file_set_sha256"] == observed["measurement_file_set_sha256"], "MEASUREMENT_DIGEST_" + circuit)
        require(finding["historical_digest_still_matches"] is True, "HISTORICAL_MATCH_" + circuit)
        require(finding["bytewise_digest_equals_v11_current"] is True, "BYTEWISE_MATCH_" + circuit)

    require(v2["circuits"]["s9234"]["historical_locale_ordered_sha256"] != v2["circuits"]["s9234"]["bytewise_ordered_sha256"], "S9234_ORDERING_CONTROL")
    require(v2["circuits"]["wb_dma"]["historical_locale_ordered_sha256"] != v2["circuits"]["wb_dma"]["bytewise_ordered_sha256"], "WB_DMA_ORDERING_CONTROL")
    require(v2["circuits"]["s38584"]["historical_locale_ordered_sha256"] == v2["circuits"]["s38584"]["bytewise_ordered_sha256"], "S38584_ORDERING_CONTROL")
    require(provenance["conclusions"]["source_content_drift_proven"] is False, "CONTENT_DRIFT_CLAIM")
    require(provenance["conclusions"]["source_path_set_drift_proven"] is False, "PATH_DRIFT_CLAIM")
    require(provenance["conclusions"]["v11_job_retry_requeue_rerun_forbidden"] is True, "V11_REPLAY_POLICY")
    require(provenance["conclusions"]["new_blind_execution_requires_v12_design_review_and_authorization"] is True, "V12_AUTHORITY")
    require(v2["candidate_rows_read"] is False and v2["candidate_join_performed"] is False, "BLIND_SCOPE")
    require(v2["execution_authorized"] is False and v2["training_allowed"] is False, "V2_AUTHORITY")
    return {"status": "PASS", "circuits": list(CIRCUITS), "v11_false_positive": True}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    args = parser.parse_args(argv)
    result = validate(os.path.abspath(args.repo_root))
    print("BLIND_INVENTORY_ORDERING_V2={}".format(result["status"]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("BLIND_INVENTORY_ORDERING_V2=FAIL {}".format(exc), file=sys.stderr)
        sys.exit(1)
