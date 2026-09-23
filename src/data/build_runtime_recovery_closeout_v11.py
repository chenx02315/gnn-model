#!/usr/bin/env python3
"""Build the fail-closed P0 state after the consumed v11 BLIND audit."""
from __future__ import print_function

import argparse
import hashlib
import json
import os


SOURCES = {
    "blind_inventory": "data/manifests/blind_input_inventory_freeze_v1.json",
    "failure": "data/manifests/blind_runtime_unseal_v11_failure_20260923.json",
    "gate_assessment": "contracts/runtime_recovery_gate_assessment_v1.json",
    "scheduler_audit": "data/manifests/blind_runtime_unseal_scheduler_audit_v11.json",
}
EXPECTED_SOURCE_SHA256 = {
    "blind_inventory": "a157c399e783110c9776bf26cfaac656f85887f96d73a2c06d10c6d09cbada35",
    "failure": "c80e6b5760b03919b660d6e6bbb91cb11ca047fa3186cf20970d29486a9115e8",
    "gate_assessment": "4c027fef987f7962547cd7e59209e1095eef9e8183076b609021b8c94dd69d69",
    "scheduler_audit": "c0b892446abbce25ae8955454af88f7446767999b90c2d8c4d5e44a088125d06",
}


class CloseoutError(ValueError):
    pass


def _require(condition, code):
    if not condition:
        raise CloseoutError(code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _read_json(root, label):
    path = os.path.join(root, SOURCES[label])
    with open(path, "rb") as stream:
        raw = stream.read()
    _require(_sha(raw) == EXPECTED_SOURCE_SHA256[label], "SOURCE_DIGEST_" + label)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise CloseoutError("SOURCE_PARSE_" + label)


def build_closeout(repo_root):
    docs = {label: _read_json(repo_root, label) for label in SOURCES}
    failure = docs["failure"]
    scheduler = docs["scheduler_audit"]
    inventory = docs["blind_inventory"]
    gate = docs["gate_assessment"]

    _require(failure.get("schema_version") == "blind-runtime-unseal-failure-audit-v11", "FAILURE_SCHEMA")
    _require(failure.get("status") == "FAILED_INPUT_INVENTORY_DRIFT_SCHEDULER_VERIFIED", "FAILURE_STATUS")
    _require(failure.get("job_id") == "388790" and failure.get("scheduler_terminal") == "EXIT" and failure.get("exit_code") == 1, "FAILURE_TERMINAL")
    _require(failure.get("runner_receipt_status") == "FAIL" and failure.get("failure_stage") == "SOURCE_INVENTORY" and failure.get("failure_code") == "INPUT_INVENTORY_DRIFT" and failure.get("circuits") == [], "FAILURE_ENVELOPE")
    _require(failure.get("candidate_rows_released") is False and failure.get("candidate_join_performed") is False, "FAILURE_SEALED")

    _require(scheduler.get("schema_version") == "blind-runtime-unseal-scheduler-audit-v11" and scheduler.get("status") == "RELEASED_VERIFIED" and scheduler.get("job_id") == "388790", "SCHEDULER_STATUS")
    _require(failure.get("scheduler_audit_receipt_sha256") == EXPECTED_SOURCE_SHA256["scheduler_audit"], "SCHEDULER_RECEIPT_BINDING")
    for key in ("registration_receipt_sha256", "protocol_sha256", "raw_bjobs_capture_sha256", "raw_global_bjobs_capture_sha256", "bhist_raw_capture_sha256", "bacct_raw_capture_sha256", "stdout_capture_sha256", "stderr_capture_sha256", "four_artifact_sha256"):
        _require(failure.get(key) == scheduler.get(key), "SCHEDULER_BINDING_" + key)

    frozen = inventory.get("circuits", {})
    diagnosis = failure.get("inventory_diagnosis", {}).get("circuits", {})
    _require(inventory.get("status") == "PASS_AGGREGATE_ONLY" and inventory.get("blind_candidate_rows_read") is False and inventory.get("candidate_join_performed") is False, "INVENTORY_STATUS")
    _require(set(frozen) == {"s9234", "s38584", "wb_dma"} and set(diagnosis) == set(frozen), "INVENTORY_SCOPE")
    expected_status = {"s9234": "DRIFT", "s38584": "MATCH", "wb_dma": "DRIFT"}
    for name in sorted(frozen):
        row = diagnosis[name]
        _require(row.get("measurement_status") == "MATCH" and row.get("measurement_file_set_sha256") == frozen[name]["measurement_file_set_sha256"], "MEASUREMENT_" + name)
        _require(row.get("driver_log_count") == frozen[name]["driver_log_count"], "LOG_COUNT_" + name)
        _require(row.get("expected_driver_log_file_set_sha256") == frozen[name]["driver_log_file_set_sha256"], "LOG_EXPECTED_" + name)
        _require(row.get("driver_log_status") == expected_status[name], "LOG_STATUS_" + name)
        _require((row.get("current_driver_log_file_set_sha256") == row.get("expected_driver_log_file_set_sha256")) == (expected_status[name] == "MATCH"), "LOG_DIGEST_" + name)

    checks = gate.get("checks", {})
    _require(gate.get("assessment_status") == "BLOCKED" and gate.get("training_allowed") is False, "GATE_STATUS")
    remaining = {key: checks.get(key, {}).get("status") for key in ("R06", "R07", "R13")}
    _require(remaining == {"R06": "PARTIAL", "R07": "BLOCKED", "R13": "BLOCKED"}, "GATE_REMAINING")
    policy = failure.get("execution_policy", {})
    _require(all(policy.get(key) is True for key in ("job_388790_retry_forbidden", "job_388790_requeue_forbidden", "job_388790_rerun_forbidden", "training_forbidden", "blind_candidate_reinspection_forbidden", "new_execution_requires_new_version_and_authorization")), "EXECUTION_POLICY")

    return {
        "schema_version": "runtime-recovery-closeout-v11",
        "status": "BLOCKED_AFTER_V11_INPUT_INVENTORY_DRIFT",
        "training_allowed": False,
        "source_sha256": {label: EXPECTED_SOURCE_SHA256[label] for label in sorted(SOURCES)},
        "v11_failure": {
            "job_id": "388790",
            "scheduler_audit_status": "RELEASED_VERIFIED",
            "scheduler_terminal": "EXIT",
            "exit_code": 1,
            "failure_stage": "SOURCE_INVENTORY",
            "failure_code": "INPUT_INVENTORY_DRIFT",
            "circuits": [],
        },
        "inventory_result": {
            "measurement_match_circuits": ["s9234", "s38584", "wb_dma"],
            "driver_log_match_circuits": ["s38584"],
            "driver_log_drift_circuits": ["s9234", "wb_dma"],
            "driver_log_counts_unchanged": True,
            "candidate_rows_released": False,
            "candidate_join_performed": False,
        },
        "remaining_gates": remaining,
        "declarations": {
            "job_388790_retry_requeue_rerun_forbidden": True,
            "training_forbidden": True,
            "frozen_digest_replacement_without_provenance_forbidden": True,
            "new_blind_execution_requires_new_version_and_authorization": True,
        },
        "next_gate": "Establish provenance for the s9234 and wb_dma driver-log digest differences and freeze a new immutable source snapshot before designing any new one-shot audit.",
    }


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = build_closeout(os.path.abspath(args.repo_root))
        with open(args.output, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(_canonical(result))
    except (OSError, CloseoutError) as error:
        print("RUNTIME_RECOVERY_CLOSEOUT_V11=FAIL:%s" % error)
        return 1
    print("RUNTIME_RECOVERY_CLOSEOUT_V11=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
