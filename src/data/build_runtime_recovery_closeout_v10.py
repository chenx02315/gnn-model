#!/usr/bin/env python3
"""Build a path-free, fail-closed local closeout after v10 scheduler failure."""
from __future__ import print_function

import argparse
import hashlib
import json
import os

SOURCES = {
    "nonblind_join_audit": "data/manifests/runtime_nonblind_join_audit_v2.json",
    "source_ledger": "data/manifests/runtime_source_ledger_v1.json",
    "blind_inventory": "data/manifests/blind_input_inventory_freeze_v1.json",
    "v10_failure": "data/manifests/blind_runtime_unseal_v10_failure_20260922.json",
    "gate_assessment": "contracts/runtime_recovery_gate_assessment_v1.json",
}
EXPECTED_SOURCE_SHA256 = {
    "blind_inventory": "a157c399e783110c9776bf26cfaac656f85887f96d73a2c06d10c6d09cbada35",
    "gate_assessment": "4c027fef987f7962547cd7e59209e1095eef9e8183076b609021b8c94dd69d69",
    "nonblind_join_audit": "d453c8a672b2766311c4541e581bf562d7a057676324e88d781bbad0b8081d1e",
    "source_ledger": "45d00b6fc66c4e274c87b397bd6e09176b388e956dcf846c39c5ae79044a2afd",
    "v10_failure": "e438c44f63b13bd85340132958c791c474da6a3a709ff5d54eba7b957bbf287a",
}
BLIND_COUNTS = {"s38584": 753, "s9234": 4520, "wb_dma": 2581}


class CloseoutError(ValueError):
    pass


def _require(condition, code):
    if not condition:
        raise CloseoutError(code)


def _read_json(root, label, relative):
    path = os.path.join(root, relative)
    with open(path, "rb") as stream:
        raw = stream.read()
    try:
        _require(_sha(raw) == EXPECTED_SOURCE_SHA256[label], "SOURCE_DIGEST_" + label)
        decoded = json.loads(raw.decode("utf-8"))
        _require(_sha(raw) == EXPECTED_SOURCE_SHA256[label], "SOURCE_DIGEST_" + label)
        return raw, decoded
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CloseoutError("SOURCE_PARSE_" + relative.replace("/", "_"))


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def build_closeout(repo_root):
    """Read only the five fixed checked-in summaries and return a deterministic closeout."""
    raw, docs = {}, {}
    for label, relative in SOURCES.items():
        raw[label], docs[label] = _read_json(repo_root, label, relative)
    nonblind, ledger, inventory, failure, gate = (docs[key] for key in (
        "nonblind_join_audit", "source_ledger", "blind_inventory", "v10_failure", "gate_assessment"))

    aggregate = nonblind.get("aggregate", {})
    _require(nonblind.get("schema_version") == "runtime_nonblind_join_audit_v2" and nonblind.get("status") == "PASS_NONBLIND_JOIN_AUDIT_PARTIAL_FORMAL_SPLIT", "NONBLIND_STATUS")
    _require({key: aggregate.get(key) for key in ("circuit_count", "row_count", "unique_join_count", "missing_count", "ambiguity_count")} == {"circuit_count": 6, "row_count": 7015, "unique_join_count": 5659, "missing_count": 0, "ambiguity_count": 0}, "NONBLIND_AGGREGATE")

    readback = ledger.get("external_readback", {})
    _require(ledger.get("schema_version") == "runtime-source-ledger-v1" and ledger.get("status") == "MATCHED_ALL_EXPECTED_SOURCE_DIGESTS", "LEDGER_STATUS")
    _require({key: readback.get(key) for key in ("expected_bindable_count", "matched_count", "missing_expected_count", "mismatched_count", "unbound_count")} == {"expected_bindable_count": 73, "matched_count": 73, "missing_expected_count": 0, "mismatched_count": 0, "unbound_count": 0} and readback.get("status") == "MATCHED", "LEDGER_READBACK")

    circuits = inventory.get("circuits", {})
    _require(inventory.get("schema_version") == "blind-input-inventory-freeze-v1" and inventory.get("status") == "PASS_AGGREGATE_ONLY", "BLIND_INVENTORY_STATUS")
    _require(set(circuits) == set(BLIND_COUNTS) and all(circuits[name].get("driver_log_count") == count for name, count in BLIND_COUNTS.items()), "BLIND_COUNTS")
    _require(inventory.get("blind_candidate_rows_read") is False and inventory.get("candidate_join_performed") is False and inventory.get("training_allowed") is False, "BLIND_SEALED")

    _require(failure.get("schema_version") == "blind-runtime-unseal-failure-audit-v10" and failure.get("status") == "FAILED_SCHEDULER_AUDIT" and failure.get("job_id") == "388761", "V10_FAILURE_STATUS")
    _require(failure.get("scheduler_terminal") == "EXIT" and failure.get("exit_code") == 1 and failure.get("runner_receipt_status") == "FAIL" and failure.get("failure_code") == "SEALED_AUDIT_FAILED" and failure.get("circuits") == [], "V10_FAILURE_ENVELOPE")

    checks = gate.get("checks", {})
    _require(gate.get("schema_version") == "runtime-recovery-gate-assessment-v1" and gate.get("assessment_status") == "BLOCKED" and gate.get("training_allowed") is False, "GATE_STATUS")
    _require({key: checks.get(key, {}).get("status") for key in ("R06", "R07", "R13")} == {"R06": "PARTIAL", "R07": "BLOCKED", "R13": "BLOCKED"}, "GATE_REMAINING")

    return {
        "schema_version": "runtime-recovery-closeout-v10",
        "status": "BLOCKED_AFTER_V10_FAILURE",
        "training_allowed": False,
        "source_sha256": {label: EXPECTED_SOURCE_SHA256[label] for label in sorted(raw)},
        "nonblind_aggregate": {key: aggregate[key] for key in ("circuit_count", "row_count", "unique_join_count", "missing_count", "ambiguity_count")},
        "ledger_readback": {key: readback[key] for key in ("expected_bindable_count", "matched_count", "missing_expected_count", "mismatched_count", "unbound_count")},
        "blind_aggregate_only": {"driver_log_count": {name: circuits[name]["driver_log_count"] for name in sorted(BLIND_COUNTS)}, "total_driver_log_count": sum(BLIND_COUNTS.values()), "candidate_join_performed": False},
        "v10_failure": {"failure_manifest_sha256": _sha(raw["v10_failure"]), "job_id": "388761", "scheduler_terminal": "EXIT", "exit_code": 1, "runner_receipt_status": "FAIL", "failure_code": "SEALED_AUDIT_FAILED", "circuits": []},
        "remaining_gates": {key: checks[key]["status"] for key in ("R06", "R07", "R13")},
        "declarations": {
            "candidate_level_blind_read_forbidden": True,
            "rerun_job_388761_forbidden": True,
            "training_forbidden": True,
            "nonblind_replay_is_not_root_cause": True,
        },
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
        print("RUNTIME_RECOVERY_CLOSEOUT_V10=FAIL:%s" % error)
        return 1
    print("RUNTIME_RECOVERY_CLOSEOUT_V10=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
