#!/usr/bin/env python3
"""Build and verify the sealed, evidence-bound v7 BLIND gate snapshot.

The snapshot deliberately contains no BLIND candidate, run, path, outcome, or
elapsed-time record.  It turns the already checked-in aggregate evidence into
a deterministic input for a later sealed runner.  R06/R07/R13 are intentionally
not inferred: they remain PENDING_BLIND_AUDIT until the one-shot audit completes.
"""

from __future__ import print_function

import argparse
import hashlib
import json
import os
import sys


ASSESSMENT = "contracts/runtime_recovery_gate_assessment_v1.json"
GATE_CONTRACT = "contracts/runtime_recovery_gate_v1.json"
SPLIT = "contracts/data_split_v1.json"
SOURCE_LEDGER = "data/manifests/runtime_source_ledger_v1.json"
PHASE2_RECEIPT = "data/manifests/phase2_manifest_recovery_receipt_v1.json"
BLIND_PRECONDITION_CONTRACT = "contracts/blind_attempt_preconditions_v1.json"
BLIND_PRECONDITION_ASSESSMENT = "data/manifests/blind_attempt_preconditions_v1/assessment.json"
NONBLIND_JOIN_AUDIT = "data/manifests/runtime_nonblind_join_audit_v2.json"
PHASE2_WALL_TIME = "data/manifests/phase2_wall_time_semantics_v1.json"
RUNTIME_POLICY = "contracts/runtime_policy_v1.json"
CANDIDATE_SPACE_AUDIT = "data/manifests/candidate_space_audit_v1.json"

BLIND_RECEIPTS = {
    "s38584": "data/manifests/blind_attempt_preconditions_v1/s38584.json",
    "s9234": "data/manifests/blind_attempt_preconditions_v1/s9234.json",
    "wb_dma": "data/manifests/blind_attempt_preconditions_v1/wb_dma.json",
}

UPSTREAM_FILES = sorted([
    ASSESSMENT,
    GATE_CONTRACT,
    SPLIT,
    SOURCE_LEDGER,
    PHASE2_RECEIPT,
    BLIND_PRECONDITION_CONTRACT,
    BLIND_PRECONDITION_ASSESSMENT,
    NONBLIND_JOIN_AUDIT,
    PHASE2_WALL_TIME,
    RUNTIME_POLICY,
    CANDIDATE_SPACE_AUDIT,
] + list(BLIND_RECEIPTS.values()))

EXPECTED_ASSESSMENT_STATUSES = {
    "R01": "PASS", "R02": "PASS", "R03": "PASS", "R04": "PASS",
    "R05": "PASS", "R06": "PARTIAL", "R07": "BLOCKED",
    "R08": "PASS", "R09": "PASS", "R10": "PASS", "R11": "PASS",
    "R12": "PASS", "R13": "BLOCKED", "R14": "PASS",
}
PENDING_BLIND_CHECKS = ("R06", "R07", "R13")


def _full_path(root, relative):
    return os.path.join(os.path.abspath(root), *relative.split("/"))


def _read_json(root, relative):
    with open(_full_path(root, relative), "r") as handle:
        return json.load(handle)


def _sha256_file(root, relative):
    digest = hashlib.sha256()
    with open(_full_path(root, relative), "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _assessment_statuses(assessment):
    return dict((name, item.get("status"))
                for name, item in assessment.get("checks", {}).items())


def _validate_split(split):
    membership = split.get("formal_runtime_membership", {})
    entries = []
    for role in ("BLIND_TEST", "PILOT", "TRAIN", "VALIDATION"):
        entries.extend(membership.get(role, []))
    circuits = [entry.get("circuit") for entry in entries]
    families = [entry.get("family") for entry in entries]
    _require(len(entries) == 15 and len(set(circuits)) == 15,
             "R01 formal split must contain exactly 15 unique circuits")
    _require(len(set(families)) == 12,
             "R01 formal split must contain exactly 12 families")
    pilot_circuits = [entry.get("circuit") for entry in membership.get("PILOT", [])]
    other_circuits = [entry.get("circuit") for role, rows in membership.items()
                      if role != "PILOT" for entry in rows]
    _require(pilot_circuits.count("b18") == 1 and "b18" not in other_circuits,
             "R02 b18 must occur only in PILOT")
    _require(split.get("sealed_blind_test") is True,
             "R14 requires a sealed BLIND split")
    _require(split.get("pre_split_access", {}).get("candidate_level_future_blind_mapping_seen") is False,
             "R14 requires no candidate-level future BLIND mapping access")
    return split.get("formal_runtime_membership_sha256")


def _validate_r03(ledger, phase2_receipt, gate_sha256):
    external = ledger.get("external_readback", {})
    _require(ledger.get("status") == "MATCHED_ALL_EXPECTED_SOURCE_DIGESTS",
             "R03 ledger status drift")
    _require(external.get("matched_count") == 73 and
             external.get("missing_expected_count") == 0 and
             external.get("mismatched_count") == 0 and
             external.get("unbound_count") == 0,
             "R03 source ledger counts drift")
    _require(ledger.get("local_artifacts", {}).get(GATE_CONTRACT) == gate_sha256,
             "R03 ledger gate-contract binding drift")
    _require(phase2_receipt.get("validation", {}).get("blind_data_accessed") is False,
             "R03 Phase2 receipt must remain non-BLIND")
    _require(phase2_receipt.get("validation", {}).get("all_rows_have_wall_time") is True,
             "R03 Phase2 receipt lost wall-time validation")


def _validate_blind_preconditions(contract, assessment, receipts):
    _require(assessment.get("status") == "PASS", "BLIND aggregate assessment status drift")
    _require(assessment.get("candidate_join_performed") is False,
             "BLIND aggregate assessment must not perform a candidate join")
    _require(assessment.get("training_allowed") is False,
             "BLIND aggregate assessment must keep training sealed")
    required_counts = contract.get("required_counts", {})
    _require(sorted(receipts) == sorted(required_counts),
             "BLIND aggregate receipt circuit set drift")
    for circuit in sorted(receipts):
        receipt = receipts[circuit]
        validation = receipt.get("validation", {})
        count = receipt.get("counts", {})
        expected = required_counts[circuit]
        _require(receipt.get("role") == "BLIND_TEST", "BLIND receipt role drift for " + circuit)
        _require(count.get("discovered_log_count") == expected and
                 count.get("recovered_attempt_count") == expected and
                 count.get("unique_attempt_id_count") == expected,
                 "BLIND aggregate count drift for " + circuit)
        for field in contract.get("required_true_validations", []):
            _require(validation.get(field) is True,
                     "BLIND aggregate true validation drift: " + circuit + ":" + field)
        for field in contract.get("required_false_validations", []):
            _require(validation.get(field) is False,
                     "BLIND aggregate false validation drift: " + circuit + ":" + field)
        assessment_row = assessment.get("circuits", {}).get(circuit, {})
        _require(assessment_row.get("attempt_count") == expected,
                 "BLIND assessment count drift for " + circuit)


def _validate_r08_r09(policy, nonblind_audit, gate):
    timing = policy.get("timing", {})
    retry = policy.get("retry", {})
    _require(timing.get("failed_attempt_elapsed_in_primary") is True and
             timing.get("retry_elapsed_in_primary") is True and
             retry.get("charge_all_attempts") is True and
             retry.get("select_fastest_success") is False,
             "R05 timing/retry policy drift")
    _require(policy.get("missing_historical_timing", {}).get("policy") == "missing_label_no_imputation" and
             policy.get("missing_historical_timing", {}).get("zero_cost_precompute_forbidden") is True,
             "R09 no-imputation policy drift")
    execution = gate.get("execution_state_policy", {})
    _require("F is NOT_RUN" in execution.get("TARGET_BEFORE_F", "") and
             "F is NOT_RUN" in execution.get("INFEASIBLE_AT_D95", "") and
             "only a pathless mode is NOT_RUN" in execution.get("NOT_RUN", "") and
             "NO_RESULT_PATH" in execution.get("repeatability", ""),
             "R08 execution-state policy drift")
    policies = nonblind_audit.get("policies", {})
    _require("never charged runtime" in policies.get("not_run", "") and
             "no fastest-success" in policies.get("prefix_reuse", ""),
             "R05/R08 non-BLIND audit policy drift")


def _validate_r10(wall_time):
    _require(wall_time.get("validation_status") == "PASS", "R10 wall-time status drift")
    _require(wall_time.get("missing_elapsed_policy") == "never_impute" and
             wall_time.get("retry_attempt_policy") == "include_each_attempt_elapsed" and
             wall_time.get("failed_attempt_policy") == "include_observed_elapsed",
             "R10 timing semantics policy drift")
    for circuit in ("b18", "s35932", "s38417"):
        checks = wall_time.get("circuits", {}).get(circuit, {}).get("checks", {})
        _require(all(checks.get(name) == 0 for name in (
            "circuit_mismatch_count", "duplicate_run_id_count", "footer_mismatch_count",
            "invalid_footer_wall_count", "invalid_wall_count", "missing_csv_wall_count",
            "missing_driver_count", "missing_footer_count")),
            "R10 nonzero audit counter for " + circuit)


def _validate_r12(candidate_space, gate):
    _require(candidate_space.get("outcome_conflict_action_count") == 0,
             "R12 candidate outcome-conflict count drift")
    _require("never select an outcome" in candidate_space.get("deduplication_policy", ""),
             "R12 candidate deduplication policy drift")
    forbidden = set(gate.get("forbidden_runtime_proxies", []))
    _require({"h_cycles", "m_cycles", "f_cycles", "pattern_count"}.issubset(forbidden),
             "R12 forbidden-runtime-proxy policy drift")


def build_snapshot(root):
    """Return canonical snapshot bytes after validating all pinned evidence."""
    root = os.path.abspath(root)
    files = dict((relative, _sha256_file(root, relative)) for relative in UPSTREAM_FILES)
    assessment = _read_json(root, ASSESSMENT)
    gate = _read_json(root, GATE_CONTRACT)
    split = _read_json(root, SPLIT)
    ledger = _read_json(root, SOURCE_LEDGER)
    phase2_receipt = _read_json(root, PHASE2_RECEIPT)
    blind_contract = _read_json(root, BLIND_PRECONDITION_CONTRACT)
    blind_assessment = _read_json(root, BLIND_PRECONDITION_ASSESSMENT)
    blind_receipts = dict((name, _read_json(root, path)) for name, path in BLIND_RECEIPTS.items())
    nonblind_audit = _read_json(root, NONBLIND_JOIN_AUDIT)
    wall_time = _read_json(root, PHASE2_WALL_TIME)
    policy = _read_json(root, RUNTIME_POLICY)
    candidate_space = _read_json(root, CANDIDATE_SPACE_AUDIT)

    statuses = _assessment_statuses(assessment)
    _require(assessment.get("assessment_status") == "BLOCKED", "assessment must remain BLOCKED")
    _require(assessment.get("training_allowed") is False, "assessment must keep training disabled")
    _require(statuses == EXPECTED_ASSESSMENT_STATUSES, "assessment status drift")
    _require(assessment.get("gate_contract_sha256") == files[GATE_CONTRACT],
             "assessment gate-contract digest drift")
    _require(gate.get("training_allowed") is False, "gate contract must keep training disabled")

    split_hash = _validate_split(split)
    _require(split_hash == ledger.get("formal_split", {}).get("formal_runtime_membership_sha256"),
             "R01/R14 split-hash binding drift")
    _validate_r03(ledger, phase2_receipt, files[GATE_CONTRACT])
    _validate_blind_preconditions(blind_contract, blind_assessment, blind_receipts)
    _validate_r08_r09(policy, nonblind_audit, gate)
    _validate_r10(wall_time)
    _validate_r12(candidate_space, gate)

    support = {
        "R01": [SPLIT, ASSESSMENT],
        "R02": [SPLIT, ASSESSMENT],
        "R03": [SOURCE_LEDGER, PHASE2_RECEIPT, ASSESSMENT, GATE_CONTRACT],
        "R04": [NONBLIND_JOIN_AUDIT, BLIND_PRECONDITION_CONTRACT,
                BLIND_PRECONDITION_ASSESSMENT] + [BLIND_RECEIPTS[name] for name in sorted(BLIND_RECEIPTS)],
        "R05": [RUNTIME_POLICY, NONBLIND_JOIN_AUDIT, BLIND_PRECONDITION_CONTRACT,
                BLIND_PRECONDITION_ASSESSMENT] + [BLIND_RECEIPTS[name] for name in sorted(BLIND_RECEIPTS)],
        "R08": [GATE_CONTRACT, RUNTIME_POLICY, NONBLIND_JOIN_AUDIT],
        "R09": [RUNTIME_POLICY, PHASE2_WALL_TIME, GATE_CONTRACT],
        "R10": [PHASE2_WALL_TIME, ASSESSMENT],
        "R11": [NONBLIND_JOIN_AUDIT, BLIND_PRECONDITION_CONTRACT,
                BLIND_PRECONDITION_ASSESSMENT] + [BLIND_RECEIPTS[name] for name in sorted(BLIND_RECEIPTS)],
        "R12": [CANDIDATE_SPACE_AUDIT, GATE_CONTRACT],
        "R14": [SPLIT, SOURCE_LEDGER, ASSESSMENT],
    }
    frozen_checks = {}
    for check in sorted(support):
        frozen_checks[check] = {
            "status": "PASS",
            "supporting_files": sorted(support[check]),
        }
    for check in PENDING_BLIND_CHECKS:
        frozen_checks[check] = {
            "status": "PENDING_BLIND_AUDIT",
            "reason": "candidate-level BLIND audit is sealed and this snapshot must not infer its result",
            "supporting_files": [],
        }

    snapshot = {
        "schema_version": "blind-gate-snapshot-v1",
        "purpose": "deterministic digest-bound precondition snapshot for a future sealed BLIND audit",
        "snapshot_status": "SEALED_PENDING_BLIND_AUDIT",
        "training_allowed": False,
        "blind_data_accessed": False,
        "candidate_level_blind_join_performed": False,
        "assessment": {
            "path": ASSESSMENT,
            "sha256": files[ASSESSMENT],
            "assessment_status": assessment.get("assessment_status"),
            "observed_statuses": statuses,
        },
        "gate_contract": {
            "path": GATE_CONTRACT,
            "sha256": files[GATE_CONTRACT],
        },
        "frozen_checks": frozen_checks,
        "pending_blind_checks": list(PENDING_BLIND_CHECKS),
        "upstream_files": files,
    }
    return (json.dumps(snapshot, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode("utf-8")


def verify_snapshot(root, snapshot_path):
    """Fail unless *snapshot_path* exactly equals a fresh canonical rebuild."""
    with open(snapshot_path, "rb") as handle:
        existing = handle.read()
    rebuilt = build_snapshot(root)
    _require(existing == rebuilt, "snapshot differs from deterministic rebuild")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="data/manifests/blind_gate_snapshot_v1.json")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    output = _full_path(args.root, args.output)
    if args.verify:
        verify_snapshot(args.root, output)
        print("PASS blind gate snapshot verified")
        return 0
    payload = build_snapshot(args.root)
    with open(output, "wb") as handle:
        handle.write(payload)
    print("WROTE " + args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
