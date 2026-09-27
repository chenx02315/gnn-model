#!/usr/bin/env python3
"""Fresh-output v12-r9 join with every local runtime dependency digest-bound."""
from __future__ import print_function

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
if BUNDLE_ROOT not in sys.path:
    sys.path.insert(0, BUNDLE_ROOT)

from src.data import run_blind_join_v12_r8 as prior

base = prior.base
CONTRACT_RELATIVE = "contracts/blind_runtime_join_v12_r9.json"
OUTPUT_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/21_blind_runtime_join_v12_r9"
RECOVERY_CLOSEOUT_RELATIVE = "data/manifests/blind_runtime_recovery_execution_v3_audit_20260927.json"
R8_FAILURE_RELATIVE = "data/manifests/blind_runtime_join_v12_r8_failure_closeout_20260927.json"
REQUIRED_RECOVERY_ANCHORS = dict(prior.REQUIRED_RECOVERY_ANCHORS)
REQUIRED_ARTIFACTS = {
    "src/data/blind_inventory_v12_r2.py",
    "src/data/blind_join_core_v12_r3.py",
    "src/data/run_blind_join_v12_r3.py",
    "src/data/run_blind_join_v12_r5.py",
    "src/data/run_blind_join_v12_r6.py",
    "src/data/run_blind_join_v12_r7.py",
    "src/data/run_blind_join_v12_r8.py",
    "src/data/run_blind_join_v12_r9.py",
    "tests/test_run_blind_join_v12_r9.py",
    RECOVERY_CLOSEOUT_RELATIVE,
    R8_FAILURE_RELATIVE,
}


class Refusal(Exception):
    pass


def validate_bundle():
    path = os.path.join(BUNDLE_ROOT, *CONTRACT_RELATIVE.split("/"))
    contract = base._json(path, "CONTRACT_PARSE")
    recovery = contract.get("recovery", {})
    if (contract.get("schema_version") != "blind-runtime-join-v12-r9" or
        contract.get("status") != "AUTHORIZED_EXECUTION_REVIEWED" or
        contract.get("circuits") != list(base.CIRCUIT_ORDER) or
        contract.get("output_root") != OUTPUT_ROOT or
        contract.get("training_allowed") is not False or
        contract.get("historical_inventory_sha256") != base.HISTORICAL_INVENTORY_SHA256 or
        recovery.get("job_id") != base.JOB_ID or
        recovery.get("receipt_set_algorithm") !=
        "sha256(LF-joined '<filename> <sha256(receipt_bytes)>' lines with one trailing LF, in validated manifest order)"):
        raise Refusal("CONTRACT_SCOPE")
    for key, expected in REQUIRED_RECOVERY_ANCHORS.items():
        value = recovery.get(key)
        if not prior.prior._is_sha256(value) or value != expected:
            raise Refusal("CONTRACT_RECOVERY_ANCHOR_" + key.upper())
    artifacts = contract.get("implementation", {}).get("artifact_sha256", {})
    if set(artifacts) != REQUIRED_ARTIFACTS:
        raise Refusal("CONTRACT_ARTIFACT_SET")
    for relative, digest in artifacts.items():
        if not prior.prior._is_sha256(digest):
            raise Refusal("CONTRACT_ARTIFACT_DIGEST")
        artifact = os.path.join(BUNDLE_ROOT, *relative.split("/"))
        if os.path.islink(artifact) or base._sha(base._read(artifact)) != digest:
            raise Refusal("ARTIFACT_DIGEST_MISMATCH")
    raw = base._read(path)
    return base._sha(raw), base.core._sha_lines(
        relative + ":" + digest for relative, digest in artifacts.items())


def _write(receipt):
    if os.path.lexists(OUTPUT_ROOT):
        raise Refusal("OUTPUT_ROOT_ALREADY_EXISTS")
    parent = os.path.dirname(OUTPUT_ROOT)
    if not os.path.isdir(parent):
        raise Refusal("OUTPUT_PARENT_MISSING")
    os.mkdir(OUTPUT_ROOT, 0o700)
    raw = json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    digest = base._sha(raw)
    base._exclusive(os.path.join(OUTPUT_ROOT, "receipt.json"), raw)
    base._exclusive(os.path.join(OUTPUT_ROOT, "receipt.json.sha256"),
                    (digest + "  receipt.json\n").encode("ascii"))
    released = {"schema_version": "blind-runtime-join-release-v12-r9",
                "status": "RELEASED_AUDIT_PENDING", "receipt_sha256": digest}
    base._exclusive(os.path.join(OUTPUT_ROOT, "RELEASED"),
                    json.dumps(released, sort_keys=True).encode("utf-8") + b"\n")


def run():
    contract_sha, implementation_sha = validate_bundle()
    try:
        base.historical._validate_runtime_platform()
        closeout_sha = base._validate_closeout()
        plan = base._plan()
        recovery = prior._recovery(plan)
        base.historical.secure._run_verified_sort = base.historical._verified_sort_fd
        control = base.historical.impl.open_trusted_control()
        rows = []
        for circuit in base.CIRCUIT_ORDER:
            old, measurements = base.historical.impl.snapshot_circuit(control, circuit)
            old.update(recovery[circuit])
            rows.append(base.core.audit_circuit(circuit, old, measurements))
        if not base._valid(rows):
            raise base.core.JoinFailure("COVERAGE_GATE", "R06_R07_FAILED")
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r9",
                   "status": "PASS_R06_R07_AUDIT_PENDING",
                   "formal_runtime_membership_sha256": base.FORMAL_MEMBERSHIP_SHA256,
                   "split_contract_sha256": base.SPLIT_SHA256,
                   "method_registry_sha256": base.METHOD_REGISTRY_SHA256,
                   "contract_sha256": contract_sha,
                   "implementation_set_sha256": implementation_sha,
                   "recovery_closeout_sha256": closeout_sha,
                   "recovery_execution_audit_sha256": prior.prior.EXECUTION_AUDIT_SHA256,
                   "recovery_job_id": base.JOB_ID,
                   "recovery_plan_sha256": base.PLAN_SHA256,
                   "recovery_source_manifest_sha256": base.SOURCE_MANIFEST_SHA256,
                   "recovery_copy_verification_sha256": base.COPY_VERIFICATION_SHA256,
                   "recovery_receipt_set_sha256": base.RECEIPT_SET_SHA256,
                   "circuits": rows, "failure_code": None, "training_allowed": False}
        code = 0
    except base.core.JoinFailure as error:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r9", "status": "FAIL",
                   "contract_sha256": contract_sha, "implementation_set_sha256": implementation_sha,
                   "failure_stage": error.stage, "failure_code": error.code,
                   "circuits": [], "training_allowed": False}
        code = 1
    except (base.Refusal, base.historical.Refusal, base.historical.impl.Refusal,
            base.historical.secure.Refusal, prior.Refusal, Refusal,
            OSError, ValueError, KeyError) as error:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r9", "status": "FAIL",
                   "contract_sha256": contract_sha, "implementation_set_sha256": implementation_sha,
                   "failure_stage": "SOURCE_INVENTORY", "failure_code": str(error),
                   "circuits": [], "training_allowed": False}
        code = 1
    except Exception:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r9", "status": "FAIL",
                   "contract_sha256": contract_sha, "implementation_set_sha256": implementation_sha,
                   "failure_stage": "INTERNAL_AUDIT", "failure_code": "INTERNAL_AUDIT_FAILURE",
                   "circuits": [], "training_allowed": False}
        code = 1
    _write(receipt)
    return code


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv):
        print("BLIND_JOIN_V12_R9=REFUSED_FIXED_ARGV")
        return 2
    try:
        code = run()
    except Refusal as error:
        print("BLIND_JOIN_V12_R9=REFUSED_" + str(error))
        return 2
    print("BLIND_JOIN_V12_R9=" + ("R06_R07_AUDIT_PENDING" if code == 0 else "FAILED_CLOSED"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
