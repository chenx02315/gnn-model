#!/usr/bin/env python3
"""Fresh-output v12-r8 join reproducing the sealed v3 receipt-set digest."""
from __future__ import print_function

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
if BUNDLE_ROOT not in sys.path:
    sys.path.insert(0, BUNDLE_ROOT)

from src.data import run_blind_join_v12_r7 as prior

base = prior.base
CONTRACT_RELATIVE = "contracts/blind_runtime_join_v12_r8.json"
OUTPUT_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/20_blind_runtime_join_v12_r8"
REQUIRED_RECOVERY_ANCHORS = {
    "closeout_sha256": base.CLOSEOUT_SHA256,
    "execution_audit_sha256": prior.EXECUTION_AUDIT_SHA256,
    "plan_sha256": base.PLAN_SHA256,
    "source_manifest_sha256": base.SOURCE_MANIFEST_SHA256,
    "copy_verification_sha256": base.COPY_VERIFICATION_SHA256,
    "receipt_set_sha256": base.RECEIPT_SET_SHA256,
}
REQUIRED_ARTIFACTS = {
    "src/data/blind_inventory_v12_r2.py",
    "src/data/blind_join_core_v12_r3.py",
    "src/data/run_blind_join_v12_r3.py",
    "src/data/run_blind_join_v12_r5.py",
    "src/data/run_blind_join_v12_r6.py",
    "src/data/run_blind_join_v12_r7.py",
    "src/data/run_blind_join_v12_r8.py",
    "tests/test_run_blind_join_v12_r8.py",
}


class Refusal(Exception):
    pass


def _receipt_set_sha256(named_raw_receipts):
    lines = [name + " " + base._sha(raw) for name, raw in named_raw_receipts]
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_bundle():
    path = os.path.join(BUNDLE_ROOT, *CONTRACT_RELATIVE.split("/"))
    contract = base._json(path, "CONTRACT_PARSE")
    recovery = contract.get("recovery", {})
    if (contract.get("schema_version") != "blind-runtime-join-v12-r8" or
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
        if not prior._is_sha256(value) or value != expected:
            raise Refusal("CONTRACT_RECOVERY_ANCHOR_" + key.upper())
    artifacts = contract.get("implementation", {}).get("artifact_sha256", {})
    if set(artifacts) != REQUIRED_ARTIFACTS:
        raise Refusal("CONTRACT_ARTIFACT_SET")
    for relative, digest in artifacts.items():
        if not prior._is_sha256(digest):
            raise Refusal("CONTRACT_ARTIFACT_DIGEST")
        artifact = os.path.join(BUNDLE_ROOT, *relative.split("/"))
        if os.path.islink(artifact) or base._sha(base._read(artifact)) != digest:
            raise Refusal("ARTIFACT_DIGEST_MISMATCH")
    raw = base._read(path)
    return base._sha(raw), base.core._sha_lines(
        relative + ":" + digest for relative, digest in artifacts.items())


def _recovery(plan):
    source_digest, source_raw = base._read_recovery_relative("source_manifest.json")
    copy_digest, copy_raw = base._read_recovery_relative("copy_verification.json")
    if source_digest != base.SOURCE_MANIFEST_SHA256 or copy_digest != base.COPY_VERIFICATION_SHA256:
        raise base.Refusal("RECOVERY_MANIFEST_DIGEST")
    try:
        source_doc = json.loads(source_raw.decode("utf-8"))
        copy_doc = json.loads(copy_raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise base.Refusal("RECOVERY_MANIFEST_PARSE")
    if (source_doc.get("schema_version") != "blind-runtime-recovery-source-manifest-v1" or
        copy_doc.get("copy_matches_source") is not True):
        raise base.Refusal("RECOVERY_MANIFEST_BINDING")
    audit_path = os.path.join(base.REGISTRATION_ROOT, "execution_audit.json")
    audit = base._json(audit_path, "EXECUTION_AUDIT_PARSE")
    if (base._sha(base._read(audit_path)) != prior.EXECUTION_AUDIT_SHA256 or
        audit.get("schema_version") != "blind-runtime-recovery-execution-v3-audit" or
        audit.get("status") != "PASS_V3_EXECUTION_AUDIT_JOIN_PENDING" or
        audit.get("lsf_job_id") != base.JOB_ID or audit.get("attempt_count") != 44 or
        audit.get("receipt_count") != 44 or audit.get("receipt_set_sha256") != base.RECEIPT_SET_SHA256 or
        audit.get("source_manifest_sha256") != base.SOURCE_MANIFEST_SHA256 or
        audit.get("copy_verification_sha256") != base.COPY_VERIFICATION_SHA256 or
        audit.get("candidate_join_performed") is not False or audit.get("training_allowed") is not False):
        raise base.Refusal("EXECUTION_AUDIT_BINDING")
    expected = dict((row["source_marker"], (row, index))
                    for index, row in enumerate(plan, 1))
    root_fd = base.historical.secure._open_root(base.RECOVERY_ROOT)
    try:
        receipt_fd = os.open("receipts", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=root_fd)
        try:
            names = sorted(x for x in base.historical.secure._directory_members(receipt_fd)
                           if x.endswith(".json"))
        finally:
            os.close(receipt_fd)
    finally:
        os.close(root_fd)
    if len(names) != 44:
        raise base.Refusal("RECOVERY_RECEIPT_COUNT")
    receipts = []
    named_raw = []
    for name in names:
        try:
            raw = base._read_recovery_relative("receipts/" + name)[1]
            named_raw.append((name, raw))
            receipts.append(json.loads(raw.decode("utf-8")))
        except (ValueError, UnicodeDecodeError):
            raise base.Refusal("RECOVERY_RECEIPT_PARSE")
    if _receipt_set_sha256(named_raw) != base.RECEIPT_SET_SHA256:
        raise base.Refusal("RECOVERY_RECEIPT_SET_DIGEST")
    receipt_by_marker = {}
    seen_indices = set()
    for receipt, name in zip(receipts, names):
        marker = receipt.get("mode", "") + "_" + receipt.get("run_id", "")
        expected_pair = expected.get(marker)
        row, expected_index = expected_pair if expected_pair is not None else (None, None)
        marker, index, unused_digest = base._validate_receipt_binding(
            receipt, name, row, expected_index)
        if marker in receipt_by_marker or index in seen_indices:
            raise base.Refusal("RECOVERY_RECEIPT_SET")
        receipt_by_marker[marker] = receipt
        seen_indices.add(index)
    if seen_indices != set(range(1, 45)) or set(receipt_by_marker) != set(expected):
        raise base.Refusal("RECOVERY_RECEIPT_SET")
    recovered = dict((circuit, {}) for circuit in base.CIRCUIT_ORDER)
    for circuit in base.CIRCUIT_ORDER:
        root_fd = base.historical.secure._open_root(os.path.join(base.RECOVERY_ROOT, "logs", circuit))
        try:
            logs = base.historical.impl._walk_log_snapshots(root_fd)
        finally:
            os.close(root_fd)
        for relative, pair in logs.items():
            digest, payload = pair
            name = relative.rsplit("/", 1)[-1]
            if not name.endswith(".driver.log") or "_" not in name:
                raise base.Refusal("RECOVERY_LOG_NAME")
            marker = name.split("_", 1)[1][:-len(".driver.log")]
            expected_pair = expected.get(marker)
            row = expected_pair[0] if expected_pair is not None else None
            if row is None or row.get("circuit") != circuit or marker in recovered[circuit]:
                raise base.Refusal("RECOVERY_LOG_PLAN_MISMATCH")
            receipt = receipt_by_marker.get(marker)
            if receipt is None or relative != "%03d_%s_%s.driver.log" % (
                    receipt["attempt_index"], receipt["mode"], receipt["run_id"]):
                raise base.Refusal("RECOVERY_LOG_RECEIPT_PATH")
            if digest != receipt["driver_log_sha256"]:
                raise base.Refusal("RECOVERY_LOG_DIGEST_MISMATCH")
            text = payload.decode("utf-8", "replace")
            if ("Elapsed (wall clock) time" not in text or "Exit status: 0" not in text or
                ("MAPPED_COMMON_ATPG_STATUS=PASS" not in text and
                 "MAPPED_INCREMENTAL_ATPG_STATUS=PASS" not in text)):
                raise base.Refusal("RECOVERY_LOG_FOOTER")
            adapted = "recovery/%s/%s/%s.driver.log" % (circuit, row["stage"], marker)
            recovered[circuit][adapted] = (digest, payload)
    if sum(len(value) for value in recovered.values()) != 44:
        raise base.Refusal("RECOVERY_LOG_SET")
    return recovered


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
    released = {"schema_version": "blind-runtime-join-release-v12-r8",
                "status": "RELEASED_AUDIT_PENDING", "receipt_sha256": digest}
    base._exclusive(os.path.join(OUTPUT_ROOT, "RELEASED"),
                    json.dumps(released, sort_keys=True).encode("utf-8") + b"\n")


def run():
    contract_sha, implementation_sha = validate_bundle()
    try:
        base.historical._validate_runtime_platform()
        closeout_sha = base._validate_closeout()
        plan = base._plan()
        recovery = _recovery(plan)
        base.historical.secure._run_verified_sort = base.historical._verified_sort_fd
        control = base.historical.impl.open_trusted_control()
        rows = []
        for circuit in base.CIRCUIT_ORDER:
            old, measurements = base.historical.impl.snapshot_circuit(control, circuit)
            old.update(recovery[circuit])
            rows.append(base.core.audit_circuit(circuit, old, measurements))
        if not base._valid(rows):
            raise base.core.JoinFailure("COVERAGE_GATE", "R06_R07_FAILED")
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r8",
                   "status": "PASS_R06_R07_AUDIT_PENDING",
                   "formal_runtime_membership_sha256": base.FORMAL_MEMBERSHIP_SHA256,
                   "split_contract_sha256": base.SPLIT_SHA256,
                   "method_registry_sha256": base.METHOD_REGISTRY_SHA256,
                   "contract_sha256": contract_sha,
                   "implementation_set_sha256": implementation_sha,
                   "recovery_closeout_sha256": closeout_sha,
                   "recovery_execution_audit_sha256": prior.EXECUTION_AUDIT_SHA256,
                   "recovery_job_id": base.JOB_ID,
                   "recovery_plan_sha256": base.PLAN_SHA256,
                   "recovery_source_manifest_sha256": base.SOURCE_MANIFEST_SHA256,
                   "recovery_copy_verification_sha256": base.COPY_VERIFICATION_SHA256,
                   "recovery_receipt_set_sha256": base.RECEIPT_SET_SHA256,
                   "circuits": rows, "failure_code": None, "training_allowed": False}
        code = 0
    except base.core.JoinFailure as error:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r8", "status": "FAIL",
                   "contract_sha256": contract_sha, "implementation_set_sha256": implementation_sha,
                   "failure_stage": error.stage, "failure_code": error.code,
                   "circuits": [], "training_allowed": False}
        code = 1
    except (base.Refusal, base.historical.Refusal, base.historical.impl.Refusal,
            base.historical.secure.Refusal, Refusal, OSError, ValueError, KeyError) as error:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r8", "status": "FAIL",
                   "contract_sha256": contract_sha, "implementation_set_sha256": implementation_sha,
                   "failure_stage": "SOURCE_INVENTORY", "failure_code": str(error),
                   "circuits": [], "training_allowed": False}
        code = 1
    except Exception:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r8", "status": "FAIL",
                   "contract_sha256": contract_sha, "implementation_set_sha256": implementation_sha,
                   "failure_stage": "INTERNAL_AUDIT", "failure_code": "INTERNAL_AUDIT_FAILURE",
                   "circuits": [], "training_allowed": False}
        code = 1
    _write(receipt)
    return code


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv):
        print("BLIND_JOIN_V12_R8=REFUSED_FIXED_ARGV")
        return 2
    try:
        code = run()
    except Refusal as error:
        print("BLIND_JOIN_V12_R8=REFUSED_" + str(error))
        return 2
    print("BLIND_JOIN_V12_R8=" + ("R06_R07_AUDIT_PENDING" if code == 0 else "FAILED_CLOSED"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
