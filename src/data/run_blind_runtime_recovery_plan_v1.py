#!/usr/bin/env python3
"""Create an A-private, non-executable focused BLIND recovery plan.

There is intentionally no scheduler, Tessent, shell, or remote-transfer code
here.  This runner only snapshots the already-authorized frozen BLIND inputs
through the r5 reader and writes a plan that still needs an independent
execution-runner gate.
"""
from __future__ import print_function

import hashlib
import json
import os
import sys

from src.data import build_blind_runtime_recovery_plan_v1 as planner
from src.data import run_blind_join_v12_r5 as r5


HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CONTRACT_RELATIVE = "contracts/blind_runtime_recovery_v1.json"
OUTPUT_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/12_blind_runtime_recovery_v1_r4_private"
CIRCUITS = planner.FIXED_CIRCUITS
REQUIRED_ARTIFACTS = frozenset((
    "src/data/build_blind_runtime_recovery_plan_v1.py",
    "src/data/run_blind_runtime_recovery_plan_v1.py",
    "tests/test_build_blind_runtime_recovery_plan_v1.py",
    "tests/test_run_blind_runtime_recovery_plan_v1.py",
))


class Refusal(Exception):
    pass


class PublicationCleanupFailure(Exception):
    pass


def _sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"


def _exclusive(path, payload):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def _contract_path():
    return os.path.join(BUNDLE_ROOT, *CONTRACT_RELATIVE.split("/"))


def validate_recovery_contract():
    """Validate scope, but reject unsealed artifacts for a real deployment."""
    path = _contract_path()
    if os.path.islink(path) or not os.path.isfile(path):
        raise Refusal("CONTRACT_MISSING_OR_SYMLINK")
    with open(path, "rb") as stream:
        raw = stream.read()
    try:
        contract = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal("CONTRACT_PARSE")
    private = contract.get("private_plan", {})
    expected_fields = ["circuit", "stage", "mode", "run_id", "source_marker", "pattern_limit",
                       "run_kind", "depends_on_h_marker"]
    if (contract.get("schema_version") != "blind-runtime-recovery-v1" or
            contract.get("status") != "PLAN_ONLY_AUTHORIZED_REVIEWED" or
            contract.get("circuits") != list(CIRCUITS) or
            private.get("output_root") != OUTPUT_ROOT or
            private.get("permissions") != "0700 directory and 0600 plan files" or
            private.get("allowed_fields") != expected_fields or
            contract.get("training_allowed") is not False):
        raise Refusal("CONTRACT_SCOPE")
    artifacts = contract.get("implementation", {}).get("artifact_sha256")
    if not isinstance(artifacts, dict) or set(artifacts) != REQUIRED_ARTIFACTS:
        raise Refusal("CONTRACT_ARTIFACT_SET")
    if any(value == "PENDING_ROOT_SEAL" for value in artifacts.values()):
        raise Refusal("CONTRACT_NOT_SEALED")
    if not all(isinstance(value, str) and len(value) == 64 for value in artifacts.values()):
        raise Refusal("CONTRACT_ARTIFACT_DIGEST")
    for relative, expected in artifacts.items():
        artifact_path = os.path.join(BUNDLE_ROOT, *relative.split("/"))
        if (os.path.islink(artifact_path) or not os.path.isfile(artifact_path) or
                _sha256_file(artifact_path) != expected):
            raise Refusal("CONTRACT_ARTIFACT_DIGEST_MISMATCH")
    return _sha256(raw)


def _mkdir_private_root():
    if os.path.lexists(OUTPUT_ROOT):
        raise Refusal("OUTPUT_ROOT_ALREADY_EXISTS")
    parent = os.path.dirname(OUTPUT_ROOT)
    if not os.path.isdir(parent):
        raise Refusal("OUTPUT_PARENT_MISSING")
    os.mkdir(OUTPUT_ROOT, 0o700)
    os.chmod(OUTPUT_ROOT, 0o700)


def _fsync_directory(path):
    # The authorized target is Linux. Windows has no portable directory-fsync
    # equivalent, so local unit tests must not turn that into a false failure.
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_unpublished_payload(path):
    """Remove only known files, then persist the parent-directory deletion."""
    for name in ("plan.json", "plan.json.sha256", "summary.json"):
        candidate = os.path.join(path, name)
        if os.path.lexists(candidate):
            os.unlink(candidate)
    if os.path.lexists(path):
        os.rmdir(path)
    _fsync_directory(os.path.dirname(path))


def _write_failure(contract_sha256, stage, code):
    raw = _json_bytes({"schema_version": "blind-runtime-recovery-receipt-v1", "status": "FAIL",
                       "contract_sha256": contract_sha256, "failure_stage": stage,
                       "failure_code": code, "circuits": []})
    _exclusive(os.path.join(OUTPUT_ROOT, "receipt.json"), raw)
    _exclusive(os.path.join(OUTPUT_ROOT, "receipt.json.sha256"),
               (_sha256(raw) + "  receipt.json\n").encode("ascii"))


def _plan_document(groups):
    return {"schema_version": "blind-runtime-recovery-plan-v1", "status": "PLAN_ONLY",
            "training_allowed": False, "circuits": groups}


def _bind_r5_verified_sort():
    """Use the r5 descriptor-bound sorter before opening any BLIND snapshot."""
    r5.impl.secure._run_verified_sort = r5._verified_sort_fd


def _publish_payload(plan_raw, summary_raw):
    """Publish row-level data only after all files are durably staged."""
    staging = os.path.join(OUTPUT_ROOT, "payload.staging")
    payload = os.path.join(OUTPUT_ROOT, "payload")
    if os.path.lexists(staging) or os.path.lexists(payload):
        raise Refusal("PAYLOAD_PATH_ALREADY_EXISTS")
    os.mkdir(staging, 0o700)
    os.chmod(staging, 0o700)
    published = False
    try:
        plan_sha256 = _sha256(plan_raw)
        _exclusive(os.path.join(staging, "plan.json"), plan_raw)
        _exclusive(os.path.join(staging, "plan.json.sha256"),
                   (plan_sha256 + "  plan.json\n").encode("ascii"))
        _exclusive(os.path.join(staging, "summary.json"), summary_raw)
        _fsync_directory(staging)
        os.rename(staging, payload)
        published = True
        _fsync_directory(OUTPUT_ROOT)
    except Exception:
        try:
            _remove_unpublished_payload(payload if published else staging)
        except Exception:
            # The caller must not write an apparently clean FAIL receipt if
            # row-level data might still be present or directory cleanup was
            # not made durable.
            raise PublicationCleanupFailure("PAYLOAD_CLEANUP_FAILED")
        raise


def run():
    # The r5 validator and platform gate run before any BLIND snapshot.
    r5_contract_sha256, r5_implementation_sha256 = r5.validate_bundle()
    recovery_contract_sha256 = validate_recovery_contract()
    r5._validate_runtime_platform()
    _bind_r5_verified_sort()
    _mkdir_private_root()
    try:
        control = r5.impl.open_trusted_control()
        groups = []
        for circuit in CIRCUITS:
            logs, measurements = r5.impl.snapshot_circuit(control, circuit)
            attempts = planner.build_recovery_plan(circuit, logs, measurements)
            groups.append({"circuit": circuit, "attempts": attempts})
        plan_raw = _json_bytes(_plan_document(groups))
        plan_sha256 = _sha256(plan_raw)
        summary_circuits = []
        for group in groups:
            attempts_raw = _json_bytes(group["attempts"])
            summary_circuits.append({"circuit": group["circuit"], "attempt_count": len(group["attempts"]),
                                     "attempt_set_sha256": _sha256(attempts_raw)})
        summary = {"schema_version": "blind-runtime-recovery-summary-v1", "status": "PLAN_GENERATED_AUDIT_PENDING",
                   "training_allowed": False, "r5_contract_sha256": r5_contract_sha256,
                   "r5_implementation_set_sha256": r5_implementation_sha256,
                   "recovery_contract_sha256": recovery_contract_sha256,
                   "plan_sha256": plan_sha256, "circuits": summary_circuits}
        _publish_payload(plan_raw, _json_bytes(summary))
        return 0
    except planner.RecoveryPlanFailure as error:
        _write_failure(recovery_contract_sha256, error.stage, error.code)
        return 1
    except PublicationCleanupFailure:
        raise
    except Exception:
        _write_failure(recovery_contract_sha256, "SOURCE_INVENTORY", "RECOVERY_PLAN_INTERNAL_FAILURE")
        return 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("BLIND_RUNTIME_RECOVERY_PLAN_V1=REFUSED_FIXED_ARGV")
        return 2
    try:
        code = run()
    except (Refusal, r5.Refusal):
        print("BLIND_RUNTIME_RECOVERY_PLAN_V1=REFUSED")
        return 2
    print("BLIND_RUNTIME_RECOVERY_PLAN_V1=" + ("PLAN_GENERATED_AUDIT_PENDING" if code == 0 else "FAILED_CLOSED"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
