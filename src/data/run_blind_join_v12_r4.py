#!/usr/bin/env python3
"""Python-3.6-compatible one-shot BLIND runtime join.

This is a focused compatibility repair for v12-r3: GNU sort receives an
immutable in-process byte snapshot through stdin when memfd_create is absent.
No source path is reopened and no row-level output is persisted.
"""
from __future__ import print_function

import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CONTRACT_RELATIVE = "contracts/blind_runtime_join_v12_r4.json"
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import blind_inventory_v12_r2 as secure
import blind_join_core_v12_r3 as core
import run_blind_join_v12_r3 as impl

SORT_PATH = impl.SORT_PATH
SORT_SHA256 = impl.SORT_SHA256
SORT_VERSION = impl.SORT_VERSION
OUTPUT_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/11_blind_runtime_join_v12_r4"
FORMAL_MEMBERSHIP_SHA256 = impl.FORMAL_MEMBERSHIP_SHA256
SPLIT_SHA256 = impl.SPLIT_SHA256
METHOD_REGISTRY_SHA256 = impl.METHOD_REGISTRY_SHA256
CIRCUITS = impl.CIRCUITS
CIRCUIT_ORDER = impl.CIRCUIT_ORDER


class Refusal(Exception):
    pass


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _digest_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def _verified_sort_compat(control, paths):
    """Run the frozen GNU sort over an immutable byte snapshot.

    Python 3.6 on the authorized host lacks os.memfd_create. The bytes have
    already been read once from descriptor-anchored source files, so passing
    that immutable bytes object as stdin preserves the path-race boundary.
    """
    if not isinstance(paths, list) or not all(isinstance(item, str) for item in paths):
        raise secure.Refusal("HISTORICAL_SORT_INPUT")
    payload = b"".join((b"./" + item.encode("utf-8") + b"\0") for item in paths)
    try:
        version = subprocess.run([control._sort_path, "--version"], executable=control._sort_path,
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env={"LANG": "en_US.UTF-8"})
        if version.stdout.decode("utf-8", "strict").splitlines()[0].strip() != control._sort_version:
            raise secure.Refusal("SORT_VERSION_DRIFT")
        result = subprocess.run([control._sort_path, "-z"], executable=control._sort_path,
                                input=payload, check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env={"LANG": "en_US.UTF-8"})
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError, ValueError, TypeError):
        raise secure.Refusal("HISTORICAL_SORT_FAILED")
    ordered = result.stdout.split(b"\0")
    if ordered and ordered[-1] == b"":
        ordered.pop()
    try:
        decoded = [item.decode("utf-8", "strict") for item in ordered]
    except UnicodeDecodeError:
        raise secure.Refusal("HISTORICAL_SORT_ENCODING")
    expected = ["./" + item for item in paths]
    if len(decoded) != len(expected) or set(decoded) != set(expected):
        raise secure.Refusal("HISTORICAL_SORT_PERMUTATION")
    return [item[2:] for item in decoded]


def validate_bundle():
    contract_path = os.path.join(BUNDLE_ROOT, *CONTRACT_RELATIVE.split("/"))
    if os.path.islink(contract_path) or not os.path.isfile(contract_path):
        raise Refusal("CONTRACT_MISSING_OR_SYMLINK")
    with open(contract_path, "rb") as stream:
        raw = stream.read()
    try:
        contract = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal("CONTRACT_PARSE")
    if (contract.get("schema_version") != "blind-runtime-join-v12-r4" or
            contract.get("status") != "AUTHORIZED_EXECUTION_REVIEWED" or
            contract.get("circuits") != list(CIRCUIT_ORDER) or
            contract.get("output_root") != OUTPUT_ROOT or
            contract.get("training_allowed") is not False):
        raise Refusal("CONTRACT_SCOPE")
    artifacts = contract.get("implementation", {}).get("artifact_sha256")
    required = {
        "src/data/blind_inventory_v12_r2.py", "src/data/blind_join_core_v12_r3.py",
        "src/data/run_blind_join_v12_r3.py", "src/data/run_blind_join_v12_r4.py",
        "src/data/build_blind_method_binding_v12_r3.py",
        "tests/test_blind_join_core_v12_r3.py", "tests/test_run_blind_join_v12_r3.py",
        "tests/test_build_blind_method_binding_v12_r3.py",
    }
    if not isinstance(artifacts, dict) or set(artifacts) != required:
        raise Refusal("CONTRACT_ARTIFACT_SET")
    for relative, expected in artifacts.items():
        path = os.path.join(BUNDLE_ROOT, *relative.split("/"))
        if os.path.islink(path) or not os.path.isfile(path) or _sha256_file(path) != expected:
            raise Refusal("ARTIFACT_DIGEST_MISMATCH")
    implementation_set_sha256 = core._sha_lines(relative + ":" + digest for relative, digest in artifacts.items())
    return _digest_bytes(raw), implementation_set_sha256


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"


def _exclusive(path, payload):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _write_receipt(receipt):
    if os.path.lexists(OUTPUT_ROOT):
        raise Refusal("OUTPUT_ROOT_ALREADY_EXISTS")
    parent = os.path.dirname(OUTPUT_ROOT)
    if not os.path.isdir(parent):
        raise Refusal("OUTPUT_PARENT_MISSING")
    os.mkdir(OUTPUT_ROOT, 0o700)
    raw = _json_bytes(receipt)
    digest = _digest_bytes(raw)
    _exclusive(os.path.join(OUTPUT_ROOT, "receipt.json"), raw)
    _exclusive(os.path.join(OUTPUT_ROOT, "receipt.json.sha256"), (digest + "  receipt.json\n").encode("ascii"))
    _exclusive(os.path.join(OUTPUT_ROOT, "RELEASED"), _json_bytes({
        "schema_version": "blind-runtime-join-release-v12-r4",
        "status": "RELEASED_AUDIT_PENDING", "receipt_sha256": digest}))


def run():
    contract_sha256, implementation_set_sha256 = validate_bundle()
    impl.secure._run_verified_sort = _verified_sort_compat
    control = impl.open_trusted_control()
    try:
        rows = []
        for circuit in CIRCUIT_ORDER:
            logs, measurements = impl.snapshot_circuit(control, circuit)
            rows.append(core.audit_circuit(circuit, logs, measurements))
        if not impl._valid_pass(rows):
            raise core.JoinFailure("COVERAGE_GATE", "R06_R07_FAILED")
        receipt = {
            "schema_version": "blind-runtime-join-receipt-v12-r4",
            "status": "PASS_R06_R07_AUDIT_PENDING",
            "formal_runtime_membership_sha256": FORMAL_MEMBERSHIP_SHA256,
            "split_contract_sha256": SPLIT_SHA256,
            "method_registry_sha256": METHOD_REGISTRY_SHA256,
            "contract_sha256": contract_sha256,
            "implementation_set_sha256": implementation_set_sha256,
            "circuits": rows, "failure_code": None}
        code = 0
    except core.JoinFailure as error:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r4", "status": "FAIL",
                   "contract_sha256": contract_sha256, "implementation_set_sha256": implementation_set_sha256,
                   "failure_stage": error.stage, "failure_code": error.code, "circuits": []}
        code = 1
    except (Refusal, secure.Refusal):
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r4", "status": "FAIL",
                   "contract_sha256": contract_sha256, "implementation_set_sha256": implementation_set_sha256,
                   "failure_stage": "SOURCE_INVENTORY", "failure_code": "INPUT_INVENTORY_DRIFT", "circuits": []}
        code = 1
    except Exception:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r4", "status": "FAIL",
                   "contract_sha256": contract_sha256, "implementation_set_sha256": implementation_set_sha256,
                   "failure_stage": "INTERNAL_AUDIT", "failure_code": "INTERNAL_AUDIT_FAILURE", "circuits": []}
        code = 1
    _write_receipt(receipt)
    return code


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("BLIND_JOIN_V12_R4=REFUSED_FIXED_ARGV")
        return 2
    try:
        code = run()
    except Refusal as error:
        print("BLIND_JOIN_V12_R4=REFUSED_" + str(error))
        return 2
    print("BLIND_JOIN_V12_R4=" + ("R06_R07_AUDIT_PENDING" if code == 0 else "FAILED_CLOSED"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
