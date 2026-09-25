#!/usr/bin/env python3
"""One-shot descriptor-only BLIND runtime join for the authorized v12-r3 gate."""
from __future__ import print_function

import hashlib
import json
import os
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CONTRACT_RELATIVE = "contracts/blind_runtime_join_v12_r3.json"
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import blind_inventory_v12_r2 as secure
import blind_join_core_v12_r3 as core


SORT_PATH = "/usr/bin/sort"
SORT_SHA256 = "5f0e1c7aa4d9280a86af8132e3f4aac751bece1d45b817324aaa7f8f437e8f3b"
SORT_VERSION = "sort (GNU coreutils) 8.22"
OUTPUT_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/11_blind_runtime_join_v12_r3"
SPLIT_SHA256 = "ffecd5093453f69c11263501b822ad7bb8f7eefd5da60dd7863331088f6fbcda"
METHOD_REGISTRY_SHA256 = "8fb8d4a90981c2479e3e6ea3a8a4669286080e921ad0c2ff8d82e8a2a5c4191f"
FORMAL_MEMBERSHIP_SHA256 = "c8f589d67d80470dcf49ffbcab51da763162e9ae82af0308b36d6771cbd97cac"
MEASUREMENT_FILES = tuple(item[0] for item in core.LAYOUTS)
CIRCUITS = {
    "s9234": {
        "root": "/temp/jiangchuanc/multimode_ate_phase3_20260811_A/10_circuits/s9234/10_coverage95_v3_merge_reclassify",
        "driver_log_count": 4520,
        "historical_locale_ordered_sha256": "18667b93b640ec8a86da2e4e438211269f08e01ea9e9549325a5d1b05e939f9b",
        "bytewise_ordered_sha256": "daed4e14a160438198fc6931f59fb26eb6762bee347c7c1bf7076d1bb76ce943",
        "measurement_file_set_sha256": "6fa277e0094f48498fa29ab2a7540e95942911c9e4fff248fbea3c196ddb763d",
    },
    "s38584": {
        "root": "/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s38584/10_coverage95_v1",
        "driver_log_count": 753,
        "historical_locale_ordered_sha256": "a04f26a36ed3b12f5dfa07846ac12414b7d66d089e67a4afe908bfce4360ffe4",
        "bytewise_ordered_sha256": "a04f26a36ed3b12f5dfa07846ac12414b7d66d089e67a4afe908bfce4360ffe4",
        "measurement_file_set_sha256": "4c0b8402533f16ec00adedca389daef0ebb7f898981def6f387cf4553c535bce",
    },
    "wb_dma": {
        "root": "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/wb_dma/10_coverage95_phase4_v2",
        "driver_log_count": 2581,
        "historical_locale_ordered_sha256": "48cda86af2a5359f2e4b55c2fd7b27c6ce47fd2e0493127b8b2cf5ad95f1decf",
        "bytewise_ordered_sha256": "2b94b993937876c219d72a4d41b6ed8137660549a2cfc01524711f6a9cd677df",
        "measurement_file_set_sha256": "6759d31cd1d8d076e7a785091e5d4cc26abbda68b7d9d2af18371ef006e8a36f",
    },
}
CIRCUIT_ORDER = ("s9234", "s38584", "wb_dma")
FAILURE_CODES = {
    "SOURCE_INVENTORY": "INPUT_INVENTORY_DRIFT",
    "ATTEMPT_PARSE": "ATTEMPT_INTEGRITY_FAILURE",
    "MEASUREMENT_PARSE": "MEASUREMENT_SCHEMA_FAILURE",
    "JOIN_CLASSIFICATION": "JOIN_CLASSIFICATION_FAILURE",
    "COVERAGE_GATE": "R06_R07_FAILED",
    "INTERNAL_AUDIT": "INTERNAL_AUDIT_FAILURE",
}


class Refusal(Exception):
    pass


class _Control(object):
    __slots__ = ("_sort_path", "_sort_sha256", "_sort_version")

    def __init__(self):
        self._sort_path = SORT_PATH
        self._sort_sha256 = SORT_SHA256
        self._sort_version = SORT_VERSION


def open_trusted_control():
    """Zero-argument production factory with code-frozen anchors."""
    return _Control()


def _digest_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
    if (contract.get("schema_version") != "blind-runtime-join-v12-r3" or
            contract.get("status") != "AUTHORIZED_EXECUTION_REVIEWED" or
            contract.get("circuits") != list(CIRCUIT_ORDER) or
            contract.get("output_root") != OUTPUT_ROOT or contract.get("training_allowed") is not False):
        raise Refusal("CONTRACT_SCOPE")
    platform = contract.get("platform_anchors", {})
    if (platform.get("sort_path"), platform.get("sort_version"), platform.get("sort_sha256")) != (SORT_PATH, SORT_VERSION, SORT_SHA256):
        raise Refusal("CONTRACT_PLATFORM")
    if contract.get("inventory_freeze", {}).get("sha256") != "cf7b37773516b39b1e3001e43aba1d4157f577a1906fe81605e37b10cb5645c9":
        raise Refusal("CONTRACT_INVENTORY")
    artifacts = contract.get("implementation", {}).get("artifact_sha256")
    if not isinstance(artifacts, dict) or not artifacts:
        raise Refusal("CONTRACT_ARTIFACTS")
    required = {
        "src/data/blind_inventory_v12_r2.py", "src/data/blind_join_core_v12_r3.py",
        "src/data/run_blind_join_v12_r3.py", "src/data/build_blind_method_binding_v12_r3.py",
        "tests/test_blind_join_core_v12_r3.py", "tests/test_run_blind_join_v12_r3.py",
        "tests/test_build_blind_method_binding_v12_r3.py",
    }
    if set(artifacts) != required:
        raise Refusal("CONTRACT_ARTIFACT_SET")
    for relative, expected in artifacts.items():
        path = os.path.join(BUNDLE_ROOT, *relative.split("/"))
        if os.path.islink(path) or not os.path.isfile(path) or _sha256_file(path) != expected:
            raise Refusal("ARTIFACT_DIGEST_MISMATCH")
    implementation_set_sha256 = core._sha_lines(relative + ":" + digest for relative, digest in artifacts.items())
    return _digest_bytes(raw), implementation_set_sha256


def _digest_inventory(order, snapshots):
    data = "".join(snapshots[path][0] + "  ./" + path + "\n" for path in order)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _walk_log_snapshots(parent_fd, prefix=""):
    """Read each selected log exactly once from an anchored descriptor tree."""
    before = os.fstat(parent_fd)
    before_members = secure._directory_members(parent_fd)
    result = {}
    for name in sorted(before_members):
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        relative = prefix + name
        if stat.S_ISLNK(entry.st_mode):
            raise Refusal("LOG_SYMLINK")
        if stat.S_ISDIR(entry.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
            try:
                opened = os.fstat(child)
                if not stat.S_ISDIR(opened.st_mode) or not secure._same_directory_entry(opened, entry):
                    raise Refusal("LOG_RACE_DETECTED")
                result.update(_walk_log_snapshots(child, relative + "/"))
                after_entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not secure._same_directory_entry(entry, after_entry):
                    raise Refusal("LOG_RACE_DETECTED")
            finally:
                os.close(child)
        elif relative.endswith(".driver.log"):
            if not stat.S_ISREG(entry.st_mode):
                raise Refusal("LOG_FILE_TYPE")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent_fd)
            try:
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
                    raise Refusal("LOG_RACE_DETECTED")
                digest, payload = secure._read_and_hash_fd(fd)
                after_fd = os.fstat(fd)
                after_entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if secure._metadata(after_fd) != secure._metadata(opened) or secure._metadata(after_entry) != secure._metadata(entry):
                    raise Refusal("LOG_RACE_DETECTED")
                result[relative] = (digest, payload)
            finally:
                os.close(fd)
        elif not stat.S_ISREG(entry.st_mode):
            raise Refusal("LOG_FILE_TYPE")
    after = os.fstat(parent_fd)
    after_members = secure._directory_members(parent_fd)
    if secure._metadata(before) != secure._metadata(after) or before_members != after_members:
        raise Refusal("LOG_RACE_DETECTED")
    return result


def _read_relative_once(root_fd, relative):
    parts = relative.split("/")
    if not parts or not all(secure._portable_component(part) for part in parts):
        raise Refusal("MEASUREMENT_PATH_INVALID")
    parent = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            entry = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(entry.st_mode) or stat.S_ISLNK(entry.st_mode):
                raise Refusal("MEASUREMENT_PATH_INVALID")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            opened = os.fstat(child)
            if not secure._same_directory_entry(opened, entry):
                os.close(child)
                raise Refusal("MEASUREMENT_RACE_DETECTED")
            os.close(parent)
            parent = child
        entry = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode):
            raise Refusal("MEASUREMENT_PATH_INVALID")
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
                raise Refusal("MEASUREMENT_RACE_DETECTED")
            digest, payload = secure._read_and_hash_fd(fd)
            after_fd = os.fstat(fd)
            after_entry = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            if secure._metadata(after_fd) != secure._metadata(opened) or secure._metadata(after_entry) != secure._metadata(entry):
                raise Refusal("MEASUREMENT_RACE_DETECTED")
            return digest, payload
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def snapshot_circuit(control, circuit):
    expected = CIRCUITS[circuit]
    root_fd = secure._open_root(expected["root"])
    try:
        logs = _walk_log_snapshots(root_fd)
        measurements = {relative: _read_relative_once(root_fd, relative) for relative in MEASUREMENT_FILES}
    finally:
        os.close(root_fd)
    paths = list(logs)
    historical = secure._run_verified_sort(control, paths)
    bytewise = sorted(paths, key=lambda item: ("./" + item).encode("utf-8"))
    observed = {
        "driver_log_count": len(paths),
        "historical_locale_ordered_sha256": _digest_inventory(historical, logs),
        "bytewise_ordered_sha256": _digest_inventory(bytewise, logs),
        "measurement_file_set_sha256": hashlib.sha256(
            "".join(measurements[path][0] + "  " + path + "\n" for path in MEASUREMENT_FILES).encode("utf-8")
        ).hexdigest(),
    }
    frozen = {key: expected[key] for key in observed}
    if observed != frozen:
        raise core.JoinFailure("SOURCE_INVENTORY", "INPUT_INVENTORY_DRIFT")
    return logs, measurements


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"


def _exclusive(path, payload):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _valid_pass(rows):
    required = {"circuit", "executed_stage_reference_count", "unique_runtime_join_count",
                "missing_runtime_join_count", "ambiguous_runtime_join_count", "coverage_rate",
                "distinct_runtime_attempt_count", "cross_stage_reference_count", "eligible_action_count",
                "all_unique_action_count", "frozen_runtime_eligible_action_space_sha256",
                "source_artifact_set_sha256"}
    return ([row.get("circuit") for row in rows] == list(CIRCUIT_ORDER) and
            all(set(row) == required for row in rows) and core.gates_pass(rows))


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
    _exclusive(os.path.join(OUTPUT_ROOT, "receipt.json.sha256"),
               (digest + "  receipt.json\n").encode("ascii"))
    _exclusive(os.path.join(OUTPUT_ROOT, "RELEASED"), _json_bytes({
        "schema_version": "blind-runtime-join-release-v12-r3",
        "status": "RELEASED_AUDIT_PENDING",
        "receipt_sha256": digest,
    }))


def run():
    contract_sha256, implementation_set_sha256 = validate_bundle()
    control = open_trusted_control()
    try:
        rows = []
        for circuit in CIRCUIT_ORDER:
            logs, measurements = snapshot_circuit(control, circuit)
            rows.append(core.audit_circuit(circuit, logs, measurements))
        if not _valid_pass(rows):
            raise core.JoinFailure("COVERAGE_GATE", "R06_R07_FAILED")
        receipt = {
            "schema_version": "blind-runtime-join-receipt-v12-r3",
            "status": "PASS_R06_R07_AUDIT_PENDING",
            "formal_runtime_membership_sha256": FORMAL_MEMBERSHIP_SHA256,
            "split_contract_sha256": SPLIT_SHA256,
            "method_registry_sha256": METHOD_REGISTRY_SHA256,
            "contract_sha256": contract_sha256,
            "implementation_set_sha256": implementation_set_sha256,
            "circuits": rows,
            "failure_code": None,
        }
        code = 0
    except core.JoinFailure as error:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r3", "status": "FAIL",
                   "contract_sha256": contract_sha256, "implementation_set_sha256": implementation_set_sha256,
                   "failure_stage": error.stage, "failure_code": error.code, "circuits": []}
        code = 1
    except (Refusal, secure.Refusal):
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r3", "status": "FAIL",
                   "contract_sha256": contract_sha256, "implementation_set_sha256": implementation_set_sha256,
                   "failure_stage": "SOURCE_INVENTORY", "failure_code": "INPUT_INVENTORY_DRIFT", "circuits": []}
        code = 1
    except Exception:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r3", "status": "FAIL",
                   "contract_sha256": contract_sha256, "implementation_set_sha256": implementation_set_sha256,
                   "failure_stage": "INTERNAL_AUDIT", "failure_code": "INTERNAL_AUDIT_FAILURE", "circuits": []}
        code = 1
    _write_receipt(receipt)
    return code


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("BLIND_JOIN_V12_R3=REFUSED_FIXED_ARGV")
        return 2
    try:
        code = run()
    except Refusal as error:
        print("BLIND_JOIN_V12_R3=REFUSED_" + str(error))
        return 2
    print("BLIND_JOIN_V12_R3=" + ("R06_R07_AUDIT_PENDING" if code == 0 else "FAILED_CLOSED"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
