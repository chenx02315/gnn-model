#!/usr/bin/env python3
"""Python-3.6-compatible BLIND join with descriptor-bound GNU sort.

The sort executable is opened once with ``O_NOFOLLOW``, checked and hashed
through that descriptor, then executed through the inherited descriptor.  In
particular, no pathname lookup occurs between the hash and ``exec``.
"""
from __future__ import print_function

import hashlib
import json
import os
import stat
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CONTRACT_RELATIVE = "contracts/blind_runtime_join_v12_r5.json"
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import blind_inventory_v12_r2 as secure
import blind_join_core_v12_r3 as core
import run_blind_join_v12_r3 as impl

SORT_PATH = impl.SORT_PATH
SORT_SHA256 = impl.SORT_SHA256
SORT_VERSION = impl.SORT_VERSION
OUTPUT_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/11_blind_runtime_join_v12_r5"
FORMAL_MEMBERSHIP_SHA256 = impl.FORMAL_MEMBERSHIP_SHA256
SPLIT_SHA256 = impl.SPLIT_SHA256
METHOD_REGISTRY_SHA256 = impl.METHOD_REGISTRY_SHA256
CIRCUITS = impl.CIRCUITS
CIRCUIT_ORDER = impl.CIRCUIT_ORDER
INVENTORY_FREEZE = {"path": "data/manifests/blind_input_inventory_freeze_v2.json",
                    "sha256": "cf7b37773516b39b1e3001e43aba1d4157f577a1906fe81605e37b10cb5645c9"}
PLATFORM_ANCHORS = {"host": "bupt-vncs2", "linux": "3.10.0-1160.119.1.el7.x86_64",
                    "python": "3.6.8", "sort_path": SORT_PATH, "sort_version": SORT_VERSION,
                    "sort_sha256": SORT_SHA256, "LANG": "en_US.UTF-8"}


class Refusal(Exception):
    pass


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_fd(fd):
    """Hash from an already opened descriptor and restore its offset."""
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _digest_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def _validate_runtime_platform():
    """Fail closed unless the authorized Linux/Python runtime is exact.

    LANG is deliberately not read from the parent: child sort processes receive
    the contract's LANG value directly in ``_run_sort_fd``.
    """
    try:
        uname = os.uname()
        observed = {"host": uname.nodename, "linux": uname.release,
                    "python": ".".join(str(value) for value in sys.version_info[:3])}
    except (AttributeError, TypeError):
        raise Refusal("RUNTIME_PLATFORM_UNAVAILABLE")
    expected = {key: PLATFORM_ANCHORS[key] for key in ("host", "linux", "python")}
    if observed != expected:
        raise Refusal("RUNTIME_PLATFORM_DRIFT")


def _open_verified_sort(control):
    """Return a verified executable descriptor, or refuse before use."""
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    except AttributeError:
        raise secure.Refusal("SORT_NO_NOFOLLOW")
    try:
        fd = os.open(control._sort_path, flags)
    except OSError:
        raise secure.Refusal("SORT_OPEN_FAILED")
    try:
        identity = os.fstat(fd)
        if (not stat.S_ISREG(identity.st_mode) or identity.st_uid != 0 or
                (identity.st_mode & 0o022) != 0):
            raise secure.Refusal("SORT_IDENTITY_DRIFT")
        if _sha256_fd(fd) != control._sort_sha256:
            raise secure.Refusal("SORT_DIGEST_DRIFT")
        return fd
    except Exception:
        os.close(fd)
        raise


def _sort_command(fd):
    # ``pass_fds`` is supported by Python 3.6 and clears close-on-exec for the
    # child only. /proc/self is resolved by the child after inheritance.
    return "/proc/self/fd/%d" % fd


def _run_sort_fd(fd, argv, payload):
    try:
        return subprocess.run(argv, executable=argv[0], input=payload, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env={"LANG": "en_US.UTF-8"}, pass_fds=(fd,))
    except (OSError, subprocess.CalledProcessError, ValueError, TypeError):
        raise secure.Refusal("HISTORICAL_SORT_FAILED")


def _verified_sort_fd(control, paths):
    if not isinstance(paths, list) or not all(isinstance(item, str) for item in paths):
        raise secure.Refusal("HISTORICAL_SORT_INPUT")
    payload = b"".join((b"./" + item.encode("utf-8") + b"\0") for item in paths)
    fd = _open_verified_sort(control)
    try:
        command = _sort_command(fd)
        version = _run_sort_fd(fd, [command, "--version"], b"")
        try:
            banner = version.stdout.decode("utf-8", "strict").splitlines()[0].strip()
        except (UnicodeDecodeError, IndexError):
            raise secure.Refusal("SORT_VERSION_DRIFT")
        if banner != control._sort_version:
            raise secure.Refusal("SORT_VERSION_DRIFT")
        result = _run_sort_fd(fd, [command, "-z"], payload)
    finally:
        os.close(fd)
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
    if (contract.get("schema_version") != "blind-runtime-join-v12-r5" or
            contract.get("status") != "AUTHORIZED_EXECUTION_REVIEWED" or
            contract.get("circuits") != list(CIRCUIT_ORDER) or
            contract.get("output_root") != OUTPUT_ROOT or
            contract.get("training_allowed") is not False):
        raise Refusal("CONTRACT_SCOPE")
    if contract.get("inventory_freeze") != INVENTORY_FREEZE:
        raise Refusal("CONTRACT_INVENTORY")
    inventory_path = os.path.join(BUNDLE_ROOT, *INVENTORY_FREEZE["path"].split("/"))
    if (os.path.islink(inventory_path) or not os.path.isfile(inventory_path) or
            _sha256_file(inventory_path) != INVENTORY_FREEZE["sha256"]):
        raise Refusal("INVENTORY_FREEZE_DRIFT")
    if contract.get("platform_anchors") != PLATFORM_ANCHORS:
        raise Refusal("CONTRACT_PLATFORM")
    artifacts = contract.get("implementation", {}).get("artifact_sha256")
    required = {"src/data/blind_inventory_v12_r2.py", "src/data/blind_join_core_v12_r3.py",
                "src/data/run_blind_join_v12_r3.py", "src/data/run_blind_join_v12_r5.py",
                "src/data/build_blind_method_binding_v12_r3.py", "tests/test_blind_join_core_v12_r3.py",
                "tests/test_run_blind_join_v12_r3.py", "tests/test_run_blind_join_v12_r5.py",
                "tests/test_build_blind_method_binding_v12_r3.py"}
    if not isinstance(artifacts, dict) or set(artifacts) != required:
        raise Refusal("CONTRACT_ARTIFACT_SET")
    for relative, expected in artifacts.items():
        path = os.path.join(BUNDLE_ROOT, *relative.split("/"))
        if os.path.islink(path) or not os.path.isfile(path) or _sha256_file(path) != expected:
            raise Refusal("ARTIFACT_DIGEST_MISMATCH")
    return _digest_bytes(raw), core._sha_lines(relative + ":" + digest for relative, digest in artifacts.items())


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
        "schema_version": "blind-runtime-join-release-v12-r5", "status": "RELEASED_AUDIT_PENDING", "receipt_sha256": digest}))


def run():
    contract_sha256, implementation_set_sha256 = validate_bundle()
    _validate_runtime_platform()
    impl.secure._run_verified_sort = _verified_sort_fd
    control = impl.open_trusted_control()
    try:
        rows = []
        for circuit in CIRCUIT_ORDER:
            logs, measurements = impl.snapshot_circuit(control, circuit)
            rows.append(core.audit_circuit(circuit, logs, measurements))
        if not impl._valid_pass(rows):
            raise core.JoinFailure("COVERAGE_GATE", "R06_R07_FAILED")
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r5", "status": "PASS_R06_R07_AUDIT_PENDING",
                   "formal_runtime_membership_sha256": FORMAL_MEMBERSHIP_SHA256, "split_contract_sha256": SPLIT_SHA256,
                   "method_registry_sha256": METHOD_REGISTRY_SHA256, "contract_sha256": contract_sha256,
                   "implementation_set_sha256": implementation_set_sha256, "circuits": rows, "failure_code": None}
        code = 0
    except core.JoinFailure as error:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r5", "status": "FAIL", "contract_sha256": contract_sha256,
                   "implementation_set_sha256": implementation_set_sha256, "failure_stage": error.stage,
                   "failure_code": error.code, "circuits": []}; code = 1
    except (Refusal, secure.Refusal):
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r5", "status": "FAIL", "contract_sha256": contract_sha256,
                   "implementation_set_sha256": implementation_set_sha256, "failure_stage": "SOURCE_INVENTORY",
                   "failure_code": "INPUT_INVENTORY_DRIFT", "circuits": []}; code = 1
    except Exception:
        receipt = {"schema_version": "blind-runtime-join-receipt-v12-r5", "status": "FAIL", "contract_sha256": contract_sha256,
                   "implementation_set_sha256": implementation_set_sha256, "failure_stage": "INTERNAL_AUDIT",
                   "failure_code": "INTERNAL_AUDIT_FAILURE", "circuits": []}; code = 1
    _write_receipt(receipt)
    return code


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("BLIND_JOIN_V12_R5=REFUSED_FIXED_ARGV")
        return 2
    try:
        code = run()
    except Refusal as error:
        print("BLIND_JOIN_V12_R5=REFUSED_" + str(error))
        return 2
    print("BLIND_JOIN_V12_R5=" + ("R06_R07_AUDIT_PENDING" if code == 0 else "FAILED_CLOSED"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
