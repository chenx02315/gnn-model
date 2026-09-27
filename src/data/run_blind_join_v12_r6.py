#!/usr/bin/env python3
"""Fail-closed aggregate join of frozen BLIND logs plus v3 recovery logs."""
from __future__ import print_function
import hashlib, json, os, sys

from src.data import blind_join_core_v12_r3 as core
from src.data import run_blind_join_v12_r5 as historical

BUNDLE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONTRACT_RELATIVE = "contracts/blind_runtime_join_v12_r6.json"
OUTPUT_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/18_blind_runtime_join_v12_r6"
RECOVERY_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/17_blind_runtime_recovery_execution_v3_r1_private"
REGISTRATION_ROOT = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/logs/blind_runtime_recovery_execution_v3_registration_r1"
PLAN_PATH = "/temp/jiangchuanc/multimode_ate_phase4_20260825_A/16_blind_runtime_recovery_execution_v3_inputs_r1/plan.json"
CIRCUIT_ORDER = ("s9234", "s38584", "wb_dma")
JOB_ID = "388797"
PLAN_SHA256 = "b5cf0525b635fd4832fb1b1d7cc9f88f61c2d13cedbe77b9ce0d7b0d5dd2d4e1"
CLOSEOUT_RELATIVE = "data/manifests/blind_runtime_recovery_execution_v3_audit_20260927.json"
CLOSEOUT_SHA256 = "671410d9687a725a0a1ac610bbac7c5247dd4ab4ebe918738c9ea5e9309806a5"
SOURCE_MANIFEST_SHA256 = "06e6160ccacc3adbcb844751ccc56e2d0f9ab745ec81a7bac3493f9c6a3ad867"
COPY_VERIFICATION_SHA256 = "dbd3691085f740aa3589541fc61c57aebe6d8220e1485e4be11237f72901bbfd"
RECEIPT_SET_SHA256 = "87955e9abc32970a8af2febdec7856734b9ee1d59e11098240f66fa816f39f19"
EXECUTION_AUDIT_SHA256 = "38f2f99dd50da71ddfc20445edd40dfa6a82bb217e195a38900620de4c56de9"
HISTORICAL_INVENTORY_SHA256 = "cf7b37773516b39b1e3001e43aba1d4157f577a1906fe81605e37b10cb5645c9"
METHOD_REGISTRY_SHA256 = historical.METHOD_REGISTRY_SHA256
FORMAL_MEMBERSHIP_SHA256 = historical.FORMAL_MEMBERSHIP_SHA256
SPLIT_SHA256 = historical.SPLIT_SHA256

class Refusal(Exception):
    pass

def _sha(payload):
    return hashlib.sha256(payload).hexdigest()

def _read(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (AttributeError, OSError):
        raise Refusal("NOFOLLOW_OPEN")
    try:
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block: break
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(fd)

def _json(path, code):
    try: return json.loads(_read(path).decode("utf-8"))
    except (ValueError, UnicodeDecodeError): raise Refusal(code)

def _read_recovery_relative(relative):
    root_fd = historical.secure._open_root(RECOVERY_ROOT)
    try:
        return historical.impl._read_relative_once(root_fd, relative)
    finally:
        os.close(root_fd)

def _exclusive(path, payload):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload); stream.flush(); os.fsync(stream.fileno())

def _validate_closeout():
    path = os.path.join(BUNDLE_ROOT, *CLOSEOUT_RELATIVE.split("/"))
    raw = _read(path)
    # The closeout digest is bound by the contract; the manifest is treated as
    # immutable source-of-truth and its expected digest is patched at seal time.
    if _sha(raw) != CLOSEOUT_SHA256:
        raise Refusal("CLOSEOUT_DIGEST_DRIFT")
    expected = _json(path, "CLOSEOUT_PARSE")
    execution, integrity = expected.get("execution", {}), expected.get("data_integrity", {})
    if (expected.get("schema_version") != "blind-runtime-recovery-execution-v3-closeout" or
        expected.get("status") != "PASS_V3_EXECUTION_AUDIT_JOIN_PENDING" or
        expected.get("job_id") != JOB_ID or expected.get("plan_sha256") != PLAN_SHA256 or
        expected.get("training_allowed") is not False or expected.get("candidate_join_performed") is not False or
        execution.get("attempt_count") != 44 or execution.get("completed_attempt_count") != 44 or
        execution.get("unique_run_id_count") != 44 or execution.get("receipt_count") != 44 or
        execution.get("driver_log_count") != 44 or execution.get("zero_exit_count") != 44 or
        execution.get("zero_retry_count") != 44 or execution.get("wall_time_footer_count") != 44 or
        execution.get("counts_by_circuit") != {"s38584": 42, "s9234": 1, "wb_dma": 1} or
        execution.get("counts_by_mode") != {"H": 22, "M": 22} or
        execution.get("counts_by_stage") != {"01_single_mode_full": 2, "02_hf_coarse": 12, "03_hmf_coarse": 30} or
        integrity.get("source_manifest_sha256") != SOURCE_MANIFEST_SHA256 or
        integrity.get("copy_verification_sha256") != COPY_VERIFICATION_SHA256 or
        integrity.get("receipt_set_sha256") != RECEIPT_SET_SHA256):
        raise Refusal("CLOSEOUT_BINDING")
    return _sha(raw)

def _plan():
    raw = _read(PLAN_PATH)
    if _sha(raw) != PLAN_SHA256: raise Refusal("PLAN_DIGEST_DRIFT")
    doc = _json(PLAN_PATH, "PLAN_PARSE"); rows = []
    for item in doc.get("circuits", []): rows.extend(item.get("attempts", []))
    if len(rows) != 44: raise Refusal("PLAN_ATTEMPT_SET")
    seen = set()
    for row in rows:
        marker = row.get("source_marker")
        if (row.get("circuit") not in CIRCUIT_ORDER or row.get("mode") not in ("H", "M") or
            marker != row.get("mode") + "_" + row.get("run_id") or marker in seen):
            raise Refusal("PLAN_MARKER_BINDING")
        seen.add(marker)
    return rows

def _validate_receipt_binding(receipt, name, row, expected_index):
    marker = receipt.get("mode", "") + "_" + receipt.get("run_id", "")
    index = receipt.get("attempt_index")
    if (receipt.get("schema_version") != "blind-runtime-recovery-attempt-receipt-v1" or
        receipt.get("status") != "PASS" or receipt.get("return_code") != 0 or
        receipt.get("retry_count") != 0 or receipt.get("source_manifest_sha256") != SOURCE_MANIFEST_SHA256 or
        row is None or receipt.get("circuit") != row.get("circuit") or
        receipt.get("stage") != row.get("stage") or receipt.get("mode") != row.get("mode") or
        receipt.get("run_id") != row.get("run_id") or marker != row.get("source_marker")):
        raise Refusal("RECOVERY_RECEIPT_PLAN_BINDING")
    if (not isinstance(index, int) or index != expected_index or index < 1 or index > 44 or
        name != "%03d_%s_%s.json" % (index, receipt["mode"], receipt["run_id"])):
        raise Refusal("RECOVERY_RECEIPT_SET")
    expected_log = os.path.join(RECOVERY_ROOT, "logs", receipt["circuit"],
                                "%03d_%s_%s.driver.log" % (index, receipt["mode"], receipt["run_id"]))
    if receipt.get("driver_log") != expected_log:
        raise Refusal("RECOVERY_RECEIPT_LOG_PATH")
    digest = receipt.get("driver_log_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise Refusal("RECOVERY_RECEIPT_LOG_DIGEST")
    return marker, index, digest

def _recovery(plan):
    source = os.path.join(RECOVERY_ROOT, "source_manifest.json")
    copied = os.path.join(RECOVERY_ROOT, "copy_verification.json")
    source_digest, source_raw = _read_recovery_relative("source_manifest.json")
    copy_digest, copy_raw = _read_recovery_relative("copy_verification.json")
    if source_digest != SOURCE_MANIFEST_SHA256 or copy_digest != COPY_VERIFICATION_SHA256:
        raise Refusal("RECOVERY_MANIFEST_DIGEST")
    try:
        source_doc = json.loads(source_raw.decode("utf-8")); copy_doc = json.loads(copy_raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise Refusal("RECOVERY_MANIFEST_PARSE")
    if (source_doc.get("schema_version") != "blind-runtime-recovery-source-manifest-v1" or
        copy_doc.get("copy_matches_source") is not True):
        raise Refusal("RECOVERY_MANIFEST_BINDING")
    audit_path = os.path.join(REGISTRATION_ROOT, "execution_audit.json")
    audit = _json(audit_path, "EXECUTION_AUDIT_PARSE")
    if (_sha(_read(audit_path)) != EXECUTION_AUDIT_SHA256 or
        audit.get("schema_version") != "blind-runtime-recovery-execution-v3-audit" or
        audit.get("status") != "PASS_V3_EXECUTION_AUDIT_JOIN_PENDING" or
        audit.get("lsf_job_id") != JOB_ID or audit.get("attempt_count") != 44 or
        audit.get("receipt_count") != 44 or audit.get("receipt_set_sha256") != RECEIPT_SET_SHA256 or
        audit.get("source_manifest_sha256") != SOURCE_MANIFEST_SHA256 or
        audit.get("copy_verification_sha256") != COPY_VERIFICATION_SHA256 or
        audit.get("candidate_join_performed") is not False or audit.get("training_allowed") is not False):
        raise Refusal("EXECUTION_AUDIT_BINDING")
    expected = dict((row["source_marker"], (row, index))
                    for index, row in enumerate(plan, 1))
    root_fd = historical.secure._open_root(RECOVERY_ROOT)
    try:
        receipt_fd = os.open("receipts", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        try: names = sorted(x for x in historical.secure._directory_members(receipt_fd) if x.endswith(".json"))
        finally: os.close(receipt_fd)
    finally: os.close(root_fd)
    if len(names) != 44: raise Refusal("RECOVERY_RECEIPT_COUNT")
    receipts = []
    raw_receipts = []
    for name in names:
        try:
            raw = _read_recovery_relative("receipts/" + name)[1]
            raw_receipts.append(raw)
            receipts.append(json.loads(raw.decode("utf-8")))
        except (ValueError, UnicodeDecodeError): raise Refusal("RECOVERY_RECEIPT_PARSE")
    if _sha(b"".join(raw_receipts)) != RECEIPT_SET_SHA256:
        raise Refusal("RECOVERY_RECEIPT_SET_DIGEST")
    receipt_by_marker = {}
    seen_indices = set()
    for receipt, name in zip(receipts, names):
        marker = receipt.get("mode", "") + "_" + receipt.get("run_id", "")
        expected_pair = expected.get(marker)
        row, expected_index = expected_pair if expected_pair is not None else (None, None)
        marker, index, unused_digest = _validate_receipt_binding(
            receipt, name, row, expected_index)
        if marker in receipt_by_marker or index in seen_indices:
            raise Refusal("RECOVERY_RECEIPT_SET")
        receipt_by_marker[marker] = receipt
        seen_indices.add(index)
    if seen_indices != set(range(1, 45)) or set(receipt_by_marker) != set(expected):
        raise Refusal("RECOVERY_RECEIPT_SET")
    recovered = dict((circuit, {}) for circuit in CIRCUIT_ORDER)
    for circuit in CIRCUIT_ORDER:
        root_fd = historical.secure._open_root(os.path.join(RECOVERY_ROOT, "logs", circuit))
        try: logs = historical.impl._walk_log_snapshots(root_fd)
        finally: os.close(root_fd)
        for relative, pair in logs.items():
            digest, payload = pair; name = relative.rsplit("/", 1)[-1]
            if not name.endswith(".driver.log") or "_" not in name: raise Refusal("RECOVERY_LOG_NAME")
            marker = name.split("_", 1)[1][:-len(".driver.log")]
            expected_pair = expected.get(marker)
            row = expected_pair[0] if expected_pair is not None else None
            if row is None or row.get("circuit") != circuit or marker in recovered[circuit]:
                raise Refusal("RECOVERY_LOG_PLAN_MISMATCH")
            receipt = receipt_by_marker.get(marker)
            if receipt is None or relative != "%03d_%s_%s.driver.log" % (
                    receipt["attempt_index"], receipt["mode"], receipt["run_id"]):
                raise Refusal("RECOVERY_LOG_RECEIPT_PATH")
            if digest != receipt["driver_log_sha256"]:
                raise Refusal("RECOVERY_LOG_DIGEST_MISMATCH")
            text = payload.decode("utf-8", "replace")
            if ("Elapsed (wall clock) time" not in text or "Exit status: 0" not in text or
                ("MAPPED_COMMON_ATPG_STATUS=PASS" not in text and "MAPPED_INCREMENTAL_ATPG_STATUS=PASS" not in text)):
                raise Refusal("RECOVERY_LOG_FOOTER")
            adapted = "recovery/%s/%s/%s.driver.log" % (circuit, row["stage"], marker)
            recovered[circuit][adapted] = (digest, payload)
    if sum(len(v) for v in recovered.values()) != 44: raise Refusal("RECOVERY_LOG_SET")
    return recovered

def _valid(rows):
    required = {"circuit", "executed_stage_reference_count", "unique_runtime_join_count", "missing_runtime_join_count", "ambiguous_runtime_join_count", "coverage_rate", "distinct_runtime_attempt_count", "cross_stage_reference_count", "eligible_action_count", "all_unique_action_count", "frozen_runtime_eligible_action_space_sha256", "source_artifact_set_sha256"}
    return ([r.get("circuit") for r in rows] == list(CIRCUIT_ORDER) and all(set(r) == required for r in rows) and core.gates_pass(rows))

def validate_bundle():
    contract = _json(os.path.join(BUNDLE_ROOT, *CONTRACT_RELATIVE.split("/")), "CONTRACT_PARSE")
    if (contract.get("schema_version") != "blind-runtime-join-v12-r6" or contract.get("status") != "AUTHORIZED_EXECUTION_REVIEWED" or contract.get("circuits") != list(CIRCUIT_ORDER) or contract.get("output_root") != OUTPUT_ROOT or contract.get("training_allowed") is not False or contract.get("historical_inventory_sha256") != HISTORICAL_INVENTORY_SHA256 or contract.get("recovery", {}).get("closeout_sha256") != CLOSEOUT_SHA256): raise Refusal("CONTRACT_SCOPE")
    artifacts = contract.get("implementation", {}).get("artifact_sha256", {})
    required = {"src/data/blind_inventory_v12_r2.py", "src/data/blind_join_core_v12_r3.py", "src/data/run_blind_join_v12_r3.py", "src/data/run_blind_join_v12_r5.py", "src/data/run_blind_join_v12_r6.py", "src/data/build_blind_method_binding_v12_r6.py", "tests/test_run_blind_join_v12_r6.py", "tests/test_build_blind_method_binding_v12_r6.py"}
    if set(artifacts) != required: raise Refusal("CONTRACT_ARTIFACT_SET")
    for rel, digest in artifacts.items():
        path = os.path.join(BUNDLE_ROOT, *rel.split("/"))
        if os.path.islink(path) or _sha(_read(path)) != digest: raise Refusal("ARTIFACT_DIGEST_MISMATCH")
    raw = _read(os.path.join(BUNDLE_ROOT, *CONTRACT_RELATIVE.split("/")))
    return _sha(raw), core._sha_lines(rel + ":" + digest for rel, digest in artifacts.items())

def _write(receipt):
    if os.path.lexists(OUTPUT_ROOT): raise Refusal("OUTPUT_ROOT_ALREADY_EXISTS")
    parent = os.path.dirname(OUTPUT_ROOT)
    if not os.path.isdir(parent): raise Refusal("OUTPUT_PARENT_MISSING")
    os.mkdir(OUTPUT_ROOT, 0o700); raw = json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"; digest = _sha(raw)
    _exclusive(os.path.join(OUTPUT_ROOT, "receipt.json"), raw)
    _exclusive(os.path.join(OUTPUT_ROOT, "receipt.json.sha256"), (digest + "  receipt.json\n").encode("ascii"))
    _exclusive(os.path.join(OUTPUT_ROOT, "RELEASED"), json.dumps({"schema_version":"blind-runtime-join-release-v12-r6","status":"RELEASED_AUDIT_PENDING","receipt_sha256":digest}, sort_keys=True).encode("utf-8") + b"\n")

def run():
    contract_sha, impl_sha = validate_bundle()
    try:
        historical._validate_runtime_platform()
        closeout_sha = _validate_closeout(); plan = _plan(); recovery = _recovery(plan)
        historical.secure._run_verified_sort = historical._verified_sort_fd; control = historical.impl.open_trusted_control()
        rows = []
        for circuit in CIRCUIT_ORDER:
            old, measurements = historical.impl.snapshot_circuit(control, circuit)
            old.update(recovery[circuit]); rows.append(core.audit_circuit(circuit, old, measurements))
        if not _valid(rows): raise core.JoinFailure("COVERAGE_GATE", "R06_R07_FAILED")
        receipt = {"schema_version":"blind-runtime-join-receipt-v12-r6","status":"PASS_R06_R07_AUDIT_PENDING","formal_runtime_membership_sha256":FORMAL_MEMBERSHIP_SHA256,"split_contract_sha256":SPLIT_SHA256,"method_registry_sha256":METHOD_REGISTRY_SHA256,"contract_sha256":contract_sha,"implementation_set_sha256":impl_sha,"recovery_closeout_sha256":closeout_sha,"recovery_job_id":JOB_ID,"recovery_plan_sha256":PLAN_SHA256,"recovery_source_manifest_sha256":SOURCE_MANIFEST_SHA256,"recovery_copy_verification_sha256":COPY_VERIFICATION_SHA256,"recovery_receipt_set_sha256":RECEIPT_SET_SHA256,"circuits":rows,"failure_code":None,"training_allowed":False}; code = 0
    except core.JoinFailure as error:
        receipt = {"schema_version":"blind-runtime-join-receipt-v12-r6","status":"FAIL","contract_sha256":contract_sha,"implementation_set_sha256":impl_sha,"failure_stage":error.stage,"failure_code":error.code,"circuits":[],"training_allowed":False}; code = 1
    except (Refusal, historical.Refusal, historical.impl.Refusal, historical.secure.Refusal, OSError, ValueError, KeyError) as error:
        receipt = {"schema_version":"blind-runtime-join-receipt-v12-r6","status":"FAIL","contract_sha256":contract_sha,"implementation_set_sha256":impl_sha,"failure_stage":"SOURCE_INVENTORY","failure_code":str(error),"circuits":[],"training_allowed":False}; code = 1
    except Exception as error:
        receipt = {"schema_version":"blind-runtime-join-receipt-v12-r6","status":"FAIL","contract_sha256":contract_sha,"implementation_set_sha256":impl_sha,"failure_stage":"INTERNAL_AUDIT","failure_code":"INTERNAL_AUDIT_FAILURE","circuits":[],"training_allowed":False}; code = 1
    _write(receipt); return code

def main(argv=None):
    if (sys.argv[1:] if argv is None else argv): print("BLIND_JOIN_V12_R6=REFUSED_FIXED_ARGV"); return 2
    try: code = run()
    except Refusal as error: print("BLIND_JOIN_V12_R6=REFUSED_" + str(error)); return 2
    print("BLIND_JOIN_V12_R6=" + ("R06_R07_AUDIT_PENDING" if code == 0 else "FAILED_CLOSED")); return code

if __name__ == "__main__": raise SystemExit(main())
