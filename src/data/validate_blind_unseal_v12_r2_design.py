#!/usr/bin/env python3
"""Validate the sealed design-only v12-r2 correction contract."""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import sys


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_git_text(path):
    """Hash checked-in text independently of Windows checkout line endings."""
    with open(path, "rb") as stream:
        payload = stream.read().replace(b"\r\n", b"\n")
    return hashlib.sha256(payload).hexdigest()


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def validate(repo_root):
    contract_path = os.path.join(repo_root, "contracts", "blind_runtime_unseal_v12_r2_design.json")
    with open(contract_path, encoding="utf-8") as stream:
        design = json.load(stream)
    _require(design["schema_version"] == "blind-runtime-unseal-v12-r2-design", "SCHEMA")
    _require(design["status"] == "SYNTHETIC_LINUX_VALIDATED_NO_EXECUTION_AUTHORITY", "STATUS")
    _require(design["old_v12_failure_authoritative"] is True, "OLD_V12_FAILURE")
    impl = design["implementation"]
    for path_key, digest_key in (("inventory_module", "inventory_module_sha256"),
                                 ("focused_tests", "focused_tests_sha256"),
                                 ("linux_integration_tests", "linux_integration_tests_sha256")):
        path = os.path.join(repo_root, *impl[path_key].split("/"))
        _require(_sha256(path) == impl[digest_key], "DIGEST_" + path_key.upper())
    controls = design["authority"]
    for key in ("candidate_join_implemented", "release_implemented", "scheduler_entrypoint_implemented",
                "held_job_registration_allowed", "execution_authorized", "training_allowed"):
        _require(controls[key] is False, "AUTHORITY_" + key.upper())
    _require(controls["direct_entrypoint_result"] == "LINUX_SYNTHETIC_PASS_NO_PRODUCTION_EXECUTION",
             "DIRECT_ENTRYPOINT")
    _require(design["trust_anchor_state"] == "UNFINALIZED_FAIL_CLOSED", "ANCHOR_STATE")
    _require(design["platform_positive_integration"] == "PASS_LOCAL_SYNTHETIC_ONLY", "PLATFORM_STATE")
    _require(impl["linux_integration_execution_summary"] ==
             "BLIND_INVENTORY_V12_R2_LINUX_SUMMARY JSON with gate_pass; direct entry is nonzero unless testsRun>0 skipped=0 failures=0 errors=0 and Linux prerequisites hold", "LINUX_SUMMARY")
    _require(design["external_review_request_binding"] ==
             "PASS_DESIGN_GATE_BE59C419_TEST_ONLY_DELTA_31D8D49", "EXTERNAL_REVIEW_BINDING")
    _require("SEALED_MEMFD_REQUIRED" in design["repair_rules"]["sort"], "SEALED_MEMFD_RULE")
    required = set(("SOURCE_CAPABILITY_CALLER_CONTROLLED", "LOG_OPEN_TOCTOU", "SORT_IDENTITY_PATH_CONTROLLED"))
    remediation = design["remediation_implementation_status"]
    _require(set(remediation) == required, "FINDINGS")
    _require(all(value == "DESIGN_REVIEW_PASSED_LINUX_SYNTHETIC_PASS" for value in remediation.values()),
             "REMEDIATION_REVIEW_STATE")
    receipt_path = os.path.join(repo_root, *impl["linux_execution_receipt"].split("/"))
    log_path = os.path.join(repo_root, *impl["linux_execution_log"].split("/"))
    _require(_sha256_git_text(receipt_path) == impl["linux_execution_receipt_git_blob_sha256"],
             "DIGEST_LINUX_EXECUTION_RECEIPT")
    _require(_sha256_git_text(log_path) == impl["linux_execution_log_git_blob_sha256"],
             "DIGEST_LINUX_EXECUTION_LOG")
    with open(receipt_path, encoding="utf-8") as stream:
        receipt = json.load(stream)
    _require(receipt["schema_version"] == "blind-inventory-v12-r2-linux-gate-execution-v1",
             "LINUX_RECEIPT_SCHEMA")
    _require(receipt["status"] == "PASS_LOCAL_SYNTHETIC_ONLY", "LINUX_RECEIPT_STATUS")
    _require(receipt["source_commit"] == impl["linux_execution_source_commit"], "LINUX_SOURCE_COMMIT")
    _require(receipt["gate_exit_code"] == 0, "LINUX_EXIT_CODE")
    summary = receipt["gate_summary"]
    expected_summary = {"testsRun": 6, "skipped": 0, "failures": 0, "errors": 0,
                        "gate_pass": True, "platform_positive_integration": "PASS_LOCAL_SYNTHETIC_ONLY"}
    _require(all(summary.get(key) == value for key, value in expected_summary.items()), "LINUX_SUMMARY_RESULT")
    _require(all(value is False for value in receipt["authority"].values()), "LINUX_RECEIPT_AUTHORITY")
    _require(receipt["artifacts"]["raw_log_sha256"] == impl["linux_execution_log_git_blob_sha256"],
             "LINUX_LOG_BINDING")
    _require(receipt["artifacts"]["inventory_module_sha256"] == impl["inventory_module_sha256"],
             "LINUX_MODULE_BINDING")
    _require(receipt["artifacts"]["linux_test_sha256"] == impl["linux_integration_tests_sha256"],
             "LINUX_TEST_BINDING")
    closeout_path = os.path.join(repo_root, "data", "manifests",
                                 "blind_inventory_v12_r2_linux_gate_closeout.json")
    with open(closeout_path, encoding="utf-8") as stream:
        closeout = json.load(stream)
    _require(closeout["schema_version"] == "blind-inventory-v12-r2-linux-gate-closeout-v1",
             "CLOSEOUT_SCHEMA")
    _require(closeout["status"] == "PASS_LINUX_SYNTHETIC_GATE_CLOSED", "CLOSEOUT_STATUS")
    _require(all(value is False for value in closeout["authority"].values()), "CLOSEOUT_AUTHORITY")
    successful = closeout["execution_history"][-1]
    _require(successful["source_commit"] == impl["linux_execution_source_commit"],
             "CLOSEOUT_SOURCE_COMMIT")
    _require(successful["evidence_commit"] == impl["linux_execution_evidence_commit"],
             "CLOSEOUT_EVIDENCE_COMMIT")
    _require(successful["status"] == "PASS_LOCAL_SYNTHETIC_ONLY" and
             successful["gate_pass"] is True and successful["exit_code"] == 0,
             "CLOSEOUT_RESULT")
    _require(closeout["verification"] == {"focused_tests": 26, "full_tests": 384,
                                          "full_tests_skipped": 8,
                                          "design_validator": "PASS",
                                          "git_diff_check": "PASS"},
             "CLOSEOUT_VERIFICATION")
    for relative, digest in closeout["artifact_git_blob_sha256"].items():
        path = os.path.join(repo_root, *relative.split("/"))
        _require(_sha256_git_text(path) == digest,
                 "CLOSEOUT_DIGEST_" + relative.replace("/", "_").replace(".", "_").upper())
    return {"status": "PASS", "execution_authorized": False, "training_allowed": False}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    args = parser.parse_args(argv)
    try:
        result = validate(os.path.abspath(args.repo_root))
    except Exception as exc:
        print("BLIND_UNSEAL_V12_R2_DESIGN=FAIL {}".format(exc), file=sys.stderr)
        return 1
    print("BLIND_UNSEAL_V12_R2_DESIGN={}".format(result["status"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
