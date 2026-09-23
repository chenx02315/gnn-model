#!/usr/bin/env python3
"""Fail-closed validation for the non-executable v11 production draft."""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re

SHA256 = re.compile(r"^[0-9a-f]{64}$")
DESIGN_PATH = "contracts/blind_runtime_unseal_v11_design.json"
DESIGN_SHA256 = "c5d5df154a1c677c9521cfaa6138bfb502b358761246f9baf7064d72d4f2ca8a"
TAXONOMY = (
    ("SOURCE_INVENTORY", "INPUT_INVENTORY_DRIFT"),
    ("ATTEMPT_PARSE", "ATTEMPT_INTEGRITY_FAILURE"),
    ("MEASUREMENT_PARSE", "MEASUREMENT_SCHEMA_FAILURE"),
    ("JOIN_CLASSIFICATION", "JOIN_CLASSIFICATION_FAILURE"),
    ("COVERAGE_GATE", "R06_R07_FAILED"),
    ("RELEASE_INTEGRITY", "RELEASE_INTEGRITY_FAILURE"),
    ("INTERNAL_AUDIT", "INTERNAL_AUDIT_FAILURE"),
)
REQUIRED_FINAL_ARTIFACTS = (
    "NEW_VERSIONED_CONTRACT", "NEW_JOB_IDENTIFIER", "NEW_OUTPUT_ROOT",
    "NEW_EXTERNAL_CONTROL_MANIFEST", "SYNTHETIC_FAILURE_STAGE_TESTS_PASS",
    "INDEPENDENT_REVIEW_PASS", "EXPLICIT_EXECUTION_AUTHORIZATION",
)
RECEIPT_FIELDS = (
    "schema_version", "status", "contract_sha256", "tool_set_sha256",
    "failure_stage", "failure_code", "circuits",
)
FORBIDDEN_RECEIPT_FIELDS = (
    "candidate", "result_path", "source_path", "run_identifier", "wall_time",
    "exception_text", "traceback",
)


class DraftError(ValueError):
    pass


def _require(value, code):
    if not value:
        raise DraftError(code)


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def load_draft(repo_root, draft_path):
    with open(draft_path, "r", encoding="utf-8") as stream:
        draft = json.load(stream)
    expected = {
        "schema_version", "status", "purpose", "authority", "p0", "design_reference",
        "required_final_artifacts", "draft_bindings", "post_consumption_failure_taxonomy",
        "pre_consumption_refusal", "public_failure_receipt", "v10_non_reuse",
    }
    _require(set(draft) == expected, "DRAFT_FIELDS")
    _require(draft["schema_version"] == "blind-runtime-unseal-v11-draft", "DRAFT_SCHEMA")
    _require(draft["status"] == "DRAFT_NO_EXECUTION", "DRAFT_STATUS")
    _require(draft["authority"] == {
        "execution_authorized": False, "blind_read_allowed": False,
        "lsf_registration_allowed": False, "training_allowed": False,
    }, "DRAFT_AUTHORITY")
    _require(draft["p0"] == {"status": "BLOCKED", "remaining_gates": {"R06": "PARTIAL", "R07": "BLOCKED", "R13": "BLOCKED"}}, "P0")
    _require(draft["design_reference"] == {"path": DESIGN_PATH, "sha256": DESIGN_SHA256}, "DESIGN_REFERENCE")
    design_path = os.path.join(repo_root, DESIGN_PATH)
    with open(design_path, "rb") as stream:
        _require(sha256_bytes(stream.read()) == DESIGN_SHA256, "DESIGN_DIGEST")
    _require(tuple(draft["required_final_artifacts"]) == REQUIRED_FINAL_ARTIFACTS, "FINAL_ARTIFACTS")
    _require(draft["draft_bindings"] == {
        "final_contract_sha256": None, "pre_reviewed_tool_set_sha256": None,
        "independent_review_receipt": None, "job_spec": None,
        "output_root": None, "external_control_manifest": None,
    }, "DRAFT_BINDINGS")
    _require(tuple(tuple(item) for item in draft["post_consumption_failure_taxonomy"]) == TAXONOMY, "TAXONOMY")
    _require(draft["pre_consumption_refusal"] == {
        "terminal_class": "REFUSED_NOT_CONSUMED", "creates_consumed_marker": False,
        "creates_public_failure_receipt": False, "creates_output_root": False,
    }, "PRE_CONSUMPTION")
    receipt = draft["public_failure_receipt"]
    _require(set(receipt) == {"exact_fields", "status", "circuits", "forbidden_fields"}, "RECEIPT_POLICY_FIELDS")
    _require(tuple(receipt["exact_fields"]) == RECEIPT_FIELDS and receipt["status"] == "FAIL" and receipt["circuits"] == [], "RECEIPT_POLICY")
    _require(tuple(receipt["forbidden_fields"]) == FORBIDDEN_RECEIPT_FIELDS, "RECEIPT_PRIVACY")
    _require(draft["v10_non_reuse"] == {
        "job_id": "388761", "retry_requeue_rerun_forbidden": True,
        "consumed_marker_reuse_forbidden": True, "output_root_reuse_forbidden": True,
        "v10_failure_or_success_inheritance_forbidden": True,
    }, "V10_NON_REUSE")
    return draft


def allowed_pair(stage, code):
    return (stage, code) in TAXONOMY


def validate_post_consumption_context(final_contract_bytes, pre_reviewed_tool_set_bytes):
    """Validate a test-only, already-finalized byte binding.

    The draft has no final contract or tool manifest.  Consequently this helper
    accepts bytes only from a caller that has already finalized both artifacts;
    it never opens a path and cannot confer runner authorization.
    """
    _require(isinstance(final_contract_bytes, bytes) and final_contract_bytes, "FINAL_CONTRACT_BYTES")
    _require(isinstance(pre_reviewed_tool_set_bytes, bytes) and pre_reviewed_tool_set_bytes, "TOOL_SET_BYTES")
    contract_sha256 = sha256_bytes(final_contract_bytes)
    tool_set_sha256 = sha256_bytes(pre_reviewed_tool_set_bytes)
    _require(SHA256.fullmatch(contract_sha256) is not None and SHA256.fullmatch(tool_set_sha256) is not None, "DIGEST_FORMAT")
    return contract_sha256, tool_set_sha256


def validate_failure_receipt(draft, receipt, expected_contract_sha256, expected_tool_set_sha256):
    _require(isinstance(receipt, dict) and set(receipt) == set(RECEIPT_FIELDS), "RECEIPT_FIELDS")
    _require(receipt["schema_version"] == "blind-runtime-unseal-receipt-v11", "RECEIPT_SCHEMA")
    _require(receipt["status"] == "FAIL" and receipt["circuits"] == [], "RECEIPT_FAIL_ONLY")
    _require(receipt["contract_sha256"] == expected_contract_sha256 and receipt["tool_set_sha256"] == expected_tool_set_sha256, "RECEIPT_EXACT_BINDING")
    _require(allowed_pair(receipt["failure_stage"], receipt["failure_code"]), "RECEIPT_STAGE_CODE")
    serialized = json.dumps(receipt, ensure_ascii=True, sort_keys=True).lower()
    for forbidden in FORBIDDEN_RECEIPT_FIELDS:
        _require(forbidden not in receipt and forbidden not in serialized, "RECEIPT_PRIVACY")
    _require(draft["status"] == "DRAFT_NO_EXECUTION", "DRAFT_NOT_ACTIVE")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--draft", required=True)
    args = parser.parse_args(argv)
    try:
        load_draft(os.path.abspath(args.repo_root), os.path.abspath(args.draft))
    except (OSError, ValueError, DraftError) as error:
        print("BLIND_UNSEAL_V11_DRAFT=FAIL:%s" % error)
        return 1
    print(json.dumps({"schema_version": "blind-runtime-unseal-v11-draft-validation", "status": "PASS_DRAFT_NO_EXECUTION", "execution_authorized": False, "blind_read_allowed": False, "lsf_registration_allowed": False, "training_allowed": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
