#!/usr/bin/env python3
"""Validate the design-only v11 failure taxonomy without touching BLIND data."""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re

SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_INPUTS = {
    "runtime_recovery_closeout_v10": (
        "data/manifests/runtime_recovery_closeout_v10.json",
        "62a5c518b5ea7097769ed7126ed0fbbe8e0c3d65580e7f26abc66274a5bc43b2",
    ),
    "v10_failure_audit": (
        "data/manifests/blind_runtime_unseal_v10_failure_20260922.json",
        "e438c44f63b13bd85340132958c791c474da6a3a709ff5d54eba7b957bbf287a",
    ),
    "v10_runner_reference": (
        "src/data/run_blind_unseal_v10.py",
        "f5871261b5396a426022ea1c3af32c0369c58132cc788b0689ec0f81c1962848",
    ),
}
EXPECTED_TAXONOMY = [
    ("SOURCE_INVENTORY", "INPUT_INVENTORY_DRIFT"),
    ("ATTEMPT_PARSE", "ATTEMPT_INTEGRITY_FAILURE"),
    ("MEASUREMENT_PARSE", "MEASUREMENT_SCHEMA_FAILURE"),
    ("JOIN_CLASSIFICATION", "JOIN_CLASSIFICATION_FAILURE"),
    ("COVERAGE_GATE", "R06_R07_FAILED"),
    ("RELEASE_INTEGRITY", "RELEASE_INTEGRITY_FAILURE"),
    ("INTERNAL_AUDIT", "INTERNAL_AUDIT_FAILURE"),
]
EXPECTED_GATES = [
    "NEW_VERSIONED_CONTRACT",
    "NEW_JOB_IDENTIFIER",
    "NEW_OUTPUT_ROOT",
    "NEW_EXTERNAL_CONTROL_MANIFEST",
    "SYNTHETIC_FAILURE_STAGE_TESTS_PASS",
    "INDEPENDENT_REVIEW_PASS",
    "EXPLICIT_EXECUTION_AUTHORIZATION",
]
FORBIDDEN_TOKENS = (
    "candidate", "result_path", "source_path", "run_identifier",
    "wall_time", "exception_text", "traceback",
)


class DesignError(ValueError):
    pass


def _require(condition, code):
    if not condition:
        raise DesignError(code)


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_design(repo_root, contract_path):
    with open(contract_path, "r", encoding="utf-8") as stream:
        contract = json.load(stream)
    expected_fields = {
        "schema_version", "status", "purpose", "authority", "frozen_inputs",
        "failure_taxonomy", "pre_consumption_refusal", "public_failure_receipt", "synthetic_failure_fixture", "required_pre_execution_gates",
        "non_reuse_rules", "p0",
    }
    _require(set(contract) == expected_fields, "CONTRACT_FIELDS")
    _require(contract.get("schema_version") == "blind-runtime-unseal-v11-design", "SCHEMA")
    _require(contract.get("status") == "DESIGN_ONLY_NO_EXECUTION", "STATUS")

    authority = contract.get("authority")
    _require(authority == {
        "blind_read_allowed": False,
        "execution_authorized": False,
        "lsf_registration_allowed": False,
        "training_allowed": False,
    }, "AUTHORITY")

    frozen = contract.get("frozen_inputs")
    _require(set(frozen or {}) == set(EXPECTED_INPUTS), "FROZEN_INPUT_SET")
    for name, (relative, expected_digest) in EXPECTED_INPUTS.items():
        item = frozen[name]
        _require(item == {"path": relative, "sha256": expected_digest}, "FROZEN_INPUT_" + name)
        _require(SHA256.match(expected_digest) is not None, "FROZEN_DIGEST_FORMAT")
        _require(_sha256_file(os.path.join(repo_root, relative)) == expected_digest, "FROZEN_DIGEST_" + name)

    taxonomy = contract.get("failure_taxonomy")
    _require(isinstance(taxonomy, list) and len(taxonomy) == len(EXPECTED_TAXONOMY), "TAXONOMY_COUNT")
    observed = []
    for item in taxonomy:
        _require(set(item) == {"stage", "code", "after_consumed", "retryable"}, "TAXONOMY_FIELDS")
        _require(item.get("after_consumed") is True and item.get("retryable") is False, "TAXONOMY_ONE_SHOT")
        observed.append((item.get("stage"), item.get("code")))
    _require(observed == EXPECTED_TAXONOMY and len(set(observed)) == len(observed), "TAXONOMY_VALUES")

    _require(contract.get("pre_consumption_refusal") == {
        "terminal_class": "REFUSED_NOT_CONSUMED",
        "creates_consumed_marker": False,
        "creates_public_failure_receipt": False,
        "automatic_retry_allowed": False,
    }, "PRE_CONSUMPTION_REFUSAL")

    receipt = contract.get("public_failure_receipt")
    _require(set(receipt or {}) == {"scope", "exact_fields", "binding_rules", "required_status", "required_circuits", "forbidden_fields"}, "RECEIPT_SCHEMA")
    _require(receipt.get("scope") == "POST_CONSUMPTION_ONLY", "RECEIPT_SCOPE")
    _require(receipt.get("exact_fields") == ["schema_version", "status", "contract_sha256", "tool_set_sha256", "failure_stage", "failure_code", "circuits"], "RECEIPT_FIELDS")
    _require(receipt.get("binding_rules") == {
        "contract_sha256": "EXACT_FINALIZED_V11_CONTRACT_DIGEST",
        "tool_set_sha256": "EXACT_PRE_REVIEWED_IMPLEMENTATION_SET_DIGEST",
    }, "RECEIPT_BINDING")
    _require(receipt.get("required_status") == "FAIL" and receipt.get("required_circuits") == [], "RECEIPT_FAILURE_ONLY")
    _require(receipt.get("forbidden_fields") == list(FORBIDDEN_TOKENS), "RECEIPT_PRIVACY")

    _require(contract.get("synthetic_failure_fixture") == {
        "scope": "SHAPE_TEST_ONLY_NOT_PUBLIC_EVIDENCE",
        "wrapper_schema_version": "blind-runtime-unseal-v11-synthetic-failure-fixture",
        "wrapper_status": "SYNTHETIC_ONLY_NO_EXECUTION",
        "execution_authorized": False,
        "embedded_receipt_is_public_evidence": False,
        "contract_sha256": "66b149ff7ac6090efd8cba9f490c52ef88ea1c03174709f9d3922ab9a5e6afe6",
        "tool_set_sha256": "bd85881d2b4d985efc7ae0f4874c0836ca344b4a37a678ffa2c8180928e1dd8d",
    }, "SYNTHETIC_FIXTURE_BINDING")

    _require(contract.get("required_pre_execution_gates") == EXPECTED_GATES, "PRE_EXECUTION_GATES")
    _require(contract.get("non_reuse_rules") == {
        "job_388761_must_not_be_retried_or_requeued": True,
        "v10_consumed_marker_must_not_be_reused": True,
        "v10_output_root_must_not_be_reused": True,
        "nonblind_replay_must_not_be_claimed_as_v10_root_cause": True,
    }, "NON_REUSE")
    _require(contract.get("p0") == {
        "status": "BLOCKED",
        "remaining_gates": {"R06": "PARTIAL", "R07": "BLOCKED", "R13": "BLOCKED"},
    }, "P0_BLOCKED")

    serialized = json.dumps(contract, ensure_ascii=True, sort_keys=True)
    _require("DESIGN_ONLY_NO_EXECUTION" in serialized and "execution_authorized\": false" in serialized, "NO_EXECUTION_CLAIM")
    return {
        "schema_version": "blind-runtime-unseal-v11-design-validation",
        "status": "PASS_DESIGN_ONLY",
        "execution_authorized": False,
        "blind_read_allowed": False,
        "training_allowed": False,
        "failure_stage_count": len(taxonomy),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--contract", required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_design(os.path.abspath(args.repo_root), os.path.abspath(args.contract))
    except (OSError, ValueError, DesignError) as error:
        print("BLIND_UNSEAL_V11_DESIGN=FAIL:%s" % error)
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
