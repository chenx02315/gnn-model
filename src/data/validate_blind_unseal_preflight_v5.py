#!/usr/bin/env python3
"""Recompute the v5 BLIND-unseal static gate without reading BLIND inputs."""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import tempfile


def read_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve(root, relative_path):
    return os.path.join(root, *relative_path.replace("\\", "/").split("/"))


def validate(root):
    contract_path = resolve(root, "contracts/blind_runtime_unseal_v5.json")
    contract = read_json(contract_path)
    prior_path = resolve(root, contract["supersedes"]["contract"])
    assessment = read_json(resolve(root, contract["preconditions"]["required_assessment"]))
    split_path = resolve(root, contract["scope"]["split_contract"])
    split = read_json(split_path)
    registry_path = resolve(root, contract["scope"]["method_registry"])
    registry = read_json(registry_path)
    job_path = resolve(root, contract["inputs"]["job_spec"])
    job = read_json(job_path)
    freeze_path = resolve(root, contract["inputs"]["inventory_freeze_receipt"])
    freeze = read_json(freeze_path)

    assessment_statuses = dict((name, item["status"]) for name, item in assessment["checks"].items())
    nonpass = sorted(name for name, status in assessment_statuses.items() if status != "PASS")
    blind_membership = split["formal_runtime_membership"]["BLIND_TEST"]
    split_scope = [(item["circuit"], item["family"]) for item in blind_membership]
    job_scope = [(item.get("circuit"), item.get("family")) for item in job.get("circuits", [])]
    freeze_circuits = freeze.get("circuits", {})
    source_bindings_match = all(
        freeze_circuits.get(item["circuit"], {}).get("measurement_file_set_sha256") == item.get("measurement_file_set_sha256") and
        freeze_circuits.get(item["circuit"], {}).get("driver_log_file_set_sha256") == item.get("driver_log_file_set_sha256") and
        freeze_circuits.get(item["circuit"], {}).get("driver_log_count") == item.get("expected_driver_log_count")
        for item in job.get("circuits", []))
    tool_hashes_match = all(
        os.path.isfile(resolve(root, path)) and sha256_file(resolve(root, path)) == digest
        for path, digest in contract["toolchain"]["artifact_sha256"].items())
    required = contract["preconditions"]["required_check_status"]

    checks = {
        "authority_is_v5": contract.get("schema_version") == "blind-runtime-unseal-v5",
        "v4_is_preserved_and_pinned": sha256_file(prior_path) == contract["supersedes"]["sha256"],
        "split_file_digest_matches": sha256_file(split_path) == contract["scope"]["split_contract_sha256"],
        "split_membership_digest_matches": split.get("formal_runtime_membership_sha256") == contract["scope"]["formal_runtime_membership_sha256"],
        "method_registry_digest_matches": sha256_file(registry_path) == contract["scope"]["method_registry_sha256"],
        "method_registry_is_complete": registry.get("method_count") == len(registry.get("methods", [])) == len(set(registry.get("methods", []))),
        "job_spec_digest_matches": sha256_file(job_path) == contract["inputs"]["job_spec_sha256"],
        "inventory_freeze_digest_matches": sha256_file(freeze_path) == contract["inputs"]["inventory_freeze_receipt_sha256"],
        "blind_scope_and_order_match": split_scope == job_scope and [x[0] for x in split_scope] == contract["scope"]["blind_circuits"],
        "source_set_bindings_match": source_bindings_match,
        "toolchain_hashes_match": tool_hashes_match,
        "assessment_remains_blocked": assessment.get("assessment_status") == "BLOCKED",
        "all_required_checks_pass": all(assessment_statuses.get(name) == status for name, status in required.items()),
        "only_r06_r07_r13_nonpass": nonpass == ["R06", "R07", "R13"],
        "review_required_before_execution": contract["review_gate"].get("required_status") == "PASS" and contract["review_gate"].get("execution_allowed_without_receipt") is False,
        "durable_four_artifact_release": contract["one_shot_protocol"].get("required_release_artifacts") == ["CONSUMED", "receipt.json", "receipt.json.sha256", "RELEASED"],
        "pathless_formal_rows_are_missing": "MISSING_RESULT_PATH" in contract["one_shot_protocol"]["executed_stage_reference_definition"],
        "candidate_output_forbidden": contract["one_shot_protocol"].get("candidate_level_output_allowed") is False,
        "training_remains_forbidden": not contract.get("training_allowed") and not registry.get("training_allowed") and not assessment.get("training_allowed"),
        "no_blind_read_in_preflight": True
    }
    return {
        "schema_version": "blind-runtime-unseal-preflight-v5",
        "status": "PASS" if all(checks.values()) else "FAIL",
        "contract": "contracts/blind_runtime_unseal_v5.json",
        "contract_sha256": sha256_file(contract_path),
        "job_spec_sha256": sha256_file(job_path),
        "inventory_freeze_receipt_sha256": sha256_file(freeze_path),
        "formal_runtime_membership_sha256": contract["scope"]["formal_runtime_membership_sha256"],
        "blind_circuits": [item["circuit"] for item in job["circuits"]],
        "assessment_nonpass_checks": nonpass,
        "checks": checks,
        "blind_data_read": False,
        "candidate_join_performed": False,
        "training_allowed": False
    }


def write_atomic(path, payload):
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory)
    descriptor, temporary = tempfile.mkstemp(prefix=".preflight-v5-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    except Exception:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = validate(os.path.abspath(args.repo_root))
    write_atomic(args.output, result)
    print("BLIND_UNSEAL_PREFLIGHT=%s" % result["status"])
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
