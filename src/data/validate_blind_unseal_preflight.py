#!/usr/bin/env python3
"""Validate the v3 BLIND unseal contract without reading BLIND data."""
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
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve(root, relative_path):
    return os.path.join(root, *relative_path.replace("\\", "/").split("/"))


def validate(root):
    contract_path = resolve(root, "contracts/blind_runtime_unseal_v3.json")
    contract = read_json(contract_path)
    assessment = read_json(resolve(root, contract["preconditions"]["required_assessment"]))
    split = read_json(resolve(root, contract["scope"]["split_contract"]))
    registry_path = resolve(root, contract["scope"]["method_registry"])
    registry = read_json(registry_path)
    prior_path = resolve(root, contract["supersedes"]["contract"])

    blind_membership = split["formal_runtime_membership"]["BLIND_TEST"]
    split_blind = [entry["circuit"] for entry in blind_membership]
    required = contract["preconditions"]["required_check_status"]
    assessment_statuses = dict(
        (name, item["status"]) for name, item in assessment["checks"].items())
    nonpass = sorted(name for name, status in assessment_statuses.items()
                     if status != "PASS")
    allowed_nonpass = sorted(
        contract["preconditions"]["only_checks_allowed_to_remain_nonpass_before_unseal"])
    receipt_fields = set(contract["allowed_receipt"]["circuit_row_fields"])
    receipt_fields.update(contract["allowed_receipt"]["envelope_fields"])
    forbidden = set(contract["prohibited"]["outcome_or_runtime_fields"])
    forbidden.update(contract["prohibited"]["release_forms"])

    checks = {
        "authority_is_v3": contract.get("schema_version") == "blind-runtime-unseal-v3",
        "prior_contract_digest_matches": sha256_file(prior_path) == contract["supersedes"]["sha256"],
        "method_registry_digest_matches": sha256_file(registry_path) == contract["scope"]["method_registry_sha256"],
        "split_membership_digest_matches": split.get("formal_runtime_membership_sha256") == contract["scope"]["formal_runtime_membership_sha256"],
        "blind_circuit_set_and_order_match": split_blind == contract["scope"]["blind_circuits"],
        "blind_circuit_count_matches": len(split_blind) == contract["scope"]["blind_circuit_count"],
        "assessment_remains_blocked": assessment.get("assessment_status") == contract["preconditions"]["required_assessment_status"],
        "all_required_checks_pass": all(assessment_statuses.get(name) == status for name, status in required.items()),
        "only_r06_r07_r13_nonpass": nonpass == allowed_nonpass == ["R06", "R07", "R13"],
        "one_shot_is_irreplayable": contract["one_shot_protocol"]["maximum_unseal_attempts"] == 1 and not contract["one_shot_protocol"]["replay_allowed"],
        "candidate_level_output_forbidden": not contract["one_shot_protocol"]["candidate_level_output_allowed"] and "candidate_level_records" in contract["prohibited"]["release_forms"],
        "receipt_fields_exclude_forbidden": not receipt_fields.intersection(forbidden),
        "methods_are_preregistered": registry.get("method_count") == len(registry.get("methods", [])) == len(set(registry.get("methods", []))),
        "method_specific_exclusion_forbidden": not registry["binding_policy"]["method_specific_exclusion_allowed"],
        "training_remains_forbidden": not contract["training_allowed"] and not registry["training_allowed"] and not assessment["training_allowed"]
    }
    return {
        "schema_version": "blind-runtime-unseal-preflight-v3",
        "status": "PASS" if all(checks.values()) else "FAIL",
        "contract": "contracts/blind_runtime_unseal_v3.json",
        "contract_sha256": sha256_file(contract_path),
        "method_registry": contract["scope"]["method_registry"],
        "method_registry_sha256": sha256_file(registry_path),
        "formal_runtime_membership_sha256": contract["scope"]["formal_runtime_membership_sha256"],
        "blind_circuits": split_blind,
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
    handle, temporary = tempfile.mkstemp(prefix=".preflight-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
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
