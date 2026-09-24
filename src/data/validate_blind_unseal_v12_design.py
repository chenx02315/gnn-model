#!/usr/bin/env python3
"""Fail-closed validator for the design-only v12 inventory correction."""

import argparse
import hashlib
import json
import os
import sys


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def require(condition, code):
    if not condition:
        raise ValueError(code)


def validate(repo_root):
    path = os.path.join(repo_root, "contracts", "blind_runtime_unseal_v12_design.json")
    design = load(path)
    require(design["schema_version"] == "blind-runtime-unseal-v12-design", "SCHEMA")
    require(design["status"] == "IMPLEMENTATION_DRAFT_NO_EXECUTION", "STATUS")
    require(design["predecessor"]["job_id"] == "388790", "PREDECESSOR_JOB")
    require(design["predecessor"]["retry_requeue_rerun_forbidden"] is True, "PREDECESSOR_REPLAY")

    bindings = {
        "failure_evidence": design["predecessor"],
        "ordering_contract": design["frozen_inputs"],
        "dual_inventory": design["frozen_inputs"],
        "provenance": design["frozen_inputs"],
    }
    for name, section in bindings.items():
        relative = section[name]
        expected = section[name + "_sha256"]
        require(sha256_file(os.path.join(repo_root, *relative.split("/"))) == expected, "DIGEST_" + name.upper())

    algorithm = design["inventory_algorithm"]
    require(algorithm["historical_lane"]["expected_field"] == "historical_locale_ordered_sha256", "HISTORICAL_FIELD")
    require(algorithm["canonical_lane"]["expected_field"] == "bytewise_ordered_sha256", "CANONICAL_FIELD")
    require(algorithm["partial_match_policy"] == "FAIL_CLOSED_NO_CANDIDATE_READ", "PARTIAL_POLICY")
    require("Both lanes" in algorithm["acceptance"], "DUAL_ACCEPTANCE")

    required = set(design["required_negative_tests"])
    require("historical digest match plus bytewise mismatch refuses" in required, "NEGATIVE_HISTORICAL_ONLY")
    require("bytewise digest match plus historical mismatch refuses" in required, "NEGATIVE_BYTEWISE_ONLY")
    require("inventory refusal publishes circuits empty and no candidate values" in required, "NEGATIVE_NONDISCLOSURE")
    implementation = design["implementation_draft"]
    for path_field, digest_field in (("inventory_module", "inventory_module_sha256"), ("focused_tests", "focused_tests_sha256")):
        relative = implementation[path_field]
        expected = implementation[digest_field]
        require(sha256_file(os.path.join(repo_root, *relative.split("/"))) == expected, "DIGEST_" + path_field.upper())
    require(implementation["candidate_join_implemented"] is False, "CANDIDATE_JOIN_IMPLEMENTATION")
    require(implementation["release_implemented"] is False, "RELEASE_IMPLEMENTATION")
    require(implementation["scheduler_entrypoint_implemented"] is False, "SCHEDULER_IMPLEMENTATION")
    require(implementation["direct_entrypoint_result"] == "DESIGN_ONLY_NO_EXECUTION", "DIRECT_ENTRYPOINT")
    require(design["new_output_root_required"] is True, "NEW_OUTPUT_ROOT")
    require(design["held_job_registration_allowed"] is False, "HELD_JOB_AUTHORITY")
    require(design["execution_authorized"] is False, "EXECUTION_AUTHORITY")
    require(design["training_allowed"] is False, "TRAINING_AUTHORITY")
    return {"status": "PASS", "execution_authorized": False, "training_allowed": False}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    args = parser.parse_args(argv)
    result = validate(os.path.abspath(args.repo_root))
    print("BLIND_UNSEAL_V12_DESIGN={}".format(result["status"]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("BLIND_UNSEAL_V12_DESIGN=FAIL {}".format(exc), file=sys.stderr)
        sys.exit(1)
