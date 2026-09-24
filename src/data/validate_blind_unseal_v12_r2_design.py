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


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def validate(repo_root):
    contract_path = os.path.join(repo_root, "contracts", "blind_runtime_unseal_v12_r2_design.json")
    with open(contract_path, encoding="utf-8") as stream:
        design = json.load(stream)
    _require(design["schema_version"] == "blind-runtime-unseal-v12-r2-design", "SCHEMA")
    _require(design["status"] == "DESIGN_ONLY_NO_EXECUTION", "STATUS")
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
    _require(controls["direct_entrypoint_result"] == "DESIGN_ONLY_NO_EXECUTION", "DIRECT_ENTRYPOINT")
    _require(design["trust_anchor_state"] == "UNFINALIZED_FAIL_CLOSED", "ANCHOR_STATE")
    _require(design["platform_positive_integration"] == "PENDING_LINUX_ONLY", "PLATFORM_STATE")
    _require(impl["linux_integration_execution_summary"] ==
             "BLIND_INVENTORY_V12_R2_LINUX_SUMMARY JSON with testsRun and skipped; Linux gate requires testsRun>0 and skipped=0", "LINUX_SUMMARY")
    _require(design["external_review_request_binding"] == "PENDING_EXACT_COMMIT", "EXTERNAL_REVIEW_BINDING")
    _require("SEALED_MEMFD_REQUIRED" in design["repair_rules"]["sort"], "SEALED_MEMFD_RULE")
    required = set(("SOURCE_CAPABILITY_CALLER_CONTROLLED", "LOG_OPEN_TOCTOU", "SORT_IDENTITY_PATH_CONTROLLED"))
    remediation = design["remediation_implementation_status"]
    _require(set(remediation) == required, "FINDINGS")
    _require(all(value == "IMPLEMENTED_DESIGN_ONLY_PENDING_INDEPENDENT_REVIEW" for value in remediation.values()),
             "REMEDIATION_REVIEW_STATE")
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
