#!/usr/bin/env python3
"""Validate the fail-closed v12 inventory independent-review receipt."""

from __future__ import print_function

import argparse
import hashlib
import json
import os
import sys


RECEIPT = "data/manifests/blind_inventory_independent_review_v12.json"
TARGET = "1f77383f367defcb6572a2ccf875a1b25be2e63f"
REQUEST_COMMIT = "e6898f4cc48473311ebce01d01a7cebcac07c156"
REQUEST = "contracts/blind_inventory_independent_review_v12_request.json"
FINDING_CODES = {
    "SOURCE_CAPABILITY_CALLER_CONTROLLED",
    "LOG_OPEN_TOCTOU",
    "SORT_IDENTITY_PATH_CONTROLLED",
}


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def validate(repo_root):
    receipt = _load(os.path.join(repo_root, *RECEIPT.split("/")))
    _require(receipt["schema_version"] == "blind-inventory-independent-review-v12", "SCHEMA")
    _require(receipt["status"] == "FAIL", "STATUS")
    _require(receipt["decision"] == "FAIL_CLOSED_REMEDIATION_REQUIRED", "DECISION")
    _require(receipt["review_target_commit"] == TARGET, "TARGET_COMMIT")
    _require(receipt["review_request_commit"] == REQUEST_COMMIT, "REQUEST_COMMIT")
    _require(receipt["review_request"] == REQUEST, "REQUEST_PATH")
    _require(_sha256_file(os.path.join(repo_root, *REQUEST.split("/"))) == receipt["review_request_sha256"], "REQUEST_DIGEST")
    _require(receipt["review_tracks"] == {
        "implementation_security_review": "FAIL",
        "commit_binding_and_authority_review": "PASS",
    }, "REVIEW_TRACKS")
    findings = receipt["findings"]
    _require({item["code"] for item in findings} == FINDING_CODES, "FINDINGS")
    _require(all(item["severity"] in ("P0", "P1") and item["required_remediation"] for item in findings), "FINDING_DETAIL")
    _require(receipt["reviewed_artifact_hashes_matched"] is True, "ARTIFACT_BINDING")
    for field in (
        "blind_data_read", "a_or_b_host_accessed", "real_execution_performed",
        "execution_allowed", "held_job_registration_allowed", "candidate_join_allowed",
        "release_implementation_allowed", "training_allowed", "p0_unlocked",
    ):
        _require(receipt[field] is False, "AUTHORITY_" + field.upper())
    return {"status": "FAIL", "p0_unlocked": False, "execution_allowed": False}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    args = parser.parse_args(argv)
    result = validate(os.path.abspath(args.repo_root))
    print("BLIND_INVENTORY_V12_REVIEW={}".format(result["status"]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("BLIND_INVENTORY_V12_REVIEW=INVALID {}".format(exc), file=sys.stderr)
        sys.exit(1)
