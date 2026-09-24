#!/usr/bin/env python3
"""Validate the commit-bound, read-only v12 inventory review request."""

from __future__ import print_function

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REQUEST_PATH = "contracts/blind_inventory_independent_review_v12_request.json"
EXPECTED_ARTIFACTS = {
    "contracts/blind_runtime_unseal_v12_design.json",
    "src/data/blind_inventory_v12.py",
    "src/data/validate_blind_unseal_v12_design.py",
    "tests/test_blind_inventory_v12.py",
    "tests/test_blind_unseal_v12_design.py",
}


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _load(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _sha256_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def _git_blob(repo_root, commit, relative):
    try:
        return subprocess.check_output(
            ["git", "-C", repo_root, "show", commit + ":" + relative],
            stderr=subprocess.STDOUT,
        )
    except (OSError, subprocess.CalledProcessError):
        raise ValueError("REVIEWED_GIT_BLOB")


def validate(repo_root):
    request = _load(os.path.join(repo_root, *REQUEST_PATH.split("/")))
    _require(request["schema_version"] == "blind-inventory-independent-review-v12-request", "SCHEMA")
    _require(request["status"] == "PENDING_INDEPENDENT_READ_ONLY_REVIEW", "STATUS")
    commit = request["review_target_commit"]
    _require(COMMIT_RE.match(commit or "") is not None, "REVIEW_TARGET_COMMIT")

    artifacts = request["reviewed_artifacts"]
    _require(isinstance(artifacts, dict) and set(artifacts) == EXPECTED_ARTIFACTS, "REVIEWED_ARTIFACTS")
    for relative, expected in artifacts.items():
        _require(re.match(r"^[0-9a-f]{64}$", expected or "") is not None, "ARTIFACT_DIGEST")
        _require(_sha256_bytes(_git_blob(repo_root, commit, relative)) == expected, "ARTIFACT_BLOB_" + relative)

    checks = set(request["required_checks"])
    required_fragments = (
        "exact target commit",
        "single-lane mismatch refuses",
        "public API exposes no injected orderer",
        "no candidate join release publisher scheduler entrypoint",
        "no A B or BLIND source access",
    )
    for fragment in required_fragments:
        _require(any(fragment in item for item in checks), "REQUIRED_CHECK_" + fragment.upper().replace(" ", "_"))

    future = request["future_pass_requirements"]
    _require(future["reviewed_commit_must_equal"] == commit, "FUTURE_COMMIT_BINDING")
    for field in ("all_required_checks_must_pass",):
        _require(future[field] is True, "FUTURE_" + field.upper())
    for field in ("execution_allowed", "training_allowed", "blind_data_read", "real_execution_performed"):
        _require(future[field] is False, "FUTURE_" + field.upper())
    _require(request["review_scope"] == "READ_ONLY_GIT_BLOBS_NO_A_B_OR_BLIND_ACCESS", "REVIEW_SCOPE")
    _require(request["future_review_receipt"] == "data/manifests/blind_inventory_independent_review_v12.json", "REVIEW_RECEIPT_PATH")
    _require(request["execution_allowed_before_review_pass"] is False, "EXECUTION_AUTHORITY")
    _require(request["held_job_registration_allowed"] is False, "HELD_JOB_AUTHORITY")
    _require(request["training_allowed"] is False, "TRAINING_AUTHORITY")
    return {"status": "PASS", "review_status": request["status"], "execution_allowed": False}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    args = parser.parse_args(argv)
    result = validate(os.path.abspath(args.repo_root))
    print("BLIND_INVENTORY_V12_REVIEW_REQUEST={}".format(result["status"]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("BLIND_INVENTORY_V12_REVIEW_REQUEST=FAIL {}".format(exc), file=sys.stderr)
        sys.exit(1)
