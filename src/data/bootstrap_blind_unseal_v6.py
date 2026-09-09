#!/usr/bin/env python3
"""Minimal stdlib-only trust bootstrap for the sealed v6 BLIND audit."""
from __future__ import print_function

import argparse
import hashlib
import importlib
import json
import os
import re
import subprocess
import sys


SHA40 = re.compile(r"^[0-9a-f]{40}$")


class BootstrapError(Exception):
    pass


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
    root_real = os.path.realpath(root)
    path = os.path.realpath(os.path.join(root_real, *relative_path.replace("\\", "/").split("/")))
    if os.path.commonpath((root_real, path)) != root_real:
        raise BootstrapError("BUNDLE_PATH_ESCAPE")
    return path


def git_bytes(root, arguments):
    try:
        return subprocess.check_output(["git", "-C", root] + list(arguments), stderr=subprocess.STDOUT)
    except (OSError, subprocess.CalledProcessError):
        raise BootstrapError("GIT_BINDING_FAILED")


def verify_artifacts(root, artifacts):
    for relative_path, expected in artifacts.items():
        path = resolve(root, relative_path)
        if not os.path.isfile(path) or os.path.islink(path) or sha256_file(path) != expected:
            raise BootstrapError("ARTIFACT_DIGEST_MISMATCH")


def verify_review(root, contract_path, contract, artifacts):
    receipt_path = resolve(root, contract["review_gate"]["receipt"])
    if not os.path.isfile(receipt_path) or os.path.islink(receipt_path):
        raise BootstrapError("REVIEW_RECEIPT_MISSING")
    receipt = read_json(receipt_path)
    contract_sha = sha256_file(contract_path)
    if receipt.get("status") != "PASS" or not receipt.get("execution_allowed"):
        raise BootstrapError("REVIEW_NOT_PASS")
    if receipt.get("contract_sha256") != contract_sha or receipt.get("reviewed_artifacts") != artifacts:
        raise BootstrapError("REVIEW_DIGEST_BINDING")
    commit = receipt.get("reviewed_commit", "")
    if SHA40.match(commit) is None:
        raise BootstrapError("REVIEW_COMMIT_FORMAT")

    top = git_bytes(root, ["rev-parse", "--show-toplevel"]).decode("utf-8").strip()
    if os.path.realpath(top) != os.path.realpath(root):
        raise BootstrapError("GIT_ROOT_MISMATCH")
    resolved = git_bytes(root, ["rev-parse", commit + "^{commit}"]).decode("ascii").strip()
    if resolved != commit:
        raise BootstrapError("REVIEW_COMMIT_UNRESOLVED")
    git_bytes(root, ["merge-base", "--is-ancestor", commit, "HEAD"])
    if git_bytes(root, ["status", "--porcelain=v1", "--untracked-files=all"]).strip():
        raise BootstrapError("GIT_CHECKOUT_NOT_CLEAN")

    committed_contract = git_bytes(root, ["show", commit + ":contracts/blind_runtime_unseal_v6.json"])
    if hashlib.sha256(committed_contract).hexdigest() != contract_sha:
        raise BootstrapError("REVIEWED_CONTRACT_NOT_AT_COMMIT")
    for relative_path, expected in artifacts.items():
        committed = git_bytes(root, ["show", commit + ":" + relative_path])
        if hashlib.sha256(committed).hexdigest() != expected:
            raise BootstrapError("REVIEWED_ARTIFACT_NOT_AT_COMMIT")
    return receipt, contract_sha, commit


def validate_static_gate(root, contract):
    assessment = read_json(resolve(root, contract["preconditions"]["required_assessment"]))
    split_path = resolve(root, contract["scope"]["split_contract"])
    registry_path = resolve(root, contract["scope"]["method_registry"])
    job_path = resolve(root, contract["inputs"]["job_spec"])
    freeze_path = resolve(root, contract["inputs"]["inventory_freeze_receipt"])
    split = read_json(split_path)
    registry = read_json(registry_path)
    job = read_json(job_path)
    freeze = read_json(freeze_path)
    if sha256_file(split_path) != contract["scope"]["split_contract_sha256"]:
        raise BootstrapError("SPLIT_FILE_DIGEST")
    if sha256_file(registry_path) != contract["scope"]["method_registry_sha256"]:
        raise BootstrapError("REGISTRY_DIGEST")
    if sha256_file(job_path) != contract["inputs"]["job_spec_sha256"]:
        raise BootstrapError("JOB_DIGEST")
    if sha256_file(freeze_path) != contract["inputs"]["inventory_freeze_receipt_sha256"]:
        raise BootstrapError("FREEZE_DIGEST")
    if assessment.get("assessment_status") != contract["preconditions"]["required_assessment_status"]:
        raise BootstrapError("ASSESSMENT_STATUS")
    statuses = dict((name, row.get("status")) for name, row in assessment.get("checks", {}).items())
    required = contract["preconditions"]["required_check_status"]
    if any(statuses.get(name) != value for name, value in required.items()):
        raise BootstrapError("REQUIRED_GATE_STATUS")
    if sorted(name for name, value in statuses.items() if value != "PASS") != ["R06", "R07", "R13"]:
        raise BootstrapError("NONPASS_GATE_SET")
    split_scope = [(row["circuit"], row["family"])
                   for row in split["formal_runtime_membership"]["BLIND_TEST"]]
    job_scope = [(row.get("circuit"), row.get("family")) for row in job.get("circuits", [])]
    if split_scope != job_scope or [row[0] for row in split_scope] != contract["scope"]["blind_circuits"]:
        raise BootstrapError("BLIND_SCOPE")
    for entry in job["circuits"]:
        frozen = freeze.get("circuits", {}).get(entry["circuit"], {})
        if (frozen.get("measurement_file_set_sha256") != entry.get("measurement_file_set_sha256") or
                frozen.get("driver_log_file_set_sha256") != entry.get("driver_log_file_set_sha256") or
                frozen.get("driver_log_count") != entry.get("expected_driver_log_count")):
            raise BootstrapError("SOURCE_SET_BINDING")
        receipt_path = resolve(root, entry["aggregate_precondition_receipt"])
        if sha256_file(receipt_path) != entry["aggregate_precondition_receipt_sha256"]:
            raise BootstrapError("AGGREGATE_RECEIPT_DIGEST")
        aggregate = read_json(receipt_path)
        if (aggregate.get("circuit") != entry["circuit"] or
                aggregate.get("source_inventory_manifest_sha256") != entry["source_inventory_manifest_sha256"] or
                aggregate.get("counts", {}).get("recovered_attempt_count") != entry["expected_driver_log_count"]):
            raise BootstrapError("AGGREGATE_RECEIPT_CONTENT")
    if registry.get("method_count") != len(registry.get("methods", [])):
        raise BootstrapError("METHOD_REGISTRY_CONTENT")
    if contract.get("training_allowed") or assessment.get("training_allowed") or registry.get("training_allowed"):
        raise BootstrapError("TRAINING_NOT_SEALED")
    return job, split


def bootstrap(bundle_root):
    root = os.path.realpath(bundle_root)
    contract_path = resolve(root, "contracts/blind_runtime_unseal_v6.json")
    contract = read_json(contract_path)
    if contract.get("schema_version") != "blind-runtime-unseal-v6":
        raise BootstrapError("CONTRACT_VERSION")
    artifacts = dict(contract["bootstrap"]["reviewed_artifact_sha256"])
    verify_artifacts(root, artifacts)
    _receipt, contract_sha, commit = verify_review(root, contract_path, contract, artifacts)
    job, split = validate_static_gate(root, contract)

    data_path = resolve(root, "src/data")
    if data_path not in sys.path:
        sys.path.insert(0, data_path)
    runner = importlib.import_module("run_blind_unseal_v6")
    attestation = {
        "status": "BOOTSTRAP_VERIFIED",
        "contract_sha256": contract_sha,
        "reviewed_commit": commit,
        "reviewed_artifacts": artifacts
    }
    return runner.execute_from_bootstrap(root, contract, job, split, attestation)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-root", required=True)
    args = parser.parse_args()
    try:
        status = bootstrap(args.bundle_root)
    except BootstrapError:
        print("BLIND_UNSEAL=REFUSED_BOOTSTRAP")
        return 2
    print("BLIND_UNSEAL=%s" % ("PASS" if status == 0 else "FAIL"))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
