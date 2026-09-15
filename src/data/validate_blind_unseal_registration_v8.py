#!/usr/bin/env python3
"""Fail-closed v8 registration validator using the raw A-side bjobs capture."""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re
import subprocess

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
JOB_RE = re.compile(r"^[1-9][0-9]*$")
FIELDS = (
    "schema_version", "status", "job_id", "owner", "submission_host", "submit_time_raw", "reviewed_commit",
    "contract_sha256", "protocol_sha256", "gate_snapshot_sha256", "runner_sha256", "job_template_sha256", "normalized_argv",
    "normalized_argv_sha256", "queue", "resource_request", "cwd", "stdout_path", "stderr_path",
    "raw_bjobs_capture_sha256", "raw_global_bjobs_capture_sha256"
)


class ValidationError(ValueError):
    pass


def _require(condition, code):
    if not condition:
        raise ValidationError(code)


def sha256_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def _argv_sha256(argv):
    return sha256_bytes(json.dumps(argv, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))


def parse_bjobs_rows(raw):
    """Parse LSF 9.1 delimiter rows; no trailing delimiter field is emitted."""
    _require(isinstance(raw, bytes), "BJOBS_NOT_BYTES")
    try:
        lines = [line for line in raw.decode("utf-8").splitlines() if line]
    except UnicodeDecodeError:
        raise ValidationError("BJOBS_NOT_UTF8")
    _require(bool(lines), "BJOBS_ROW_COUNT")
    parsed=[]
    for line in lines:
        columns = line.split("^")
        _require(len(columns) == 11, "BJOBS_COLUMN_COUNT")
        _require(all("^" not in value and value.strip() == value for value in columns), "BJOBS_FIELD_NORMALIZATION")
        parsed.append(columns)
    result=[]
    for job_id, state, owner, queue, command, from_host, submitted, resources, stdout_path, stderr_path, cwd in parsed:
        _require(JOB_RE.match(job_id) is not None and "[" not in job_id and "]" not in job_id, "BJOBS_JOB_ID_OR_ARRAY")
        _require(bool(submitted), "BJOBS_SUBMISSION_TIME")
        result.append({"job_id": job_id, "state": state, "owner": owner, "queue": queue, "command": command, "submission_host": from_host,
                       "submit_time_raw": submitted, "resource_request": resources, "stdout_path": stdout_path,
                       "stderr_path": stderr_path, "cwd": cwd})
    return result


def parse_bjobs_capture(raw, expected_job_id, require_single=True):
    rows=parse_bjobs_rows(raw)
    _require(len(rows) == 1 or not require_single, "BJOBS_ROW_COUNT")
    matches=[row for row in rows if row["job_id"] == expected_job_id]
    _require(len(matches) == 1, "BJOBS_TARGET_ROW_COUNT")
    raw=matches[0]
    _require(raw["state"] == "PSUSP", "BJOBS_NOT_PSUSP")
    return raw


def _load_json_bytes(path, code):
    try:
        with open(path, "rb") as stream:
            raw = stream.read()
        return json.loads(raw.decode("utf-8")), raw
    except (OSError, UnicodeDecodeError, ValueError):
        raise ValidationError(code)


def _validate_job_template(job_template, receipt):
    _require(isinstance(job_template, dict) and isinstance(job_template.get("registration"), dict), "JOB_TEMPLATE")
    _require(set(job_template) == {"schema_version", "status", "registration", "measurement_files", "circuits", "template_rule", "lifecycle"}, "JOB_TEMPLATE_FIELD_DRIFT")
    _require(job_template.get("status") == "FINAL_HELD_JOB_TEMPLATE", "JOB_TEMPLATE_STATUS")
    registration = job_template["registration"]
    required = ("job_id", "git_commit", "initial_scheduler_state", "array_allowed", "retry_allowed", "requeue_allowed", "rerun_allowed", "command_argv", "queue", "resource_request", "cwd", "stdout_path", "stderr_path")
    _require(set(registration) == set(required), "JOB_TEMPLATE_FIELDS")
    _require(registration["job_id"] == receipt["job_id"], "JOB_TEMPLATE_JOB_ID")
    _require(registration["git_commit"] == receipt["reviewed_commit"], "JOB_TEMPLATE_GIT_COMMIT")
    _require(registration["command_argv"] == receipt["normalized_argv"], "JOB_TEMPLATE_ARGV")
    for key in ("queue", "resource_request", "cwd", "stdout_path", "stderr_path"):
        _require(registration[key] == receipt[key], "JOB_TEMPLATE_" + key)
    _require(registration["initial_scheduler_state"] == "PSUSP", "JOB_TEMPLATE_NOT_PSUSP")
    _require(all(registration[key] is False for key in ("array_allowed", "retry_allowed", "requeue_allowed", "rerun_allowed")), "JOB_TEMPLATE_FORBIDDEN_OPTION")
    lifecycle = job_template.get("lifecycle", {})
    _require(set(lifecycle) == {"implementation_freeze_commit", "held_job_id", "finalization_event"}, "JOB_TEMPLATE_LIFECYCLE_FIELD_DRIFT")
    _require(lifecycle.get("implementation_freeze_commit") == receipt["reviewed_commit"], "JOB_TEMPLATE_FREEZE_COMMIT")
    _require(lifecycle.get("held_job_id") == receipt["job_id"], "JOB_TEMPLATE_HELD_JOB")
    _require(registration.get("job_id") == receipt["job_id"], "JOB_TEMPLATE_JOB_ID")


def _repo_root_for_runner(runner_path):
    """Runner must be the canonical file under the checked repository root."""
    try:
        root = subprocess.check_output(
            ["git", "-C", os.path.dirname(os.path.abspath(runner_path)), "rev-parse", "--show-toplevel"],
            stderr=subprocess.STDOUT).decode("utf-8").strip()
    except (OSError, UnicodeDecodeError, subprocess.CalledProcessError):
        raise ValidationError("RUNNER_GIT_ROOT")
    _require(bool(root) and os.path.isdir(root), "RUNNER_GIT_ROOT")
    expected = os.path.join(root, "src", "data", "run_blind_unseal_v8.py")
    _require(os.path.realpath(os.path.abspath(runner_path)) == os.path.realpath(expected), "RUNNER_CANONICAL_PATH")
    return root


def _git_blob_equals_worktree(repo_root, reviewed_commit, relpath, expected_digest):
    _require(".." not in relpath.replace("\\", "/").split("/"), "ARTIFACT_RELATIVE_PATH")
    path = repo_root + "/" + relpath.replace("\\", "/")
    try:
        with open(path, "rb") as stream:
            worktree = stream.read()
        blob = subprocess.check_output(["git", "-C", repo_root, "show", reviewed_commit + ":" + relpath.replace("\\", "/")], stderr=subprocess.STDOUT)
    except (OSError, subprocess.CalledProcessError):
        raise ValidationError("IMPLEMENTATION_BLOB_READ")
    _require(sha256_bytes(worktree) == expected_digest, "IMPLEMENTATION_WORKTREE_DIGEST")
    _require(sha256_bytes(blob) == expected_digest, "IMPLEMENTATION_BLOB_DIGEST")


def validate_registration(receipt, raw_bjobs, expected_job_id, job_template_path, implementation_contract_path, runner_path, raw_global_bjobs, verify_git_blob=True):
    _require(isinstance(receipt, dict), "RECEIPT_NOT_OBJECT")
    _require(set(receipt) == set(FIELDS), "FIELD_DRIFT")
    _require(receipt["schema_version"] == "blind-runtime-unseal-registration-v8", "SCHEMA_VERSION")
    _require(receipt["status"] == "REGISTERED_HELD", "STATUS_NOT_REGISTERED_HELD")
    _require(JOB_RE.match(expected_job_id or "") is not None, "EXPECTED_JOB_ID")
    _require(receipt["job_id"] == expected_job_id, "RECEIPT_JOB_ID")
    _require(receipt["raw_bjobs_capture_sha256"] == sha256_bytes(raw_bjobs), "BJOBS_CAPTURE_DIGEST")
    _require(isinstance(raw_global_bjobs, bytes) and receipt["raw_global_bjobs_capture_sha256"] == sha256_bytes(raw_global_bjobs), "GLOBAL_BJOBS_CAPTURE_DIGEST")
    raw = parse_bjobs_capture(raw_bjobs, expected_job_id)
    for key in ("owner", "submission_host", "submit_time_raw", "queue", "resource_request", "cwd", "stdout_path", "stderr_path"):
        _require(receipt[key] == raw[key] and isinstance(receipt[key], str) and receipt[key], "BJOBS_BINDING_" + key)
    _require(COMMIT_RE.match(receipt["reviewed_commit"] or "") is not None, "REVIEWED_COMMIT")
    for key in ("contract_sha256", "protocol_sha256", "gate_snapshot_sha256", "runner_sha256", "job_template_sha256", "normalized_argv_sha256"):
        _require(SHA256_RE.match(receipt[key] or "") is not None, "DIGEST_" + key)
    argv = receipt["normalized_argv"]
    _require(isinstance(argv, list) and argv and all(isinstance(x, str) and x and x == x.strip() and "\n" not in x and "\r" not in x and "^" not in x for x in argv), "NORMALIZED_ARGV")
    _require(receipt["normalized_argv_sha256"] == _argv_sha256(argv), "NORMALIZED_ARGV_DIGEST")
    _require(raw["command"] == " ".join(argv), "BJOBS_COMMAND")
    job_template, raw_template = _load_json_bytes(job_template_path, "JOB_TEMPLATE_READ")
    contract, raw_contract = _load_json_bytes(implementation_contract_path, "IMPLEMENTATION_CONTRACT_READ")
    _require(receipt["job_template_sha256"] == sha256_bytes(raw_template), "JOB_TEMPLATE_DIGEST")
    _require(receipt["contract_sha256"] == sha256_bytes(raw_contract), "IMPLEMENTATION_CONTRACT_DIGEST")
    _require(contract.get("schema_version") == "blind-runtime-unseal-v8", "IMPLEMENTATION_CONTRACT_SCHEMA")
    _require(contract.get("status") == "FINAL_HELD_UNSEAL_REVIEW_REQUIRED", "IMPLEMENTATION_CONTRACT_STATUS")
    _require(set(contract) == {"schema_version", "status", "purpose", "scope", "inputs", "job_template", "protocol", "gate_snapshot", "scheduler_fixture", "implementation", "review_gate", "post_run_scheduler_audit", "receipt_schema", "failure_codes", "training_allowed", "lifecycle"}, "IMPLEMENTATION_CONTRACT_FIELD_DRIFT")
    _require(set(contract.get("job_template", {})) == {"path", "sha256"}, "IMPLEMENTATION_TEMPLATE_FIELD_DRIFT")
    lifecycle = contract.get("lifecycle", {})
    _require(set(lifecycle) == {"implementation_freeze_commit", "final_template_sha256", "artifact_blob_equals_worktree_required", "finalization_rule", "required_order"}, "IMPLEMENTATION_LIFECYCLE_FIELD_DRIFT")
    _require(lifecycle.get("implementation_freeze_commit") == receipt["reviewed_commit"], "IMPLEMENTATION_FREEZE_COMMIT")
    _require(lifecycle.get("final_template_sha256") == receipt["job_template_sha256"], "IMPLEMENTATION_TEMPLATE_BINDING")
    _require(lifecycle.get("artifact_blob_equals_worktree_required") is True, "IMPLEMENTATION_BLOB_RULE")
    repo_root = _repo_root_for_runner(runner_path)
    try:
        with open(runner_path, "rb") as stream:
            runner_digest = sha256_bytes(stream.read())
    except OSError:
        raise ValidationError("RUNNER_READ")
    _require(contract.get("implementation", {}).get("artifact_sha256", {}).get("src/data/run_blind_unseal_v8.py") == receipt["runner_sha256"], "RUNNER_CONTRACT_BINDING")
    _require(runner_digest == receipt["runner_sha256"], "RUNNER_FILE_DIGEST")
    artifact_digests = contract.get("implementation", {}).get("artifact_sha256", {})
    _require(isinstance(artifact_digests, dict) and artifact_digests, "IMPLEMENTATION_ARTIFACTS")
    if verify_git_blob:
        for relpath, digest in sorted(artifact_digests.items()):
            _require(isinstance(relpath, str) and SHA256_RE.match(digest or "") is not None, "IMPLEMENTATION_ARTIFACT_FORMAT")
            _git_blob_equals_worktree(repo_root, receipt["reviewed_commit"], relpath, digest)
    rows = parse_bjobs_rows(raw_global_bjobs)
    identity_keys=("owner", "state", "queue", "command", "cwd", "stdout_path", "stderr_path")
    same=[row for row in rows if all(row[key] == raw[key] for key in identity_keys)]
    _require(len(same) == 1 and same[0]["job_id"] == expected_job_id, "GLOBAL_DUPLICATE_HELD_IDENTITY")
    _validate_job_template(job_template, receipt)
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt")
    parser.add_argument("raw_bjobs_capture")
    parser.add_argument("expected_job_id")
    parser.add_argument("job_template")
    parser.add_argument("implementation_contract")
    parser.add_argument("runner")
    parser.add_argument("raw_global_bjobs_capture")
    args = parser.parse_args(argv)
    try:
        with open(args.receipt, "r", encoding="utf-8") as stream:
            receipt = json.load(stream)
        with open(args.raw_bjobs_capture, "rb") as stream:
            raw = stream.read()
        with open(args.raw_global_bjobs_capture, "rb") as stream:
            global_raw = stream.read()
        validate_registration(receipt, raw, args.expected_job_id, args.job_template, args.implementation_contract, args.runner, global_raw)
    except (OSError, ValueError, ValidationError) as error:
        print("BLIND_UNSEAL_REGISTRATION_V8=FAIL:%s" % error)
        return 1
    print("BLIND_UNSEAL_REGISTRATION_V8=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
