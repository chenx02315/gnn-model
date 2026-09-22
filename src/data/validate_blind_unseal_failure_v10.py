#!/usr/bin/env python3
"""Fail-closed v10 evidence validator for a sealed BLIND runner failure."""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import re

from validate_blind_unseal_registration_v10 import ValidationError, sha256_bytes, validate_registration
from validate_blind_unseal_scheduler_audit_v10 import _parse_history_capture, _job_section

FIELDS = (
    "schema_version", "status", "job_id", "scheduler_terminal", "exit_code",
    "runner_receipt_status", "failure_code", "circuits", "registration_receipt_sha256",
    "protocol_sha256", "raw_bjobs_capture_sha256", "raw_global_bjobs_capture_sha256",
    "raw_bjobs_al_capture_sha256", "bhist_raw_capture_sha256", "bacct_raw_capture_sha256",
    "stdout_capture_sha256", "stderr_capture_sha256", "external_control_manifest_sha256",
    "final_job_spec_sha256", "independent_review_sha256", "evidence_file_map", "four_artifact_sha256",
)
ARTIFACT_KEYS = frozenset(("CONSUMED", "receipt.json", "receipt.json.sha256", "RELEASED"))
EVIDENCE_FILE_MAP = {
    "registration_receipt": "blind_runtime_unseal_registration_v10.json",
    "target_bjobs": "raw_target_bjobs.txt", "global_bjobs": "raw_global_bjobs.txt", "bjobs_al": "raw_bjobs_al.txt",
    "bhist": "bhist_audit_capture.txt", "bacct": "bacct_audit_capture.txt", "stdout": "stdout.log", "stderr": "stderr.log",
    "external_control_manifest": "blind_runtime_unseal_v10_control_manifest.json",
    "final_job_spec": "blind_runtime_unseal_job_v10.json", "independent_review": "blind_unseal_independent_review_v10.json",
    "four_artifacts": {name: name for name in sorted(ARTIFACT_KEYS)},
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LEAK_RE = re.compile(r"(?:candidate|run[ _-]?id|result[ _-]?path|wall[ _-]?time)", re.I)
FORBIDDEN_RE = re.compile(r"\b(?:rerun|requeue|retry)\b", re.I)
CONT_RE = re.compile(r"Signal\s+<CONT>\s+requested", re.I)
RESUME_RE = re.compile(r"Waiting for scheduling after resumed", re.I)
START_RE = re.compile(r"(?m)^[A-Z][a-z]{2}\s+.+:\s+Starting\s+\(Pid\s+[0-9]+\);")
EVENT_RE = re.compile(r"(?m)^[^\n]*?(Signal\s+<CONT>\s+requested|Waiting for scheduling after resumed|Starting\s+\(Pid\s+[0-9]+\);|Done successfully\.|Exited with exit code\s+[0-9]+\.)")


def _require(condition, code):
    if not condition:
        raise ValidationError(code)


def _read(path):
    with open(path, "rb") as stream:
        return stream.read()


def _sha_file(path):
    return sha256_bytes(_read(path))


def _tool_set_sha256(artifacts):
    return sha256_bytes("".join(item + "\n" for item in sorted(path + ":" + digest for path, digest in artifacts.items())).encode("utf-8"))


def _verify_no_leak(raw, label):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValidationError(label + "_NOT_UTF8")
    _require(LEAK_RE.search(text) is None, label + "_CANDIDATE_LEAK")
    _require("RELEASED_VERIFIED" not in text, label + "_RELEASE_CLAIM")


def _verify_exit_history(bhist_raw, bacct_raw, expected_job_id):
    bhist = _parse_history_capture(bhist_raw, "BHIST")
    bacct = _parse_history_capture(bacct_raw, "BACCT")
    for key in ("registered_at_utc", "resumed_at_utc", "captured_at_utc"):
        _require(bhist[key] == bacct[key], "HISTORY_METADATA_DISAGREEMENT")
    _require(bhist["registered_at_utc"] <= bhist["resumed_at_utc"] <= bhist["captured_at_utc"], "HISTORY_TIME_ORDER")
    _require((bhist["captured_at_utc"] - bhist["resumed_at_utc"]).total_seconds() <= 5 * 3600, "HISTORY_CAPTURE_LATE")
    bhist_section = _job_section(bhist["body"], expected_job_id, "BHIST")
    bacct_section = _job_section(bacct["body"], expected_job_id, "BACCT")
    combined = bhist_section + "\n" + bacct_section
    _require(FORBIDDEN_RE.search(combined) is None, "HISTORY_FORBIDDEN_EVENT")
    events = []
    for match in EVENT_RE.finditer(bhist_section):
        text = match.group(1)
        if CONT_RE.search(text): events.append("CONT")
        elif RESUME_RE.search(text): events.append("RESUME")
        elif text.startswith("Starting "): events.append("START")
        elif text == "Done successfully.": events.append("DONE")
        else: events.append("EXIT" + re.search(r"[0-9]+", text).group(0))
    _require(events == ["CONT", "RESUME", "START", "EXIT1"], "HISTORY_EVENT_ORDER_OR_TERMINAL")
    statuses = re.findall(r"Status\s+<([^>]+)>", bacct_section, re.I)
    completed = re.findall(r"Completed\s+<([^>]+)>", bacct_section, re.I)
    _require(statuses == ["EXIT"] and completed == ["exit"], "BACCT_SOLE_EXIT_PAIR")


def _verify_failure_artifacts(directory, contract, contract_sha):
    paths = {name: os.path.join(directory, name) for name in ARTIFACT_KEYS}
    _require(all(os.path.isfile(path) and not os.path.islink(path) for path in paths.values()), "FOUR_ARTIFACT_FILES")
    try:
        consumed = json.loads(_read(paths["CONSUMED"]).decode("utf-8"))
        receipt = json.loads(_read(paths["receipt.json"]).decode("utf-8"))
        released = json.loads(_read(paths["RELEASED"]).decode("utf-8"))
        receipt_sha = _sha_file(paths["receipt.json"])
        sidecar = _read(paths["receipt.json.sha256"]).decode("ascii").strip().split()
    except (UnicodeDecodeError, ValueError):
        raise ValidationError("FOUR_ARTIFACT_PARSE")
    artifacts = contract.get("implementation", {}).get("artifact_sha256", {})
    tool_sha = _tool_set_sha256(artifacts)
    _require(sidecar == [receipt_sha, "receipt.json"], "FOUR_ARTIFACT_SIDECAR")
    _require(consumed == {"schema_version": "blind-runtime-unseal-consumed-v10", "status": "CONSUMED", "contract_sha256": contract_sha, "tool_set_sha256": tool_sha}, "CONSUMED_SCHEMA")
    _require(released == {"schema_version": "blind-runtime-unseal-release-v10", "status": "RELEASED_RUNNER_VERIFIED_SCHEDULER_AUDIT_PENDING", "contract_sha256": contract_sha, "receipt_sha256": receipt_sha}, "RELEASED_SCHEMA")
    envelope = {"schema_version", "status", "formal_runtime_membership_sha256", "method_registry_sha256", "tool_set_sha256", "contract_sha256", "circuits", "failure_code"}
    _require(set(receipt) == envelope, "RUNNER_RECEIPT_FIELDS")
    _require(receipt == {"schema_version": "blind-runtime-unseal-receipt-v10", "status": "FAIL", "formal_runtime_membership_sha256": contract.get("scope", {}).get("formal_runtime_membership_sha256"), "method_registry_sha256": contract.get("scope", {}).get("method_registry_sha256"), "tool_set_sha256": tool_sha, "contract_sha256": contract_sha, "circuits": [], "failure_code": "SEALED_AUDIT_FAILED"}, "RUNNER_FAIL_ENVELOPE")
    return {name: _sha_file(path) for name, path in paths.items()}


def _verify_job_and_review(final_job_spec_path, independent_review_path, artifact_directory, expected_job_id, registration, raw_registration, template_raw, contract):
    job_raw, review_raw = _read(final_job_spec_path), _read(independent_review_path)
    try:
        job, review, template = json.loads(job_raw.decode("utf-8")), json.loads(review_raw.decode("utf-8")), json.loads(template_raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValidationError("JOB_OR_REVIEW_PARSE")
    job_fields = {"schema_version", "status", "contract_sha256", "job_template_sha256", "registration_receipt", "registration_receipt_sha256", "registration", "measurement_files", "circuits", "output_root"}
    registration_fields = {"job_id", "git_commit", "initial_scheduler_state", "array_allowed", "retry_allowed", "requeue_allowed", "rerun_allowed", "command_argv", "queue", "resource_request", "cwd", "stdout_path", "stderr_path"}
    _require(set(job) == job_fields and job.get("schema_version") == "blind-runtime-unseal-job-v10" and job.get("status") == "REGISTERED_HELD", "JOB_SCHEMA")
    nested = job.get("registration")
    _require(isinstance(nested, dict) and set(nested) == registration_fields, "JOB_REGISTRATION_SCHEMA")
    _require(os.path.realpath(job.get("output_root", "")) == os.path.realpath(artifact_directory), "JOB_OUTPUT_ROOT_BINDING")
    _require(job.get("registration_receipt") == "contracts/blind_runtime_unseal_registration_v10.json" and job.get("registration_receipt_sha256") == sha256_bytes(raw_registration) and job.get("contract_sha256") == registration.get("contract_sha256") and job.get("job_template_sha256") == registration.get("job_template_sha256") and job.get("job_template_sha256") == sha256_bytes(template_raw), "JOB_BINDING")
    _require(nested == {"job_id": expected_job_id, "git_commit": registration["reviewed_commit"], "initial_scheduler_state": "PSUSP", "array_allowed": False, "retry_allowed": False, "requeue_allowed": False, "rerun_allowed": False, "command_argv": registration["normalized_argv"], "queue": registration["queue"], "resource_request": registration["resource_request"], "cwd": registration["cwd"], "stdout_path": registration["stdout_path"], "stderr_path": registration["stderr_path"]}, "JOB_REGISTRATION_BINDING")
    _require(nested == template.get("registration") and job.get("measurement_files") == template.get("measurement_files") and job.get("circuits") == template.get("circuits"), "JOB_TEMPLATE_PAYLOAD_BINDING")
    review_fields = {"schema_version", "status", "execution_allowed", "blind_data_read", "real_unseal_executed", "contract_sha256", "registration_receipt_sha256", "job_spec_sha256", "output_root", "job_id", "reviewed_commit", "protocol_sha256", "gate_snapshot_sha256", "scheduler_fixture_manifest_sha256", "normalized_argv", "raw_bjobs_capture_sha256", "raw_global_bjobs_capture_sha256", "raw_bjobs_al_capture_sha256", "external_control_manifest_path", "external_control_manifest_sha256", "specified_cwd", "queue", "resource_request", "cwd", "stdout_path", "stderr_path", "reviewed_artifacts", "registration_validator_pass", "psusp_verified", "nonarray_verified", "no_retry", "no_requeue", "no_rerun", "no_blind_parse", "no_blind_output"}
    _require(set(review) == review_fields and review.get("schema_version") == "blind-unseal-independent-review-v10" and review.get("status") == "PASS", "REVIEW_SCHEMA")
    _require(review.get("execution_allowed") is True and review.get("blind_data_read") is False and review.get("real_unseal_executed") is False and all(review.get(key) is True for key in ("registration_validator_pass", "psusp_verified", "nonarray_verified", "no_retry", "no_requeue", "no_rerun", "no_blind_parse", "no_blind_output")), "REVIEW_GATES")
    bindings = {"contract_sha256": registration["contract_sha256"], "registration_receipt_sha256": sha256_bytes(raw_registration), "job_spec_sha256": sha256_bytes(job_raw), "output_root": job["output_root"], "job_id": expected_job_id, "reviewed_commit": registration["reviewed_commit"], "protocol_sha256": registration["protocol_sha256"], "gate_snapshot_sha256": registration["gate_snapshot_sha256"], "normalized_argv": registration["normalized_argv"], "raw_bjobs_capture_sha256": registration["raw_bjobs_capture_sha256"], "raw_global_bjobs_capture_sha256": registration["raw_global_bjobs_capture_sha256"], "raw_bjobs_al_capture_sha256": registration["raw_bjobs_al_capture_sha256"], "external_control_manifest_path": registration["external_control_manifest_path"], "external_control_manifest_sha256": registration["external_control_manifest_sha256"], "specified_cwd": registration["specified_cwd"], "queue": registration["queue"], "resource_request": registration["resource_request"], "cwd": registration["cwd"], "stdout_path": registration["stdout_path"], "stderr_path": registration["stderr_path"]}
    _require(all(review.get(key) == value for key, value in bindings.items()), "REVIEW_BINDING")
    reviewed = review.get("reviewed_artifacts")
    _require(isinstance(reviewed, dict) and bool(reviewed) and all(isinstance(path, str) and isinstance(digest, str) and SHA256_RE.match(digest) for path, digest in reviewed.items()), "REVIEWED_ARTIFACTS")
    _require(review.get("protocol_sha256") == contract.get("protocol", {}).get("sha256") and review.get("gate_snapshot_sha256") == contract.get("gate_snapshot", {}).get("sha256") and review.get("scheduler_fixture_manifest_sha256") == contract.get("scheduler_fixture", {}).get("sha256") and reviewed == contract.get("implementation", {}).get("artifact_sha256"), "REVIEW_CONTRACT_BINDING")
    return job_raw, review_raw


def validate_failure_audit(manifest, registration, raw_registration, raw_bjobs, raw_global_bjobs, raw_bjobs_al, raw_bhist, raw_bacct, stdout_raw, stderr_raw, artifact_directory, expected_job_id, job_template_path, implementation_contract_path, runner_path, external_control_manifest, final_job_spec_path, independent_review_path):
    """Validate the one permitted terminal failure outcome; returns True or raises."""
    validate_registration(registration, raw_bjobs, expected_job_id, job_template_path, implementation_contract_path,
                          runner_path, raw_global_bjobs, raw_bjobs_al, external_control_manifest)
    _require(isinstance(manifest, dict) and set(manifest) == set(FIELDS), "FAILURE_AUDIT_FIELD_DRIFT")
    _require(manifest["schema_version"] == "blind-runtime-unseal-failure-audit-v10", "FAILURE_AUDIT_SCHEMA_VERSION")
    _require(manifest["status"] == "FAILED_SCHEDULER_AUDIT", "FAILURE_AUDIT_STATUS")
    _require(manifest["job_id"] == expected_job_id, "FAILURE_AUDIT_JOB_ID")
    _require(manifest["scheduler_terminal"] == "EXIT" and manifest["exit_code"] == 1, "FAILURE_AUDIT_TERMINAL")
    _require(manifest["runner_receipt_status"] == "FAIL" and manifest["failure_code"] == "SEALED_AUDIT_FAILED" and manifest["circuits"] == [], "FAILURE_AUDIT_RUNNER_OUTCOME")
    _require(manifest["evidence_file_map"] == EVIDENCE_FILE_MAP, "EVIDENCE_FILE_MAP")
    bindings = (("registration_receipt_sha256", raw_registration), ("raw_bjobs_capture_sha256", raw_bjobs),
                ("raw_global_bjobs_capture_sha256", raw_global_bjobs), ("raw_bjobs_al_capture_sha256", raw_bjobs_al),
                ("bhist_raw_capture_sha256", raw_bhist), ("bacct_raw_capture_sha256", raw_bacct),
                ("stdout_capture_sha256", stdout_raw), ("stderr_capture_sha256", stderr_raw),
                ("external_control_manifest_sha256", external_control_manifest))
    for key, raw in bindings:
        _require(manifest[key] == sha256_bytes(raw), "FAILURE_AUDIT_DIGEST_" + key)
    _require(manifest["protocol_sha256"] == registration["protocol_sha256"], "FAILURE_AUDIT_PROTOCOL")
    try:
        template_raw = _read(job_template_path)
        with open(implementation_contract_path, "r", encoding="utf-8") as stream:
            contract = json.load(stream)
    except (OSError, ValueError):
        raise ValidationError("TEMPLATE_OR_CONTRACT_PARSE")
    job_raw, review_raw = _verify_job_and_review(final_job_spec_path, independent_review_path, artifact_directory, expected_job_id, registration, raw_registration, template_raw, contract)
    _require(manifest["final_job_spec_sha256"] == sha256_bytes(job_raw) and manifest["independent_review_sha256"] == sha256_bytes(review_raw), "JOB_OR_REVIEW_DIGEST")
    _verify_exit_history(raw_bhist, raw_bacct, expected_job_id)
    _verify_no_leak(stdout_raw, "STDOUT")
    _verify_no_leak(stderr_raw, "STDERR")
    artifacts = _verify_failure_artifacts(artifact_directory, contract, registration["contract_sha256"])
    _require(manifest["four_artifact_sha256"] == artifacts, "FOUR_ARTIFACT_DIGESTS")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("failure_manifest"); parser.add_argument("registration_receipt")
    parser.add_argument("raw_bjobs_capture"); parser.add_argument("raw_global_bjobs_capture"); parser.add_argument("raw_bjobs_al_capture")
    parser.add_argument("raw_bhist_capture"); parser.add_argument("raw_bacct_capture"); parser.add_argument("stdout_capture"); parser.add_argument("stderr_capture")
    parser.add_argument("artifact_directory"); parser.add_argument("expected_job_id"); parser.add_argument("job_template"); parser.add_argument("implementation_contract"); parser.add_argument("runner"); parser.add_argument("external_control_manifest"); parser.add_argument("final_job_spec"); parser.add_argument("independent_review")
    args = parser.parse_args(argv)
    try:
        raw_registration = _read(args.registration_receipt)
        validate_failure_audit(json.loads(_read(args.failure_manifest).decode("utf-8")), json.loads(raw_registration.decode("utf-8")), raw_registration,
                               _read(args.raw_bjobs_capture), _read(args.raw_global_bjobs_capture), _read(args.raw_bjobs_al_capture), _read(args.raw_bhist_capture), _read(args.raw_bacct_capture), _read(args.stdout_capture), _read(args.stderr_capture), args.artifact_directory, args.expected_job_id, args.job_template, args.implementation_contract, args.runner, _read(args.external_control_manifest), args.final_job_spec, args.independent_review)
    except (OSError, ValueError, ValidationError) as error:
        print("BLIND_UNSEAL_FAILURE_AUDIT_v10=FAIL:%s" % error); return 1
    print("BLIND_UNSEAL_FAILURE_AUDIT_v10=PASS"); return 0


if __name__ == "__main__":
    raise SystemExit(main())
