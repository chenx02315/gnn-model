#!/usr/bin/env python3
"""Fail-closed v10 post-run scheduler audit from A-side raw evidence files."""
from __future__ import print_function

import argparse
import datetime
import hashlib
import json
import os
import re

from validate_blind_unseal_registration_v10 import ValidationError, sha256_bytes, validate_registration

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
FIELDS = (
    "schema_version", "status", "job_id", "registration_receipt_sha256", "protocol_sha256", "raw_bjobs_capture_sha256",
    "raw_global_bjobs_capture_sha256", "bhist_raw_capture_sha256", "bacct_raw_capture_sha256", "stdout_capture_sha256",
    "stderr_capture_sha256", "four_artifact_sha256"
)
ARTIFACT_KEYS = {"CONSUMED", "receipt.json", "receipt.json.sha256", "RELEASED"}
LEAK_RE = re.compile(r"(?:candidate|run[ _-]?id|result[ _-]?path|wall[ _-]?time)", re.I)
FORBIDDEN_EVENT_RE = re.compile(r"\b(?:rerun|requeue|retry)\b", re.I)
CONT_RE = re.compile(r"Signal\s+<CONT>\s+requested", re.I)
RESUME_RE = re.compile(r"Waiting for scheduling after resumed", re.I)
START_RE = re.compile(r"(?m)^[A-Z][a-z]{2}\s+.+:\s+Starting\s+\(Pid\s+[0-9]+\);")
TERMINAL_RE = re.compile(r"(?m)^[A-Z][a-z]{2}\s+.+:\s+(?:Done successfully\.|Exited with exit code\s+[0-9]+\.)")
BACCT_STATUS_RE = re.compile(r"Status\s+<(DONE|EXIT)>")
BACCT_TERMINAL_RE = re.compile(r"Completed\s+<(done|exit)>", re.I)
JOB_HEADER_RE = re.compile(r"(?m)^\s*Job\s*<([0-9]+)>")


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


def _parse_history_capture(raw, label):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValidationError(label + "_NOT_UTF8")
    lines = text.splitlines()
    _require(len(lines) >= 4, label + "_TOO_SHORT")
    expected = ("registered_at_utc", "resumed_at_utc", "captured_at_utc")
    values = {}
    for index, key in enumerate(expected):
        prefix = "# " + key + "="
        _require(lines[index].startswith(prefix), label + "_METADATA")
        value = lines[index][len(prefix):]
        try:
            values[key] = datetime.datetime.strptime(value, UTC_FORMAT)
        except ValueError:
            raise ValidationError(label + "_UTC")
    _require(bool("\n".join(lines[3:]).strip()), label + "_EMPTY_OUTPUT")
    values["body"] = "\n".join(lines[3:])
    return values


def _contains_exact_job(text, job_id):
    return re.search(r"(?<![0-9])" + re.escape(job_id) + r"(?![0-9])", text) is not None


def _job_section(text, job_id, label):
    headers = list(JOB_HEADER_RE.finditer(text))
    _require(bool(headers), label + "_JOB_HEADERS")
    matches = []
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        if header.group(1) == job_id:
            matches.append(text[header.start():end])
    _require(len(matches) == 1, label + "_TARGET_SECTION")
    return matches[0]


def _derive_history(bhist_raw, bacct_raw, expected_job_id):
    bhist = _parse_history_capture(bhist_raw, "BHIST")
    bacct = _parse_history_capture(bacct_raw, "BACCT")
    for key in ("registered_at_utc", "resumed_at_utc", "captured_at_utc"):
        _require(bhist[key] == bacct[key], "HISTORY_METADATA_DISAGREEMENT")
    _require(bhist["registered_at_utc"] <= bhist["resumed_at_utc"] <= bhist["captured_at_utc"], "HISTORY_TIME_ORDER")
    _require((bhist["captured_at_utc"] - bhist["resumed_at_utc"]).total_seconds() <= 5 * 3600, "HISTORY_CAPTURE_LATE")
    bhist_section = _job_section(bhist["body"], expected_job_id, "BHIST")
    bacct_section = _job_section(bacct["body"], expected_job_id, "BACCT")
    _require(FORBIDDEN_EVENT_RE.search(bhist_section + "\n" + bacct_section) is None, "HISTORY_FORBIDDEN_EVENT")
    _require(len(CONT_RE.findall(bhist_section)) == 1 and len(RESUME_RE.findall(bhist_section)) == 1, "HISTORY_RESUME_COUNT")
    _require(len(START_RE.findall(bhist_section)) == 1, "HISTORY_START_COUNT")
    bhist_terminals=list(TERMINAL_RE.finditer(bhist_section))
    _require(len(bhist_terminals) == 1, "HISTORY_TERMINAL_COUNT")
    bhist_status="done" if "Done successfully." in bhist_terminals[0].group(0) else "exit"
    statuses=BACCT_STATUS_RE.findall(bacct_section); terminals=BACCT_TERMINAL_RE.findall(bacct_section)
    _require(len(statuses) == 1 and len(terminals) == 1 and statuses[0].lower() == terminals[0].lower(), "BACCT_TERMINAL_STATUS")
    _require(bhist_status == statuses[0].lower(), "CROSS_SOURCE_TERMINAL_STATUS")


def _verify_no_leak(raw, label):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValidationError(label + "_NOT_UTF8")
    _require(LEAK_RE.search(text) is None, label + "_CANDIDATE_LEAK")


def _verify_four_artifacts(directory, contract, contract_sha):
    paths = {name: os.path.join(directory, name) for name in ARTIFACT_KEYS}
    _require(all(os.path.isfile(path) and not os.path.islink(path) for path in paths.values()), "FOUR_ARTIFACT_FILES")
    receipt_sha = _sha_file(paths["receipt.json"])
    try:
        consumed = json.loads(_read(paths["CONSUMED"]).decode("utf-8"))
        released = json.loads(_read(paths["RELEASED"]).decode("utf-8"))
        receipt = json.loads(_read(paths["receipt.json"]).decode("utf-8"))
        sidecar = _read(paths["receipt.json.sha256"]).decode("ascii").strip().split()
    except (UnicodeDecodeError, ValueError):
        raise ValidationError("FOUR_ARTIFACT_PARSE")
    _require(sidecar == [receipt_sha, "receipt.json"], "FOUR_ARTIFACT_SIDECAR")
    artifacts = contract.get("implementation", {}).get("artifact_sha256", {})
    tool_sha = _tool_set_sha256(artifacts)
    _require(consumed == {"schema_version": "blind-runtime-unseal-consumed-v10", "status": "CONSUMED", "contract_sha256": contract_sha, "tool_set_sha256": tool_sha}, "CONSUMED_SCHEMA")
    _require(released == {"schema_version": "blind-runtime-unseal-release-v10", "status": "RELEASED_RUNNER_VERIFIED_SCHEDULER_AUDIT_PENDING", "contract_sha256": contract_sha, "receipt_sha256": receipt_sha}, "RELEASED_SCHEMA")
    envelope = {"schema_version", "status", "formal_runtime_membership_sha256", "method_registry_sha256", "tool_set_sha256", "contract_sha256", "circuits", "failure_code"}
    _require(set(receipt) == envelope and receipt.get("schema_version") == "blind-runtime-unseal-receipt-v10" and receipt.get("status") in ("PASS", "FAIL") and receipt.get("formal_runtime_membership_sha256") == contract.get("scope", {}).get("formal_runtime_membership_sha256") and receipt.get("method_registry_sha256") == contract.get("scope", {}).get("method_registry_sha256") and receipt.get("contract_sha256") == contract_sha and receipt.get("tool_set_sha256") == tool_sha, "RUNNER_RECEIPT_SCHEMA")
    if receipt["status"] == "PASS":
        rows = receipt.get("circuits")
        required = {"circuit", "executed_stage_reference_count", "unique_runtime_join_count", "missing_runtime_join_count", "ambiguous_runtime_join_count", "coverage_rate", "distinct_runtime_attempt_count", "cross_stage_reference_count", "frozen_runtime_eligible_action_space_sha256", "source_artifact_set_sha256", "action_coverage_summary"}
        _require(isinstance(rows, list) and [row.get("circuit") for row in rows] == contract.get("scope", {}).get("blind_circuits"), "RUNNER_CIRCUIT_ORDER")
        for row in rows:
            summary = row.get("action_coverage_summary", {})
            _require(set(row) == required and row["unique_runtime_join_count"] + row["missing_runtime_join_count"] + row["ambiguous_runtime_join_count"] == row["executed_stage_reference_count"] and row["missing_runtime_join_count"] == 0 and row["ambiguous_runtime_join_count"] == 0 and row["coverage_rate"] == 1.0 and summary.get("eligible_action_count", 0) > 0 and summary.get("all_unique_action_count") == summary.get("eligible_action_count") and SHA256_RE.match(row.get("frozen_runtime_eligible_action_space_sha256", "")) and SHA256_RE.match(row.get("source_artifact_set_sha256", "")), "RUNNER_R06_R07")
        _require(receipt.get("failure_code") is None, "RUNNER_PASS_FAILURE_CODE")
    else:
        _require(receipt.get("circuits") == [] and receipt.get("failure_code") in {"SEALED_AUDIT_FAILED", "INPUT_INVENTORY_DRIFT", "ATTEMPT_INTEGRITY_FAILURE", "R06_R07_FAILED"}, "RUNNER_FAIL_ENVELOPE")
    return {name: _sha_file(path) for name, path in paths.items()}


def validate_scheduler_audit(receipt, registration, raw_registration, raw_bjobs, raw_bhist, raw_bacct, stdout_raw, stderr_raw, artifact_directory, expected_job_id, job_template_path, implementation_contract_path, runner_path, raw_global_bjobs, raw_bjobs_al, external_control_manifest):
    raw_registration_sha = sha256_bytes(raw_registration)
    validate_registration(registration, raw_bjobs, expected_job_id, job_template_path,
                          implementation_contract_path, runner_path, raw_global_bjobs,
                          raw_bjobs_al, external_control_manifest)
    _require(isinstance(receipt, dict), "AUDIT_NOT_OBJECT")
    _require(set(receipt) == set(FIELDS), "AUDIT_FIELD_DRIFT")
    _require(receipt["schema_version"] == "blind-runtime-unseal-scheduler-audit-v10", "AUDIT_SCHEMA_VERSION")
    _require(receipt["status"] == "RELEASED_VERIFIED", "AUDIT_STATUS")
    _require(receipt["job_id"] == expected_job_id, "AUDIT_JOB_ID")
    _require(receipt["registration_receipt_sha256"] == raw_registration_sha, "AUDIT_REGISTRATION_RECEIPT")
    _require(receipt["protocol_sha256"] == registration["protocol_sha256"], "AUDIT_PROTOCOL")
    for key, raw in (("raw_bjobs_capture_sha256", raw_bjobs), ("bhist_raw_capture_sha256", raw_bhist), ("bacct_raw_capture_sha256", raw_bacct), ("stdout_capture_sha256", stdout_raw), ("stderr_capture_sha256", stderr_raw)):
        _require(receipt[key] == sha256_bytes(raw), "AUDIT_DIGEST_" + key)
    _require(receipt["raw_global_bjobs_capture_sha256"] == sha256_bytes(raw_global_bjobs), "AUDIT_DIGEST_RAW_GLOBAL_BJOBS")
    _derive_history(raw_bhist, raw_bacct, expected_job_id)
    _verify_no_leak(stdout_raw, "STDOUT")
    _verify_no_leak(stderr_raw, "STDERR")
    with open(implementation_contract_path, "r", encoding="utf-8") as stream:
        contract = json.load(stream)
    artifacts = _verify_four_artifacts(artifact_directory, contract, registration["contract_sha256"])
    _require(receipt["four_artifact_sha256"] == artifacts, "FOUR_ARTIFACT_DIGESTS")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("audit_receipt")
    parser.add_argument("registration_receipt")
    parser.add_argument("raw_bjobs_capture")
    parser.add_argument("raw_bhist_capture")
    parser.add_argument("raw_bacct_capture")
    parser.add_argument("stdout_capture")
    parser.add_argument("stderr_capture")
    parser.add_argument("artifact_directory")
    parser.add_argument("expected_job_id")
    parser.add_argument("job_template")
    parser.add_argument("implementation_contract")
    parser.add_argument("runner")
    parser.add_argument("raw_global_bjobs_capture")
    parser.add_argument("raw_bjobs_al_capture")
    parser.add_argument("external_control_manifest")
    args = parser.parse_args(argv)
    try:
        raw_registration = _read(args.registration_receipt)
        registration = json.loads(raw_registration.decode("utf-8"))
        audit = json.loads(_read(args.audit_receipt).decode("utf-8"))
        global_raw = _read(args.raw_global_bjobs_capture)
        validate_scheduler_audit(audit, registration, raw_registration, _read(args.raw_bjobs_capture), _read(args.raw_bhist_capture), _read(args.raw_bacct_capture), _read(args.stdout_capture), _read(args.stderr_capture), args.artifact_directory, args.expected_job_id, args.job_template, args.implementation_contract, args.runner, global_raw, _read(args.raw_bjobs_al_capture), _read(args.external_control_manifest))
    except (OSError, ValueError, ValidationError) as error:
        print("BLIND_UNSEAL_SCHEDULER_AUDIT_v10=FAIL:%s" % error)
        return 1
    print("BLIND_UNSEAL_SCHEDULER_AUDIT_v10=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
