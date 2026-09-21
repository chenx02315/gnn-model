#!/usr/bin/env python3
"""Fail-closed, no-I/O construction of the v9 held-job lifecycle."""
from __future__ import print_function

import copy
import hashlib
import json
import os
import re
import subprocess

from validate_blind_unseal_registration_v9 import (EXPECTED_EXTERNAL_CONTROL_MANIFEST,
    FIELDS as REGISTRATION_FIELDS)
from validate_blind_unseal_registration_v9 import ValidationError, validate_registration

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
JOB_RE = re.compile(r"^[1-9][0-9]*$")
MEASUREMENT_FILES = (
    "01_single_boundaries/measurements.tsv", "02_hf_coarse/measurements.tsv",
    "03_hmf_coarse/measurements.tsv", "04_integer_refine/hf_measurements.tsv",
    "04_integer_refine/hmf_measurements.tsv", "05_repeatability/measurements.tsv",
)
BLIND_CIRCUITS = ("s9234", "s38584", "wb_dma")
EXPECTED_BUNDLE_ROOT = "/temp/jiangchuanc/blind_runtime_unseal_v9_bundle"
EXPECTED_COMMAND_ARGV = ["python3", EXPECTED_BUNDLE_ROOT + "/src/data/run_blind_unseal_v9.py", "--bundle-root", EXPECTED_BUNDLE_ROOT]
JOB_SPEC_FIELDS = (
    "schema_version", "status", "contract_sha256", "job_template_sha256",
    "registration_receipt", "registration_receipt_sha256", "registration",
    "measurement_files", "circuits", "output_root",
)


class LifecycleError(ValueError): pass


def _require(ok, code):
    if not ok: raise LifecycleError(code)


def canonical_bytes(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_bytes(value): return hashlib.sha256(value).hexdigest()


def _exact(value, keys, code): _require(isinstance(value, dict) and set(value) == set(keys), code)
def _text(value, code): _require(isinstance(value, str) and value and value == value.strip(), code)
def _digest(value, code): _require(SHA256_RE.match(value or "") is not None, code)


def _no_null_or_pending(value, code="NULL_OR_DRAFT"):
    if value is None: raise LifecycleError(code)
    if isinstance(value, str): _require("DRAFT" not in value and "PENDING" not in value and "BOUND_BY" not in value, code)
    elif isinstance(value, list):
        for item in value: _no_null_or_pending(item, code)
    elif isinstance(value, dict):
        for item in value.values(): _no_null_or_pending(item, code)


def _absolute_text(value, code):
    _text(value, code)
    _require(os.path.isabs(value), code)


def _circuit_shape(circuits, expected_names=BLIND_CIRCUITS, code="CIRCUITS"):
    _require(isinstance(circuits, list) and len(circuits) == len(expected_names), code)
    _require([item.get("name") if isinstance(item, dict) else None for item in circuits] == list(expected_names), code)
    roots=[]
    for item in circuits:
        _exact(item, ("name", "root"), code + "_FIELDS")
        _absolute_text(item["root"], code + "_ROOT")
        roots.append(item["root"])
    _require(len(set(roots)) == len(roots), code + "_ROOT_UNIQUE")


def _draft_measurement_shape(value):
    _require(isinstance(value, list) and tuple(value) == MEASUREMENT_FILES, "MEASUREMENT_FILES")


def _template_shape(value):
    _exact(value, ("schema_version", "status", "registration", "measurement_files", "circuits", "template_rule", "lifecycle"), "TEMPLATE_FIELDS")
    _exact(value["registration"], ("job_id", "git_commit", "initial_scheduler_state", "array_allowed", "retry_allowed", "requeue_allowed", "rerun_allowed", "command_argv", "queue", "resource_request", "cwd", "stdout_path", "stderr_path"), "TEMPLATE_REGISTRATION_FIELDS")
    _exact(value["lifecycle"], ("implementation_freeze_commit", "held_job_id", "finalization_event"), "TEMPLATE_LIFECYCLE_FIELDS")
    _require(value["schema_version"] == "blind-runtime-unseal-job-v9" and value["status"] == "FINAL_HELD_JOB_TEMPLATE", "TEMPLATE_STATE")
    r = value["registration"]
    _require(r["initial_scheduler_state"] == "PSUSP" and all(r[x] is False for x in ("array_allowed", "retry_allowed", "requeue_allowed", "rerun_allowed")), "TEMPLATE_OPTIONS")
    _require(r["command_argv"] == EXPECTED_COMMAND_ARGV, "TEMPLATE_ARGV")
    for key in ("job_id", "git_commit", "queue", "resource_request", "cwd", "stdout_path", "stderr_path"): _text(r[key], "TEMPLATE_" + key.upper())
    _require(JOB_RE.match(r["job_id"]) is not None and COMMIT_RE.match(r["git_commit"]) is not None, "TEMPLATE_ID_OR_COMMIT")
    _require(value["lifecycle"]["implementation_freeze_commit"] == r["git_commit"] and value["lifecycle"]["held_job_id"] == r["job_id"], "TEMPLATE_LIFECYCLE_BINDING")
    _draft_measurement_shape(value["measurement_files"])
    _circuit_shape(value["circuits"], code="TEMPLATE_CIRCUITS")


def _contract_shape(value):
    _exact(value, ("schema_version", "status", "purpose", "scope", "inputs", "job_template", "protocol", "gate_snapshot", "scheduler_fixture", "implementation", "review_gate", "post_run_scheduler_audit", "receipt_schema", "failure_codes", "training_allowed", "lifecycle"), "CONTRACT_FIELDS")
    _require(value["schema_version"] == "blind-runtime-unseal-v9" and value["status"] == "FINAL_HELD_UNSEAL_REVIEW_REQUIRED", "CONTRACT_STATE")
    _exact(value["job_template"], ("path", "sha256"), "CONTRACT_TEMPLATE_FIELDS")
    _text(value["job_template"]["path"], "CONTRACT_TEMPLATE_PATH"); _digest(value["job_template"]["sha256"], "CONTRACT_TEMPLATE_DIGEST")
    _exact(value["lifecycle"], ("implementation_freeze_commit", "final_template_sha256", "artifact_blob_equals_worktree_required", "finalization_rule", "required_order"), "CONTRACT_LIFECYCLE_FIELDS")
    l = value["lifecycle"]
    _require(COMMIT_RE.match(l["implementation_freeze_commit"] or "") is not None and l["artifact_blob_equals_worktree_required"] is True, "CONTRACT_LIFECYCLE")
    _digest(l["final_template_sha256"], "CONTRACT_FINAL_TEMPLATE")
    _require(l["final_template_sha256"] == value["job_template"]["sha256"], "CONTRACT_TEMPLATE_LINK")
    a = value["implementation"].get("artifact_sha256")
    _require(isinstance(a, dict) and a, "CONTRACT_ARTIFACTS")
    for path, digest in a.items(): _text(path, "CONTRACT_ARTIFACT_PATH"); _digest(digest, "CONTRACT_ARTIFACT_DIGEST")
    scope = value.get("scope", {})
    _require(isinstance(scope, dict) and scope.get("blind_circuits") == list(BLIND_CIRCUITS), "CONTRACT_BLIND_CIRCUITS")


def verify_implementation_freeze(repo_root, reviewed_commit, artifact_sha256):
    _require(COMMIT_RE.match(reviewed_commit or "") is not None and isinstance(artifact_sha256, dict) and artifact_sha256, "IMPLEMENTATION_INPUT")
    for relpath, digest in sorted(artifact_sha256.items()):
        _text(relpath, "ARTIFACT_PATH"); _digest(digest, "ARTIFACT_DIGEST")
        _require(".." not in relpath.replace("\\", "/").split("/"), "ARTIFACT_PATH")
        try:
            with open(os.path.join(repo_root, *relpath.replace("\\", "/").split("/")), "rb") as stream: worktree = stream.read()
            blob = subprocess.check_output(["git", "-C", repo_root, "show", reviewed_commit + ":" + relpath.replace("\\", "/")], stderr=subprocess.STDOUT)
        except (OSError, subprocess.CalledProcessError): raise LifecycleError("IMPLEMENTATION_BLOB_READ")
        _require(sha256_bytes(worktree) == digest, "IMPLEMENTATION_WORKTREE_DIGEST")
        _require(sha256_bytes(blob) == digest, "IMPLEMENTATION_BLOB_DIGEST")
    return True


def materialize_final_template(draft_template, held_job, circuit_roots):
    _require(isinstance(draft_template, dict) and draft_template.get("status") == "DRAFT_NO_EXECUTION", "TEMPLATE_NOT_DRAFT")
    draft_r = draft_template.get("registration")
    _require(isinstance(draft_r, dict) and all(draft_r.get(x) is None for x in ("job_id", "git_commit", "queue", "resource_request", "cwd", "stdout_path", "stderr_path")), "TEMPLATE_NOT_EMPTY")
    _draft_measurement_shape(draft_template.get("measurement_files"))
    _require(draft_template.get("circuits") == [], "TEMPLATE_DRAFT_CIRCUITS")
    _exact(held_job, ("job_id", "git_commit", "command_argv", "queue", "resource_request", "cwd", "stdout_path", "stderr_path"), "HELD_JOB_FIELDS")
    _require(held_job["command_argv"] == EXPECTED_COMMAND_ARGV, "HELD_JOB_ARGV")
    _require(isinstance(circuit_roots, dict) and set(circuit_roots) == set(BLIND_CIRCUITS), "CIRCUIT_ROOTS")
    circuits = [{"name": name, "root": circuit_roots[name]} for name in BLIND_CIRCUITS]
    _circuit_shape(circuits)
    result = {"schema_version": "blind-runtime-unseal-job-v9", "status": "FINAL_HELD_JOB_TEMPLATE",
      "registration": {"job_id": held_job["job_id"], "git_commit": held_job["git_commit"], "initial_scheduler_state": "PSUSP", "array_allowed": False, "retry_allowed": False, "requeue_allowed": False, "rerun_allowed": False, "command_argv": copy.deepcopy(held_job["command_argv"]), "queue": held_job["queue"], "resource_request": held_job["resource_request"], "cwd": held_job["cwd"], "stdout_path": held_job["stdout_path"], "stderr_path": held_job["stderr_path"]},
      "measurement_files": copy.deepcopy(draft_template.get("measurement_files")), "circuits": circuits,
      "template_rule": "One final held-job template with only pre-existing scheduler and implementation bindings.",
      "lifecycle": {"implementation_freeze_commit": held_job["git_commit"], "held_job_id": held_job["job_id"], "finalization_event": "bsub_H_then_raw_bjobs_capture"}}
    _no_null_or_pending(result); _template_shape(result)
    return result


def finalize_contract(draft_contract, final_template_bytes, implementation_freeze_commit, implementation_artifact_sha256):
    _require(isinstance(draft_contract, dict) and draft_contract.get("status") == "DRAFT_NO_EXECUTION", "CONTRACT_NOT_DRAFT")
    _require(COMMIT_RE.match(implementation_freeze_commit or "") is not None and isinstance(implementation_artifact_sha256, dict) and implementation_artifact_sha256, "IMPLEMENTATION_INPUT")
    template = json.loads(final_template_bytes.decode("utf-8")); _template_shape(template)
    _require(template["registration"]["git_commit"] == implementation_freeze_commit, "TEMPLATE_COMMIT")
    result = copy.deepcopy(draft_contract)
    result["status"] = "FINAL_HELD_UNSEAL_REVIEW_REQUIRED"
    result["purpose"] = "v9 sealed BLIND runtime audit with pre-staged clean Git checkout and exact absolute CWD bindings."
    result["job_template"] = {"path": "contracts/blind_runtime_unseal_job_v9_template.json", "sha256": sha256_bytes(final_template_bytes)}
    result["implementation"] = copy.deepcopy(result["implementation"]); result["implementation"]["artifact_sha256"] = copy.deepcopy(implementation_artifact_sha256)
    result["lifecycle"] = {"implementation_freeze_commit": implementation_freeze_commit, "final_template_sha256": sha256_bytes(final_template_bytes), "artifact_blob_equals_worktree_required": True, "finalization_rule": "The external manifest binds only immutable pre-submission implementation and input controls; final lifecycle artifacts are separately digest-linked.", "required_order": ["implementation_freeze_commit", "create_bundle", "upload_stage_bundle", "write_external_immutable_control_manifest", "verify_clean_git_and_external_manifest", "bsub_H", "raw_bjobs_capture", "raw_bjobs_al_capture", "final_template", "final_contract", "registration_receipt", "final_job_spec", "pre_review_clean_commit", "independent_review", "final_review_clean_commit", "bresume"]}
    _no_null_or_pending(result); _contract_shape(result)
    return result


def build_registration_receipt(final_template_bytes, final_contract_bytes, raw_bjobs_sha256, raw_global_bjobs_sha256, raw_bjobs_al_sha256, external_control_manifest_sha256, owner, submission_host, submit_time_raw, specified_cwd=EXPECTED_BUNDLE_ROOT):
    template = json.loads(final_template_bytes.decode("utf-8")); contract = json.loads(final_contract_bytes.decode("utf-8")); _template_shape(template); _contract_shape(contract)
    for d in (raw_bjobs_sha256, raw_global_bjobs_sha256, raw_bjobs_al_sha256, external_control_manifest_sha256): _digest(d, "RAW_CAPTURE_DIGEST")
    for v, c in ((owner, "OWNER"), (submission_host, "SUBMISSION_HOST"), (submit_time_raw, "SUBMIT_TIME")): _text(v, c)
    r = template["registration"]; argv = r["command_argv"]
    _require(specified_cwd == EXPECTED_BUNDLE_ROOT and r["cwd"] == EXPECTED_BUNDLE_ROOT, "ABSOLUTE_CWD_BINDING")
    return {"schema_version": "blind-runtime-unseal-registration-v9", "status": "REGISTERED_HELD", "job_id": r["job_id"], "owner": owner, "submission_host": submission_host, "submit_time_raw": submit_time_raw, "reviewed_commit": r["git_commit"], "contract_sha256": sha256_bytes(final_contract_bytes), "protocol_sha256": contract["protocol"]["sha256"], "gate_snapshot_sha256": contract["gate_snapshot"]["sha256"], "runner_sha256": contract["implementation"]["artifact_sha256"]["src/data/run_blind_unseal_v9.py"], "job_template_sha256": sha256_bytes(final_template_bytes), "normalized_argv": argv, "normalized_argv_sha256": sha256_bytes(json.dumps(argv, ensure_ascii=True, separators=(",", ":")).encode("utf-8")), "queue": r["queue"], "resource_request": r["resource_request"], "cwd": r["cwd"], "stdout_path": r["stdout_path"], "stderr_path": r["stderr_path"], "raw_bjobs_capture_sha256": raw_bjobs_sha256, "raw_global_bjobs_capture_sha256": raw_global_bjobs_sha256, "raw_bjobs_al_capture_sha256": raw_bjobs_al_sha256, "external_control_manifest_path": EXPECTED_EXTERNAL_CONTROL_MANIFEST, "external_control_manifest_sha256": external_control_manifest_sha256, "specified_cwd": specified_cwd}


def build_final_job_spec(receipt_bytes, final_template_bytes, final_contract_bytes, output_root, registration_receipt_path="contracts/blind_runtime_unseal_registration_v9.json"):
    receipt = json.loads(receipt_bytes.decode("utf-8")); template = json.loads(final_template_bytes.decode("utf-8")); contract = json.loads(final_contract_bytes.decode("utf-8")); _template_shape(template); _contract_shape(contract)
    _require(receipt.get("status") == "REGISTERED_HELD", "RECEIPT_STATUS"); _absolute_text(output_root, "OUTPUT_ROOT"); _text(registration_receipt_path, "RECEIPT_PATH")
    _require(not os.path.isabs(registration_receipt_path) and ".." not in registration_receipt_path.replace("\\", "/").split("/"), "RECEIPT_PATH")
    result = {"schema_version": "blind-runtime-unseal-job-v9", "status": "REGISTERED_HELD", "contract_sha256": sha256_bytes(final_contract_bytes), "job_template_sha256": sha256_bytes(final_template_bytes), "registration_receipt": registration_receipt_path, "registration_receipt_sha256": sha256_bytes(receipt_bytes), "registration": copy.deepcopy(template["registration"]), "measurement_files": copy.deepcopy(template["measurement_files"]), "circuits": copy.deepcopy(template["circuits"]), "output_root": output_root}
    _job_spec_shape(result, template, receipt, contract, receipt_bytes, final_template_bytes, final_contract_bytes)
    return result


def _job_spec_shape(spec, template, receipt, contract, receipt_bytes, final_template_bytes, final_contract_bytes):
    _exact(spec, JOB_SPEC_FIELDS, "JOB_SPEC_FIELDS")
    _require(spec["schema_version"] == "blind-runtime-unseal-job-v9" and spec["status"] == "REGISTERED_HELD", "JOB_SPEC_STATE")
    _digest(spec["contract_sha256"], "JOB_SPEC_CONTRACT_DIGEST")
    _digest(spec["job_template_sha256"], "JOB_SPEC_TEMPLATE_DIGEST")
    _digest(spec["registration_receipt_sha256"], "JOB_SPEC_RECEIPT_DIGEST")
    _text(spec["registration_receipt"], "JOB_SPEC_RECEIPT_PATH")
    _require(not os.path.isabs(spec["registration_receipt"]) and ".." not in spec["registration_receipt"].replace("\\", "/").split("/"), "JOB_SPEC_RECEIPT_PATH")
    _absolute_text(spec["output_root"], "JOB_SPEC_OUTPUT_ROOT")
    _require(spec["contract_sha256"] == sha256_bytes(final_contract_bytes), "JOB_SPEC_CONTRACT_BINDING")
    _require(spec["job_template_sha256"] == sha256_bytes(final_template_bytes), "JOB_SPEC_TEMPLATE_BINDING")
    _require(spec["registration_receipt_sha256"] == sha256_bytes(receipt_bytes), "JOB_SPEC_RECEIPT_BINDING")
    _require(set(receipt) == set(REGISTRATION_FIELDS) and receipt.get("status") == "REGISTERED_HELD", "JOB_SPEC_RECEIPT_SCHEMA")
    _require(receipt.get("contract_sha256") == spec["contract_sha256"] and receipt.get("job_template_sha256") == spec["job_template_sha256"], "JOB_SPEC_RECEIPT_DIGEST_BINDING")
    _require(spec["registration"] == template["registration"], "JOB_SPEC_REGISTRATION_TEMPLATE")
    _require(spec["registration"]["job_id"] == receipt["job_id"] and spec["registration"]["git_commit"] == receipt["reviewed_commit"], "JOB_SPEC_REGISTRATION_RECEIPT")
    _draft_measurement_shape(spec["measurement_files"])
    _require(spec["measurement_files"] == template["measurement_files"], "JOB_SPEC_MEASUREMENT_TEMPLATE")
    _circuit_shape(spec["circuits"], tuple(contract["scope"]["blind_circuits"]), "JOB_SPEC_CIRCUITS")
    _require(spec["circuits"] == template["circuits"], "JOB_SPEC_CIRCUIT_TEMPLATE")


def build_independent_review(receipt_bytes, job_spec_bytes, final_contract_bytes, raw_bjobs, raw_global_bjobs, raw_bjobs_al, external_control_manifest, expected_job_id, job_template_path, implementation_contract_path, runner_path):
    """A PASS requires real raw bjobs/global bytes to pass the registration validator."""
    receipt = json.loads(receipt_bytes.decode("utf-8")); job = json.loads(job_spec_bytes.decode("utf-8")); contract = json.loads(final_contract_bytes.decode("utf-8")); _contract_shape(contract)
    template, template_bytes = _load_final_template(job_template_path)
    _template_shape(template)
    _job_spec_shape(job, template, receipt, contract, receipt_bytes, template_bytes, final_contract_bytes)
    try: validate_registration(receipt, raw_bjobs, expected_job_id, job_template_path, implementation_contract_path, runner_path, raw_global_bjobs, raw_bjobs_al, external_control_manifest)
    except ValidationError as error: raise LifecycleError("REGISTRATION_VALIDATOR_" + str(error))
    _require(receipt["contract_sha256"] == sha256_bytes(final_contract_bytes) == job["contract_sha256"], "REVIEW_CONTRACT_BINDING")
    return {"schema_version": "blind-unseal-independent-review-v9", "status": "PASS", "execution_allowed": True, "blind_data_read": False, "real_unseal_executed": False, "contract_sha256": sha256_bytes(final_contract_bytes), "registration_receipt_sha256": sha256_bytes(receipt_bytes), "job_spec_sha256": sha256_bytes(job_spec_bytes), "output_root": job["output_root"], "job_id": receipt["job_id"], "reviewed_commit": receipt["reviewed_commit"], "protocol_sha256": receipt["protocol_sha256"], "gate_snapshot_sha256": receipt["gate_snapshot_sha256"], "scheduler_fixture_manifest_sha256": contract["scheduler_fixture"]["sha256"], "normalized_argv": copy.deepcopy(receipt["normalized_argv"]), "raw_bjobs_capture_sha256": receipt["raw_bjobs_capture_sha256"], "raw_global_bjobs_capture_sha256": receipt["raw_global_bjobs_capture_sha256"], "raw_bjobs_al_capture_sha256": receipt["raw_bjobs_al_capture_sha256"], "external_control_manifest_path": receipt["external_control_manifest_path"], "external_control_manifest_sha256": receipt["external_control_manifest_sha256"], "specified_cwd": receipt["specified_cwd"], "queue": receipt["queue"], "resource_request": receipt["resource_request"], "cwd": receipt["cwd"], "stdout_path": receipt["stdout_path"], "stderr_path": receipt["stderr_path"], "reviewed_artifacts": copy.deepcopy(contract["implementation"]["artifact_sha256"]), "registration_validator_pass": True, "psusp_verified": True, "nonarray_verified": True, "no_retry": True, "no_requeue": True, "no_rerun": True, "no_blind_parse": True, "no_blind_output": True}


def _load_final_template(path):
    try:
        with open(path, "rb") as stream: raw = stream.read()
        return json.loads(raw.decode("utf-8")), raw
    except (OSError, UnicodeDecodeError, ValueError):
        raise LifecycleError("FINAL_TEMPLATE_READ")


def validate_one_way_lifecycle(final_template_bytes, final_contract_bytes, receipt_bytes, job_spec_bytes, review_bytes):
    template = json.loads(final_template_bytes.decode("utf-8")); contract = json.loads(final_contract_bytes.decode("utf-8")); receipt = json.loads(receipt_bytes.decode("utf-8")); spec = json.loads(job_spec_bytes.decode("utf-8")); review = json.loads(review_bytes.decode("utf-8"))
    _no_null_or_pending(template); _no_null_or_pending(contract); _template_shape(template); _contract_shape(contract)
    _job_spec_shape(spec, template, receipt, contract, receipt_bytes, final_template_bytes, final_contract_bytes)
    review_fields = ("schema_version", "status", "execution_allowed", "blind_data_read", "real_unseal_executed", "contract_sha256", "registration_receipt_sha256", "job_spec_sha256", "output_root", "job_id", "reviewed_commit", "protocol_sha256", "gate_snapshot_sha256", "scheduler_fixture_manifest_sha256", "normalized_argv", "raw_bjobs_capture_sha256", "raw_global_bjobs_capture_sha256", "raw_bjobs_al_capture_sha256", "external_control_manifest_path", "external_control_manifest_sha256", "specified_cwd", "queue", "resource_request", "cwd", "stdout_path", "stderr_path", "reviewed_artifacts", "registration_validator_pass", "psusp_verified", "nonarray_verified", "no_retry", "no_requeue", "no_rerun", "no_blind_parse", "no_blind_output")
    _require(receipt.get("status") == "REGISTERED_HELD" and spec.get("status") == "REGISTERED_HELD" and set(review) == set(review_fields) and review.get("status") == "PASS", "LIFECYCLE_STATUS")
    _require(all(review.get(key) is True for key in ("execution_allowed", "registration_validator_pass", "psusp_verified", "nonarray_verified", "no_retry", "no_requeue", "no_rerun", "no_blind_parse", "no_blind_output")) and review.get("blind_data_read") is False and review.get("real_unseal_executed") is False, "LIFECYCLE_REVIEW_FLAGS")
    _require(contract["job_template"]["sha256"] == sha256_bytes(final_template_bytes), "C_TO_T")
    _require(receipt["contract_sha256"] == sha256_bytes(final_contract_bytes), "R_TO_C")
    _require(spec["registration_receipt_sha256"] == sha256_bytes(receipt_bytes), "S_TO_R")
    _require(review.get("contract_sha256") == sha256_bytes(final_contract_bytes) and review.get("job_spec_sha256") == sha256_bytes(job_spec_bytes) and review.get("registration_receipt_sha256") == sha256_bytes(receipt_bytes), "V_BINDING")
    _require(review.get("job_id") == receipt.get("job_id") and review.get("reviewed_commit") == receipt.get("reviewed_commit") and review.get("output_root") == spec.get("output_root"), "V_ID_BINDING")
    for key in ("protocol_sha256", "gate_snapshot_sha256", "normalized_argv", "raw_bjobs_capture_sha256", "raw_global_bjobs_capture_sha256", "raw_bjobs_al_capture_sha256", "external_control_manifest_path", "external_control_manifest_sha256", "specified_cwd", "queue", "resource_request", "cwd", "stdout_path", "stderr_path"):
        _require(review.get(key) == receipt.get(key), "V_RECEIPT_BINDING_" + key.upper())
    _require(review.get("reviewed_artifacts") == contract.get("implementation", {}).get("artifact_sha256"), "V_ARTIFACT_BINDING")
    return True
