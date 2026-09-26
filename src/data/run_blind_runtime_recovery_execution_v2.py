#!/usr/bin/env python3
"""Isolated v2 control plane for the sealed 44-attempt recovery runner.

The v1 execution engine remains immutable and is digest-bound as a read-only
base.  This module replaces every scheduler/control binding and implements the
LSF 9.1 non-array rule LSB_JOBINDEX == "0".
"""
from __future__ import print_function

import argparse
import datetime
import json
import os
import re
import sys

from src.data import run_blind_runtime_recovery_execution_v1 as base


CONTRACT_RELATIVE = "contracts/blind_runtime_recovery_execution_v2.json"
JOB_TEMPLATE_RELATIVE = "contracts/blind_runtime_recovery_execution_v2_job_template.json"
BUNDLE_MANIFEST_RELATIVE = "bundle_manifest_v2.json"
JOB_BUNDLE_ROOT = "/temp/jiangchuanc/blind_runtime_recovery_execution_v2_authorized_r1_bundle"
JOB_REGISTRATION_ROOT = ("/temp/jiangchuanc/multimode_ate_phase4_20260825_A/logs/"
                         "blind_runtime_recovery_execution_v2_registration_r1")
AUTHORIZATION_PATH = JOB_REGISTRATION_ROOT + "/authorization.json"
REGISTRATION_REVIEW_PATH = JOB_REGISTRATION_ROOT + "/independent_review.json"
BJOBS_CAPTURE_PATH = JOB_REGISTRATION_ROOT + "/bjobs.txt"
BJOBS_AL_CAPTURE_PATH = JOB_REGISTRATION_ROOT + "/bjobs_al.txt"
BSUB_CAPTURE_PATH = JOB_REGISTRATION_ROOT + "/bsub.txt"
REGISTRATION_COMMAND_PATH = JOB_REGISTRATION_ROOT + "/registration_command.txt"
PRE_RESUME_REVIEW_PATH = JOB_REGISTRATION_ROOT + "/pre_resume_review.json"
PRE_RESUME_BJOBS_PATH = JOB_REGISTRATION_ROOT + "/pre_resume_bjobs.txt"
PRE_RESUME_BJOBS_AL_PATH = JOB_REGISTRATION_ROOT + "/pre_resume_bjobs_al.txt"
V1_FAILURE_RELATIVE = (
    "data/manifests/blind_runtime_recovery_execution_v1_failure_20260926.json")

Refusal = base.Refusal
_require = base._require
_read_bytes = base._read_bytes
_load_json_bytes = base._load_json_bytes
_sha256_bytes = base._sha256_bytes


def validate_job_template(document):
    _require(isinstance(document, dict) and set(document) == {
        "schema_version", "status", "registration", "lifecycle"},
        "JOB_TEMPLATE_CONTAINER")
    _require(document.get("schema_version") ==
             "blind-runtime-recovery-execution-v2-job-template" and
             document.get("status") == "AUTHORIZED_PRE_REGISTRATION_TEMPLATE",
             "JOB_TEMPLATE_STATUS")
    registration = document.get("registration")
    _require(isinstance(registration, dict) and set(registration) == {
        "queue", "initial_scheduler_state", "job_name", "command_argv", "cwd",
        "stdout_path", "stderr_path", "array_allowed", "retry_allowed",
        "requeue_allowed", "rerun_allowed"}, "JOB_TEMPLATE_REGISTRATION")
    _require(registration == {
        "queue": "normal",
        "initial_scheduler_state": "PSUSP",
        "job_name": "blind_rt_recovery_v2_r1",
        "command_argv": [
            "/bin/bash",
            JOB_BUNDLE_ROOT + "/src/data/launch_blind_runtime_recovery_execution_v2.sh"],
        "cwd": JOB_BUNDLE_ROOT,
        "stdout_path": JOB_REGISTRATION_ROOT + "/stdout.log",
        "stderr_path": JOB_REGISTRATION_ROOT + "/stderr.log",
        "array_allowed": False,
        "retry_allowed": False,
        "requeue_allowed": False,
        "rerun_allowed": False,
    }, "JOB_TEMPLATE_EXACT_REGISTRATION")
    lifecycle = document.get("lifecycle")
    _require(isinstance(lifecycle, dict) and set(lifecycle) == {
        "register", "after_registration", "resume", "forbidden"},
        "JOB_TEMPLATE_LIFECYCLE")
    _require(lifecycle.get("register") == "bsub -H exactly once" and
             lifecycle.get("resume") ==
             "only bresume of the independently reviewed registered Job ID" and
             lifecycle.get("forbidden") == [
                 "second bsub", "bmod", "rerun", "requeue", "array submission",
                 "resume before a fresh pre-resume check"],
             "JOB_TEMPLATE_EXACT_LIFECYCLE")
    return document


def validate_bundle_manifest(root, contract):
    binding = contract.get("bundle_manifest")
    _require(isinstance(binding, dict) and set(binding) == {
        "root", "path", "sha256", "reviewed_commit"},
        "BUNDLE_MANIFEST_BINDING")
    _require(binding.get("root") == JOB_BUNDLE_ROOT and
             binding.get("path") == BUNDLE_MANIFEST_RELATIVE and
             re.match(r"^[0-9a-f]{64}$", binding.get("sha256", "")) and
             re.match(r"^[0-9a-f]{40}$", binding.get("reviewed_commit", "")),
             "BUNDLE_MANIFEST_BINDING")
    payload = _read_bytes(os.path.join(root, binding["path"]))
    _require(_sha256_bytes(payload) == binding["sha256"],
             "BUNDLE_MANIFEST_DIGEST")
    document = _load_json_bytes(payload, "BUNDLE_MANIFEST_JSON")
    _require(isinstance(document, dict) and set(document) == {
        "schema_version", "status", "reviewed_commit", "artifact_sha256"},
        "BUNDLE_MANIFEST_SCHEMA")
    _require(document.get("schema_version") ==
             "blind-runtime-recovery-execution-v2-bundle-manifest" and
             document.get("status") == "SEALED" and
             document.get("reviewed_commit") == binding["reviewed_commit"],
             "BUNDLE_MANIFEST_STATUS")
    artifacts = contract.get("implementation", {}).get("artifact_sha256", {})
    _require(document.get("artifact_sha256") == artifacts,
             "BUNDLE_MANIFEST_ARTIFACTS")
    for relative, expected in artifacts.items():
        _require(_sha256_bytes(_read_bytes(os.path.join(root, relative))) == expected,
                 "BUNDLE_MANIFEST_ARTIFACT_DIGEST")
    return document


def validate_contract(root):
    path = os.path.join(root, CONTRACT_RELATIVE)
    payload = _read_bytes(path)
    contract = _load_json_bytes(payload, "CONTRACT_JSON")
    _require(contract.get("schema_version") ==
             "blind-runtime-recovery-execution-v2", "CONTRACT_SCHEMA")
    _require(contract.get("status") == "REVIEWED_EXECUTION_AUTHORIZED" and
             contract.get("authority") == {
                 "execution_authorized": True,
                 "lsf_submission_allowed": True,
                 "training_allowed": False}, "CONTRACT_AUTHORITY")
    plan = contract.get("private_plan", {})
    _require(plan.get("sha256") == base.PLAN_SHA256 and
             plan.get("expected_attempts") == 44 and
             plan.get("expected_counts") == base.PLAN_COUNTS,
             "PLAN_BINDING")
    _require(contract.get("attempt_order") == ["H", "M"], "ATTEMPT_ORDER")
    _require(contract.get("historical_evidence", {}).get("write_policy") ==
             "READ_ONLY", "HISTORICAL_WRITE_POLICY")
    _require(contract.get("output", {}).get("overwrite") == "REFUSE",
             "OUTPUT_OVERWRITE_POLICY")
    _require(contract.get("command", {}).get("time_argv") ==
             ["/usr/bin/time", "-v"], "TIME_COMMAND")
    _require(contract.get("command", {}).get("tessent_argv") == [
        "/cad/mentor/tessent2021_2/bin/tessent", "-shell", "-license_wait", "5"],
        "TESSENT_COMMAND")
    _require(contract.get("command", {}).get("artifact_sha256") == {
        "/usr/bin/time": "54643b2f510907c0bc0a1d13373f1d8233deb38c90dd97ebd9ecb27010e4d803",
        "/cad/mentor/tessent2021_2/bin/tessent": "d92e81eaacf0727fd18d4cafa67d7c9a066069c6d8f7fc05caaf1252c3e44905",
        "stage_mapped_common_atpg_no_tsdb.tcl": "100d58c816d7e318e81e03aae2d9436405cbb90bf629c4104f462b4c7047d529",
        "stage_mapped_incremental_atpg_no_tsdb.tcl": "c2419bac5569192bfa04987d2e71c3e0aa4dadb8d8c22e755cc08318b2aaca95",
    }, "COMMAND_DIGEST_BINDING")
    template = _load_json_bytes(_read_bytes(os.path.join(root, JOB_TEMPLATE_RELATIVE)),
                                "JOB_TEMPLATE_JSON")
    validate_job_template(template)
    artifacts = contract.get("implementation", {}).get("artifact_sha256", {})
    expected_artifacts = {
        "src/data/run_blind_runtime_recovery_execution_v1.py",
        "src/data/run_blind_runtime_recovery_execution_v2.py",
        "src/data/launch_blind_runtime_recovery_execution_v2.sh",
        JOB_TEMPLATE_RELATIVE,
        "tests/test_run_blind_runtime_recovery_execution_v2.py",
        V1_FAILURE_RELATIVE,
    }
    _require(set(artifacts) == expected_artifacts, "IMPLEMENTATION_SET")
    for relative, expected in artifacts.items():
        _require(isinstance(expected, str) and re.match(r"^[0-9a-f]{64}$", expected),
                 "IMPLEMENTATION_DIGEST_SCHEMA")
        _require(_sha256_bytes(_read_bytes(os.path.join(root, relative))) == expected,
                 "IMPLEMENTATION_DIGEST")
    prior = contract.get("prior_failure", {})
    _require(prior == {"path": V1_FAILURE_RELATIVE,
                       "sha256": artifacts[V1_FAILURE_RELATIVE],
                       "job_id": "388791", "attempts_started": 0,
                       "reuse_allowed": False}, "PRIOR_FAILURE_BINDING")
    validate_bundle_manifest(root, contract)
    return contract, _sha256_bytes(payload)


def validate_registration_review(path, authorization, contract_sha, runner_sha):
    payload = _read_bytes(path)
    document = _load_json_bytes(payload, "REGISTRATION_REVIEW_JSON")
    expected_fields = {
        "schema_version", "status", "registered_at_utc", "lsf_job_id", "initial_scheduler_state",
        "submission_count", "contract_sha256", "plan_sha256", "runner_sha256",
        "launcher_sha256", "job_template_sha256", "bundle_manifest_sha256",
        "reviewed_commit", "no_retry", "no_requeue", "nonarray",
        "training_allowed", "bsub_path", "bsub_sha256",
        "registration_command_path", "registration_command_sha256",
        "bjobs_path", "bjobs_sha256", "bjobs_al_path", "bjobs_al_sha256"}
    _require(isinstance(document, dict) and set(document) == expected_fields,
             "REGISTRATION_REVIEW_SCHEMA")
    _require(document.get("schema_version") ==
             "blind-runtime-recovery-execution-v2-registration-review" and
             document.get("status") == "PASS" and
             document.get("initial_scheduler_state") == "PSUSP" and
             document.get("submission_count") == 1 and
             document.get("training_allowed") is False,
             "REGISTRATION_REVIEW_STATUS")
    for field in ("registered_at_utc", "lsf_job_id", "launcher_sha256", "job_template_sha256",
                  "bundle_manifest_sha256", "reviewed_commit", "bsub_path",
                  "bsub_sha256", "registration_command_path",
                  "registration_command_sha256", "bjobs_path", "bjobs_sha256",
                  "bjobs_al_path", "bjobs_al_sha256"):
        _require(document.get(field) == authorization.get(field),
                 "REGISTRATION_REVIEW_BINDING")
    _require(document.get("contract_sha256") == contract_sha and
             document.get("plan_sha256") == base.PLAN_SHA256 and
             document.get("runner_sha256") == runner_sha,
             "REGISTRATION_REVIEW_BINDING")
    _require(document.get("no_retry") is True and
             document.get("no_requeue") is True and
             document.get("nonarray") is True,
             "REGISTRATION_REVIEW_SCHEDULER")
    _require(_sha256_bytes(payload) == authorization.get("registration_review_sha256"),
             "REGISTRATION_REVIEW_DIGEST")
    return document


def _validate_scheduler_captures(document, prefix=""):
    job_id = document["lsf_job_id"]
    bjobs_path = document[prefix + "bjobs_path"]
    bjobs_al_path = document[prefix + "bjobs_al_path"]
    bjobs = _read_bytes(bjobs_path)
    bjobs_al = _read_bytes(bjobs_al_path)
    _require(_sha256_bytes(bjobs) == document[prefix + "bjobs_sha256"] and
             _sha256_bytes(bjobs_al) == document[prefix + "bjobs_al_sha256"],
             "AUTHORIZATION_CAPTURE_DIGEST")
    try:
        compact = [line.strip() for line in bjobs.decode("utf-8").splitlines()
                   if line.strip()]
        detail = bjobs_al.decode("utf-8")
    except UnicodeDecodeError:
        raise Refusal("AUTHORIZATION_CAPTURE_ENCODING")
    expected = re.compile(r"^%s\s+PSUSP\s+blind_rt_recovery_v2_r1\s+normal$" %
                          re.escape(job_id))
    _require(len(compact) == 1 and expected.match(compact[0]),
             "AUTHORIZATION_SCHEDULER_CAPTURE")
    normalized = re.sub(r"\s+", "", detail)
    expected_command = ("Command</bin/bash%s/src/data/"
                        "launch_blind_runtime_recovery_execution_v2.sh>" %
                        JOB_BUNDLE_ROOT)
    _require(normalized.count("Job<%s>" % job_id) == 1 and
             "JobName<blind_rt_recovery_v2_r1>" in normalized and
             "Status<PSUSP>" in normalized and "Queue<normal>" in normalized and
             expected_command in normalized and
             "withhold,CWD<%s>" % JOB_BUNDLE_ROOT in normalized and
             "OutputFile<%s/stdout.log>" % JOB_REGISTRATION_ROOT in normalized and
             "ErrorFile<%s/stderr.log>" % JOB_REGISTRATION_ROOT in normalized and
             "NotRe-runnable;" in normalized and
             not re.search(r"job\s*array|jobindex|\[[0-9]+\]", detail,
                           re.IGNORECASE),
             "AUTHORIZATION_SCHEDULER_CAPTURE")


def _parse_utc(value, code):
    _require(isinstance(value, str) and
             re.match(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
                      value), code)
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
    except ValueError:
        raise Refusal(code)


def validate_pre_resume_review(path, authorization, contract_sha, runner_sha,
                               now_utc=None):
    payload = _read_bytes(path)
    document = _load_json_bytes(payload, "PRE_RESUME_REVIEW_JSON")
    expected_fields = {
        "schema_version", "status", "registered_at_utc", "checked_at_utc", "lsf_job_id",
        "scheduler_state", "contract_sha256", "runner_sha256",
        "bundle_manifest_sha256", "reviewed_commit", "nonarray", "no_retry",
        "no_requeue", "training_allowed", "pre_resume_bjobs_path",
        "pre_resume_bjobs_sha256", "pre_resume_bjobs_al_path",
        "pre_resume_bjobs_al_sha256"}
    _require(isinstance(document, dict) and set(document) == expected_fields,
             "PRE_RESUME_REVIEW_SCHEMA")
    _require(document.get("schema_version") ==
             "blind-runtime-recovery-execution-v2-pre-resume-review" and
             document.get("status") == "PASS" and
             document.get("scheduler_state") == "PSUSP" and
             document.get("nonarray") is True and
             document.get("no_retry") is True and
             document.get("no_requeue") is True and
             document.get("training_allowed") is False,
             "PRE_RESUME_REVIEW_STATUS")
    for field in ("registered_at_utc", "lsf_job_id", "contract_sha256", "runner_sha256",
                  "bundle_manifest_sha256", "reviewed_commit",
                  "pre_resume_bjobs_path", "pre_resume_bjobs_sha256",
                  "pre_resume_bjobs_al_path", "pre_resume_bjobs_al_sha256"):
        _require(document.get(field) == authorization.get(field),
                 "PRE_RESUME_REVIEW_BINDING")
    registered = _parse_utc(document.get("registered_at_utc"),
                            "PRE_RESUME_REVIEW_TIME")
    checked = _parse_utc(document.get("checked_at_utc"),
                         "PRE_RESUME_REVIEW_TIME")
    now = (datetime.datetime.now(datetime.timezone.utc) if now_utc is None
           else now_utc)
    _require(registered <= checked <= now + datetime.timedelta(minutes=2) and
             now - checked <= datetime.timedelta(minutes=15),
             "PRE_RESUME_REVIEW_STALE")
    _validate_scheduler_captures(document, prefix="pre_resume_")
    _require(_sha256_bytes(payload) == authorization.get("pre_resume_review_sha256"),
             "PRE_RESUME_REVIEW_DIGEST")
    return document


def validate_authorization(path, contract_sha, runner_sha, contract,
                           environment=None):
    document = _load_json_bytes(_read_bytes(path), "AUTHORIZATION_JSON")
    expected_fields = {
        "schema_version", "status", "execution_allowed", "registered_at_utc", "contract_sha256",
        "plan_sha256", "runner_sha256", "launcher_sha256",
        "job_template_sha256", "bundle_manifest_sha256", "reviewed_commit",
        "lsf_job_id", "no_retry", "no_requeue", "nonarray", "training_allowed",
        "registration_review_path", "registration_review_sha256", "bsub_path",
        "bsub_sha256", "registration_command_path",
        "registration_command_sha256", "bjobs_path", "bjobs_sha256",
        "bjobs_al_path", "bjobs_al_sha256", "pre_resume_review_path",
        "pre_resume_review_sha256", "pre_resume_bjobs_path",
        "pre_resume_bjobs_sha256", "pre_resume_bjobs_al_path",
        "pre_resume_bjobs_al_sha256"}
    _require(isinstance(document, dict) and set(document) == expected_fields,
             "AUTHORIZATION_SCHEMA")
    _require(document.get("schema_version") ==
             "blind-runtime-recovery-execution-v2-authorization" and
             document.get("status") == "PASS" and
             document.get("execution_allowed") is True and
             document.get("training_allowed") is False,
             "AUTHORIZATION_STATUS")
    implementation = contract.get("implementation", {}).get("artifact_sha256", {})
    _require(document.get("contract_sha256") == contract_sha and
             document.get("plan_sha256") == base.PLAN_SHA256 and
             document.get("runner_sha256") == runner_sha and
             document.get("launcher_sha256") == implementation.get(
                 "src/data/launch_blind_runtime_recovery_execution_v2.sh") and
             document.get("job_template_sha256") == implementation.get(
                 JOB_TEMPLATE_RELATIVE), "AUTHORIZATION_BINDING")
    _require(document.get("bundle_manifest_sha256") ==
             contract.get("bundle_manifest", {}).get("sha256") and
             document.get("reviewed_commit") ==
             contract.get("bundle_manifest", {}).get("reviewed_commit"),
             "AUTHORIZATION_BUNDLE_BINDING")
    _require(re.match(r"^[1-9][0-9]*$", document.get("lsf_job_id", "")),
             "AUTHORIZATION_JOB")
    _require(document.get("no_retry") is True and
             document.get("no_requeue") is True and
             document.get("nonarray") is True, "AUTHORIZATION_SCHEDULER")
    _require(document.get("registration_review_path") == REGISTRATION_REVIEW_PATH and
             document.get("bsub_path") == BSUB_CAPTURE_PATH and
             document.get("registration_command_path") == REGISTRATION_COMMAND_PATH and
             document.get("bjobs_path") == BJOBS_CAPTURE_PATH and
             document.get("bjobs_al_path") == BJOBS_AL_CAPTURE_PATH and
             document.get("pre_resume_review_path") == PRE_RESUME_REVIEW_PATH and
             document.get("pre_resume_bjobs_path") == PRE_RESUME_BJOBS_PATH and
             document.get("pre_resume_bjobs_al_path") == PRE_RESUME_BJOBS_AL_PATH,
             "AUTHORIZATION_CONTROL_PATH")
    for field in ("bundle_manifest_sha256", "registration_review_sha256",
                  "bsub_sha256", "registration_command_sha256", "bjobs_sha256",
                  "bjobs_al_sha256", "pre_resume_review_sha256",
                  "pre_resume_bjobs_sha256", "pre_resume_bjobs_al_sha256"):
        _require(re.match(r"^[0-9a-f]{64}$", document.get(field, "")),
                 "AUTHORIZATION_DIGEST_SCHEMA")
    for path_field, digest_field in (("bsub_path", "bsub_sha256"),
                                     ("registration_command_path",
                                      "registration_command_sha256")):
        capture = _read_bytes(document[path_field])
        _require(capture and _sha256_bytes(capture) == document[digest_field],
                 "AUTHORIZATION_CAPTURE_DIGEST")
    bsub_text = _read_bytes(document["bsub_path"]).decode("utf-8").strip()
    _require(bsub_text == "Job <%s> is submitted to queue <normal>." %
             document["lsf_job_id"], "AUTHORIZATION_SUBMISSION_CAPTURE")
    command_text = _read_bytes(document["registration_command_path"]).decode(
        "utf-8").strip()
    expected_command = (
        "bsub -H -rn -q normal -J blind_rt_recovery_v2_r1 -oo %s/stdout.log "
        "-eo %s/stderr.log /bin/bash %s/src/data/launch_blind_runtime_recovery_execution_v2.sh" %
        (JOB_REGISTRATION_ROOT, JOB_REGISTRATION_ROOT, JOB_BUNDLE_ROOT))
    _require(command_text == expected_command, "AUTHORIZATION_REGISTRATION_COMMAND")
    _validate_scheduler_captures(document)
    validate_registration_review(document["registration_review_path"], document,
                                 contract_sha, runner_sha)
    validate_pre_resume_review(document["pre_resume_review_path"], document,
                               contract_sha, runner_sha)
    current = os.environ if environment is None else environment
    _require(current.get("LSB_JOBID") == document.get("lsf_job_id"),
             "AUTHORIZATION_CURRENT_JOB")
    _require(current.get("LSB_JOBINDEX") == "0", "AUTHORIZATION_JOB_INDEX")
    for field in ("LSB_JOBINDEX_END", "LSB_JOBINDEX_STEP"):
        _require(current.get(field) in (None, "", "0"),
                 "AUTHORIZATION_ARRAY_RANGE")
    return document


def validate_only(root, plan_path, source_preflight=False):
    contract, contract_sha = validate_contract(root)
    plan = base.validate_plan_bytes(_read_bytes(plan_path), contract)
    manifest = base.build_command_manifest(plan, contract)
    if source_preflight:
        base.preflight_sources(contract)
    return {"status": "PASS_V2_DESIGN_NO_EXECUTION", "attempts": len(manifest),
            "contract_sha256": contract_sha,
            "plan_sha256": base.PLAN_SHA256,
            "execution_authorized": True, "training_allowed": False}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--source-preflight", action="store_true")
    parser.add_argument("--authorization")
    args = parser.parse_args(argv)
    try:
        root = os.path.abspath(args.root)
        result = validate_only(root, args.plan,
                               source_preflight=args.source_preflight)
        if args.execute:
            contract, contract_sha = validate_contract(root)
            _require(args.authorization and
                     os.path.realpath(args.authorization) == AUTHORIZATION_PATH,
                     "AUTHORIZATION_FIXED_PATH")
            runner_sha = contract["implementation"]["artifact_sha256"][
                "src/data/run_blind_runtime_recovery_execution_v2.py"]
            validate_authorization(args.authorization, contract_sha, runner_sha,
                                   contract)
            plan = base.validate_plan_bytes(_read_bytes(args.plan), contract)
            manifest = base.build_command_manifest(plan, contract)
            config_values, source_manifest_sha = base.prepare_workspaces(contract)
            base.execute_manifest(manifest, contract, config_values,
                                  source_manifest_sha)
            result["status"] = "PASS_V2_EXECUTION_COMPLETE_AUDIT_PENDING"
        print(json.dumps(result, sort_keys=True))
        return 0
    except (IOError, OSError, Refusal) as exc:
        print("BLIND_RUNTIME_RECOVERY_EXECUTION_V2=REFUSED:%s" % exc,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
