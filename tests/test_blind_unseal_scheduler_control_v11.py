import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUNDLE = "/temp/jiangchuanc/blind_runtime_unseal_v11_bundle"
ARGV = ["python3", BUNDLE + "/src/data/run_blind_unseal_v11_final.py", "--bundle-root", BUNDLE]
sys.path.insert(0, str(ROOT / "src" / "data"))

from validate_blind_unseal_registration_v11 import ValidationError, sha256_bytes, validate_registration
from validate_blind_unseal_scheduler_audit_v11 import validate_scheduler_audit


def digest(label):
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def bjobs_row(job_id="12345", state="PSUSP", command=None, owner="jiangchuanc", queue="normal", cwd=BUNDLE):
    """LSF 9.1 delimiter output has exactly 11 columns and no final ^."""
    command = command or " ".join(ARGV)
    return "^".join((job_id, state, owner, queue, command, "host-a", "Wed Sep 10 07:07:59", "select[type==X]", "/evidence/stdout.log", "/evidence/stderr.log", cwd))


def raw_bjobs(**kwargs):
    return (bjobs_row(**kwargs) + "\n").encode("utf-8")


def global_bjobs(*rows):
    return ("\n".join(rows) + "\n").encode("utf-8")


def bjobs_al(cwd=BUNDLE):
    return ("Job <12345>, Status <PSUSP>\nSubmitted with hold, CWD <" + cwd + ">, Specified CWD <" + cwd + ">;\n").encode("utf-8")


def job_template():
    return {"schema_version": "blind-runtime-unseal-job-v11", "status": "FINAL_HELD_JOB_TEMPLATE", "registration": {"job_id": "12345", "git_commit": "a" * 40, "initial_scheduler_state": "PSUSP", "array_allowed": False, "retry_allowed": False, "requeue_allowed": False, "rerun_allowed": False, "command_argv": ARGV, "queue": "normal", "resource_request": "select[type==X]", "cwd": BUNDLE, "stdout_path": "/evidence/stdout.log", "stderr_path": "/evidence/stderr.log"}, "measurement_files": ["01_single_boundaries/measurements.tsv"], "circuits": [{"name": "s9234", "root": "/blind/s9234"}], "template_rule": "synthetic final template", "lifecycle": {"implementation_freeze_commit": "a" * 40, "held_job_id": "12345", "finalization_event": "bsub_H_then_raw_bjobs_capture"}}


def registration(raw, global_raw, template_bytes, contract_bytes, raw_al=None, manifest=None):
    raw_al = bjobs_al() if raw_al is None else raw_al
    manifest = b'{"schema_version":"blind-runtime-unseal-control-manifest-v11"}\n' if manifest is None else manifest
    argv = job_template()["registration"]["command_argv"]
    return {"schema_version": "blind-runtime-unseal-registration-v11", "status": "REGISTERED_HELD", "job_id": "12345", "owner": "jiangchuanc", "submission_host": "host-a", "submit_time_raw": "Wed Sep 10 07:07:59", "reviewed_commit": "a" * 40, "contract_sha256": sha256_bytes(contract_bytes), "protocol_sha256": digest("protocol"), "gate_snapshot_sha256": digest("gate"), "runner_sha256": sha256_bytes((ROOT / "src" / "data" / "run_blind_unseal_v11_final.py").read_bytes()), "job_template_sha256": sha256_bytes(template_bytes), "normalized_argv": argv, "normalized_argv_sha256": hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode("utf-8")).hexdigest(), "queue": "normal", "resource_request": "select[type==X]", "cwd": BUNDLE, "stdout_path": "/evidence/stdout.log", "stderr_path": "/evidence/stderr.log", "raw_bjobs_capture_sha256": sha256_bytes(raw), "raw_global_bjobs_capture_sha256": sha256_bytes(global_raw), "raw_bjobs_al_capture_sha256": sha256_bytes(raw_al), "external_control_manifest_path": "/temp/jiangchuanc/blind_runtime_unseal_v11_control_manifest.json", "external_control_manifest_sha256": sha256_bytes(manifest), "specified_cwd": BUNDLE}


def history(kind, *, cont=True, resumes=1, terminal="done", status="DONE", forbidden=""):
    metadata = "# registered_at_utc=2026-09-10T07:07:58Z\n# resumed_at_utc=2026-09-10T07:08:05Z\n# captured_at_utc=2026-09-10T07:08:10Z\n"
    if kind == "bhist":
        resume = "\n".join("Wed Sep 10 07:08:05: Signal <CONT> requested by user." for _ in range(resumes)) if cont else ""
        wait = "\n".join("Wed Sep 10 07:08:05: Waiting for scheduling after resumed." for _ in range(resumes)) if cont else ""
        terminal_line = "Wed Sep 10 07:08:07: Done successfully." if terminal == "done" else "Wed Sep 10 07:08:07: Exited with exit code 1."
        body = "\n".join(("Job <12345>, User <jiangchuanc>, Project <default>", resume, wait, "Wed Sep 10 07:08:05: Starting (Pid 7391);", terminal_line, forbidden))
    else:
        body = "\n".join(("Job <12345>, User <jiangchuanc>, Project <default>", "Status <%s>" % status, "Completed <%s>" % terminal, forbidden))
    return (metadata + body + "\n").encode("utf-8")


def write_artifacts(directory, contract, contract_sha, tool):
    rows = []
    for circuit in ("s9234", "s38584", "wb_dma"):
        rows.append({"circuit": circuit, "executed_stage_reference_count": 2, "unique_runtime_join_count": 2, "missing_runtime_join_count": 0, "ambiguous_runtime_join_count": 0, "coverage_rate": 1.0, "distinct_runtime_attempt_count": 2, "cross_stage_reference_count": 0, "frozen_runtime_eligible_action_space_sha256": digest(circuit + "action"), "source_artifact_set_sha256": digest(circuit + "source"), "action_coverage_summary": {"eligible_action_count": 1, "all_unique_action_count": 1, "formal_action_count": 1, "attempt_reference_count": 2}})
    # This is the runner's strict eight-field receipt envelope.
    receipt = {"schema_version": "blind-runtime-unseal-receipt-v11", "status": "PASS", "formal_runtime_membership_sha256": contract["scope"]["formal_runtime_membership_sha256"], "method_registry_sha256": contract["scope"]["method_registry_sha256"], "tool_set_sha256": tool, "contract_sha256": contract_sha, "circuits": rows, "failure_code": None}
    receipt_bytes = json.dumps(receipt, sort_keys=True).encode("utf-8")
    receipt_sha = sha256_bytes(receipt_bytes)
    files = {"CONSUMED": json.dumps({"schema_version": "blind-runtime-unseal-consumed-v11", "status": "CONSUMED", "contract_sha256": contract_sha, "tool_set_sha256": tool}).encode("utf-8"), "receipt.json": receipt_bytes, "receipt.json.sha256": (receipt_sha + "  receipt.json\n").encode("ascii"), "RELEASED": json.dumps({"schema_version": "blind-runtime-unseal-release-v11", "status": "RELEASED_RUNNER_VERIFIED_SCHEDULER_AUDIT_PENDING", "contract_sha256": contract_sha, "receipt_sha256": receipt_sha}).encode("utf-8")}
    for name, data in files.items():
        (directory / name).write_bytes(data)
    return {name: sha256_bytes(data) for name, data in files.items()}


def audit(raw_registration, bjobs, global_raw, bhist, bacct, stdout, stderr, artifacts):
    return {"schema_version": "blind-runtime-unseal-scheduler-audit-v11", "status": "RELEASED_VERIFIED", "job_id": "12345", "registration_receipt_sha256": sha256_bytes(raw_registration), "protocol_sha256": digest("protocol"), "raw_bjobs_capture_sha256": sha256_bytes(bjobs), "raw_global_bjobs_capture_sha256": sha256_bytes(global_raw), "bhist_raw_capture_sha256": sha256_bytes(bhist), "bacct_raw_capture_sha256": sha256_bytes(bacct), "stdout_capture_sha256": sha256_bytes(stdout), "stderr_capture_sha256": sha256_bytes(stderr), "four_artifact_sha256": artifacts}


class SchedulerControlv11Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.blob_check = mock.patch("validate_blind_unseal_registration_v11._git_blob_equals_worktree")
        self.blob_check.start()
        self.staging_check = mock.patch("validate_blind_unseal_registration_v11.verify_staged_bundle", return_value="synthetic-staging-verified")
        self.staging_check.start()
        self.directory = pathlib.Path(self.temp.name)
        self.template_path = self.directory / "job-template.json"
        self.template_path.write_bytes(json.dumps(job_template(), sort_keys=True).encode("utf-8"))
        self.runner_path = ROOT / "src" / "data" / "run_blind_unseal_v11_final.py"
        self.contract_path = self.directory / "implementation-contract.json"
        runner_sha = sha256_bytes(self.runner_path.read_bytes())
        self.contract = json.loads((ROOT / "contracts" / "blind_runtime_unseal_v11.json").read_text(encoding="utf-8"))
        self.contract["status"] = "FINAL_HELD_UNSEAL_REVIEW_REQUIRED"
        self.contract["job_template"] = {"path": "contracts/blind_runtime_unseal_job_v11_template.json", "sha256": sha256_bytes(self.template_path.read_bytes())}
        self.contract["scope"]["formal_runtime_membership_sha256"] = digest("membership")
        self.contract["scope"]["method_registry_sha256"] = digest("registry")
        self.contract["implementation"]["artifact_sha256"] = {"src/data/run_blind_unseal_v11_final.py": runner_sha}
        self.contract["lifecycle"] = {"implementation_freeze_commit": "a" * 40, "final_template_sha256": sha256_bytes(self.template_path.read_bytes()), "artifact_blob_equals_worktree_required": True, "finalization_rule": "synthetic stable contract", "required_order": ["implementation_freeze_commit", "bsub_H", "raw_bjobs_capture", "final_template", "final_contract", "registration_receipt", "final_job_spec", "pre_review_clean_commit", "independent_review", "final_review_clean_commit", "bresume"]}
        self.contract_path.write_bytes(json.dumps(self.contract, sort_keys=True, indent=2).encode("utf-8") + b"\n")
        self.bjobs, self.global_bjobs = raw_bjobs(), global_bjobs(bjobs_row())
        self.raw_al = bjobs_al(); self.manifest = b'{"schema_version":"blind-runtime-unseal-control-manifest-v11"}\n'
        self.reg = registration(self.bjobs, self.global_bjobs, self.template_path.read_bytes(), self.contract_path.read_bytes(), self.raw_al, self.manifest)
        self.raw_registration = json.dumps(self.reg, sort_keys=True).encode("utf-8")
        self.bhist, self.bacct = history("bhist"), history("bacct")
        self.stdout, self.stderr = b"aggregate only\n", b"no detailed rows\n"
        self.tool = sha256_bytes(("src/data/run_blind_unseal_v11_final.py:" + runner_sha + "\n").encode("utf-8"))
        self.artifacts = write_artifacts(self.directory, self.contract, self.reg["contract_sha256"], self.tool)
        self.audit = audit(self.raw_registration, self.bjobs, self.global_bjobs, self.bhist, self.bacct, self.stdout, self.stderr, self.artifacts)

    def tearDown(self):
        self.staging_check.stop()
        self.blob_check.stop()
        self.temp.cleanup()

    def valid_audit(self):
        return validate_scheduler_audit(self.audit, self.reg, self.raw_registration, self.bjobs, self.bhist, self.bacct, self.stdout, self.stderr, str(self.directory), "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest)

    def test_real_lsf_9_1_resume_fixture_and_exact_receipt_pass(self):
        self.assertTrue(validate_registration(self.reg, self.bjobs, "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest))
        self.assertTrue(self.valid_audit())

    def test_exact_stage_specific_fail_receipt_is_auditable(self):
        receipt = {"schema_version": "blind-runtime-unseal-receipt-v11", "status": "FAIL",
                   "contract_sha256": self.reg["contract_sha256"], "tool_set_sha256": self.tool,
                   "failure_stage": "COVERAGE_GATE", "failure_code": "R06_R07_FAILED",
                   "circuits": []}
        receipt_bytes = json.dumps(receipt, sort_keys=True).encode("utf-8")
        receipt_sha = sha256_bytes(receipt_bytes)
        (self.directory / "receipt.json").write_bytes(receipt_bytes)
        (self.directory / "receipt.json.sha256").write_bytes((receipt_sha + "  receipt.json\n").encode("ascii"))
        (self.directory / "RELEASED").write_bytes(json.dumps({
            "schema_version": "blind-runtime-unseal-release-v11",
            "status": "RELEASED_RUNNER_VERIFIED_SCHEDULER_AUDIT_PENDING",
            "contract_sha256": self.reg["contract_sha256"], "receipt_sha256": receipt_sha,
        }, sort_keys=True).encode("utf-8"))
        fail_artifacts = {name: sha256_bytes((self.directory / name).read_bytes())
                          for name in ("CONSUMED", "receipt.json", "receipt.json.sha256", "RELEASED")}
        item = audit(self.raw_registration, self.bjobs, self.global_bjobs, self.bhist,
                     self.bacct, self.stdout, self.stderr, fail_artifacts)
        self.assertTrue(validate_scheduler_audit(item, self.reg, self.raw_registration,
            self.bjobs, self.bhist, self.bacct, self.stdout, self.stderr, str(self.directory),
            "12345", str(self.template_path), str(self.contract_path), str(self.runner_path),
            self.global_bjobs, self.raw_al, self.manifest))
        bad = dict(receipt); bad["failure_code"] = "INTERNAL_AUDIT_FAILURE"
        (self.directory / "receipt.json").write_bytes(json.dumps(bad, sort_keys=True).encode("utf-8"))
        with self.assertRaises(ValidationError):
            validate_scheduler_audit(item, self.reg, self.raw_registration, self.bjobs,
                self.bhist, self.bacct, self.stdout, self.stderr, str(self.directory), "12345",
                str(self.template_path), str(self.contract_path), str(self.runner_path),
                self.global_bjobs, self.raw_al, self.manifest)

    def test_no_trailing_delimiter_and_extra_receipt_field_fail(self):
        self.assertFalse(self.bjobs.rstrip().endswith(b"^"))
        with self.assertRaises(ValidationError): validate_registration(self.reg, self.bjobs.rstrip() + b"^\n", "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest)
        changed = copy.deepcopy(self.reg); changed["unexpected"] = True
        with self.assertRaises(ValidationError): validate_registration(changed, self.bjobs, "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest)

    def test_global_duplicate_identity_rejected_foreign_held_allowed(self):
        duplicate = global_bjobs(bjobs_row(), bjobs_row(job_id="67890"))
        changed = registration(self.bjobs, duplicate, self.template_path.read_bytes(), self.contract_path.read_bytes())
        with self.assertRaises(ValidationError): validate_registration(changed, self.bjobs, "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), duplicate, self.raw_al, self.manifest)
        foreign = global_bjobs(bjobs_row(), bjobs_row(job_id="67890", command="/bin/sleep 2", owner="other", queue="low", cwd="/tmp"))
        changed = registration(self.bjobs, foreign, self.template_path.read_bytes(), self.contract_path.read_bytes())
        self.assertTrue(validate_registration(changed, self.bjobs, "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), foreign, self.raw_al, self.manifest))

    def test_bjobs_mutations_fail(self):
        for changed in (raw_bjobs(state="PEND"), raw_bjobs(command="evil --candidate"), self.bjobs.replace(b"jiangchuanc", b"other-user")):
            changed_reg = registration(changed, self.global_bjobs, self.template_path.read_bytes(), self.contract_path.read_bytes())
            with self.assertRaises(ValidationError): validate_registration(changed_reg, changed, "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest)

    def test_raw_bjobs_array_job_ids_are_rejected_before_registration(self):
        for array_job_id in ("12345[0]", "12345[1]"):
            raw = raw_bjobs(job_id=array_job_id)
            global_raw = global_bjobs(bjobs_row(job_id=array_job_id))
            changed = registration(raw, global_raw, self.template_path.read_bytes(), self.contract_path.read_bytes())
            with self.assertRaisesRegex(ValidationError, "^BJOBS_JOB_ID_OR_ARRAY$"):
                validate_registration(changed, raw, "12345", str(self.template_path),
                                      str(self.contract_path), str(self.runner_path), global_raw,
                                      self.raw_al, self.manifest)

    def test_v11_absolute_cwd_and_long_capture_are_mandatory(self):
        home_raw = raw_bjobs(cwd="$HOME")
        home_reg = registration(home_raw, self.global_bjobs, self.template_path.read_bytes(), self.contract_path.read_bytes())
        with self.assertRaises(ValidationError):
            validate_registration(home_reg, home_raw, "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest)
        wrong_al = bjobs_al("/temp/jiangchuanc/wrong_bundle")
        wrong_reg = registration(self.bjobs, self.global_bjobs, self.template_path.read_bytes(), self.contract_path.read_bytes(), wrong_al, self.manifest)
        with self.assertRaises(ValidationError):
            validate_registration(wrong_reg, self.bjobs, "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, wrong_al, self.manifest)
        missing_al = b"Job <12345>, Status <PSUSP>\n"
        missing_reg = registration(self.bjobs, self.global_bjobs, self.template_path.read_bytes(), self.contract_path.read_bytes(), missing_al, self.manifest)
        with self.assertRaises(ValidationError):
            validate_registration(missing_reg, self.bjobs, "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, missing_al, self.manifest)

    def test_bjobs_al_cwd_must_belong_to_target_record(self):
        target_missing_other_expected = (
            "Job <12345>, Status <PSUSP>\nSubmitted with hold;\n"
            "Job <99999>, Status <PSUSP>\nSpecified CWD <" + BUNDLE + ">\n").encode("utf-8")
        changed = registration(self.bjobs, self.global_bjobs, self.template_path.read_bytes(),
                               self.contract_path.read_bytes(), target_missing_other_expected, self.manifest)
        with self.assertRaises(ValidationError):
            validate_registration(changed, self.bjobs, "12345", str(self.template_path),
                                  str(self.contract_path), str(self.runner_path), self.global_bjobs,
                                  target_missing_other_expected, self.manifest)
        target_wrong_other_expected = (
            "Job <12345>, Status <PSUSP>\nSpecified CWD </temp/jiangchuanc/wrong_bundle>\n"
            "Job <99999>, Status <PSUSP>\nSpecified CWD <" + BUNDLE + ">\n").encode("utf-8")
        changed = registration(self.bjobs, self.global_bjobs, self.template_path.read_bytes(),
                               self.contract_path.read_bytes(), target_wrong_other_expected, self.manifest)
        with self.assertRaises(ValidationError):
            validate_registration(changed, self.bjobs, "12345", str(self.template_path),
                                  str(self.contract_path), str(self.runner_path), self.global_bjobs,
                                  target_wrong_other_expected, self.manifest)

    def test_v11_external_manifest_digest_is_bound(self):
        with self.assertRaises(ValidationError):
            validate_registration(self.reg, self.bjobs, "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest + b"drift")

    def test_history_missing_cont_duplicate_resume_and_terminal_mismatch_fail(self):
        cases = [
            (history("bhist", cont=False), self.bacct),
            (history("bhist", resumes=2), self.bacct),
            # A bacct terminal is valid only when Status and Completed agree.
            (history("bhist", terminal="exit"), history("bacct", terminal="exit", status="DONE")),
            # The same job may not be DONE in bhist but EXIT in bacct.
            (history("bhist", terminal="done"), history("bacct", terminal="exit", status="EXIT")),
        ]
        for bhist, bacct in cases:
            item = audit(self.raw_registration, self.bjobs, self.global_bjobs, bhist, bacct, self.stdout, self.stderr, self.artifacts)
            with self.assertRaises(ValidationError): validate_scheduler_audit(item, self.reg, self.raw_registration, self.bjobs, bhist, bacct, self.stdout, self.stderr, str(self.directory), "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest)

    def test_clock_skew_allowed_wrapper_order_and_window_enforced(self):
        skewed = self.bhist.replace(b"Wed Sep 10 07:08:05", b"Wed Sep 10 15:08:05")
        item = audit(self.raw_registration, self.bjobs, self.global_bjobs, skewed, self.bacct, self.stdout, self.stderr, self.artifacts)
        self.assertTrue(validate_scheduler_audit(item, self.reg, self.raw_registration, self.bjobs, skewed, self.bacct, self.stdout, self.stderr, str(self.directory), "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest))
        late = self.bhist.replace(b"# captured_at_utc=2026-09-10T07:08:10Z", b"# captured_at_utc=2026-09-10T13:08:10Z")
        late_bacct = self.bacct.replace(b"# captured_at_utc=2026-09-10T07:08:10Z", b"# captured_at_utc=2026-09-10T13:08:10Z")
        item = audit(self.raw_registration, self.bjobs, self.global_bjobs, late, late_bacct, self.stdout, self.stderr, self.artifacts)
        with self.assertRaises(ValidationError): validate_scheduler_audit(item, self.reg, self.raw_registration, self.bjobs, late, late_bacct, self.stdout, self.stderr, str(self.directory), "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest)

    def test_foreign_history_ignored_target_forbidden_and_artifact_leak_fail(self):
        foreign_bhist = self.bhist + b"Job <999>\nSignal <CONT> requested\nWaiting for scheduling after resumed\nStarting (Pid 9);\nDone successfully.\n"
        foreign_bacct = self.bacct + b"Job <999>\nStatus <EXIT>\nCompleted <exit>\n"
        item = audit(self.raw_registration, self.bjobs, self.global_bjobs, foreign_bhist, foreign_bacct, self.stdout, self.stderr, self.artifacts)
        self.assertTrue(validate_scheduler_audit(item, self.reg, self.raw_registration, self.bjobs, foreign_bhist, foreign_bacct, self.stdout, self.stderr, str(self.directory), "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest))
        bad = history("bhist", forbidden="Wed Sep 10 07:08:06: retry requested")
        item = audit(self.raw_registration, self.bjobs, self.global_bjobs, bad, self.bacct, self.stdout, self.stderr, self.artifacts)
        with self.assertRaises(ValidationError): validate_scheduler_audit(item, self.reg, self.raw_registration, self.bjobs, bad, self.bacct, self.stdout, self.stderr, str(self.directory), "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest)
        item = audit(self.raw_registration, self.bjobs, self.global_bjobs, self.bhist, self.bacct, b"candidate=123\n", self.stderr, self.artifacts)
        with self.assertRaises(ValidationError): validate_scheduler_audit(item, self.reg, self.raw_registration, self.bjobs, self.bhist, self.bacct, b"candidate=123\n", self.stderr, str(self.directory), "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest)

    def test_audit_global_hash_and_release_drift_fail(self):
        item = copy.deepcopy(self.audit); item["raw_global_bjobs_capture_sha256"] = digest("wrong")
        with self.assertRaises(ValidationError): validate_scheduler_audit(item, self.reg, self.raw_registration, self.bjobs, self.bhist, self.bacct, self.stdout, self.stderr, str(self.directory), "12345", str(self.template_path), str(self.contract_path), str(self.runner_path), self.global_bjobs, self.raw_al, self.manifest)
        (self.directory / "RELEASED").write_text("{}", encoding="utf-8")
        with self.assertRaises(ValidationError): self.valid_audit()


if __name__ == "__main__":
    unittest.main()


