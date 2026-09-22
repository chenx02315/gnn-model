import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))

from validate_blind_unseal_registration_v10 import ValidationError, sha256_bytes
import validate_blind_unseal_failure_v10 as failure_validator
from validate_blind_unseal_failure_v10 import validate_failure_audit

BUNDLE = "/temp/jiangchuanc/blind_runtime_unseal_v10_bundle"
ARGV = ["python3", BUNDLE + "/src/data/run_blind_unseal_v10.py", "--bundle-root", BUNDLE]


def digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def bjobs_row(job_id="388761"):
    return "^".join((job_id, "PSUSP", "jiangchuanc", "normal", " ".join(ARGV), "host-a", "Wed Sep 10 07:07:59", "select[type==X]", "/evidence/stdout.log", "/evidence/stderr.log", BUNDLE))


def history(kind, *, terminal="exit", forbidden=""):
    meta = "# registered_at_utc=2026-09-10T07:07:58Z\n# resumed_at_utc=2026-09-10T07:08:05Z\n# captured_at_utc=2026-09-10T07:08:10Z\n"
    if kind == "bhist":
        tail = "Wed Sep 10 07:08:07: Exited with exit code 1." if terminal == "exit" else "Wed Sep 10 07:08:07: Done successfully."
        body = "\n".join(("Job <388761>, User <jiangchuanc>", "Wed Sep 10 07:08:05: Signal <CONT> requested by user.", "Wed Sep 10 07:08:05: Waiting for scheduling after resumed.", "Wed Sep 10 07:08:05: Starting (Pid 7391);", tail, forbidden))
    else:
        status = "EXIT" if terminal == "exit" else "DONE"
        completed = "exit" if terminal == "exit" else "done"
        body = "\n".join(("Job <388761>, User <jiangchuanc>", "Status <%s>" % status, "Completed <%s>" % completed, forbidden))
    return (meta + body + "\n").encode("utf-8")


class FailureAuditV10Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.temp.name)
        self.template_path = self.directory / "job-template.json"
        template = {"schema_version": "blind-runtime-unseal-job-v10", "status": "FINAL_HELD_JOB_TEMPLATE", "registration": {"job_id": "388761", "git_commit": "a" * 40, "initial_scheduler_state": "PSUSP", "array_allowed": False, "retry_allowed": False, "requeue_allowed": False, "rerun_allowed": False, "command_argv": ARGV, "queue": "normal", "resource_request": "select[type==X]", "cwd": BUNDLE, "stdout_path": "/evidence/stdout.log", "stderr_path": "/evidence/stderr.log"}, "measurement_files": ["measurements.tsv"], "circuits": [{"name": "s9234", "root": "/blind/s9234"}], "template_rule": "synthetic", "lifecycle": {"implementation_freeze_commit": "a" * 40, "held_job_id": "388761", "finalization_event": "bsub_H_then_raw_bjobs_capture"}}
        self.template_path.write_text(json.dumps(template), encoding="utf-8")
        self.runner_path = ROOT / "src" / "data" / "run_blind_unseal_v10.py"
        runner_sha = sha256_bytes(self.runner_path.read_bytes())
        self.contract = json.loads((ROOT / "contracts" / "blind_runtime_unseal_v10.json").read_text(encoding="utf-8"))
        self.contract.update({"status": "FINAL_HELD_UNSEAL_REVIEW_REQUIRED", "job_template": {"path": "job-template.json", "sha256": sha256_bytes(self.template_path.read_bytes())}})
        self.contract["scope"]["formal_runtime_membership_sha256"] = digest("membership")
        self.contract["scope"]["method_registry_sha256"] = digest("registry")
        self.contract["protocol"]["sha256"] = digest("protocol")
        self.contract["gate_snapshot"]["sha256"] = digest("gate")
        self.contract["scheduler_fixture"]["sha256"] = digest("fixture")
        self.contract["implementation"]["artifact_sha256"] = {"src/data/run_blind_unseal_v10.py": runner_sha}
        self.contract["lifecycle"] = {"implementation_freeze_commit": "a" * 40, "final_template_sha256": sha256_bytes(self.template_path.read_bytes()), "artifact_blob_equals_worktree_required": True, "finalization_rule": "synthetic", "required_order": ["implementation_freeze_commit", "bsub_H", "raw_bjobs_capture", "final_template", "final_contract", "registration_receipt", "final_job_spec", "pre_review_clean_commit", "independent_review", "final_review_clean_commit", "bresume"]}
        self.contract_path = self.directory / "contract.json"; self.contract_path.write_text(json.dumps(self.contract), encoding="utf-8")
        self.bjobs = (bjobs_row() + "\n").encode(); self.global_bjobs = self.bjobs
        self.bjobs_al = ("Job <388761>, Status <PSUSP>\nSpecified CWD <" + BUNDLE + ">\n").encode()
        self.external = b'{"schema_version":"blind-runtime-unseal-control-manifest-v10"}\n'
        template_bytes, contract_bytes = self.template_path.read_bytes(), self.contract_path.read_bytes()
        self.registration = {"schema_version": "blind-runtime-unseal-registration-v10", "status": "REGISTERED_HELD", "job_id": "388761", "owner": "jiangchuanc", "submission_host": "host-a", "submit_time_raw": "Wed Sep 10 07:07:59", "reviewed_commit": "a" * 40, "contract_sha256": sha256_bytes(contract_bytes), "protocol_sha256": digest("protocol"), "gate_snapshot_sha256": digest("gate"), "runner_sha256": sha256_bytes(self.runner_path.read_bytes()), "job_template_sha256": sha256_bytes(template_bytes), "normalized_argv": ARGV, "normalized_argv_sha256": sha256_bytes(json.dumps(ARGV, separators=(",", ":")).encode()), "queue": "normal", "resource_request": "select[type==X]", "cwd": BUNDLE, "stdout_path": "/evidence/stdout.log", "stderr_path": "/evidence/stderr.log", "raw_bjobs_capture_sha256": sha256_bytes(self.bjobs), "raw_global_bjobs_capture_sha256": sha256_bytes(self.global_bjobs), "raw_bjobs_al_capture_sha256": sha256_bytes(self.bjobs_al), "external_control_manifest_path": "/temp/jiangchuanc/blind_runtime_unseal_v10_control_manifest.json", "external_control_manifest_sha256": sha256_bytes(self.external), "specified_cwd": BUNDLE}
        self.raw_registration = json.dumps(self.registration, sort_keys=True).encode()
        self.bhist, self.bacct = history("bhist"), history("bacct")
        self.stdout, self.stderr = b"aggregate failure only\n", b"sealed audit stopped\n"
        tool = sha256_bytes(("src/data/run_blind_unseal_v10.py:" + runner_sha + "\n").encode())
        receipt = {"schema_version": "blind-runtime-unseal-receipt-v10", "status": "FAIL", "formal_runtime_membership_sha256": self.contract["scope"]["formal_runtime_membership_sha256"], "method_registry_sha256": self.contract["scope"]["method_registry_sha256"], "tool_set_sha256": tool, "contract_sha256": self.registration["contract_sha256"], "circuits": [], "failure_code": "SEALED_AUDIT_FAILED"}
        receipt_raw = json.dumps(receipt, sort_keys=True).encode(); receipt_sha = sha256_bytes(receipt_raw)
        files = {"CONSUMED": json.dumps({"schema_version": "blind-runtime-unseal-consumed-v10", "status": "CONSUMED", "contract_sha256": self.registration["contract_sha256"], "tool_set_sha256": tool}).encode(), "receipt.json": receipt_raw, "receipt.json.sha256": (receipt_sha + "  receipt.json\n").encode(), "RELEASED": json.dumps({"schema_version": "blind-runtime-unseal-release-v10", "status": "RELEASED_RUNNER_VERIFIED_SCHEDULER_AUDIT_PENDING", "contract_sha256": self.registration["contract_sha256"], "receipt_sha256": receipt_sha}).encode()}
        for name, raw in files.items(): (self.directory / name).write_bytes(raw)
        self.job_path = self.directory / "final-job.json"
        job = {"schema_version": "blind-runtime-unseal-job-v10", "status": "REGISTERED_HELD", "contract_sha256": self.registration["contract_sha256"], "job_template_sha256": sha256_bytes(self.template_path.read_bytes()), "registration_receipt": "contracts/blind_runtime_unseal_registration_v10.json", "registration_receipt_sha256": sha256_bytes(self.raw_registration), "registration": {"job_id": "388761", "git_commit": self.registration["reviewed_commit"], "initial_scheduler_state": "PSUSP", "array_allowed": False, "retry_allowed": False, "requeue_allowed": False, "rerun_allowed": False, "command_argv": ARGV, "queue": "normal", "resource_request": "select[type==X]", "cwd": BUNDLE, "stdout_path": "/evidence/stdout.log", "stderr_path": "/evidence/stderr.log"}, "measurement_files": ["measurements.tsv"], "circuits": [{"name": "s9234", "root": "/blind/s9234"}], "output_root": str(self.directory)}
        self.job_path.write_text(json.dumps(job), encoding="utf-8")
        self.review_path = self.directory / "review.json"
        review = {"schema_version": "blind-unseal-independent-review-v10", "status": "PASS", "execution_allowed": True, "blind_data_read": False, "real_unseal_executed": False, "contract_sha256": self.registration["contract_sha256"], "registration_receipt_sha256": sha256_bytes(self.raw_registration), "job_spec_sha256": sha256_bytes(self.job_path.read_bytes()), "output_root": str(self.directory), "job_id": "388761", "reviewed_commit": self.registration["reviewed_commit"], "protocol_sha256": self.registration["protocol_sha256"], "gate_snapshot_sha256": self.registration["gate_snapshot_sha256"], "scheduler_fixture_manifest_sha256": digest("fixture"), "normalized_argv": ARGV, "raw_bjobs_capture_sha256": sha256_bytes(self.bjobs), "raw_global_bjobs_capture_sha256": sha256_bytes(self.global_bjobs), "raw_bjobs_al_capture_sha256": sha256_bytes(self.bjobs_al), "external_control_manifest_path": self.registration["external_control_manifest_path"], "external_control_manifest_sha256": sha256_bytes(self.external), "specified_cwd": BUNDLE, "queue": "normal", "resource_request": "select[type==X]", "cwd": BUNDLE, "stdout_path": "/evidence/stdout.log", "stderr_path": "/evidence/stderr.log", "reviewed_artifacts": self.contract["implementation"]["artifact_sha256"], "registration_validator_pass": True, "psusp_verified": True, "nonarray_verified": True, "no_retry": True, "no_requeue": True, "no_rerun": True, "no_blind_parse": True, "no_blind_output": True}
        self.review_path.write_text(json.dumps(review), encoding="utf-8")
        self.manifest = {"schema_version": "blind-runtime-unseal-failure-audit-v10", "status": "FAILED_SCHEDULER_AUDIT", "job_id": "388761", "scheduler_terminal": "EXIT", "exit_code": 1, "runner_receipt_status": "FAIL", "failure_code": "SEALED_AUDIT_FAILED", "circuits": [], "registration_receipt_sha256": sha256_bytes(self.raw_registration), "protocol_sha256": digest("protocol"), "raw_bjobs_capture_sha256": sha256_bytes(self.bjobs), "raw_global_bjobs_capture_sha256": sha256_bytes(self.global_bjobs), "raw_bjobs_al_capture_sha256": sha256_bytes(self.bjobs_al), "bhist_raw_capture_sha256": sha256_bytes(self.bhist), "bacct_raw_capture_sha256": sha256_bytes(self.bacct), "stdout_capture_sha256": sha256_bytes(self.stdout), "stderr_capture_sha256": sha256_bytes(self.stderr), "external_control_manifest_sha256": sha256_bytes(self.external), "final_job_spec_sha256": sha256_bytes(self.job_path.read_bytes()), "independent_review_sha256": sha256_bytes(self.review_path.read_bytes()), "evidence_file_map": failure_validator.EVIDENCE_FILE_MAP, "four_artifact_sha256": {name: sha256_bytes(raw) for name, raw in files.items()}}
        self.registration_check = mock.patch.object(failure_validator, "validate_registration", return_value=True); self.registration_check.start()

    def tearDown(self):
        self.registration_check.stop(); self.temp.cleanup()

    def validate(self, manifest=None, **changed):
        values = {"raw_bhist": self.bhist, "raw_bacct": self.bacct, "stdout": self.stdout, "stderr": self.stderr}
        values.update(changed)
        return validate_failure_audit(self.manifest if manifest is None else manifest, self.registration, self.raw_registration, self.bjobs, self.global_bjobs, self.bjobs_al, values["raw_bhist"], values["raw_bacct"], values["stdout"], values["stderr"], values.get("artifact_directory", str(self.directory)), "388761", str(self.template_path), str(self.contract_path), str(self.runner_path), self.external, values.get("job_path", str(self.job_path)), values.get("review_path", str(self.review_path)))

    def test_exact_exit1_fail_closeout_passes(self): self.assertTrue(self.validate())

    def test_success_semantics_and_nonempty_circuits_rejected(self):
        for key, value in (("status", "RELEASED_VERIFIED"), ("runner_receipt_status", "PASS"), ("scheduler_terminal", "DONE"), ("exit_code", 0), ("circuits", ["s9234"])):
            changed = copy.deepcopy(self.manifest); changed[key] = value
            with self.assertRaises(ValidationError): self.validate(changed)

    def test_hash_resume_retry_and_log_leaks_rejected(self):
        changed = copy.deepcopy(self.manifest); changed["stdout_capture_sha256"] = digest("drift")
        with self.assertRaises(ValidationError): self.validate(changed)
        with self.assertRaises(ValidationError): self.validate(raw_bhist=history("bhist", forbidden="Wed Sep 10 07:08:06: retry requested"))
        second_resume = self.bhist.replace(b"Waiting for scheduling after resumed.", b"Waiting for scheduling after resumed.\nWed Sep 10 07:08:06: Signal <CONT> requested by user.\nWed Sep 10 07:08:06: Waiting for scheduling after resumed.")
        with self.assertRaises(ValidationError): self.validate(raw_bhist=second_resume)
        exit2 = self.bhist.replace(b"Exited with exit code 1.", b"Exited with exit code 1.\nWed Sep 10 07:08:08: Exited with exit code 2.")
        with self.assertRaises(ValidationError): self.validate(raw_bhist=exit2)
        done_exit = self.bhist.replace(b"Exited with exit code 1.", b"Done successfully.\nWed Sep 10 07:08:08: Exited with exit code 1.")
        with self.assertRaises(ValidationError): self.validate(raw_bhist=done_exit)
        out_of_order = self.bhist.replace(b"Signal <CONT> requested by user.\nWed Sep 10 07:08:05: Waiting", b"Waiting\nWed Sep 10 07:08:05: Signal <CONT> requested by user.")
        with self.assertRaises(ValidationError): self.validate(raw_bhist=out_of_order)
        with self.assertRaises(ValidationError): self.validate(stdout=b"candidate=secret\n")
        with self.assertRaises(ValidationError): self.validate(raw_bhist=history("bhist", terminal="done"), raw_bacct=history("bacct", terminal="done"))

    def test_runner_receipt_or_four_artifact_drift_rejected(self):
        (self.directory / "receipt.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(ValidationError): self.validate()

    def test_artifact_directory_job_spec_and_review_binding_rejected(self):
        with self.assertRaises(ValidationError): self.validate(artifact_directory=str(self.directory / "arbitrary"))
        bad_job = self.directory / "bad-job.json"; bad_job.write_text(json.dumps({"registration": {"job_id": "388761"}, "output_root": str(self.directory), "registration_receipt_sha256": "0" * 64, "contract_sha256": self.registration["contract_sha256"]}), encoding="utf-8")
        with self.assertRaises(ValidationError): self.validate(job_path=str(bad_job))
        bad_review = self.directory / "bad-review.json"; bad_review.write_text(json.dumps({"job_id": "wrong", "job_spec_sha256": sha256_bytes(self.job_path.read_bytes()), "registration_receipt_sha256": sha256_bytes(self.raw_registration), "contract_sha256": self.registration["contract_sha256"]}), encoding="utf-8")
        with self.assertRaises(ValidationError): self.validate(review_path=str(bad_review))

    def test_forged_job_or_review_schema_status_and_gate_rejected(self):
        forged_job = json.loads(self.job_path.read_text(encoding="utf-8")); forged_job["extra"] = True
        path = self.directory / "forged-job.json"; path.write_text(json.dumps(forged_job), encoding="utf-8")
        with self.assertRaises(ValidationError): self.validate(job_path=str(path))
        wrong_status = json.loads(self.job_path.read_text(encoding="utf-8")); wrong_status["status"] = "DRAFT_NO_EXECUTION"
        path.write_text(json.dumps(wrong_status), encoding="utf-8")
        with self.assertRaises(ValidationError): self.validate(job_path=str(path))
        for key, value in (("status", "FAIL"), ("execution_allowed", False), ("no_retry", False)):
            changed = json.loads(self.review_path.read_text(encoding="utf-8")); changed[key] = value
            review_path = self.directory / ("bad-review-" + key + ".json"); review_path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(ValidationError): self.validate(review_path=str(review_path))

    def test_template_payload_fixture_and_reviewed_artifact_drift_rejected(self):
        for key, value in (("measurement_files", ["other.tsv"]), ("circuits", [])):
            changed = json.loads(self.job_path.read_text(encoding="utf-8")); changed[key] = value
            path = self.directory / ("drift-job-" + key + ".json"); path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(ValidationError): self.validate(job_path=str(path))
        fixture = json.loads(self.review_path.read_text(encoding="utf-8")); fixture["scheduler_fixture_manifest_sha256"] = digest("wrong-fixture")
        path = self.directory / "drift-review-fixture.json"; path.write_text(json.dumps(fixture), encoding="utf-8")
        with self.assertRaises(ValidationError): self.validate(review_path=str(path))
        artifacts = json.loads(self.review_path.read_text(encoding="utf-8")); artifacts["reviewed_artifacts"] = {"src/data/run_blind_unseal_v10.py": digest("wrong-runner")}
        path = self.directory / "drift-review-artifacts.json"; path.write_text(json.dumps(artifacts), encoding="utf-8")
        with self.assertRaises(ValidationError): self.validate(review_path=str(path))


if __name__ == "__main__": unittest.main()
