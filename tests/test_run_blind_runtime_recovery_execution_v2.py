import copy
import datetime
import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

from src.data import run_blind_runtime_recovery_execution_v2 as runner


def repository_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_json(relative):
    with open(os.path.join(repository_root(), relative), "r", encoding="utf-8") as handle:
        return json.load(handle)


def file_sha256(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


class BlindRuntimeRecoveryExecutionV2Tests(unittest.TestCase):
    def test_checked_in_contract_is_v2_isolated_and_training_closed(self):
        document, digest = runner.validate_contract(repository_root())
        self.assertEqual("REVIEWED_EXECUTION_AUTHORIZED", document["status"])
        self.assertTrue(document["authority"]["execution_authorized"])
        self.assertTrue(document["authority"]["lsf_submission_allowed"])
        self.assertFalse(document["authority"]["training_allowed"])
        self.assertIn("/14_blind_runtime_recovery_execution_v2_inputs_r1/",
                      document["private_plan"]["path"])
        self.assertIn("/15_blind_runtime_recovery_execution_v2_r1_private",
                      document["output"]["root"])
        self.assertEqual(64, len(digest))

    def test_job_template_is_exactly_one_held_nonarray_nonretry_job(self):
        document = load_json(runner.JOB_TEMPLATE_RELATIVE)
        self.assertEqual("PSUSP", runner.validate_job_template(document)[
            "registration"]["initial_scheduler_state"])
        for field in ("array_allowed", "retry_allowed", "requeue_allowed",
                      "rerun_allowed"):
            bad = copy.deepcopy(document)
            bad["registration"][field] = True
            with self.subTest(field=field), self.assertRaises(runner.Refusal):
                runner.validate_job_template(bad)
        bad = copy.deepcopy(document)
        bad["lifecycle"]["register"] = "bsub twice"
        with self.assertRaisesRegex(runner.Refusal, "JOB_TEMPLATE_EXACT_LIFECYCLE"):
            runner.validate_job_template(bad)

    def _authorization_fixture(self, root):
        contract = load_json(runner.CONTRACT_RELATIVE)
        implementation = contract["implementation"]["artifact_sha256"]
        bjobs = os.path.join(root, "bjobs.txt")
        bjobs_al = os.path.join(root, "bjobs_al.txt")
        bsub = os.path.join(root, "bsub.txt")
        registration_command = os.path.join(root, "registration_command.txt")
        review = os.path.join(root, "independent_review.json")
        pre_resume_bjobs = os.path.join(root, "pre_resume_bjobs.txt")
        pre_resume_bjobs_al = os.path.join(root, "pre_resume_bjobs_al.txt")
        pre_resume_review = os.path.join(root, "pre_resume_review.json")
        with open(bjobs, "wb") as handle:
            handle.write(b"45678 PSUSP blind_rt_recovery_v2_r1 normal\n")
        with open(bjobs_al, "wb") as handle:
            handle.write((
                "Job <45678>, Job Name <blind_rt_recovery_v2_r1>, Status <PSUSP>, "
                "Queue <normal>, Command </bin/bash %s/src/data/"
                "launch_blind_runtime_recovery_execution_v2.sh>\n"
                "Submitted from host <test> with hold, CWD <%s>, Output File "
                "<%s/stdout.log>, Error File <%s/stderr.log>, Not Re-runnable;\n" %
                (runner.JOB_BUNDLE_ROOT, runner.JOB_BUNDLE_ROOT,
                 runner.JOB_REGISTRATION_ROOT, runner.JOB_REGISTRATION_ROOT)).encode("utf-8"))
        with open(bsub, "wb") as handle:
            handle.write(b"Job <45678> is submitted to queue <normal>.\n")
        command = (
            "bsub -H -rn -q normal -J blind_rt_recovery_v2_r1 -oo %s/stdout.log "
            "-eo %s/stderr.log /bin/bash %s/src/data/launch_blind_runtime_recovery_execution_v2.sh\n" %
            (runner.JOB_REGISTRATION_ROOT, runner.JOB_REGISTRATION_ROOT,
             runner.JOB_BUNDLE_ROOT))
        with open(registration_command, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(command)
        with open(pre_resume_bjobs, "wb") as handle:
            handle.write(b"45678 PSUSP blind_rt_recovery_v2_r1 normal\n")
        with open(pre_resume_bjobs_al, "wb") as handle:
            with open(bjobs_al, "rb") as source:
                handle.write(source.read())
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        registered_at = (now - datetime.timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        checked_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        document = {
            "schema_version": "blind-runtime-recovery-execution-v2-authorization",
            "status": "PASS", "execution_allowed": True,
            "registered_at_utc": registered_at,
            "contract_sha256": "c" * 64, "plan_sha256": runner.base.PLAN_SHA256,
            "runner_sha256": implementation[
                "src/data/run_blind_runtime_recovery_execution_v2.py"],
            "launcher_sha256": implementation[
                "src/data/launch_blind_runtime_recovery_execution_v2.sh"],
            "job_template_sha256": implementation[runner.JOB_TEMPLATE_RELATIVE],
            "bundle_manifest_sha256": contract["bundle_manifest"]["sha256"],
            "reviewed_commit": contract["bundle_manifest"]["reviewed_commit"],
            "lsf_job_id": "45678", "no_retry": True, "no_requeue": True,
            "nonarray": True, "training_allowed": False,
            "registration_review_path": review, "registration_review_sha256": "0" * 64,
            "bsub_path": bsub, "bsub_sha256": file_sha256(bsub),
            "registration_command_path": registration_command,
            "registration_command_sha256": file_sha256(registration_command),
            "bjobs_path": bjobs, "bjobs_sha256": file_sha256(bjobs),
            "bjobs_al_path": bjobs_al, "bjobs_al_sha256": file_sha256(bjobs_al),
            "pre_resume_review_path": pre_resume_review,
            "pre_resume_review_sha256": "0" * 64,
            "pre_resume_bjobs_path": pre_resume_bjobs,
            "pre_resume_bjobs_sha256": file_sha256(pre_resume_bjobs),
            "pre_resume_bjobs_al_path": pre_resume_bjobs_al,
            "pre_resume_bjobs_al_sha256": file_sha256(pre_resume_bjobs_al)}
        review_document = {
            "schema_version": "blind-runtime-recovery-execution-v2-registration-review",
            "status": "PASS", "registered_at_utc": registered_at,
            "lsf_job_id": "45678",
            "initial_scheduler_state": "PSUSP", "submission_count": 1,
            "contract_sha256": document["contract_sha256"],
            "plan_sha256": document["plan_sha256"],
            "runner_sha256": document["runner_sha256"],
            "launcher_sha256": document["launcher_sha256"],
            "job_template_sha256": document["job_template_sha256"],
            "bundle_manifest_sha256": document["bundle_manifest_sha256"],
            "reviewed_commit": document["reviewed_commit"],
            "no_retry": True, "no_requeue": True, "nonarray": True,
            "training_allowed": False, "bsub_path": bsub,
            "bsub_sha256": document["bsub_sha256"],
            "registration_command_path": registration_command,
            "registration_command_sha256": document["registration_command_sha256"],
            "bjobs_path": bjobs,
            "bjobs_sha256": document["bjobs_sha256"], "bjobs_al_path": bjobs_al,
            "bjobs_al_sha256": document["bjobs_al_sha256"]}
        with open(review, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(review_document, handle, sort_keys=True)
            handle.write("\n")
        document["registration_review_sha256"] = file_sha256(review)
        pre_resume_document = {
            "schema_version": "blind-runtime-recovery-execution-v2-pre-resume-review",
            "status": "PASS", "registered_at_utc": registered_at,
            "checked_at_utc": checked_at,
            "lsf_job_id": "45678", "scheduler_state": "PSUSP",
            "contract_sha256": document["contract_sha256"],
            "runner_sha256": document["runner_sha256"],
            "bundle_manifest_sha256": document["bundle_manifest_sha256"],
            "reviewed_commit": document["reviewed_commit"], "nonarray": True,
            "no_retry": True, "no_requeue": True, "training_allowed": False,
            "pre_resume_bjobs_path": pre_resume_bjobs,
            "pre_resume_bjobs_sha256": document["pre_resume_bjobs_sha256"],
            "pre_resume_bjobs_al_path": pre_resume_bjobs_al,
            "pre_resume_bjobs_al_sha256": document["pre_resume_bjobs_al_sha256"]}
        with open(pre_resume_review, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(pre_resume_document, handle, sort_keys=True)
            handle.write("\n")
        document["pre_resume_review_sha256"] = file_sha256(pre_resume_review)
        authorization = os.path.join(root, "authorization.json")
        with open(authorization, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        return (contract, document, authorization, review, bjobs, bjobs_al,
                bsub, registration_command, pre_resume_review,
                pre_resume_bjobs, pre_resume_bjobs_al)

    def test_lsf91_nonarray_zero_index_is_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            (contract, unused, authorization, review, bjobs, bjobs_al,
             bsub, command, pre_review, pre_bjobs, pre_bjobs_al) = \
                self._authorization_fixture(root)
            with mock.patch.object(runner, "REGISTRATION_REVIEW_PATH", review), \
                    mock.patch.object(runner, "BJOBS_CAPTURE_PATH", bjobs), \
                    mock.patch.object(runner, "BJOBS_AL_CAPTURE_PATH", bjobs_al), \
                    mock.patch.object(runner, "BSUB_CAPTURE_PATH", bsub), \
                    mock.patch.object(runner, "REGISTRATION_COMMAND_PATH", command), \
                    mock.patch.object(runner, "PRE_RESUME_REVIEW_PATH", pre_review), \
                    mock.patch.object(runner, "PRE_RESUME_BJOBS_PATH", pre_bjobs), \
                    mock.patch.object(runner, "PRE_RESUME_BJOBS_AL_PATH", pre_bjobs_al):
                for environment in (
                        {"LSB_JOBID": "45678", "LSB_JOBINDEX": "0"},
                        {"LSB_JOBID": "45678", "LSB_JOBINDEX": "0",
                         "LSB_JOBINDEX_END": "", "LSB_JOBINDEX_STEP": "0"}):
                    self.assertEqual("45678", runner.validate_authorization(
                        authorization, "c" * 64,
                        contract["implementation"]["artifact_sha256"][
                            "src/data/run_blind_runtime_recovery_execution_v2.py"],
                        contract, environment=environment)["lsf_job_id"])

    def test_array_and_unbound_scheduler_contexts_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            (contract, unused, authorization, review, bjobs, bjobs_al,
             bsub, command, pre_review, pre_bjobs, pre_bjobs_al) = \
                self._authorization_fixture(root)
            runner_sha = contract["implementation"]["artifact_sha256"][
                "src/data/run_blind_runtime_recovery_execution_v2.py"]
            cases = (
                ({"LSB_JOBID": "45678"}, "AUTHORIZATION_JOB_INDEX"),
                ({"LSB_JOBID": "45678", "LSB_JOBINDEX": "1"}, "AUTHORIZATION_JOB_INDEX"),
                ({"LSB_JOBID": "45678", "LSB_JOBINDEX": "-1"}, "AUTHORIZATION_JOB_INDEX"),
                ({"LSB_JOBID": "45678", "LSB_JOBINDEX": "abc"}, "AUTHORIZATION_JOB_INDEX"),
                ({"LSB_JOBID": "99999", "LSB_JOBINDEX": "0"}, "AUTHORIZATION_CURRENT_JOB"),
                ({"LSB_JOBID": "45678", "LSB_JOBINDEX": "0", "LSB_JOBINDEX_END": "2"},
                 "AUTHORIZATION_ARRAY_RANGE"),
                ({"LSB_JOBID": "45678", "LSB_JOBINDEX": "0", "LSB_JOBINDEX_STEP": "abc"},
                 "AUTHORIZATION_ARRAY_RANGE"))
            with mock.patch.object(runner, "REGISTRATION_REVIEW_PATH", review), \
                    mock.patch.object(runner, "BJOBS_CAPTURE_PATH", bjobs), \
                    mock.patch.object(runner, "BJOBS_AL_CAPTURE_PATH", bjobs_al), \
                    mock.patch.object(runner, "BSUB_CAPTURE_PATH", bsub), \
                    mock.patch.object(runner, "REGISTRATION_COMMAND_PATH", command), \
                    mock.patch.object(runner, "PRE_RESUME_REVIEW_PATH", pre_review), \
                    mock.patch.object(runner, "PRE_RESUME_BJOBS_PATH", pre_bjobs), \
                    mock.patch.object(runner, "PRE_RESUME_BJOBS_AL_PATH", pre_bjobs_al):
                for environment, code in cases:
                    with self.subTest(environment=environment), self.assertRaisesRegex(
                            runner.Refusal, code):
                        runner.validate_authorization(
                            authorization, "c" * 64, runner_sha, contract,
                            environment=environment)

    def test_authorization_capture_and_bundle_tampering_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            (contract, document, authorization, review, bjobs, bjobs_al,
             bsub, command, pre_review, pre_bjobs, pre_bjobs_al) = \
                self._authorization_fixture(root)
            runner_sha = contract["implementation"]["artifact_sha256"][
                "src/data/run_blind_runtime_recovery_execution_v2.py"]
            with mock.patch.object(runner, "REGISTRATION_REVIEW_PATH", review), \
                    mock.patch.object(runner, "BJOBS_CAPTURE_PATH", bjobs), \
                    mock.patch.object(runner, "BJOBS_AL_CAPTURE_PATH", bjobs_al), \
                    mock.patch.object(runner, "BSUB_CAPTURE_PATH", bsub), \
                    mock.patch.object(runner, "REGISTRATION_COMMAND_PATH", command), \
                    mock.patch.object(runner, "PRE_RESUME_REVIEW_PATH", pre_review), \
                    mock.patch.object(runner, "PRE_RESUME_BJOBS_PATH", pre_bjobs), \
                    mock.patch.object(runner, "PRE_RESUME_BJOBS_AL_PATH", pre_bjobs_al):
                bad = copy.deepcopy(document)
                bad["reviewed_commit"] = "f" * 40
                with open(authorization, "w", encoding="utf-8") as handle:
                    json.dump(bad, handle)
                with self.assertRaisesRegex(runner.Refusal, "AUTHORIZATION_BUNDLE_BINDING"):
                    runner.validate_authorization(
                        authorization, "c" * 64, runner_sha, contract,
                        environment={"LSB_JOBID": "45678", "LSB_JOBINDEX": "0"})
                with open(authorization, "w", encoding="utf-8") as handle:
                    json.dump(document, handle)
                with open(bjobs, "ab") as handle:
                    handle.write(b"tamper\n")
                with self.assertRaisesRegex(runner.Refusal, "AUTHORIZATION_CAPTURE_DIGEST"):
                    runner.validate_authorization(
                        authorization, "c" * 64, runner_sha, contract,
                        environment={"LSB_JOBID": "45678", "LSB_JOBINDEX": "0"})

    def test_scheduler_content_and_fresh_pre_resume_receipt_are_mandatory(self):
        with tempfile.TemporaryDirectory() as root:
            (contract, document, authorization, review, bjobs, bjobs_al,
             bsub, command, pre_review, pre_bjobs, pre_bjobs_al) = \
                self._authorization_fixture(root)
            runner_sha = document["runner_sha256"]
            patches = (
                mock.patch.object(runner, "REGISTRATION_REVIEW_PATH", review),
                mock.patch.object(runner, "BJOBS_CAPTURE_PATH", bjobs),
                mock.patch.object(runner, "BJOBS_AL_CAPTURE_PATH", bjobs_al),
                mock.patch.object(runner, "BSUB_CAPTURE_PATH", bsub),
                mock.patch.object(runner, "REGISTRATION_COMMAND_PATH", command),
                mock.patch.object(runner, "PRE_RESUME_REVIEW_PATH", pre_review),
                mock.patch.object(runner, "PRE_RESUME_BJOBS_PATH", pre_bjobs),
                mock.patch.object(runner, "PRE_RESUME_BJOBS_AL_PATH", pre_bjobs_al))
            with patches[0], patches[1], patches[2], patches[3], patches[4], \
                    patches[5], patches[6], patches[7]:
                with open(bjobs, "wb") as handle:
                    handle.write(b"45678 RUN blind_rt_recovery_v2_r1 normal\n")
                document["bjobs_sha256"] = file_sha256(bjobs)
                with open(authorization, "w", encoding="utf-8") as handle:
                    json.dump(document, handle)
                with self.assertRaisesRegex(runner.Refusal,
                                            "AUTHORIZATION_SCHEDULER_CAPTURE"):
                    runner.validate_authorization(
                        authorization, "c" * 64, runner_sha, contract,
                        environment={"LSB_JOBID": "45678", "LSB_JOBINDEX": "0"})
                with open(bjobs, "wb") as handle:
                    handle.write(b"45678 PSUSP blind_rt_recovery_v2_r1 normal\n")
                document["bjobs_sha256"] = file_sha256(bjobs)
                with open(authorization, "w", encoding="utf-8") as handle:
                    json.dump(document, handle)
                os.remove(pre_review)
                with self.assertRaises(OSError):
                    runner.validate_authorization(
                        authorization, "c" * 64, runner_sha, contract,
                        environment={"LSB_JOBID": "45678", "LSB_JOBINDEX": "0"})

    def test_scheduler_detail_identity_and_stale_review_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            (contract, document, authorization, review, bjobs, bjobs_al,
             bsub, command, pre_review, pre_bjobs, pre_bjobs_al) = \
                self._authorization_fixture(root)
            runner_sha = document["runner_sha256"]
            patches = (
                mock.patch.object(runner, "REGISTRATION_REVIEW_PATH", review),
                mock.patch.object(runner, "BJOBS_CAPTURE_PATH", bjobs),
                mock.patch.object(runner, "BJOBS_AL_CAPTURE_PATH", bjobs_al),
                mock.patch.object(runner, "BSUB_CAPTURE_PATH", bsub),
                mock.patch.object(runner, "REGISTRATION_COMMAND_PATH", command),
                mock.patch.object(runner, "PRE_RESUME_REVIEW_PATH", pre_review),
                mock.patch.object(runner, "PRE_RESUME_BJOBS_PATH", pre_bjobs),
                mock.patch.object(runner, "PRE_RESUME_BJOBS_AL_PATH", pre_bjobs_al))
            with patches[0], patches[1], patches[2], patches[3], patches[4], \
                    patches[5], patches[6], patches[7]:
                with open(bjobs_al, "rb") as handle:
                    original = handle.read()
                for old, new in ((b"Not Re-runnable", b"Re-runnable"),
                                 (b"/bin/bash", b"/bin/false"),
                                 (b"CWD <", b"CWD </wrong/")):
                    with open(bjobs_al, "wb") as handle:
                        handle.write(original.replace(old, new, 1))
                    document["bjobs_al_sha256"] = file_sha256(bjobs_al)
                    with open(authorization, "w", encoding="utf-8") as handle:
                        json.dump(document, handle)
                    with self.subTest(replacement=new), self.assertRaisesRegex(
                            runner.Refusal, "AUTHORIZATION_SCHEDULER_CAPTURE"):
                        runner.validate_authorization(
                            authorization, "c" * 64, runner_sha, contract,
                            environment={"LSB_JOBID": "45678", "LSB_JOBINDEX": "0"})
                with open(bjobs_al, "wb") as handle:
                    handle.write(original)
                document["bjobs_al_sha256"] = file_sha256(bjobs_al)
                with open(authorization, "w", encoding="utf-8") as handle:
                    json.dump(document, handle)
                stale_now = datetime.datetime.now(datetime.timezone.utc) + \
                    datetime.timedelta(hours=1)
                with self.assertRaisesRegex(runner.Refusal,
                                            "PRE_RESUME_REVIEW_STALE"):
                    runner.validate_pre_resume_review(
                        pre_review, document, "c" * 64, runner_sha,
                        now_utc=stale_now)

    def test_v1_failure_is_bound_nonreusable(self):
        document = load_json(runner.CONTRACT_RELATIVE)
        self.assertEqual({
            "path": runner.V1_FAILURE_RELATIVE,
            "sha256": "13bf448de65fd3f301d9f29551f1c6051a46437383f0e52c8a3ab7325534894a",
            "job_id": "388791", "attempts_started": 0,
            "reuse_allowed": False}, document["prior_failure"])


if __name__ == "__main__":
    unittest.main()
