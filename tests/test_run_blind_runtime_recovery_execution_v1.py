import copy
import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

from src.data import run_blind_runtime_recovery_execution_v1 as runner


def row(circuit, stage, mode, run_id, limit, dependency="", kind=""):
    return {"circuit": circuit, "stage": stage, "mode": mode,
            "run_id": run_id, "source_marker": mode + "_" + run_id,
            "pattern_limit": limit, "run_kind": kind,
            "depends_on_h_marker": dependency}


def valid_plan():
    result = [row("s9234", "01_single_mode_full", "H",
                  "s9234_H_full_phase3_v2", 64, kind="full")]
    for index in range(12):
        result.append(row("s38584", "02_hf_coarse", "H",
                          "s38584_HF_src_H_%dpct_p%d_v0_1" % (index + 1, index + 1),
                          index + 1))
    h_rows = []
    for index in range(8):
        run_id = "s38584_HMF_src_H_%dpct_p%d_v0_1" % (index + 1, index + 1)
        marker = "H_" + run_id
        h_rows.append((marker, run_id))
        result.append(row("s38584", "03_hmf_coarse", "H", run_id, index + 1))
    for index in range(22):
        marker, unused = h_rows[index % len(h_rows)]
        run_id = "s38584_HMF_H_%dpct_p%d_M_%dpct_p%d_v0_1" % (
            index % 8 + 1, index % 8 + 1, index + 1, index + 1)
        result.append(row("s38584", "03_hmf_coarse", "M", run_id,
                          index + 1, dependency=marker, kind="limited"))
    result.append(row("wb_dma", "01_single_mode_full", "H",
                      "wb_dma_H_full_phase4_v2", 128, kind="full"))
    return result


def envelope(attempts):
    return {"schema_version": "blind-runtime-recovery-plan-v1",
            "status": "PLAN_ONLY", "training_allowed": False,
            "circuits": [
                {"circuit": circuit,
                 "attempts": [item for item in attempts if item["circuit"] == circuit]}
                for circuit in ("s9234", "s38584", "wb_dma")]}


def contract():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, runner.CONTRACT_RELATIVE), "r", encoding="utf-8") as handle:
        return json.load(handle)


def file_sha256(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


class BlindRuntimeRecoveryExecutionV1Tests(unittest.TestCase):
    def test_job_template_is_exactly_held_nonarray_nonretry(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, runner.JOB_TEMPLATE_RELATIVE),
                  "r", encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertEqual("PSUSP",
                         runner.validate_job_template(document)["registration"][
                             "initial_scheduler_state"])
        mutations = []
        for field in ("array_allowed", "retry_allowed", "requeue_allowed",
                      "rerun_allowed"):
            bad = copy.deepcopy(document)
            bad["registration"][field] = True
            mutations.append(bad)
        bad = copy.deepcopy(document)
        bad["registration"]["initial_scheduler_state"] = "PEND"
        mutations.append(bad)
        bad = copy.deepcopy(document)
        bad["lifecycle"]["register"] = "bsub twice"
        mutations.append(bad)
        for bad in mutations:
            with self.subTest(bad=bad), self.assertRaises(runner.Refusal):
                runner.validate_job_template(bad)

    def test_checked_in_contract_is_authorized_but_training_closed(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        document, digest = runner.validate_contract(root)
        self.assertEqual("REVIEWED_EXECUTION_AUTHORIZED", document["status"])
        self.assertTrue(document["authority"]["execution_authorized"])
        self.assertTrue(document["authority"]["lsf_submission_allowed"])
        self.assertFalse(document["authority"]["training_allowed"])
        self.assertEqual(64, len(digest))

    def test_valid_plan_builds_h_before_m_exact_commands(self):
        plan = valid_plan()
        manifest = runner.build_command_manifest(plan, contract())
        self.assertEqual(44, len(manifest))
        self.assertTrue(all(item["argv"][:2] == ["/usr/bin/time", "-v"]
                            for item in manifest))
        m_item = next(item for item in manifest if item["mode"] == "M")
        self.assertIn("/03_hmf_coarse/H_", m_item["status_file"].replace("\\", "/"))
        self.assertEqual(m_item["status_file"], m_item["environment"]["STATUS_FILE"])
        self.assertTrue(m_item["argv"][-1].endswith("stage_mapped_incremental_atpg_no_tsdb.tcl"))
        self.assertTrue(all("13_blind_runtime_recovery_execution_v1_private" in item["output"]
                            for item in manifest))

    def test_plan_digest_count_schema_and_dependency_fail_closed(self):
        payload = json.dumps(envelope(valid_plan()), sort_keys=True).encode("utf-8")
        with mock.patch.object(runner, "PLAN_SHA256", hashlib.sha256(payload).hexdigest()):
            self.assertEqual(44, len(runner.validate_plan_bytes(payload, contract())))
        mutations = []
        bad = valid_plan(); bad[0]["runtime"] = 1; mutations.append((bad, "PLAN_ROW_SCHEMA"))
        bad = valid_plan(); bad[-1]["source_marker"] = "H_wrong"; mutations.append((bad, "PLAN_SOURCE_MARKER"))
        bad = valid_plan()
        next(item for item in bad if item["mode"] == "M")["depends_on_h_marker"] = "H_missing"
        mutations.append((bad, "M_DEPENDENCY_ORDER"))
        bad = valid_plan()
        hf_h = next(item for item in bad if item["stage"] == "02_hf_coarse")
        next(item for item in bad if item["mode"] == "M")["depends_on_h_marker"] = hf_h["source_marker"]
        mutations.append((bad, "M_DEPENDENCY_STAGE"))
        bad = valid_plan()
        hf_h = next(item for item in bad if item["stage"] == "02_hf_coarse")
        hmf_h = next(item for item in bad if item["stage"] == "03_hmf_coarse" and item["mode"] == "H")
        hmf_h["run_id"] = hf_h["run_id"]
        hmf_h["source_marker"] = hf_h["source_marker"]
        mutations.append((bad, "H_MARKER_AMBIGUOUS"))
        bad = valid_plan()[:-1]; mutations.append((bad, "PLAN_ENVELOPE_COUNTS"))
        for bad, code in mutations:
            payload = json.dumps(envelope(bad), sort_keys=True).encode("utf-8")
            with self.subTest(code=code), mock.patch.object(
                    runner, "PLAN_SHA256", hashlib.sha256(payload).hexdigest()):
                with self.assertRaisesRegex(runner.Refusal, code):
                    runner.validate_plan_bytes(payload, contract())

    def test_authority_tampering_and_execute_flag_refuse(self):
        document = contract()
        document["authority"]["training_allowed"] = True
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, runner.CONTRACT_RELATIVE)
            os.makedirs(os.path.dirname(path))
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            with self.assertRaisesRegex(runner.Refusal, "CONTRACT_AUTHORITY"):
                runner.validate_contract(tmp)
        with mock.patch.object(runner, "validate_only", return_value={}):
            self.assertEqual(2, runner.main(["--plan", "unused", "--execute"]))

    def test_full_m_omits_pattern_limit_and_outputs_are_unique(self):
        plan = valid_plan()
        m_index = next(i for i, item in enumerate(plan) if item["mode"] == "M")
        plan[m_index]["run_kind"] = "full"
        manifest = runner.build_command_manifest(plan, contract())
        self.assertNotIn("PATTERN_LIMIT", manifest[m_index]["environment"])
        self.assertEqual(len(manifest), len(set(item["output"] for item in manifest)))

    def test_external_authorization_is_exactly_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            bjobs = os.path.join(tmp, "bjobs.txt")
            bjobs_al = os.path.join(tmp, "bjobs_al.txt")
            review = os.path.join(tmp, "independent_review.json")
            for path, payload in ((bjobs, b"JOBID USER STAT\n12345 user PSUSP\n"),
                                  (bjobs_al, b"Job <12345>, Job Name <blind_rt_recovery_v1_r1>, PSUSP\n")):
                with open(path, "wb") as handle:
                    handle.write(payload)
            checked_contract = contract()
            implementation = checked_contract["implementation"]["artifact_sha256"]
            document = {
                "schema_version": "blind-runtime-recovery-execution-v1-authorization",
                "status": "PASS", "execution_allowed": True,
                "contract_sha256": "c" * 64, "plan_sha256": runner.PLAN_SHA256,
                "runner_sha256": "r" * 64,
                "launcher_sha256": implementation[
                    "src/data/launch_blind_runtime_recovery_execution_v1.sh"],
                "job_template_sha256": implementation[runner.JOB_TEMPLATE_RELATIVE],
                "bundle_manifest_sha256": checked_contract["bundle_manifest"]["sha256"],
                "reviewed_commit": checked_contract["bundle_manifest"]["reviewed_commit"],
                "lsf_job_id": "12345",
                "no_retry": True, "no_requeue": True, "nonarray": True,
                "training_allowed": False, "registration_review_path": review,
                "registration_review_sha256": "0" * 64,
                "bjobs_path": bjobs,
                "bjobs_sha256": file_sha256(bjobs),
                "bjobs_al_path": bjobs_al,
                "bjobs_al_sha256": file_sha256(bjobs_al)}
            review_document = {
                "schema_version": "blind-runtime-recovery-execution-v1-registration-review",
                "status": "PASS", "lsf_job_id": "12345",
                "initial_scheduler_state": "PSUSP", "submission_count": 1,
                "contract_sha256": "c" * 64, "plan_sha256": runner.PLAN_SHA256,
                "runner_sha256": "r" * 64,
                "launcher_sha256": document["launcher_sha256"],
                "job_template_sha256": document["job_template_sha256"],
                "bundle_manifest_sha256": document["bundle_manifest_sha256"],
                "reviewed_commit": document["reviewed_commit"],
                "no_retry": True, "no_requeue": True, "nonarray": True,
                "training_allowed": False, "bjobs_path": bjobs,
                "bjobs_sha256": document["bjobs_sha256"],
                "bjobs_al_path": bjobs_al,
                "bjobs_al_sha256": document["bjobs_al_sha256"]}
            with open(review, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(review_document, handle, sort_keys=True)
                handle.write("\n")
            document["registration_review_sha256"] = file_sha256(review)
            path = os.path.join(tmp, "authorization.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            patches = (mock.patch.object(runner, "REGISTRATION_REVIEW_PATH", review),
                       mock.patch.object(runner, "BJOBS_CAPTURE_PATH", bjobs),
                       mock.patch.object(runner, "BJOBS_AL_CAPTURE_PATH", bjobs_al))
            with patches[0], patches[1], patches[2]:
                result = runner.validate_authorization(
                    path, "c" * 64, "r" * 64, checked_contract,
                    environment={"LSB_JOBID": "12345"})
                self.assertEqual("12345", result["lsf_job_id"])
                for mutation, code, environment in (
                        (("no_retry", False), "AUTHORIZATION_SCHEDULER",
                         {"LSB_JOBID": "12345"}),
                        (("lsf_job_id", "54321"), "REGISTRATION_REVIEW_BINDING",
                         {"LSB_JOBID": "54321"}),
                        (("reviewed_commit", "f" * 40),
                         "AUTHORIZATION_BUNDLE_BINDING", {"LSB_JOBID": "12345"}),
                        (("bundle_manifest_sha256", "e" * 64),
                         "AUTHORIZATION_BUNDLE_BINDING", {"LSB_JOBID": "12345"}),
                        (None, "AUTHORIZATION_CURRENT_JOB", {"LSB_JOBID": "99999"}),
                        (None, "AUTHORIZATION_CURRENT_JOB", {}),
                        (None, "AUTHORIZATION_ARRAY_JOB",
                         {"LSB_JOBID": "12345", "LSB_JOBINDEX": "1"})):
                    bad = copy.deepcopy(document)
                    if mutation:
                        bad[mutation[0]] = mutation[1]
                    with open(path, "w", encoding="utf-8") as handle:
                        json.dump(bad, handle)
                    with self.subTest(code=code), self.assertRaisesRegex(
                            runner.Refusal, code):
                        runner.validate_authorization(
                            path, "c" * 64, "r" * 64, checked_contract,
                            environment=environment)
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(document, handle)
                with open(bjobs, "ab") as handle:
                    handle.write(b"tamper\n")
                with self.assertRaisesRegex(runner.Refusal,
                                            "AUTHORIZATION_CAPTURE_DIGEST"):
                    runner.validate_authorization(
                        path, "c" * 64, "r" * 64, checked_contract,
                        environment={"LSB_JOBID": "12345"})
                with open(bjobs, "wb") as handle:
                    handle.write(b"JOBID USER STAT\n12345 user PSUSP\n")
                os.remove(review)
                with self.assertRaises(OSError):
                    runner.validate_authorization(
                        path, "c" * 64, "r" * 64, checked_contract,
                        environment={"LSB_JOBID": "12345"})

    def test_process_start_failure_writes_fail_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "logs", "s9234"))
            os.makedirs(os.path.join(tmp, "receipts"))
            workspace = os.path.join(tmp, "workspace")
            os.makedirs(workspace)
            item = {"attempt_index": 1, "circuit": "s9234",
                    "stage": "01_single_mode_full", "mode": "H",
                    "run_id": "s9234_H_full_phase3_v2",
                    "output": os.path.join(workspace, "out"), "status_file": "",
                    "environment": {}, "argv": ["missing"], "workspace": workspace,
                    "driver_log": os.path.join(tmp, "logs", "s9234", "driver.log")}
            document = contract()
            document["output"]["root"] = tmp
            with mock.patch.object(runner.subprocess, "Popen", side_effect=OSError("start")):
                with self.assertRaises(OSError):
                    runner.execute_manifest([item], document,
                                            {"s9234": {"TOP_MODULE": "s9234",
                                                       "CELL_LIBRARY": "celllib"}}, "m" * 64)
            receipt = os.path.join(tmp, "receipts", "001_H_s9234_H_full_phase3_v2.json")
            self.assertTrue(os.path.isfile(receipt))
            with open(receipt, "r", encoding="utf-8") as handle:
                result = json.load(handle)
            self.assertEqual(("FAIL", None, 0),
                             (result["status"], result["return_code"], result["retry_count"]))


if __name__ == "__main__":
    unittest.main()
