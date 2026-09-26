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


class BlindRuntimeRecoveryExecutionV1Tests(unittest.TestCase):
    def test_checked_in_contract_is_design_only(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        document, digest = runner.validate_contract(root)
        self.assertEqual("DESIGN_REVIEW_PENDING_NO_EXECUTION", document["status"])
        self.assertFalse(document["authority"]["execution_authorized"])
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
        bad = valid_plan()[:-1]; mutations.append((bad, "PLAN_ENVELOPE_COUNTS"))
        for bad, code in mutations:
            payload = json.dumps(envelope(bad), sort_keys=True).encode("utf-8")
            with self.subTest(code=code), mock.patch.object(
                    runner, "PLAN_SHA256", hashlib.sha256(payload).hexdigest()):
                with self.assertRaisesRegex(runner.Refusal, code):
                    runner.validate_plan_bytes(payload, contract())

    def test_authority_tampering_and_execute_flag_refuse(self):
        document = contract()
        document["authority"]["execution_authorized"] = True
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
        document = {"schema_version": "blind-runtime-recovery-execution-v1-authorization",
                    "status": "PASS", "execution_allowed": True,
                    "contract_sha256": "c" * 64,
                    "plan_sha256": runner.PLAN_SHA256,
                    "runner_sha256": "r" * 64,
                    "reviewed_commit": "a" * 40, "lsf_job_id": "12345",
                    "no_retry": True, "no_requeue": True, "nonarray": True,
                    "training_allowed": False}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "authorization.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            result = runner.validate_authorization(path, "c" * 64, "r" * 64)
            self.assertEqual("12345", result["lsf_job_id"])
            document["no_retry"] = False
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            with self.assertRaisesRegex(runner.Refusal, "AUTHORIZATION_SCHEDULER"):
                runner.validate_authorization(path, "c" * 64, "r" * 64)


if __name__ == "__main__":
    unittest.main()
