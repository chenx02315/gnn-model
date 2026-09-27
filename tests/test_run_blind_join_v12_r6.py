import json
import pathlib
import tempfile
import unittest

from src.data import run_blind_join_v12_r6 as runner


class RunBlindJoinV12R6Tests(unittest.TestCase):
    def test_fixed_argv_refuses_without_running(self):
        self.assertEqual(2, runner.main(["--attacker"]))

    def test_invalid_closeout_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "closeout.json"
            path.write_text(json.dumps({"schema_version": "bad"}), encoding="utf-8")
            original = runner.CLOSEOUT_RELATIVE
            runner.CLOSEOUT_RELATIVE = str(path)
            try:
                with self.assertRaises(runner.Refusal):
                    runner._validate_closeout()
            finally:
                runner.CLOSEOUT_RELATIVE = original

    def test_failed_envelope_is_aggregate_only(self):
        receipt = {"status": "FAIL", "circuits": [], "training_allowed": False}
        self.assertEqual([], receipt["circuits"])
        self.assertFalse(receipt["training_allowed"])

    def test_action_gate_requires_all_unique(self):
        row = {"executed_stage_reference_count": 1, "unique_runtime_join_count": 1,
               "missing_runtime_join_count": 0, "ambiguous_runtime_join_count": 0,
               "coverage_rate": 1.0, "eligible_action_count": 1,
               "all_unique_action_count": 0}
        self.assertNotEqual(row["eligible_action_count"], row["all_unique_action_count"])

    def test_receipt_binds_plan_path_and_driver_digest(self):
        plan = {"circuit": "s9234", "stage": "01_single_mode_full", "mode": "H",
                "run_id": "single", "source_marker": "H_single"}
        receipt = {"schema_version": "blind-runtime-recovery-attempt-receipt-v1",
                   "status": "PASS", "return_code": 0, "retry_count": 0,
                   "source_manifest_sha256": runner.SOURCE_MANIFEST_SHA256,
                   "attempt_index": 1, "circuit": "s9234", "stage": plan["stage"],
                   "mode": "H", "run_id": "single", "driver_log_sha256": "a" * 64,
                   "driver_log": runner.os.path.join(runner.RECOVERY_ROOT, "logs", "s9234",
                                                     "001_H_single.driver.log")}
        marker, index, digest = runner._validate_receipt_binding(
            receipt, "001_H_single.json", plan, 1)
        self.assertEqual(("H_single", 1, "a" * 64), (marker, index, digest))
        receipt["driver_log_sha256"] = "z" * 64
        with self.assertRaisesRegex(runner.Refusal, "RECOVERY_RECEIPT_LOG_DIGEST"):
            runner._validate_receipt_binding(receipt, "001_H_single.json", plan, 1)

    def test_receipt_rejects_plan_or_path_drift(self):
        plan = {"circuit": "s9234", "stage": "01_single_mode_full", "mode": "H",
                "run_id": "single", "source_marker": "H_single"}
        receipt = {"schema_version": "blind-runtime-recovery-attempt-receipt-v1",
                   "status": "PASS", "return_code": 0, "retry_count": 0,
                   "source_manifest_sha256": runner.SOURCE_MANIFEST_SHA256,
                   "attempt_index": 1, "circuit": "s9234", "stage": "wrong",
                   "mode": "H", "run_id": "single", "driver_log_sha256": "a" * 64,
                   "driver_log": runner.os.path.join(runner.RECOVERY_ROOT, "logs", "s9234",
                                                     "001_H_single.driver.log")}
        with self.assertRaisesRegex(runner.Refusal, "RECOVERY_RECEIPT_PLAN_BINDING"):
            runner._validate_receipt_binding(receipt, "001_H_single.json", plan, 1)

    def test_receipt_rejects_plan_index_drift(self):
        plan = {"circuit": "s9234", "stage": "01_single_mode_full", "mode": "H",
                "run_id": "single", "source_marker": "H_single"}
        receipt = {"schema_version": "blind-runtime-recovery-attempt-receipt-v1",
                   "status": "PASS", "return_code": 0, "retry_count": 0,
                   "source_manifest_sha256": runner.SOURCE_MANIFEST_SHA256,
                   "attempt_index": 2, "circuit": "s9234", "stage": plan["stage"],
                   "mode": "H", "run_id": "single", "driver_log_sha256": "a" * 64,
                   "driver_log": runner.os.path.join(runner.RECOVERY_ROOT, "logs", "s9234",
                                                     "002_H_single.driver.log")}
        with self.assertRaisesRegex(runner.Refusal, "RECOVERY_RECEIPT_SET"):
            runner._validate_receipt_binding(receipt, "002_H_single.json", plan, 1)


if __name__ == "__main__":
    unittest.main()
