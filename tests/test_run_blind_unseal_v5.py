from __future__ import print_function

import os
import sys
import tempfile
import unittest
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src", "data"))

import run_blind_unseal_v5 as runner


def put(path, text):
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


class BlindUnsealV5RunnerTest(unittest.TestCase):
    def test_missing_review_refuses_before_output_creation(self):
        contract_sha = "a" * 64
        with tempfile.TemporaryDirectory() as work:
            output_root = os.path.join(work, "sealed-output")
            with mock.patch.object(runner, "validate_before_consumption",
                                   side_effect=runner.PreflightError("INDEPENDENT_REVIEW_NOT_PASS")):
                with self.assertRaises(runner.PreflightError):
                    runner.execute(work)
            self.assertFalse(os.path.lexists(output_root))
            with self.assertRaises(runner.PreflightError) as failure:
                runner.validate_review({}, contract_sha, {})
            self.assertEqual("INDEPENDENT_REVIEW_NOT_PASS", str(failure.exception))

    def test_real_bundle_without_pass_review_is_refused(self):
        with self.assertRaisesRegex(runner.PreflightError,
                                    "INDEPENDENT_REVIEW_(RECEIPT_MISSING|NOT_PASS)"):
            runner.validate_before_consumption(ROOT)

    def test_stale_or_forged_review_bindings_are_refused(self):
        artifacts = {"src/data/tool.py": "b" * 64}
        base = {
            "status": "PASS",
            "execution_allowed": True,
            "contract_sha256": "a" * 64,
            "reviewed_commit": "c" * 40,
            "reviewed_artifacts": artifacts,
            "blind_data_read": False,
            "real_unseal_executed": False,
        }
        stale = dict(base)
        stale["contract_sha256"] = "d" * 64
        with self.assertRaisesRegex(runner.PreflightError, "REVIEW_CONTRACT_DIGEST"):
            runner.validate_review(stale, "a" * 64, artifacts)
        forged = dict(base)
        forged["reviewed_artifacts"] = {"src/data/tool.py": "e" * 64}
        with self.assertRaisesRegex(runner.PreflightError, "REVIEW_ARTIFACT_DIGESTS"):
            runner.validate_review(forged, "a" * 64, artifacts)

    def test_missing_result_path_remains_in_r07_denominator(self):
        rows = [
            {"stage": "02_hf_coarse", "join_status": "UNIQUE"},
            {"stage": "03_hmf_coarse", "join_status": "MISSING_RESULT_PATH"},
            {"stage": "04_integer_refine", "join_status": "NOT_RUN"},
            {"stage": "05_repeatability", "join_status": "NO_RESULT_PATH"},
        ]
        summary = runner.summarize_join_rows(rows)
        self.assertEqual(2, summary["executed_stage_reference_count"])
        self.assertEqual(1, summary["missing_runtime_join_count"])
        self.assertEqual(0.5, summary["coverage_rate"])

    def test_measurement_and_log_inventory_detect_substitution(self):
        with tempfile.TemporaryDirectory() as work:
            measurements = os.path.join(work, "measurements")
            logs = os.path.join(work, "logs")
            put(os.path.join(measurements, "02_hf_coarse", "measurements.tsv"), "original\n")
            put(os.path.join(logs, "a.driver.log"), "original\n")
            measurement_first = runner.inventory_digest(
                measurements, ["02_hf_coarse/measurements.tsv"], "")
            log_first, count_first = runner.driver_log_inventory(logs)
            put(os.path.join(measurements, "02_hf_coarse", "measurements.tsv"), "substituted\n")
            put(os.path.join(logs, "a.driver.log"), "substituted\n")
            measurement_second = runner.inventory_digest(
                measurements, ["02_hf_coarse/measurements.tsv"], "")
            log_second, count_second = runner.driver_log_inventory(logs)
            self.assertNotEqual(measurement_first, measurement_second)
            self.assertNotEqual(log_first, log_second)
            self.assertEqual(1, count_first)
            self.assertEqual(count_first, count_second)

    def test_output_root_rejects_alias_and_nonempty_directory(self):
        with tempfile.TemporaryDirectory() as work:
            occupied = os.path.join(work, "occupied")
            os.mkdir(occupied)
            put(os.path.join(occupied, "existing"), "x")
            with self.assertRaisesRegex(runner.PreflightError, "OUTPUT_ROOT_NOT_EMPTY"):
                runner.prepare_output_directory(occupied)
            alias = os.path.join(work, "alias")
            with mock.patch.object(runner.os.path, "lexists", return_value=True), \
                    mock.patch.object(runner.os.path, "islink", return_value=True):
                with self.assertRaisesRegex(runner.PreflightError,
                                            "OUTPUT_ROOT_NOT_DEDICATED_DIRECTORY"):
                    runner.prepare_output_directory(alias)

    def test_release_verification_requires_all_four_artifacts(self):
        with tempfile.TemporaryDirectory() as work:
            receipt = {"contract_sha256": "c" * 64, "status": "PASS"}
            runner.durable_exclusive_write(os.path.join(work, "CONSUMED"), b"consumed\n")
            runner.release(work, receipt)
            self.assertTrue(runner.verify_release(work))
            os.unlink(os.path.join(work, "RELEASED"))
            self.assertFalse(runner.verify_release(work))

    def test_release_verification_rejects_tampered_sidecar_and_marker(self):
        receipt = {"contract_sha256": "c" * 64, "status": "PASS"}
        with tempfile.TemporaryDirectory() as work:
            runner.durable_exclusive_write(os.path.join(work, "CONSUMED"), b"consumed\n")
            runner.release(work, receipt)
            put(os.path.join(work, "receipt.json.sha256"), "0" * 64 + "  receipt.json\n")
            self.assertFalse(runner.verify_release(work))
        with tempfile.TemporaryDirectory() as work:
            runner.durable_exclusive_write(os.path.join(work, "CONSUMED"), b"consumed\n")
            runner.release(work, receipt)
            put(os.path.join(work, "RELEASED"),
                '{"schema_version":"blind-runtime-unseal-release-v5",'
                '"status":"RELEASED","receipt_sha256":"' + "0" * 64 + '"}')
            self.assertFalse(runner.verify_release(work))

    def test_action_key_ignores_f_and_outcomes(self):
        with tempfile.TemporaryDirectory() as work:
            put(os.path.join(work, "02_hf_coarse", "measurements.tsv"),
                "h_patterns\tm_patterns\tf_patterns\tdetected_faults\n10\t0\t4\t99\n")
            put(os.path.join(work, "03_hmf_coarse", "measurements.tsv"),
                "h_patterns\tm_patterns\tf_patterns\tdetected_faults\n10\t3\t2\t100\n")
            put(os.path.join(work, "04_integer_refine", "hf_measurements.tsv"),
                "h_patterns\tm_patterns\tf_patterns\tdetected_faults\n10\t0\t9\t1\n")
            put(os.path.join(work, "04_integer_refine", "hmf_measurements.tsv"),
                "h_patterns\tm_patterns\tf_patterns\tdetected_faults\n10\t3\t8\t2\n")
            first, _ = runner.canonical_action_space(work, "x")
            put(os.path.join(work, "02_hf_coarse", "measurements.tsv"),
                "h_patterns\tm_patterns\tf_patterns\tdetected_faults\n10\t0\t99\t0\n")
            second, _ = runner.canonical_action_space(work, "x")
            self.assertEqual(first, second)

    def test_exclusive_consumed_marker_refuses_replay(self):
        with tempfile.TemporaryDirectory() as work:
            marker = os.path.join(work, "CONSUMED")
            runner.durable_exclusive_write(marker, b"first\n")
            with self.assertRaises(FileExistsError):
                runner.durable_exclusive_write(marker, b"replay\n")
            with open(marker, "rb") as stream:
                self.assertEqual(b"first\n", stream.read())


if __name__ == "__main__":
    unittest.main()
