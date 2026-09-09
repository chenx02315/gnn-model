from __future__ import print_function
import json
import os
import sys
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src", "data"))
import run_blind_unseal_v4 as runner


def put(path, text):
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


class BlindUnsealV4RunnerTest(unittest.TestCase):
    def test_summary_counts_only_formal_executed_references(self):
        rows = [
            {"stage": "02_hf_coarse", "join_status": "UNIQUE"},
            {"stage": "03_hmf_coarse", "join_status": "MISSING"},
            {"stage": "04_integer_refine", "join_status": "AMBIGUOUS"},
            {"stage": "04_integer_refine", "join_status": "NOT_RUN"},
            {"stage": "05_repeatability", "join_status": "UNIQUE"},
        ]
        result = runner.summarize_join_rows(rows)
        self.assertEqual(3, result["executed_stage_reference_count"])
        self.assertEqual(1, result["unique_runtime_join_count"])
        self.assertEqual(1, result["missing_runtime_join_count"])
        self.assertEqual(1, result["ambiguous_runtime_join_count"])

    def test_action_hash_deduplicates_hf_hmf_and_ignores_outcomes(self):
        with tempfile.TemporaryDirectory() as work:
            put(os.path.join(work, "02_hf_coarse", "measurements.tsv"),
                "h_patterns\tm_patterns\tf_patterns\tdetected_faults\n10\t0\t4\t99\n")
            put(os.path.join(work, "04_integer_refine", "hf_measurements.tsv"),
                "h_patterns\tm_patterns\tf_patterns\tdetected_faults\n10\t0\t9\t100\n")
            put(os.path.join(work, "03_hmf_coarse", "measurements.tsv"),
                "h_patterns\tm_patterns\tf_patterns\tdetected_faults\n10\t3\t2\t100\n")
            first, _artifacts = runner.canonical_action_space(work, "x")
            put(os.path.join(work, "02_hf_coarse", "measurements.tsv"),
                "h_patterns\tm_patterns\tf_patterns\tdetected_faults\n10\t0\t99\t1\n")
            second, _artifacts = runner.canonical_action_space(work, "x")
            self.assertEqual(first, second)

    def test_private_join_kernel_preserves_mode_aware_not_run_semantics(self):
        with tempfile.TemporaryDirectory() as work:
            put(os.path.join(work, "02_hf_coarse", "measurements.tsv"),
                "h_patterns\tm_patterns\th_result\tf_result\tresult_status\n"
                "10\t0\t/result/H_exact\t/stale/F_old\tTARGET_BEFORE_F\n")
            split = {"formal_runtime_membership": {"BLIND_TEST": [
                {"circuit": "x", "family": "f"}]}}
            attempts = [{"circuit": "x", "mode": "H", "run_id": "different",
                         "source_log_path": "/logs/H_exact.driver.log"},
                        {"circuit": "x", "mode": "F", "run_id": "F_old",
                         "source_log_path": "/logs/F_old.driver.log"}]
            rows = runner.build_blind_join_statuses("x", work, attempts, split)
            by_status = [row["join_status"] for row in rows]
            self.assertEqual(["UNIQUE", "NOT_RUN"], by_status)

    def fixture_args(self, work):
        contract = os.path.join(ROOT, "contracts", "blind_runtime_unseal_v4.json")
        split = os.path.join(ROOT, "contracts", "data_split_v1.json")
        registry = os.path.join(ROOT, "contracts", "recommendation_method_registry_v1.json")
        contract_sha = runner.sha256_file(contract)
        preflight = os.path.join(work, "preflight.json")
        put(preflight, json.dumps({"status": "PASS", "contract_sha256": contract_sha}))
        circuits = []
        families = {"s9234": "iscas89_s9234", "s38584": "iscas89_s38584",
                    "wb_dma": "iwls_wb_dma"}
        for circuit in ("s9234", "s38584", "wb_dma"):
            measurements = os.path.join(work, circuit, "measurements")
            logs = os.path.join(work, circuit, "logs")
            os.makedirs(logs)
            put(os.path.join(measurements, "02_hf_coarse", "measurements.tsv"),
                "h_patterns\tm_patterns\tf_patterns\n10\t0\t4\n")
            circuits.append({
                "circuit": circuit, "family": families[circuit],
                "measurements_root": measurements, "log_root": logs,
                "evidence_root": work, "phase": "p", "cohort": "c",
                "environment_cohort": "environment_unverified",
                "inventory_manifest_sha256": "a" * 64
            })
        job = os.path.join(work, "job.json")
        put(job, json.dumps({"contract_sha256": contract_sha,
                             "circuits": circuits}))
        return types.SimpleNamespace(
            contract=contract, preflight_receipt=preflight,
            split_contract=split, method_registry=registry, job_spec=job,
            receipt=os.path.join(work, "receipt.json"),
            sidecar=os.path.join(work, "receipt.json.sha256"),
            consumed_marker=os.path.join(work, "CONSUMED"))

    def test_marker_exists_before_data_read_and_success_is_not_replayable(self):
        original_gnu = runner.gnu_rows
        original_build = runner.build_blind_join_statuses
        with tempfile.TemporaryDirectory() as work:
            args = self.fixture_args(work)
            seen = []

            def fake_gnu(_path, _root, meta, _extra):
                self.assertTrue(os.path.isfile(args.consumed_marker))
                seen.append(meta["circuit"])
                return [{"attempt_id": meta["circuit"] + "-1",
                         "source_artifact_sha256": "b" * 64}]

            runner.gnu_rows = fake_gnu
            runner.build_blind_join_statuses = lambda circuit, *_args, **_kwargs: [
                {"stage": "02_hf_coarse", "join_status": "UNIQUE",
                 "circuit": circuit}]
            try:
                self.assertEqual(0, runner.execute(args))
                self.assertEqual(["s9234", "s38584", "wb_dma"], seen)
                receipt = runner.read_json(args.receipt)
                self.assertEqual("PASS", receipt["status"])
                self.assertEqual(3, len(receipt["circuits"]))
                with self.assertRaises(runner.PreflightError):
                    runner.execute(args)
            finally:
                runner.gnu_rows = original_gnu
                runner.build_blind_join_statuses = original_build

    def test_failure_after_consumption_releases_no_partial_circuit_rows(self):
        original_gnu = runner.gnu_rows
        original_build = runner.build_blind_join_statuses
        with tempfile.TemporaryDirectory() as work:
            args = self.fixture_args(work)
            runner.gnu_rows = lambda _path, _root, meta, _extra: [
                {"attempt_id": meta["circuit"] + "-1",
                 "source_artifact_sha256": "b" * 64}]
            runner.build_blind_join_statuses = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("sensitive internal detail"))
            try:
                self.assertEqual(1, runner.execute(args))
                receipt = runner.read_json(args.receipt)
                self.assertEqual("FAIL", receipt["status"])
                self.assertEqual([], receipt["circuits"])
                self.assertNotIn("sensitive internal detail", str(receipt))
                self.assertTrue(os.path.isfile(args.consumed_marker))
                self.assertTrue(os.path.isfile(args.sidecar))
            finally:
                runner.gnu_rows = original_gnu
                runner.build_blind_join_statuses = original_build


if __name__ == "__main__":
    unittest.main()
