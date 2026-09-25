import json
import pathlib
import tempfile
import unittest
from unittest import mock

from src.data import blind_join_core_v12_r3 as core
from src.data import run_blind_join_v12_r3 as runner


def aggregate(circuit):
    return {
        "circuit": circuit,
        "executed_stage_reference_count": 2,
        "unique_runtime_join_count": 2,
        "missing_runtime_join_count": 0,
        "ambiguous_runtime_join_count": 0,
        "coverage_rate": 1.0,
        "distinct_runtime_attempt_count": 2,
        "cross_stage_reference_count": 0,
        "eligible_action_count": 1,
        "all_unique_action_count": 1,
        "frozen_runtime_eligible_action_space_sha256": "a" * 64,
        "source_artifact_set_sha256": "b" * 64,
    }


class RunBlindJoinV12R3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.output = str(pathlib.Path(self.tmp.name) / "out")
        self.patch = mock.patch.object(runner, "OUTPUT_ROOT", self.output)
        self.patch.start()
        self.bundle_patch = mock.patch.object(runner, "validate_bundle", return_value=("c" * 64, "i" * 64))
        self.bundle_patch.start()

    def tearDown(self):
        self.bundle_patch.stop()
        self.patch.stop()
        self.tmp.cleanup()

    def test_factory_is_zero_argument_and_anchors_are_frozen(self):
        control = runner.open_trusted_control()
        self.assertEqual("/usr/bin/sort", control._sort_path)
        self.assertEqual("sort (GNU coreutils) 8.22", control._sort_version)
        with self.assertRaises(TypeError):
            runner.open_trusted_control("attacker")
        self.assertEqual(("s9234", "s38584", "wb_dma"), runner.CIRCUIT_ORDER)

    def test_pass_writes_aggregate_only_receipt(self):
        rows = {name: aggregate(name) for name in runner.CIRCUIT_ORDER}
        with mock.patch.object(runner, "snapshot_circuit", return_value=({}, {})), \
             mock.patch.object(runner.core, "audit_circuit", side_effect=lambda name, _logs, _tables: rows[name]):
            self.assertEqual(0, runner.run())
        receipt = json.loads((pathlib.Path(self.output) / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual("PASS_R06_R07_AUDIT_PENDING", receipt["status"])
        self.assertEqual(list(runner.CIRCUIT_ORDER), [row["circuit"] for row in receipt["circuits"]])
        encoded = json.dumps(receipt, sort_keys=True)
        for forbidden in ("run_id", "wall_s", "candidate_uid", "source_log_path"):
            self.assertNotIn(forbidden, encoded)

    def test_gate_failure_is_empty_envelope(self):
        bad = aggregate("s9234")
        bad["missing_runtime_join_count"] = 1
        bad["unique_runtime_join_count"] = 1
        with mock.patch.object(runner, "snapshot_circuit", return_value=({}, {})), \
             mock.patch.object(runner.core, "audit_circuit", return_value=bad):
            self.assertEqual(1, runner.run())
        receipt = json.loads((pathlib.Path(self.output) / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual({"schema_version", "status", "contract_sha256", "implementation_set_sha256",
                          "failure_stage", "failure_code", "circuits"}, set(receipt))
        self.assertEqual([], receipt["circuits"])
        self.assertEqual("R06_R07_FAILED", receipt["failure_code"])

    def test_source_failure_is_empty_envelope(self):
        with mock.patch.object(runner, "snapshot_circuit", side_effect=runner.Refusal("LOG_RACE_DETECTED")):
            self.assertEqual(1, runner.run())
        receipt = json.loads((pathlib.Path(self.output) / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(("FAIL", "SOURCE_INVENTORY", "INPUT_INVENTORY_DRIFT", []),
                         (receipt["status"], receipt["failure_stage"], receipt["failure_code"], receipt["circuits"]))

    def test_output_is_one_shot(self):
        pathlib.Path(self.output).mkdir()
        with self.assertRaisesRegex(runner.Refusal, "OUTPUT_ROOT_ALREADY_EXISTS"):
            runner._write_receipt({"status": "FAIL"})

    def test_cli_rejects_arguments_without_source_access(self):
        with mock.patch.object(runner, "run") as run:
            self.assertEqual(2, runner.main(["--root", "/attacker"]))
            run.assert_not_called()

    def test_bundle_refusal_creates_no_output(self):
        self.bundle_patch.stop()
        self.bundle_patch = mock.patch.object(runner, "validate_bundle", side_effect=runner.Refusal("ARTIFACT_DIGEST_MISMATCH"))
        self.bundle_patch.start()
        self.assertEqual(2, runner.main([]))
        self.assertFalse(pathlib.Path(self.output).exists())


if __name__ == "__main__":
    unittest.main()
