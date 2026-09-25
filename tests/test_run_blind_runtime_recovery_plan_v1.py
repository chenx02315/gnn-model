import json
import hashlib
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from src.data import run_blind_runtime_recovery_plan_v1 as runner


class RunBlindRuntimeRecoveryPlanV1Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = str(pathlib.Path(self.tmp.name) / "private")
        self.patches = [
            mock.patch.object(runner, "OUTPUT_ROOT", self.out),
            mock.patch.object(runner.r5, "validate_bundle", return_value=("r" * 64, "i" * 64)),
            mock.patch.object(runner, "validate_recovery_contract", return_value="c" * 64),
            mock.patch.object(runner.r5, "_validate_runtime_platform"),
            mock.patch.object(runner.r5.impl, "open_trusted_control", return_value=object()),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.tmp.cleanup()

    def test_generates_private_plan_summary_and_digests(self):
        attempts = {"s9234": [{"circuit": "s9234", "stage": "02_hf_coarse", "mode": "H",
                                "run_id": "bare", "source_marker": "H_bare", "pattern_limit": 64,
                                "run_kind": "", "depends_on_h_marker": ""}], "s38584": [], "wb_dma": []}
        with mock.patch.object(runner.r5.impl, "snapshot_circuit", side_effect=lambda control, c: ({}, {c: c})), \
             mock.patch.object(runner.planner, "build_recovery_plan", side_effect=lambda c, l, m: attempts[c]):
            self.assertEqual(0, runner.run())
        root = pathlib.Path(self.out)
        if os.name == "posix":
            self.assertEqual(0o700, root.stat().st_mode & 0o777)
        self.assertEqual({"payload"}, {item.name for item in root.iterdir()})
        payload = root / "payload"
        self.assertEqual({"plan.json", "plan.json.sha256", "summary.json"}, {item.name for item in payload.iterdir()})
        if os.name == "posix":
            self.assertEqual(0o600, (payload / "plan.json").stat().st_mode & 0o777)
        plan = json.loads((payload / "plan.json").read_text(encoding="utf-8"))
        summary = json.loads((payload / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual((False, 3, 1), (plan["training_allowed"], len(plan["circuits"]),
                                        summary["circuits"][0]["attempt_count"]))
        self.assertEqual(summary["plan_sha256"] + "  plan.json\n", (payload / "plan.json.sha256").read_text("ascii"))

    def test_plan_failure_writes_only_empty_failure_receipt(self):
        failure = runner.planner.RecoveryPlanFailure("JOIN", "AMBIGUOUS_LOG_MATCH")
        with mock.patch.object(runner.r5.impl, "snapshot_circuit", return_value=({}, {})), \
             mock.patch.object(runner.planner, "build_recovery_plan", side_effect=failure):
            self.assertEqual(1, runner.run())
        root = pathlib.Path(self.out)
        self.assertEqual({"receipt.json", "receipt.json.sha256"}, {item.name for item in root.iterdir()})
        receipt = json.loads((root / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(("FAIL", [], "AMBIGUOUS_LOG_MATCH"),
                         (receipt["status"], receipt["circuits"], receipt["failure_code"]))

    def test_existing_output_refuses_before_any_snapshot_and_fixed_argv(self):
        pathlib.Path(self.out).mkdir()
        with mock.patch.object(runner.r5.impl, "snapshot_circuit") as snapshot:
            with self.assertRaisesRegex(runner.Refusal, "OUTPUT_ROOT_ALREADY_EXISTS"):
                runner.run()
            snapshot.assert_not_called()
        with mock.patch.object(runner, "run") as invoked:
            self.assertEqual(2, runner.main(["--attacker"]))
            invoked.assert_not_called()

    def test_unsealed_contract_refuses_without_output(self):
        for patcher in self.patches:
            if getattr(patcher, "attribute", None) == "validate_recovery_contract":
                patcher.stop()
        with mock.patch.object(runner, "validate_recovery_contract", side_effect=runner.Refusal("CONTRACT_NOT_SEALED")):
            with self.assertRaisesRegex(runner.Refusal, "CONTRACT_NOT_SEALED"):
                runner.run()
        self.assertFalse(pathlib.Path(self.out).exists())

    def test_staging_write_failures_leave_only_empty_receipt(self):
        original = runner._exclusive
        for failing_call in (2, 3):
            with self.subTest(failing_call=failing_call):
                out = str(pathlib.Path(self.tmp.name) / ("private_%d" % failing_call))
                counter = [0]
                def fail_at(path, payload):
                    counter[0] += 1
                    if counter[0] == failing_call:
                        raise OSError("injected")
                    return original(path, payload)
                with mock.patch.object(runner, "OUTPUT_ROOT", out), \
                     mock.patch.object(runner.r5.impl, "snapshot_circuit", return_value=({}, {})), \
                     mock.patch.object(runner.planner, "build_recovery_plan", return_value=[]), \
                     mock.patch.object(runner, "_exclusive", side_effect=fail_at):
                    self.assertEqual(1, runner.run())
                root = pathlib.Path(out)
                self.assertEqual({"receipt.json", "receipt.json.sha256"}, {item.name for item in root.iterdir()})
                receipt = json.loads((root / "receipt.json").read_text(encoding="utf-8"))
                self.assertEqual(("FAIL", []), (receipt["status"], receipt["circuits"]))

    def test_publish_fsync_order_and_postrename_failure_cleans_before_receipt(self):
        with mock.patch.object(runner.r5.impl, "snapshot_circuit", return_value=({}, {})), \
             mock.patch.object(runner.planner, "build_recovery_plan", return_value=[]), \
             mock.patch.object(runner, "_fsync_directory") as synced:
            self.assertEqual(0, runner.run())
        staging = str(pathlib.Path(self.out) / "payload.staging")
        self.assertEqual([mock.call(staging), mock.call(self.out)], synced.call_args_list)
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        out = str(pathlib.Path(self.tmp.name) / "private_postrename")
        with mock.patch.object(runner, "OUTPUT_ROOT", out), \
             mock.patch.object(runner.r5.impl, "snapshot_circuit", return_value=({}, {})), \
             mock.patch.object(runner.planner, "build_recovery_plan", return_value=[]), \
             mock.patch.object(runner, "_fsync_directory", side_effect=[None, OSError("after rename"), None]) as synced:
            self.assertEqual(1, runner.run())
        root = pathlib.Path(out)
        self.assertEqual({"receipt.json", "receipt.json.sha256"}, {item.name for item in root.iterdir()})
        self.assertFalse((root / "payload").exists())
        self.assertEqual([mock.call(str(root / "payload.staging")), mock.call(out), mock.call(out)],
                         synced.call_args_list)

    def test_cleanup_fsync_failure_raises_without_failure_receipt(self):
        out = str(pathlib.Path(self.tmp.name) / "private_cleanup_fail")
        with mock.patch.object(runner, "OUTPUT_ROOT", out), \
             mock.patch.object(runner.r5.impl, "snapshot_circuit", return_value=({}, {})), \
             mock.patch.object(runner.planner, "build_recovery_plan", return_value=[]), \
             mock.patch.object(runner, "_fsync_directory", side_effect=[None, OSError("after rename"), OSError("cleanup")]):
            with self.assertRaisesRegex(runner.PublicationCleanupFailure, "PAYLOAD_CLEANUP_FAILED"):
                runner.run()
        root = pathlib.Path(out)
        self.assertEqual(set(), {item.name for item in root.iterdir()})


class RecoveryContractValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.output = str(self.root / "out")
        self.artifacts = {}
        for relative in runner.REQUIRED_ARTIFACTS:
            path = self.root.joinpath(*relative.split("/")); path.parent.mkdir(parents=True, exist_ok=True)
            payload = ("sealed:" + relative).encode("utf-8"); path.write_bytes(payload)
            self.artifacts[relative] = hashlib.sha256(payload).hexdigest()
        self.contract_path = self.root / runner.CONTRACT_RELATIVE
        self.contract_path.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_contract(self, artifacts):
        contract = {"schema_version": "blind-runtime-recovery-v1",
                    "status": "PLAN_ONLY_AUTHORIZED_REVIEWED", "circuits": list(runner.CIRCUITS),
                    "private_plan": {"output_root": self.output,
                                     "permissions": "0700 directory and 0600 plan files",
                                     "allowed_fields": ["circuit", "stage", "mode", "run_id", "source_marker",
                                                        "pattern_limit", "run_kind", "depends_on_h_marker"]},
                    "implementation": {"artifact_sha256": artifacts}, "training_allowed": False}
        self.contract_path.write_text(json.dumps(contract), encoding="utf-8")

    def test_missing_extra_and_mismatched_artifacts_refuse(self):
        with mock.patch.object(runner, "BUNDLE_ROOT", str(self.root)), \
             mock.patch.object(runner, "OUTPUT_ROOT", self.output):
            missing = dict(self.artifacts); missing.pop(next(iter(missing)))
            self._write_contract(missing)
            with self.assertRaisesRegex(runner.Refusal, "CONTRACT_ARTIFACT_SET"):
                runner.validate_recovery_contract()
            extra = dict(self.artifacts); extra["extra.py"] = "0" * 64
            self._write_contract(extra)
            with self.assertRaisesRegex(runner.Refusal, "CONTRACT_ARTIFACT_SET"):
                runner.validate_recovery_contract()
            bad = dict(self.artifacts); bad[next(iter(bad))] = "0" * 64
            self._write_contract(bad)
            with self.assertRaisesRegex(runner.Refusal, "CONTRACT_ARTIFACT_DIGEST_MISMATCH"):
                runner.validate_recovery_contract()


if __name__ == "__main__":
    unittest.main()
