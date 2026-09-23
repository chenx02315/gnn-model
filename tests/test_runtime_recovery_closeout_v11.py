import copy
import json
import pathlib
import shutil
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))

import build_runtime_recovery_closeout_v11 as closeout


class RuntimeRecoveryCloseoutV11Test(unittest.TestCase):
    def test_checked_in_closeout_is_reproducible(self):
        expected = json.loads((ROOT / "data" / "manifests" / "runtime_recovery_closeout_v11.json").read_text(encoding="utf-8"))
        self.assertEqual(closeout.build_closeout(str(ROOT)), expected)

    def test_source_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary)
            for relative in closeout.SOURCES.values():
                source = ROOT / relative
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            failure_path = target / closeout.SOURCES["failure"]
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            failure["failure_code"] = "R06_R07_FAILED"
            failure_path.write_text(json.dumps(failure), encoding="utf-8")
            with self.assertRaises(closeout.CloseoutError):
                closeout.build_closeout(str(target))

    def test_fail_closed_fields_cannot_be_reinterpreted(self):
        result = closeout.build_closeout(str(ROOT))
        self.assertFalse(result["training_allowed"])
        self.assertEqual(result["remaining_gates"], {"R06": "PARTIAL", "R07": "BLOCKED", "R13": "BLOCKED"})
        self.assertEqual(result["inventory_result"]["driver_log_drift_circuits"], ["s9234", "wb_dma"])
        self.assertTrue(result["declarations"]["job_388790_retry_requeue_rerun_forbidden"])


if __name__ == "__main__":
    unittest.main()
