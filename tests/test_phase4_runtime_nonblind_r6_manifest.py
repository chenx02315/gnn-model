import hashlib
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST_ROOT = ROOT / "data" / "manifests" / "phase4_runtime_nonblind_v2_r6"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class Phase4RuntimeNonblindR6ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.summary_path = MANIFEST_ROOT / "summary_r6.json"
        cls.summary = json.loads(cls.summary_path.read_text(encoding="utf-8"))

    def test_summary_scope_counts_and_distinct_cross_stage_attempts(self):
        self.assertEqual(
            "482d447ed46dc5af5e225b78dad4e2c4ae2cab4333d800ab5ce7dc5602289ad2",
            sha256(self.summary_path),
        )
        self.assertEqual(
            {"b20", "b21", "b22", "aes_core", "spi", "tv80"},
            set(self.summary["circuits"]),
        )
        aggregate = self.summary["aggregate"]
        self.assertEqual(30994, aggregate["attempt"]["row_count"])
        self.assertEqual(15505, aggregate["join"]["row_count"])
        self.assertEqual(
            {"UNIQUE": 13187, "NOT_RUN": 2209, "NO_RESULT_PATH": 109},
            aggregate["join"]["join_status_counts"],
        )
        self.assertEqual(153, aggregate["join"]["cross_stage_unique_count"])
        self.assertEqual(12, aggregate["join"]["distinct_cross_stage_attempt_count"])

    def test_small_artifacts_are_bound_to_summary(self):
        for circuit, record in self.summary["circuits"].items():
            self.assertEqual(
                record["file_sha256"]["inventory_json"],
                sha256(MANIFEST_ROOT / (circuit + "_inventory_r6.json")),
            )
            self.assertEqual(
                record["file_sha256"]["join_audit_json"],
                sha256(MANIFEST_ROOT / (circuit + "_audit_r6.json")),
            )

    def test_two_runs_are_byte_identical_and_nonblind(self):
        receipt = json.loads((MANIFEST_ROOT / "determinism_r6.json").read_text(encoding="utf-8"))
        self.assertTrue(receipt["byte_identical"])
        self.assertFalse(receipt["blind_data_accessed"])
        self.assertEqual(receipt["first_run_sha256"], receipt["repeat_run_sha256"])
        self.assertEqual(sha256(self.summary_path), receipt["first_run_sha256"])

    def test_execution_state_policy_is_mode_aware(self):
        gate = json.loads((ROOT / "contracts" / "runtime_recovery_gate_v1.json").read_text(encoding="utf-8"))
        policy = gate["execution_state_policy"]
        self.assertIn("F is NOT_RUN", policy["TARGET_BEFORE_F"])
        self.assertIn("nonempty H or M paths remain executed", policy["INFEASIBLE_AT_D95"])
        self.assertIn("nonempty per-mode result path remains", policy["PRUNED_OR_UNREACHED"])


if __name__ == "__main__":
    unittest.main()
