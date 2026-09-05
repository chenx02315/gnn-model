import hashlib
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST_ROOT = ROOT / "data" / "manifests" / "phase4_runtime_nonblind_v2_r3"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class Phase4RuntimeNonblindR3ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.summary_path = MANIFEST_ROOT / "provenance" / "summary_r3.json"
        with cls.summary_path.open(encoding="utf-8") as stream:
            cls.summary = json.load(stream)

    def test_summary_hash_and_nonblind_scope_are_frozen(self):
        self.assertEqual(
            "352a66b50956fd9607274b0c28ac139adb071487da761e4faefd670edc203752",
            sha256(self.summary_path),
        )
        self.assertEqual(
            {"b20", "b21", "b22", "aes_core", "spi", "tv80"},
            set(self.summary["circuits"]),
        )
        self.assertTrue({"s9234", "s38584", "wb_dma"}.isdisjoint(self.summary["circuits"]))

    def test_aggregate_gate_counts_are_exact(self):
        aggregate = self.summary["aggregate"]
        self.assertEqual(30994, aggregate["attempt"]["row_count"])
        self.assertEqual(0, aggregate["attempt"]["missing_wall_count"])
        self.assertEqual(0, aggregate["attempt"]["nonzero_exit_count"])
        self.assertEqual(
            {"SUCCESS": 1441, "UNKNOWN_LEGACY_STATUS": 29553},
            aggregate["attempt"]["outcome_counts"],
        )
        self.assertEqual(15505, aggregate["join"]["row_count"])
        self.assertEqual(
            {"UNIQUE": 13187, "NOT_RUN": 2209, "NO_RESULT_PATH": 109},
            aggregate["join"]["join_status_counts"],
        )
        self.assertEqual(153, aggregate["join"]["cross_stage_unique_count"])
        self.assertNotIn("MISSING", aggregate["join"]["join_status_counts"])
        self.assertNotIn("MISSING_RESULT_PATH", aggregate["join"]["join_status_counts"])
        self.assertNotIn("AMBIGUOUS", aggregate["join"]["join_status_counts"])

    def test_checked_in_small_artifact_hashes_match_summary(self):
        for circuit, record in self.summary["circuits"].items():
            inventory = MANIFEST_ROOT / "inventory" / (circuit + "_inventory_v2_r3.json")
            audit = MANIFEST_ROOT / "join_audits" / (circuit + "_audit_v2_r3.json")
            self.assertEqual(record["file_sha256"]["inventory_json"], sha256(inventory))
            self.assertEqual(record["file_sha256"]["join_audit_json"], sha256(audit))

    def test_p0_status_keeps_unknown_status_and_blocker_visible(self):
        status = (ROOT / "contracts" / "p0_status.md").read_text(encoding="utf-8")
        self.assertIn("29,553", status)
        self.assertIn("UNKNOWN_LEGACY_STATUS", status)
        self.assertIn("R07", status)
        self.assertIn("不得训练", status)

    def test_policy_v2_preserves_v1_and_only_resolves_real_timing(self):
        policy_v1 = ROOT / "contracts" / "runtime_policy_v1.json"
        with (ROOT / "contracts" / "runtime_policy_v2.json").open(encoding="utf-8") as stream:
            policy_v2 = json.load(stream)
        self.assertEqual(policy_v2["base_policy_sha256"], sha256(policy_v1))
        self.assertFalse(policy_v2["training_allowed"])
        replacement = policy_v2["replacements"]["missing_historical_timing"]
        self.assertEqual([], replacement["run_ids"])
        resolved = {row["run_id"]: row for row in replacement["resolved_run_ids"]}
        self.assertEqual(
            {"H_b20_H_full_phase4_v1", "F_b20_F_full_phase4_v1"}, set(resolved)
        )
        self.assertEqual(24.78, resolved["H_b20_H_full_phase4_v1"]["wall_s"])
        self.assertEqual(13.67, resolved["F_b20_F_full_phase4_v1"]["wall_s"])
        self.assertEqual(
            sha256(self.summary_path), replacement["phase4_nonblind_r3_summary_sha256"]
        )

    def test_gate_assessment_is_conservative_and_bound_to_contract(self):
        gate = ROOT / "contracts" / "runtime_recovery_gate_v1.json"
        with (ROOT / "contracts" / "runtime_recovery_gate_assessment_v1.json").open(
            encoding="utf-8"
        ) as stream:
            assessment = json.load(stream)
        self.assertEqual(sha256(gate), assessment["gate_contract_sha256"])
        self.assertEqual("BLOCKED", assessment["assessment_status"])
        self.assertFalse(assessment["training_allowed"])
        statuses = {key: row["status"] for key, row in assessment["checks"].items()}
        self.assertEqual(set("R%02d" % number for number in range(1, 15)), set(statuses))
        self.assertEqual("BLOCKED", statuses["R07"])
        self.assertEqual("BLOCKED", statuses["R13"])
        self.assertTrue(all(value in {"PASS", "PARTIAL", "BLOCKED"} for value in statuses.values()))


if __name__ == "__main__":
    unittest.main()
