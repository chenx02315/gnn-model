import csv
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))
import audit_runtime_training_source_readiness_v1 as audit
from runtime_schema import MANIFEST_V2_FIELDS


class RuntimeTrainingSourceReadinessTests(unittest.TestCase):
    def write_tsv(self, path, fields, rows):
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    def digest(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def fixture(self, blocked=False, foreign=False):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        contract = json.loads((ROOT / "contracts" / "runtime_training_source_readiness_v1.json").read_text(encoding="utf-8"))
        contract_path = root / "contract.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        bound = []
        for spec in contract["required_roster"]:
            circuit = spec["circuit"]
            attempt_path = root / (circuit + "_attempts.tsv")
            join_path = root / (circuit + "_join.tsv")
            row = dict((field, "") for field in MANIFEST_V2_FIELDS)
            row.update({
                "attempt_id": "attempt_" + circuit, "adapter": "gnu_time_log",
                "circuit": circuit, "family": spec["family"], "role": spec["role"],
                "cohort": "c", "environment_cohort": "e", "phase": "p",
                "stage": "s", "mode": "F", "run_id": "r", "run_id_source": "marker",
                "wall_s": "1.0", "exit_status": "0", "atpg_status": "PASS",
                "timeout_status": "unknown" if blocked else "NO_TIMEOUT",
                "retry_order": "" if blocked else "1",
                "retry_order_status": "UNKNOWN_ORDER" if blocked else "KNOWN_ORDER",
                "parse_status": "PASS", "attempt_outcome_class": "UNKNOWN_LEGACY_STATUS" if blocked else "SUCCESS",
                "semantics_status": "FOOTER_VERIFIED", "semantics_contract": "tessent_process_wall_seconds",
                "elapsed_source": "gnu_time_footer", "elapsed_semantics": "tessent_process_wall_seconds",
                "retry_group_id": "g", "source_artifact": "x", "source_artifact_sha256": "a" * 64,
                "source_log_path": "x", "source_log_sha256": "b" * 64,
                "inventory_manifest_sha256": "c" * 64,
            })
            self.write_tsv(attempt_path, MANIFEST_V2_FIELDS, [row])
            join_fields = list(MANIFEST_V2_FIELDS) + ["join_status"]
            join_row = dict(row)
            join_row["join_status"] = "UNIQUE"
            if foreign and circuit == "s13207":
                join_row["attempt_id"] = "attempt_foreign"
            self.write_tsv(join_path, join_fields, [join_row])
            bound.append({
                "circuit": circuit, "family": spec["family"], "role": spec["role"],
                "attempt_manifest": {"root": str(root.resolve()), "path": attempt_path.name, "sha256": self.digest(attempt_path)},
                "join": {"root": str(root.resolve()), "path": join_path.name, "sha256": self.digest(join_path)},
            })
        bindings_path = root / "bindings.json"
        bindings_path.write_text(json.dumps({
            "schema_version": "runtime-training-source-readiness-bindings-v1",
            "circuits": bound,
        }), encoding="utf-8")
        return temp, contract_path, bindings_path

    def test_pass_fixture(self):
        temp, contract, bindings = self.fixture()
        self.addCleanup(temp.cleanup)
        receipt = audit.run(str(contract), str(bindings))
        self.assertEqual("PASS_SOURCE_PACKAGE_READY_FOR_INDEPENDENT_REVIEW", receipt["status"])
        self.assertEqual([], receipt["blockers"])
        self.assertEqual(8, receipt["totals"]["attempt_count"])
        self.assertFalse(receipt["boundaries"]["training_execution_allowed"])

    def test_unknowns_block_without_inference(self):
        temp, contract, bindings = self.fixture(blocked=True)
        self.addCleanup(temp.cleanup)
        receipt = audit.run(str(contract), str(bindings))
        self.assertEqual("BLOCKED_RETRY_ORDER_AND_OUTCOME_COMPLETENESS", receipt["status"])
        self.assertEqual(8, receipt["totals"]["unknown_retry_order_count"])
        self.assertEqual(8, receipt["totals"]["unknown_timeout_status_count"])
        self.assertEqual(8, receipt["totals"]["unknown_attempt_outcome_count"])

    def test_foreign_join_attempt_fails(self):
        temp, contract, bindings = self.fixture(foreign=True)
        self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(audit.AuditError, "JOIN_FOREIGN_ATTEMPT"):
            audit.run(str(contract), str(bindings))

    def test_sha_mismatch_fails(self):
        temp, contract, bindings = self.fixture()
        self.addCleanup(temp.cleanup)
        payload = json.loads(bindings.read_text(encoding="utf-8"))
        payload["circuits"][0]["join"]["sha256"] = "0" * 64
        bindings.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(audit.AuditError, "BINDING_SHA_MISMATCH"):
            audit.run(str(contract), str(bindings))

    def test_unc_root_fails_before_read(self):
        temp, contract, bindings = self.fixture()
        self.addCleanup(temp.cleanup)
        payload = json.loads(bindings.read_text(encoding="utf-8"))
        payload["circuits"][0]["join"]["root"] = "\\\\server\\share"
        bindings.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(audit.AuditError, "BINDING_REMOTE_ROOT"):
            audit.run(str(contract), str(bindings))

    def test_every_nonknown_retry_status_is_counted(self):
        temp, contract, bindings = self.fixture()
        self.addCleanup(temp.cleanup)
        payload = json.loads(bindings.read_text(encoding="utf-8"))
        item = payload["circuits"][0]["attempt_manifest"]
        path = Path(item["root"]) / item["path"]
        rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines(), delimiter="\t"))
        rows[0]["retry_order_status"] = "FUTURE_UNKNOWN"
        self.write_tsv(path, MANIFEST_V2_FIELDS, rows)
        item["sha256"] = self.digest(path)
        bindings.write_text(json.dumps(payload), encoding="utf-8")
        receipt = audit.run(str(contract), str(bindings))
        self.assertEqual(1, receipt["totals"]["unknown_retry_order_count"])

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlink API unavailable")
    def test_intermediate_symlink_is_rejected_when_supported(self):
        temp, contract, bindings = self.fixture()
        self.addCleanup(temp.cleanup)
        payload = json.loads(bindings.read_text(encoding="utf-8"))
        root = Path(temp.name)
        target = root / "real"
        target.mkdir()
        link = root / "link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            self.skipTest("directory symlink unavailable: %s" % exc)
        source = Path(payload["circuits"][0]["join"]["root"]) / payload["circuits"][0]["join"]["path"]
        copied = target / source.name
        copied.write_bytes(source.read_bytes())
        payload["circuits"][0]["join"]["root"] = str(root)
        payload["circuits"][0]["join"]["path"] = "link/" + source.name
        payload["circuits"][0]["join"]["sha256"] = self.digest(copied)
        bindings.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(audit.AuditError, "BINDING_ARTIFACT_REPARSE"):
            audit.run(str(contract), str(bindings))


if __name__ == "__main__":
    unittest.main()
