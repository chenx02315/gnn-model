import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "data" / "build_blind_gate_snapshot_v1.py"
SPEC = importlib.util.spec_from_file_location("blind_gate_snapshot", str(MODULE_PATH))
SNAPSHOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SNAPSHOT)


class BlindGateSnapshotV1Test(unittest.TestCase):
    def test_checked_in_snapshot_is_exact_rebuild(self):
        path = ROOT / "data" / "manifests" / "blind_gate_snapshot_v1.json"
        self.assertTrue(SNAPSHOT.verify_snapshot(str(ROOT), str(path)))

    def test_repeated_build_is_byte_identical(self):
        first = SNAPSHOT.build_snapshot(str(ROOT))
        second = SNAPSHOT.build_snapshot(str(ROOT))
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))

    def test_snapshot_binds_each_upstream_file_digest(self):
        document = json.loads(SNAPSHOT.build_snapshot(str(ROOT)).decode("utf-8"))
        self.assertEqual(sorted(SNAPSHOT.UPSTREAM_FILES), sorted(document["upstream_files"]))
        for relative, digest in document["upstream_files"].items():
            actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, relative)
        self.assertEqual(["R06", "R07", "R13"], document["pending_blind_checks"])
        for check in document["pending_blind_checks"]:
            self.assertEqual("PENDING_BLIND_AUDIT", document["frozen_checks"][check]["status"])

    def test_any_upstream_content_change_fails_verify(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            for relative in SNAPSHOT.UPSTREAM_FILES:
                source = ROOT / relative
                target = fixture / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(str(source), str(target))
            output = fixture / "snapshot.json"
            output.write_bytes(SNAPSHOT.build_snapshot(str(fixture)))
            (fixture / SNAPSHOT.RUNTIME_POLICY).write_text("{}\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                SNAPSHOT.verify_snapshot(str(fixture), str(output))

    def test_assessment_status_drift_fails_build(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            for relative in SNAPSHOT.UPSTREAM_FILES:
                source = ROOT / relative
                target = fixture / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(str(source), str(target))
            path = fixture / SNAPSHOT.ASSESSMENT
            document = json.loads(path.read_text(encoding="utf-8"))
            document["checks"]["R01"]["status"] = "BLOCKED"
            path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "assessment status drift"):
                SNAPSHOT.build_snapshot(str(fixture))


if __name__ == "__main__":
    unittest.main()
