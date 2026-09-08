import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "src", "data", "audit_phase2_wall_time_semantics.py")


def put(path, text):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


class Phase2WallTimeSemanticsAuditTest(unittest.TestCase):
    def invoke(self, root, csv_rows, footer="0:01.25"):
        circuit = os.path.join(root, "b18")
        csv_path = os.path.join(root, "b18.csv")
        collector = os.path.join(root, "collector.py")
        policy = os.path.join(root, "policy.json")
        output = os.path.join(root, "audit.json")
        put(csv_path, "circuit,phase,mode,run_id,wall_time\n" + csv_rows)
        log_text = "no elapsed footer\n" if footer is None else (
            "Elapsed (wall clock) time (h:mm:ss or m:ss): %s\n" % footer)
        put(os.path.join(circuit, "logs", "H_run.driver.log"), log_text)
        put(collector, "collector\n")
        put(policy, "{}\n")
        command = [sys.executable, SCRIPT, "--collector-script", collector,
                   "--runtime-policy", policy, "--circuit", "b18=%s,%s" % (csv_path, circuit),
                   "--output", output]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result, output

    def test_exact_footer_match_passes_with_aggregate_only_output(self):
        with tempfile.TemporaryDirectory() as root:
            result, output = self.invoke(root, "b18,p,H,run,0:01.25\n")
            self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
            with open(output, encoding="utf-8") as stream:
                audit = json.load(stream)
            self.assertEqual("PASS", audit["validation_status"])
            self.assertEqual(1, audit["circuits"]["b18"]["source_row_count"])
            serialized = json.dumps(audit)
            self.assertNotIn('"run"', serialized)
            self.assertNotIn("driver.log", serialized)

    def test_mismatch_and_duplicate_fail_without_exposing_rows(self):
        with tempfile.TemporaryDirectory() as root:
            rows = "b18,p,H,run,0:02.00\nb18,p,H,run,0:02.00\n"
            result, output = self.invoke(root, rows)
            self.assertEqual(1, result.returncode)
            with open(output, encoding="utf-8") as stream:
                audit = json.load(stream)
            checks = audit["circuits"]["b18"]["checks"]
            self.assertEqual(1, checks["duplicate_run_id_count"])
            self.assertEqual(2, checks["footer_mismatch_count"])
            self.assertEqual("FAIL", audit["validation_status"])

    def test_rejects_nonfinite_and_fractional_leading_components(self):
        for value in ("nan:00", "inf:00", "0.5:01"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as root:
                result, output = self.invoke(root, "b18,p,H,run,%s\n" % value, footer=value)
                self.assertEqual(1, result.returncode)
                with open(output, encoding="utf-8") as stream:
                    checks = json.load(stream)["circuits"]["b18"]["checks"]
                self.assertEqual(1, checks["invalid_wall_count"])
                self.assertEqual(1, checks["invalid_footer_wall_count"])

    def test_missing_footer_fails(self):
        with tempfile.TemporaryDirectory() as root:
            result, output = self.invoke(root, "b18,p,H,run,0:01.25\n", footer=None)
            self.assertEqual(1, result.returncode)
            with open(output, encoding="utf-8") as stream:
                checks = json.load(stream)["circuits"]["b18"]["checks"]
            self.assertEqual(1, checks["missing_footer_count"])

    def test_malformed_footer_fails_even_when_csv_is_valid(self):
        with tempfile.TemporaryDirectory() as root:
            result, output = self.invoke(root, "b18,p,H,run,0:01.25\n", footer="garbage")
            self.assertEqual(1, result.returncode)
            with open(output, encoding="utf-8") as stream:
                checks = json.load(stream)["circuits"]["b18"]["checks"]
            self.assertEqual(1, checks["invalid_footer_wall_count"])
            self.assertEqual(1, checks["footer_mismatch_count"])

    def test_checked_in_phase2_audit_is_frozen_and_complete(self):
        path = os.path.join(ROOT, "data", "manifests", "phase2_wall_time_semantics_v1.json")
        with open(path, "rb") as stream:
            digest = hashlib.sha256(stream.read()).hexdigest()
        self.assertEqual("f274c639d83206d0ceaab88dd741213b42bf0bbc88bdec15daf14ee9dba24f59", digest)
        with open(path, encoding="utf-8") as stream:
            audit = json.load(stream)
        self.assertEqual("PASS", audit["validation_status"])
        self.assertEqual(4609, sum(row["source_row_count"] for row in audit["circuits"].values()))
        for row in audit["circuits"].values():
            self.assertEqual("PASS", row["validation_status"])
            self.assertEqual(0, sum(value for key, value in row["checks"].items() if key != "row_count"))


if __name__ == "__main__":
    unittest.main()
