from __future__ import print_function

import csv
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "src", "data", "build_attempt_manifest.py")
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "attempt_manifest")


class AttemptManifestTest(unittest.TestCase):
    def test_recovery_audit_and_determinism(self):
        with tempfile.TemporaryDirectory() as work:
            output = os.path.join(work, "manifest.tsv")
            audit = os.path.join(work, "audit.json")
            command = [sys.executable, SCRIPT, os.path.join(FIXTURES, "atpg_run_timing_v2.tsv"), output, audit, "--log-root", os.path.join(FIXTURES, "evidence")]
            subprocess.check_call(command)
            with open(output, "rb") as stream:
                first = stream.read()
            repeat = os.path.join(work, "manifest_repeat.tsv")
            subprocess.check_call(command[:3] + [repeat] + command[4:])
            with open(repeat, "rb") as stream:
                self.assertEqual(first, stream.read())
            with open(output, "r", encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual(5, len(rows))
            marker = [row for row in rows if row["source_log"].endswith("H_marker.driver.log")][0]
            self.assertEqual(("H_marker", "log_marker", "62.500", "b20:H:lim4"), (marker["run_id"], marker["run_id_source"], marker["wall_s"], marker["config_key"]))
            fallback = [row for row in rows if row["source_log"].endswith("H_retry.driver.log")][0]
            self.assertEqual(("H_retry", "filename", "H"), (fallback["run_id"], fallback["run_id_source"], fallback["mode"]))
            duplicates = [row for row in rows if row["duplicate_run_id"] == "true"]
            self.assertEqual(2, len(duplicates))
            self.assertEqual("3601.000", [row for row in duplicates if row["source_log"].endswith("H_dup.driver.log")][0]["wall_s"])
            self.assertEqual(["0", "1"], sorted(row["retry_index"] for row in duplicates))
            missing = [row for row in rows if row["source_log"].endswith("missing.driver.log")][0]
            self.assertIn("wall_s", missing["parse_status"])
            self.assertIn("source_log_sha256", missing["parse_status"])
            self.assertEqual(5, len(set(row["attempt_id"] for row in rows)))
            with open(audit, "r", encoding="utf-8") as stream:
                summary = json.load(stream)
            self.assertEqual(["H_marker"], summary["duplicate_run_ids"])
            self.assertEqual((5, 5, [], ["b20", "b21"]), (summary["source_row_count"], summary["selected_row_count"], summary["circuit_filter"], summary["selected_circuits"]))
            self.assertIn("all input rows retained", summary["selection_policy"])

    def test_repeatable_circuit_filter(self):
        with tempfile.TemporaryDirectory() as work:
            output = os.path.join(work, "manifest.tsv")
            audit = os.path.join(work, "audit.json")
            command = [sys.executable, SCRIPT, os.path.join(FIXTURES, "atpg_run_timing_v2.tsv"), output, audit, "--log-root", os.path.join(FIXTURES, "evidence"), "--circuit", "b20"]
            subprocess.check_call(command)
            with open(output, "r", encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual(4, len(rows))
            self.assertEqual({"b20"}, set(row["circuit"] for row in rows))
            with open(audit, "r", encoding="utf-8") as stream:
                summary = json.load(stream)
            self.assertEqual((5, 4, ["b20"], ["b20"]), (summary["source_row_count"], summary["selected_row_count"], summary["circuit_filter"], summary["selected_circuits"]))

    def test_multiple_circuit_options_are_combined(self):
        with tempfile.TemporaryDirectory() as work:
            output = os.path.join(work, "manifest.tsv")
            audit = os.path.join(work, "audit.json")
            command = [sys.executable, SCRIPT, os.path.join(FIXTURES, "atpg_run_timing_v2.tsv"), output, audit, "--log-root", os.path.join(FIXTURES, "evidence"), "--circuit", "b20", "--circuit", "b21"]
            subprocess.check_call(command)
            with open(audit, "r", encoding="utf-8") as stream:
                summary = json.load(stream)
            self.assertEqual((5, 5, ["b20", "b21"], ["b20", "b21"]), (summary["source_row_count"], summary["selected_row_count"], summary["circuit_filter"], summary["selected_circuits"]))


if __name__ == "__main__":
    unittest.main()
