from __future__ import print_function
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "src", "data", "build_candidate_space.py")
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "candidate_space", "candidate_measurements_real_semantics.tsv")

class CandidateSpaceTest(unittest.TestCase):
    def test_coarse_refine_duplicates_and_conflicts_are_retained(self):
        with tempfile.TemporaryDirectory() as work:
            source = os.path.join(work, "candidate_measurements_all_phase4.tsv")
            shutil.copyfile(FIXTURE, source)
            output, audit = os.path.join(work, "actions.tsv"), os.path.join(work, "audit.json")
            subprocess.check_call([sys.executable, SCRIPT, source, output, audit])
            with open(output, "r", encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual(2, len(rows))
            hf = [row for row in rows if row["action_scheme"] == "HF"][0]
            self.assertEqual(("2", "coarse_2|refine_1", "hf_coarse|hf_refine", "true"), (hf["repeat_measurement_count"], hf["source_candidate_uids"], hf["source_stages"], hf["outcome_conflict"]))
            self.assertIn("f_patterns", hf["outcome_conflict_fields"])
            self.assertNotIn(":m", hf["action_uid"])
            with open(audit, "r", encoding="utf-8") as stream: summary = json.load(stream)
            self.assertEqual((5, 3, 2, 1, 1), (summary["input_row_count"], summary["eligible_measurement_count"], summary["action_count"], summary["duplicate_action_count"], summary["outcome_conflict_action_count"]))
            self.assertEqual({"eligible_regression_not_1": 1, "stage_not_hf_or_hmf": 1}, summary["skipped_reason_counts"])
            self.assertEqual(64, len(summary["input_sha256"])); self.assertEqual(64, len(summary["output_sha256"]))

if __name__ == "__main__": unittest.main()
