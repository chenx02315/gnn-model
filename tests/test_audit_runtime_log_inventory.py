from __future__ import print_function

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "src", "data", "audit_runtime_log_inventory.py")


class RuntimeLogInventoryTest(unittest.TestCase):
    def test_output_is_aggregate_only_and_counts_missing_footers(self):
        with tempfile.TemporaryDirectory() as work:
            with open(os.path.join(work, "H_ok.driver.log"), "w") as stream:
                stream.write("MAPPED_COMMON_ATPG_STATUS=PASS\nUser time (seconds): 1\nSystem time (seconds): 2\nElapsed (wall clock) time (h:mm:ss or m:ss): 0:03\nExit status: 0\n")
            with open(os.path.join(work, "F_bad.driver.log"), "w") as stream:
                stream.write("MAPPED_COMMON_ATPG_STATUS=FAIL\nExit status: 2\n")
            raw = subprocess.check_output([
                sys.executable, SCRIPT, "--input", work, "--circuit", "sealed",
                "--cohort", "phase3_gnu_time",
            ])
            result = json.loads(raw.decode("utf-8"))
            self.assertEqual((2, 1, 1, 1, 2), (
                result["driver_log_count"], result["elapsed_footer_count"],
                result["missing_elapsed_count"], result["nonzero_exit_count"],
                result["atpg_status_marker_count"],
            ))
            self.assertEqual((0, 1), (result["missing_atpg_status_count"], result["nonpass_atpg_status_count"]))
            forbidden = ("path", "run_id", "elapsed_s", "candidate", "pattern", "cycle", "outcome")
            self.assertFalse(any(key in result for key in forbidden))
            self.assertEqual(64, len(result["inventory_manifest_sha256"]))

    def test_extra_logs_are_hashed_as_a_sorted_evidence_root_union(self):
        with tempfile.TemporaryDirectory() as work:
            primary = os.path.join(work, "primary")
            first = os.path.join(work, "known", "H_first.driver.log")
            second = os.path.join(work, "known", "F_second.driver.log")
            os.makedirs(primary)
            os.makedirs(os.path.dirname(first))
            with open(os.path.join(primary, "M_main.driver.log"), "w") as stream:
                stream.write("Exit status: 0\n")
            with open(first, "w") as stream:
                stream.write("Elapsed (wall clock) time (h:mm:ss or m:ss): 0:01\n")
            with open(second, "w") as stream:
                stream.write("MAPPED_COMMON_ATPG_STATUS=PASS\n")
            raw = subprocess.check_output([
                sys.executable, SCRIPT, "--input", primary, "--evidence-root", work,
                "--extra-log", first, "--extra-log", second, "--circuit", "sealed",
                "--cohort", "phase4_gnu_time",
            ])
            result = json.loads(raw.decode("utf-8"))
            self.assertEqual((3, 1, 1, 1), (
                result["driver_log_count"], result["elapsed_footer_count"],
                result["exit_footer_count"], result["atpg_status_marker_count"],
            ))
            self.assertEqual(64, len(result["inventory_manifest_sha256"]))
            forbidden = ("path", "run_id", "elapsed_s", "candidate", "pattern", "cycle", "outcome")
            self.assertFalse(any(key in result for key in forbidden))
            reversed_raw = subprocess.check_output([
                sys.executable, SCRIPT, "--input", primary, "--evidence-root", work,
                "--extra-log", second, "--extra-log", first, "--circuit", "sealed",
                "--cohort", "phase4_gnu_time",
            ])
            self.assertEqual(result["inventory_manifest_sha256"], json.loads(
                reversed_raw.decode("utf-8"))["inventory_manifest_sha256"])

    def test_extra_log_rejects_outside_evidence_root_and_duplicates(self):
        with tempfile.TemporaryDirectory() as work, tempfile.TemporaryDirectory() as outside:
            primary = os.path.join(work, "primary")
            os.makedirs(primary)
            scanned = os.path.join(primary, "H_scanned.driver.log")
            external = os.path.join(outside, "H_outside.driver.log")
            with open(scanned, "w") as stream:
                stream.write("")
            with open(external, "w") as stream:
                stream.write("")
            base = [sys.executable, SCRIPT, "--input", primary, "--evidence-root", work,
                    "--circuit", "sealed", "--cohort", "phase4_gnu_time"]
            self.assertNotEqual(0, subprocess.call(base + ["--extra-log", external]))
            self.assertNotEqual(0, subprocess.call(base + ["--extra-log", scanned]))
            extra = os.path.join(work, "known", "H_extra.driver.log")
            os.makedirs(os.path.dirname(extra))
            with open(extra, "w") as stream:
                stream.write("")
            self.assertNotEqual(0, subprocess.call(base + ["--extra-log", extra, "--extra-log", extra]))


if __name__ == "__main__":
    unittest.main()
