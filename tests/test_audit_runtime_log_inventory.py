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


if __name__ == "__main__":
    unittest.main()
