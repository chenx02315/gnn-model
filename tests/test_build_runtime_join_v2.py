from __future__ import print_function
import csv
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "src", "data", "build_runtime_join_v2.py")


def put(path, text):
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def contract(path):
    put(path, json.dumps({"formal_runtime_membership": {
        "PILOT": [{"circuit": "b20", "family": "itc"}],
        "BLIND_TEST": [{"circuit": "s9234", "family": "blind"}]}}))


def manifest(path, rows):
    header = "attempt_id\tcircuit\tstage\tmode\trun_id\twall_s\tsource_log_path\n"
    put(path, header + rows)


class RuntimeJoinV2Test(unittest.TestCase):
    def invoke(self, work, circuit="b20"):
        out, audit = os.path.join(work, "join.tsv"), os.path.join(work, "audit.json")
        cmd = [sys.executable, SCRIPT, "--circuit", circuit, "--measurements-root", os.path.join(work, "measurements"),
               "--attempt-manifest", os.path.join(work, "attempt.tsv"), "--split-contract", os.path.join(work, "split.json"), out, audit]
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE), out, audit

    def test_phase2_phase3_headers_v2_attempts_and_no_cycle_proxy_fields(self):
        with tempfile.TemporaryDirectory() as work:
            contract(os.path.join(work, "split.json"))
            manifest(os.path.join(work, "attempt.tsv"),
                     "A1\tb20\t01_single_boundaries\tH\tother\t1.2\t/log/H_phase2.driver.log\n"
                     "A2\tb20\t02_hf_coarse\tF\tF_phase3\t2.3\t/log/not_the_run.driver.log\n")
            put(os.path.join(work, "measurements", "01_single_boundaries", "measurements.tsv"),
                "mode\tpattern_limit\tresult_directory\nH\t5\t/out/H_phase2\n")
            put(os.path.join(work, "measurements", "02_hf_coarse", "measurements.tsv"),
                "candidate\th_result\tf_result\n1\t\t/out/F_phase3\n")
            result, out, audit = self.invoke(work)
            self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
            with open(out, "r", encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
                self.assertNotIn("cycles", rows[0]); self.assertNotIn("patterns", rows[0]); self.assertNotIn("fault_sha", rows[0])
            self.assertEqual(("UNIQUE", "source_log_basename", "A1", "1.2"), tuple(rows[0][x] for x in ("join_status", "join_key_source", "attempt_id", "wall_s")))
            self.assertEqual("true", rows[0]["marker_run_id_mismatch"])
            fallback = [row for row in rows if row["normalized_result_basename"] == "F_phase3"][0]
            self.assertEqual(("UNIQUE", "run_id_exact"), tuple(fallback[x] for x in ("join_status", "join_key_source")))
            with open(audit, "r", encoding="utf-8") as stream:
                summary = json.load(stream)
            self.assertIn("PILOT/b20/01_single_boundaries/H", summary["by_role_circuit_stage_mode"])

    def test_blind_and_unregistered_are_rejected_before_missing_inputs_opened(self):
        with tempfile.TemporaryDirectory() as work:
            contract(os.path.join(work, "split.json"))
            result, out, audit = self.invoke(work, "s9234")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("BLIND_TEST", result.stderr.decode("utf-8"))
            self.assertFalse(os.path.exists(out)); self.assertFalse(os.path.exists(audit))
            result, out, audit = self.invoke(work, "not_registered")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("UNREGISTERED", result.stderr.decode("utf-8"))
            self.assertFalse(os.path.exists(out)); self.assertFalse(os.path.exists(audit))

    def test_ambiguity_nonzero_and_not_run_repeatability_missing(self):
        with tempfile.TemporaryDirectory() as work:
            contract(os.path.join(work, "split.json"))
            manifest(os.path.join(work, "attempt.tsv"),
                     "A1\tb20\t01_single_boundaries\tH\tx\t1\t/x/H_same.driver.log\n"
                     "A2\tb20\t02_hf_coarse\tH\ty\t2\t/y/H_same.driver.log\n")
            put(os.path.join(work, "measurements", "01_single_boundaries", "measurements.tsv"),
                "mode\trequested_limit\tresult\tstatus\tresult_status\nH\t1\t/out/H_same\tPASS\tPASS\nF\t2\t\tNOT_RUN\t\nM\t3\t\tPASS\tPRUNED_OR_UNREACHED\n")
            put(os.path.join(work, "measurements", "05_repeatability", "measurements.tsv"),
                "repeat\tscheme\n1\tH64-M16-F4\n")
            result, out, audit = self.invoke(work)
            self.assertEqual(1, result.returncode)
            with open(out, "r", encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual(1, sum(r["join_status"] == "AMBIGUOUS" for r in rows))
            self.assertEqual(2, sum(r["join_status"] == "NOT_RUN" for r in rows))
            self.assertEqual(0, sum(r["join_status"] == "MISSING_RESULT_PATH" for r in rows))
            self.assertEqual(3, sum(r["join_status"] == "NO_RESULT_PATH" for r in rows))
            pruned = [r for r in rows if r["mode"] == "M"][0]
            self.assertEqual(("NOT_RUN", "PRUNED_OR_UNREACHED"), (pruned["join_status"], pruned["join_reason"]))
            with open(audit, "r", encoding="utf-8") as stream:
                self.assertEqual(1, json.load(stream)["ambiguity_count"])

    def test_unique_cross_stage_reuse_is_retained_and_audited(self):
        with tempfile.TemporaryDirectory() as work:
            contract(os.path.join(work, "split.json"))
            manifest(os.path.join(work, "attempt.tsv"),
                     "A\tb20\t05_two_mode\tH\tdifferent_run\t3\t/log/H_reused.driver.log\n")
            put(os.path.join(work, "measurements", "02_hf_coarse", "measurements.tsv"),
                "candidate\th_result\tf_result\n1\t/out/H_reused\t\n")
            result, out, audit = self.invoke(work)
            self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
            with open(out, "r", encoding="utf-8", newline="") as stream:
                h_row = [row for row in csv.DictReader(stream, delimiter="\t") if row["mode"] == "H"][0]
            self.assertEqual(("UNIQUE", "05_two_mode", "CROSS_STAGE", "true"),
                             tuple(h_row[x] for x in ("join_status", "attempt_stage", "stage_relation", "marker_run_id_mismatch")))
            with open(audit, "r", encoding="utf-8") as stream:
                summary = json.load(stream)
            self.assertEqual((1, 1), (summary["cross_stage_unique_count"], summary["source_basename_marker_run_id_mismatch_count"]))

    def test_legacy_source_log_is_supported(self):
        with tempfile.TemporaryDirectory() as work:
            contract(os.path.join(work, "split.json"))
            put(os.path.join(work, "attempt.tsv"), "attempt_id\tcircuit\tstage\tmode\trun_id\twall_s\tsource_log\nA\tb20\t01_single_boundaries\tF\tx\t3\t/z/F_legacy.driver.log\n")
            put(os.path.join(work, "measurements", "01_single_boundaries", "measurements.tsv"), "mode\trequested_limit\tresult\nF\t7\t/F_legacy\n")
            result, out, unused = self.invoke(work)
            self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
            with open(out, "r", encoding="utf-8", newline="") as stream:
                row = next(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual(("UNIQUE", "A"), (row["join_status"], row["attempt_id"]))


if __name__ == "__main__":
    unittest.main()
