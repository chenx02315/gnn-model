from __future__ import print_function
import csv, json, os, subprocess, sys, tempfile, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "src", "data", "build_candidate_run_join.py")

def put(path, text):
    parent = os.path.dirname(path)
    if not os.path.isdir(parent): os.makedirs(parent)
    with open(path, "w", encoding="utf-8", newline="\n") as stream: stream.write(text)

class CandidateJoinTest(unittest.TestCase):
    def test_direct_paths_and_repeatability_without_paths(self):
        with tempfile.TemporaryDirectory() as work:
            raw = os.path.join(work, "raw")
            put(os.path.join(work, "attempt.tsv"), "attempt_id\tcircuit\trun_id\tsource_log\nA_H\tb20\tb20_cov_H_p4\t/x/H_b20_cov_H_p4.driver.log\nA_F\tb20\tb20_cov_F_p9\t/x/F_b20_cov_F_p9.driver.log\n")
            put(os.path.join(raw, "hf_coarse.tsv"), "candidate\th_patterns\tf_patterns\th_result\tf_result\th_fault_sha256\tf_fault_sha256\tresult_status\n1\t4\t9\t/x/H_b20_cov_H_p4\t/x/F_b20_cov_F_p9\thsha\tfsha\tPASS\n2\t5\t0\t/x/H_b20_cov_H_p4\t\t\th\tTARGET_BEFORE_F\n")
            put(os.path.join(raw, "single_boundary.tsv"), "mode\trequested_limit\tactual_patterns\tresult\tstatus\nF\t9\t9\t/x/F_b20_cov_F_p9\tPASS\n")
            put(os.path.join(raw, "repeatability.tsv"), "repeat\tscheme\th_patterns\tm_patterns\tf_patterns\th_fault_sha256\tm_fault_sha256\tf_fault_sha256\n1\tH64-M16-F4\t1\t2\t3\th\tm\tf\n")
            out, audit = os.path.join(work, "join.tsv"), os.path.join(work, "audit.json")
            subprocess.check_call([sys.executable, SCRIPT, "--circuit", "b20", "--raw-tables-dir", raw, "--attempt-manifest", os.path.join(work, "attempt.tsv"), out, audit])
            with open(out, "r", encoding="utf-8", newline="") as stream: rows = list(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual(8, len(rows))
            self.assertEqual(3, sum(row["join_status"] == "NO_RESULT_PATH" for row in rows))
            target = [row for row in rows if row["join_status"] == "NOT_RUN"]
            self.assertEqual(1, len(target)); self.assertEqual("F", target[0]["mode"]); self.assertEqual("", target[0]["attempt_id"])
            self.assertEqual(4, sum(row["join_status"] == "UNIQUE" for row in rows))
            self.assertEqual(4, sum(row["join_key_source"] == "source_log_basename" for row in rows))
            with open(audit, "r", encoding="utf-8") as stream: summary = json.load(stream)
            self.assertTrue(summary["final_direct_join_ambiguity_zero"])
            self.assertEqual(3, summary["repeatability_not_joined_count"])
            self.assertEqual(4, summary["source_basename_marker_run_id_mismatch_count"])
            self.assertIn("future incidence", summary["auxiliary_boundary_search_attempts"])

    def test_source_basename_ambiguity_is_not_hidden_by_run_id(self):
        with tempfile.TemporaryDirectory() as work:
            raw = os.path.join(work, "raw")
            put(os.path.join(work, "attempt.tsv"), "attempt_id\tcircuit\trun_id\tsource_log\nA1\tb20\tmarker_one\t/x/H_same.driver.log\nA2\tb20\tmarker_two\t/y/H_same.driver.log\n")
            put(os.path.join(raw, "single_boundary.tsv"), "mode\trequested_limit\tactual_patterns\tresult\tstatus\nH\t1\t1\t/x/H_same\tPASS\n")
            out, audit = os.path.join(work, "join.tsv"), os.path.join(work, "audit.json")
            subprocess.check_call([sys.executable, SCRIPT, "--circuit", "b20", "--raw-tables-dir", raw, "--attempt-manifest", os.path.join(work, "attempt.tsv"), out, audit])
            with open(out, "r", encoding="utf-8", newline="") as stream: row = list(csv.DictReader(stream, delimiter="\t"))[0]
            self.assertEqual(("AMBIGUOUS", "source_log_basename"), (row["join_status"], row["join_key_source"]))
if __name__ == "__main__": unittest.main()
