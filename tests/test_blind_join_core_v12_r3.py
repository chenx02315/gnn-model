import hashlib
import unittest

from src.data import blind_join_core_v12_r3 as core


def snap(text):
    payload = text.encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), payload


def log(run_id, mode, elapsed="0:01.00", exit_status="0", extra=""):
    return snap("MAPPED_COMMON_ATPG_RUN_ID=%s\nMAPPED_COMMON_ATPG_MODE=%s\n%s"
                "Elapsed (wall clock) time (h:mm:ss or m:ss): %s\nExit status: %s\n" %
                (run_id, mode, extra, elapsed, exit_status))


class BlindJoinCoreV12R3Tests(unittest.TestCase):
    def base_measurements(self):
        empty = snap("mode\tresult\n")
        return {
            "01_single_boundaries/measurements.tsv": empty,
            "02_hf_coarse/measurements.tsv": snap(
                "h_patterns\th_result\tf_result\n1\tH_case\tF_case\n"),
            "03_hmf_coarse/measurements.tsv": snap(
                "h_patterns\tm_patterns\th_result\tm_result\tf_result\n"
                "2\t3\tH_two\tM_two\tF_two\n"),
            "04_integer_refine/hf_measurements.tsv": snap(
                "h_patterns\tstatus\th_result\tf_result\n4\tTARGET_BEFORE_F\tH_four\tstale_F\n"),
            "04_integer_refine/hmf_measurements.tsv": snap(
                "h_patterns\tm_patterns\tstatus\th_result\tm_result\tf_result\n"
                "5\t6\tINFEASIBLE_AT_D95\tH_five\tM_five\tstale_F2\n"),
            "05_repeatability/measurements.tsv": snap("scheme\nH64-M16-F4\n"),
        }

    def base_logs(self):
        names = (("02_hf_coarse/H_case.driver.log", "H_case", "H"),
                 ("02_hf_coarse/F_case.driver.log", "F_case", "F"),
                 ("03_hmf_coarse/H_two.driver.log", "H_two", "H"),
                 ("03_hmf_coarse/M_two.driver.log", "M_two", "M"),
                 ("03_hmf_coarse/F_two.driver.log", "F_two", "F"),
                 ("04_integer_refine/H_four.driver.log", "H_four", "H"),
                 ("04_integer_refine/H_five.driver.log", "H_five", "H"),
                 ("04_integer_refine/M_five.driver.log", "M_five", "M"))
        return {path: log(run, mode) for path, run, mode in names}

    def test_canonical_action_uid_matches_candidate_space_rule(self):
        self.assertEqual("x:HF:h4", core.canonical_action_uid("x", "hf", {"h_patterns": "4"}))
        self.assertEqual("x:HMF:h4:m2", core.canonical_action_uid(
            "x", "hmf", {"h_patterns": "4", "m_patterns": "2"}))
        for bad in ("01", "1.0", "-1", "1\n2", ""):
            with self.subTest(value=bad), self.assertRaisesRegex(core.JoinFailure, "MEASUREMENT_SCHEMA_FAILURE"):
                core.canonical_action_uid("x", "hf", {"h_patterns": bad})

    def test_all_unique_passes_and_stale_f_is_not_charged(self):
        row = core.audit_circuit("x", self.base_logs(), self.base_measurements())
        self.assertEqual((8, 8, 0, 0),
                         (row["executed_stage_reference_count"], row["unique_runtime_join_count"],
                          row["missing_runtime_join_count"], row["ambiguous_runtime_join_count"]))
        self.assertEqual((4, 4), (row["eligible_action_count"], row["all_unique_action_count"]))
        self.assertTrue(core.gates_pass([row]))

    def test_timeout_with_wall_is_chargeable(self):
        logs = self.base_logs()
        logs["02_hf_coarse/F_case.driver.log"] = log("F_case", "F", exit_status="124", extra="TIMEOUT\n")
        row = core.audit_circuit("x", logs, self.base_measurements())
        self.assertTrue(core.gates_pass([row]))

    def test_missing_wall_fails_r07(self):
        logs = self.base_logs()
        logs["02_hf_coarse/F_case.driver.log"] = log("F_case", "F", elapsed="")
        row = core.audit_circuit("x", logs, self.base_measurements())
        self.assertEqual(1, row["missing_runtime_join_count"])
        self.assertFalse(core.gates_pass([row]))

    def test_duplicate_match_fails_r06(self):
        logs = self.base_logs()
        logs["other/F_case.driver.log"] = log("F_case", "F")
        row = core.audit_circuit("x", logs, self.base_measurements())
        self.assertEqual(1, row["ambiguous_runtime_join_count"])
        self.assertFalse(core.gates_pass([row]))

    def test_failure_exposes_no_row_values(self):
        measurements = self.base_measurements()
        measurements["02_hf_coarse/measurements.tsv"] = snap(
            "h_patterns\th_result\tf_result\n\tH_case\tF_case\n")
        with self.assertRaisesRegex(core.JoinFailure, "MEASUREMENT_SCHEMA_FAILURE"):
            core.audit_circuit("x", self.base_logs(), measurements)


if __name__ == "__main__":
    unittest.main()
