import hashlib
import unittest

from src.data import build_blind_runtime_recovery_plan_v1 as recovery


def snap(text):
    payload = text.encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), payload


def log(run_id, mode, elapsed="0:01.00"):
    return snap("MAPPED_COMMON_ATPG_RUN_ID=%s\nMAPPED_COMMON_ATPG_MODE=%s\n"
                "Elapsed (wall clock) time (h:mm:ss or m:ss): %s\nExit status: 0\n" %
                (run_id, mode, elapsed))


def measurements(hf_rows, hmf_rows, integer_hf_rows=None, integer_hmf_rows=None):
    integer_hf_rows = integer_hf_rows if integer_hf_rows is not None else []
    integer_hmf_rows = integer_hmf_rows if integer_hmf_rows is not None else []
    return {
        "02_hf_coarse/measurements.tsv": snap("h_patterns\th_result\tf_result\n" + hf_rows),
        "03_hmf_coarse/measurements.tsv": snap(
            "h_patterns\tm_patterns\th_result\tm_result\tf_result\n" + hmf_rows),
        "04_integer_refine/hf_measurements.tsv": snap(
            "h_patterns\tstatus\th_result\tf_result\n" + "".join(integer_hf_rows)),
        "04_integer_refine/hmf_measurements.tsv": snap(
            "h_patterns\tm_patterns\tstatus\th_result\tm_result\tf_result\n" + "".join(integer_hmf_rows)),
    }


class BuildBlindRuntimeRecoveryPlanV1Tests(unittest.TestCase):
    circuit = "s9234"

    def test_missing_references_are_deduplicated_and_minimal(self):
        h_run = "s9234_cov95v2_HF_c01_H_p64"; h = "H_" + h_run
        m_run = "s9234_cov95v2_HMF_h64_m01_p16"; m = "M_" + m_run
        m_second_run = "s9234_cov95v2_HMF_h64_m02_p32"; m_second = "M_" + m_second_run
        h_hmf_run = "s9234_cov95v2_HMF_h02_H_p64"; h_hmf = "H_" + h_hmf_run
        f_hf_run = "s9234_cov95v2_HF_c01_F_p4"; f_hf = "F_" + f_hf_run
        f_hmf_run = "s9234_cov95v2_HMF_h02_F_p4"; f_hmf = "F_" + f_hmf_run
        result = recovery.build_recovery_plan(
            self.circuit, {"x/%s.driver.log" % f_hf: log(f_hf_run, "F"),
                           "x/%s.driver.log" % f_hmf: log(f_hmf_run, "F")}, measurements(
                "64\t%s\t%s\n64\t%s\t%s\n" % (h, f_hf, h, f_hf),
                "64\t16\t%s\t%s\t%s\n"
                "64\t32\t%s\t%s\t%s\n" % (h_hmf, m, f_hmf, h_hmf, m_second, f_hmf)))
        self.assertEqual([
            {"circuit": "s9234", "stage": "02_hf_coarse", "mode": "H", "run_id": h_run,
             "source_marker": h, "pattern_limit": 64, "run_kind": "", "depends_on_h_marker": ""},
            {"circuit": "s9234", "stage": "03_hmf_coarse", "mode": "H",
             "run_id": h_hmf_run, "source_marker": h_hmf,
             "pattern_limit": 64, "run_kind": "", "depends_on_h_marker": ""},
            {"circuit": "s9234", "stage": "03_hmf_coarse", "mode": "M", "run_id": m_run,
             "source_marker": m, "pattern_limit": 16, "run_kind": "limited",
             "depends_on_h_marker": h_hmf},
            {"circuit": "s9234", "stage": "03_hmf_coarse", "mode": "M", "run_id": m_second_run,
             "source_marker": m_second, "pattern_limit": 32, "run_kind": "limited",
             "depends_on_h_marker": h_hmf}], result)
        self.assertTrue(all(set(item) == {"circuit", "stage", "mode", "run_id", "source_marker", "pattern_limit", "run_kind", "depends_on_h_marker"}
                            for item in result))

    def test_unique_existing_wall_time_is_skipped(self):
        marker_run = "s9234_cov95v2_HF_c01_H_p64"; marker = "H_" + marker_run
        f_run = "s9234_cov95v2_HF_c01_F_p4"; f_marker = "F_" + f_run
        logs = {"02_hf_coarse/%s.driver.log" % marker: log(marker_run, "H"),
                "02_hf_coarse/%s.driver.log" % f_marker: log(f_run, "F")}
        plan = recovery.build_recovery_plan(
            self.circuit, logs, measurements("64\t%s\t%s\n" % (marker, f_marker), ""))
        self.assertEqual([], plan)

    def test_existing_log_without_wall_time_refuses(self):
        marker_run = "s9234_cov95v2_HF_c01_H_p64"; marker = "H_" + marker_run
        logs = {"02_hf_coarse/%s.driver.log" % marker: log(marker_run, "H", elapsed="")}
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "EXISTS_MISSING_WALL"):
            recovery.build_recovery_plan(
                self.circuit, logs, measurements("64\t%s\tF_present\n" % marker, ""))

    def test_ambiguous_or_wrong_mode_log_refuses(self):
        marker_run = "s9234_cov95v2_HF_c01_H_p64"; marker = "H_" + marker_run
        base = measurements("64\t%s\tF_present\n" % marker, "")
        logs = {"x/%s.driver.log" % marker: log(marker_run, "H"),
                "y/%s.driver.log" % marker: log(marker_run, "H")}
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "AMBIGUOUS_LOG_MATCH"):
            recovery.build_recovery_plan(self.circuit, logs, base)
        logs = {"x/%s.driver.log" % marker: log(marker_run, "M")}
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "LOG_MODE_CONFLICT"):
            recovery.build_recovery_plan(self.circuit, logs, base)

    def test_illegal_run_id_and_unsupported_integer_stage_refuse(self):
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "ILLEGAL_RUN_ID"):
            recovery.build_recovery_plan(self.circuit, {}, measurements("64\tH_H_short\tF_F_short\n", ""))
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "RECOVERY_STAGE_UNSUPPORTED"):
            recovery.build_recovery_plan(
                self.circuit, {}, measurements("", "", [
                    "64\t\tH_s9234_cov95v2_HF_c01_H_p64\tF_s9234_cov95v2_HF_c01_F_p4\n"]))

    def test_missing_f_is_out_of_scope_and_phase2_mfull_binds_h_dependency(self):
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "OUT_OF_SCOPE_MODE"):
            recovery.build_recovery_plan(self.circuit, {}, measurements(
                "64\tH_s9234_cov95v2_HF_c01_H_p64\tF_s9234_cov95v2_HF_c01_F_p4\n", ""))
        h_run = "s38584_HMF_src_H_5pct_p64_v0_1"; h = "H_" + h_run
        m_run = "s38584_HMF_H_5pct_p64_Mfull_v0_1"; m = "M_" + m_run
        f_run = "s38584_legacy_f"; f = "F_" + f_run
        logs = {"x/%s.driver.log" % f: log(f_run, "F")}
        plan = recovery.build_recovery_plan("s38584", logs, measurements(
            "", "64\t16\t%s\t%s\t%s\n" % (h, m, f)))
        self.assertEqual([
            {"circuit": "s38584", "stage": "03_hmf_coarse", "mode": "H", "run_id": h_run,
             "source_marker": h, "pattern_limit": 64, "run_kind": "", "depends_on_h_marker": ""},
            {"circuit": "s38584", "stage": "03_hmf_coarse", "mode": "M", "run_id": m_run,
             "source_marker": m, "pattern_limit": 16, "run_kind": "full", "depends_on_h_marker": h}], plan)

    def test_v2_mfull_and_phase2_mlimited_are_exactly_bound(self):
        h_run = "s9234_cov95v2_HMF_h02_H_p64"; h = "H_" + h_run
        m_run = "s9234_cov95v2_HMF_h64_Mfull"; m = "M_" + m_run
        f_run = "existing_f"; f = "F_" + f_run
        plan = recovery.build_recovery_plan(self.circuit, {"x/%s.driver.log" % f: log(f_run, "F")}, measurements(
            "", "64\t16\t%s\t%s\t%s\n" % (h, m, f)))
        self.assertEqual("full", plan[1]["run_kind"])
        self.assertEqual(16, plan[1]["pattern_limit"])
        phase2_h_run = "s38584_HMF_src_H_5pct_p64_v0_1"; phase2_h = "H_" + phase2_h_run
        phase2_m_run = "s38584_HMF_H_5pct_p64_M_5pct_p16_v0_1"; phase2_m = "M_" + phase2_m_run
        plan = recovery.build_recovery_plan("s38584", {"x/%s.driver.log" % f: log(f_run, "F")}, measurements(
            "", "64\t16\t%s\t%s\t%s\n" % (phase2_h, phase2_m, f)))
        self.assertEqual(("limited", 16, phase2_h),
                         (plan[1]["run_kind"], plan[1]["pattern_limit"], plan[1]["depends_on_h_marker"]))
        bad_m = "M_s38584_HMF_H_5pct_p64_M_5pct_p32_v0_1"
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "M_PATTERN_LIMIT_MISMATCH"):
            recovery.build_recovery_plan("s38584", {"x/%s.driver.log" % f: log(f_run, "F")}, measurements(
                "", "64\t16\t%s\t%s\t%s\n" % (phase2_h, bad_m, f)))

    def test_scope_not_run_and_missing_marker_fail_closed(self):
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "CIRCUIT_NOT_AUTHORIZED"):
            recovery.build_recovery_plan("b20", {}, measurements("", ""))
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "RECOVERY_STAGE_UNSUPPORTED"):
            recovery.build_recovery_plan(self.circuit, {}, measurements("", "", [
                "64\tTARGET_BEFORE_F\tH_s9234_cov95v2_HF_c01_H_p64\tF_stale_f\n"]))
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "MISSING_RESULT_MARKER"):
            recovery.build_recovery_plan(self.circuit, {}, measurements("64\t\tF_path\n", ""))

    def test_wrong_prefix_duplicate_conflict_and_zero_mfull_refuse(self):
        h = "H_s9234_cov95v2_HF_c01_H_p64"
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "SOURCE_MARKER_PREFIX_MISMATCH"):
            recovery.build_recovery_plan(self.circuit, {}, measurements(
                "64\tM_s9234_cov95v2_HF_c01_H_p64\tF_present\n", ""))
        h_hmf = "H_s9234_cov95v2_HMF_h02_H_p64"
        m = "M_s9234_cov95v2_HMF_h64_Mfull"
        f = "F_existing"
        logs = {"x/%s.driver.log" % f: log("existing", "F")}
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "DUPLICATE_ATTEMPT_CONFLICT"):
            recovery.build_recovery_plan(self.circuit, logs, measurements("",
                "64\t16\t%s\t%s\t%s\n64\t32\t%s\t%s\t%s\n" %
                (h_hmf, m, f, h_hmf, m, f)))
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "MFULL_M_PATTERN_INVALID"):
            recovery.build_recovery_plan(self.circuit, logs, measurements("",
                "64\t0\t%s\t%s\t%s\n" % (h_hmf, m, f)))

    def test_phase3_full_h_is_exact_deduplicated_and_conflict_checked(self):
        full = "H_s9234_H_full_phase3_v2"
        f_hf = "F_hf_existing"; f_hmf = "F_hmf_existing"; m = "M_existing"
        logs = {
            "x/%s.driver.log" % f_hf: log("hf_existing", "F"),
            "x/%s.driver.log" % f_hmf: log("hmf_existing", "F"),
            "x/%s.driver.log" % m: log("existing", "M"),
        }
        hmf_rows = "".join("64\t16\t%s\t%s\t%s\n" % (full, m, f_hmf) for unused in range(21))
        plan = recovery.build_recovery_plan(self.circuit, logs, measurements(
            "64\t%s\t%s\n" % (full, f_hf), hmf_rows))
        self.assertEqual([{"circuit": "s9234", "stage": "01_single_mode_full", "mode": "H",
                           "run_id": "s9234_H_full_phase3_v2", "source_marker": full,
                           "pattern_limit": 64, "run_kind": "full", "depends_on_h_marker": ""}], plan)
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "DUPLICATE_ATTEMPT_CONFLICT"):
            recovery.build_recovery_plan(self.circuit, logs, measurements("",
                "64\t16\t%s\t%s\t%s\n32\t16\t%s\t%s\t%s\n" % (full, m, f_hmf, full, m, f_hmf)))

    def test_phase3_full_h_rejects_wrong_circuit_version_and_nonpositive_limit(self):
        f = "F_existing"; logs = {"x/%s.driver.log" % f: log("existing", "F")}
        for marker in ("H_s38584_H_full_phase3_v1", "H_s9234_H_full_phase3_v1"):
            with self.subTest(marker=marker), self.assertRaisesRegex(recovery.RecoveryPlanFailure, "ILLEGAL_RUN_ID"):
                recovery.build_recovery_plan(self.circuit, logs, measurements("64\t%s\t%s\n" % (marker, f), ""))
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "PHASE3_FULL_H_PATTERN_INVALID"):
            recovery.build_recovery_plan(self.circuit, logs, measurements(
                "0\tH_s9234_H_full_phase3_v2\t%s\n" % f, ""))
        with self.assertRaisesRegex(recovery.RecoveryPlanFailure, "RUN_ID_STAGE_MISMATCH"):
            recovery.build_recovery_plan(self.circuit, logs, measurements("", "", [
                "64\t\tH_s9234_H_full_phase3_v2\t%s\n" % f]))

    def test_wb_dma_phase4_full_h_exact_name_is_accepted(self):
        full = "H_wb_dma_H_full_phase4_v2"
        f = "F_existing"
        plan = recovery.build_recovery_plan(
            "wb_dma", {"x/%s.driver.log" % f: log("existing", "F")},
            measurements("128\t%s\t%s\n" % (full, f), ""))
        self.assertEqual(("01_single_mode_full", "wb_dma_H_full_phase4_v2", 128, "full"),
                         (plan[0]["stage"], plan[0]["run_id"],
                          plan[0]["pattern_limit"], plan[0]["run_kind"]))


if __name__ == "__main__":
    unittest.main()
