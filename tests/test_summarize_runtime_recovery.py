from __future__ import print_function

import csv
import json
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "src", "data", "summarize_runtime_recovery.py")


def put(path, value):
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)


def make_contract(path):
    put(path, json.dumps({"formal_runtime_membership": {
        "PILOT": [{"circuit": "b20", "family": "itc"}],
        "TRAIN": [{"circuit": "s13207", "family": "iscas"}],
        "BLIND_TEST": [{"circuit": "s9234", "family": "blind"}],
    }}))


def make_evidence(root, circuit, audit_rows=2, flat=False):
    inventory = os.path.join(root, circuit + "_inventory.json")
    attempt = os.path.join(root, circuit + "_attempt.tsv")
    join = os.path.join(root, circuit + "_join.tsv")
    audit = os.path.join(root, circuit + "_audit.json")
    role, family = ("PILOT", "itc") if circuit == "b20" else ("TRAIN", "iscas")
    manifest_sha = "a" * 64
    entry = {"circuit": circuit, "role": role, "family": family, "driver_log_count": 2, "elapsed_footer_count": 2,
             "exit_footer_count": 2, "atpg_status_marker_count": 1, "outcome_pending_count": 1,
             "inventory_manifest_sha256": manifest_sha, "cohort": "cohort_a", "field_policy": "footer_required"}
    payload = dict(entry) if flat else {"schema_version": "inventory_v1", "circuits": {circuit: entry}}
    if flat:
        payload["schema_version"] = "inventory_v1"
    put(inventory, json.dumps(payload))
    header = "circuit\trole\tfamily\tcohort\tenvironment_cohort\tparse_status\tattempt_outcome_class\twall_s\texit_status\tretry_order_status\tsemantics_status\ttimeout_status\tinventory_manifest_sha256\n"
    put(attempt, header +
        circuit + "\t" + role + "\t" + family + "\tcohort_a\tenv_a\tPASS\tSUCCESS\t1.0\t0\tKNOWN\tFOOTER_VERIFIED\tunknown\t" + manifest_sha + "\n" +
        circuit + "\t" + role + "\t" + family + "\tcohort_a\tenv_a\tPASS_RUNTIME_OUTCOME_PENDING\tUNKNOWN_LEGACY_STATUS\t\t2\tUNKNOWN_ORDER\tFOOTER_VERIFIED\tunknown\t" + manifest_sha + "\n")
    put(join, "circuit\trole\tfamily\tjoin_status\tatpg_status\tparse_status\tattempt_outcome_class\tstage_relation\tmarker_run_id_mismatch\n" +
        circuit + "\t" + role + "\t" + family + "\tUNIQUE\tPASS\tPASS\tSUCCESS\tSAME_STAGE\ttrue\n" +
        circuit + "\t" + role + "\t" + family + "\tUNIQUE\t\tPASS_RUNTIME_OUTCOME_PENDING\tUNKNOWN_LEGACY_STATUS\tCROSS_STAGE\tfalse\n")
    put(audit, json.dumps({"row_count": audit_rows, "ambiguity_count": 0,
                            "cross_stage_unique_count": 1,
                            "source_basename_marker_run_id_mismatch_count": 1}))
    return inventory, attempt, join, audit


class SummarizeRuntimeRecoveryTest(unittest.TestCase):
    def command(self, contract, output, specs):
        command = [sys.executable, SCRIPT, "--split-contract", contract, "--output", output]
        for name, paths in specs:
            command.extend(["--circuit", name + "=" + ",".join(paths)])
        return command

    def test_two_nonblind_circuits_are_summarized(self):
        with tempfile.TemporaryDirectory() as work:
            contract = os.path.join(work, "split.json")
            make_contract(contract)
            output = os.path.join(work, "summary.json")
            command = self.command(contract, output, [("b20", make_evidence(work, "b20")),
                                                       ("s13207", make_evidence(work, "s13207"))])
            subprocess.check_call(command)
            with open(output, "r", encoding="utf-8") as stream:
                summary = json.load(stream)
            self.assertEqual(2, summary["aggregate"]["circuit_count"])
            self.assertEqual((4, 2, 2), tuple(summary["aggregate"]["join"][key] for key in (
                "row_count", "explicit_pass_unique_count", "unknown_legacy_status_unique_count")))
            self.assertEqual((2, 2), tuple(summary["aggregate"]["attempt"][key] for key in (
                "missing_wall_count", "nonzero_exit_count")))
            self.assertEqual(4, summary["aggregate"]["inventory_counts"]["elapsed_footer_count"])
            self.assertTrue(all(len(value) == 64 for value in summary["circuits"]["b20"]["file_sha256"].values()))
            self.assertEqual({"cohort_a": 2}, summary["circuits"]["b20"]["attempt"]["cohort_counts"])

    def test_flat_inventory_schema_and_provenance(self):
        with tempfile.TemporaryDirectory() as work:
            contract = os.path.join(work, "split.json")
            make_contract(contract)
            output = os.path.join(work, "summary.json")
            subprocess.check_call(self.command(contract, output, [("b20", make_evidence(work, "b20", flat=True))]))
            with open(output, "r", encoding="utf-8") as stream:
                result = json.load(stream)
            circuit = result["circuits"]["b20"]
            self.assertEqual(2, circuit["inventory_counts"]["driver_log_count"])
            self.assertEqual(("a" * 64, "cohort_a", "footer_required"), tuple(circuit["inventory_provenance"][key] for key in (
                "inventory_manifest_sha256", "cohort", "field_policy")))

    def test_blind_is_refused_before_missing_inputs_are_opened(self):
        with tempfile.TemporaryDirectory() as work:
            contract = os.path.join(work, "split.json")
            make_contract(contract)
            command = self.command(contract, os.path.join(work, "out.json"), [
                ("b20", ("missing_inventory", "missing_attempt", "missing_join", "missing_audit")),
                ("s9234", ("missing_inventory", "missing_attempt", "missing_join", "missing_audit")),
            ])
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("BLIND_TEST", result.stderr.decode("utf-8"))

    def test_join_audit_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as work:
            contract = os.path.join(work, "split.json")
            make_contract(contract)
            command = self.command(contract, os.path.join(work, "out.json"), [("b20", make_evidence(work, "b20", audit_rows=3))])
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("join audit mismatch", result.stderr.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
