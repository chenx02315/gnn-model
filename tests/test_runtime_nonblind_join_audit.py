from __future__ import print_function

import csv
import json
import os
import re
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT = os.path.join(ROOT, "data", "manifests", "runtime_nonblind_join_audit_v2.json")
P0_STATUS = os.path.join(ROOT, "contracts", "p0_status.md")
JOIN_ROOT = os.path.normpath(os.path.join(
    ROOT, "..", "multimode_atpg_search_thesis_20260901", "runtime_recovery_v1", "joins_nonblind_v2"))
NONBLIND_CIRCUITS = ("b18", "s35932", "s38417", "s13207", "s15850", "s5378")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RuntimeNonblindJoinAuditTest(unittest.TestCase):
    def test_nonblind_join_audit_is_self_consistent(self):
        # The explicit allowlist prevents this test from opening BLIND_TEST data.
        with open(AUDIT, "r", encoding="utf-8") as stream:
            audit = json.load(stream)

        aggregate = audit["aggregate"]
        circuits = audit["circuits"]
        self.assertEqual(aggregate["circuit_count"], len(circuits))
        self.assertEqual(0, aggregate["missing_count"])
        self.assertEqual(0, aggregate["missing_result_path_count"])
        self.assertEqual(0, aggregate["ambiguity_count"])

        self.assertEqual(set(NONBLIND_CIRCUITS), set(circuits))
        summed = {key: sum(circuit[key] for circuit in circuits.values()) for key in (
            "row_count", "unique_join_count", "explicit_pass_unique_count",
            "unknown_legacy_status_unique_count", "not_run_count",
            "repeatability_no_result_path_count", "ambiguity_count",
            "cross_stage_unique_count", "marker_run_id_mismatch_count",
        )}
        self.assertEqual(aggregate["row_count"], summed["row_count"])
        self.assertEqual(aggregate["unique_join_count"], summed["unique_join_count"])
        self.assertEqual(aggregate["explicit_pass_unique_count"], summed["explicit_pass_unique_count"])
        self.assertEqual(aggregate["unknown_legacy_status_unique_count"], summed["unknown_legacy_status_unique_count"])
        self.assertEqual(aggregate["not_run_count"], summed["not_run_count"])
        self.assertEqual(aggregate["repeatability_no_result_path_count"], summed["repeatability_no_result_path_count"])
        self.assertEqual(aggregate["ambiguity_count"], summed["ambiguity_count"])
        self.assertEqual(aggregate["cross_stage_unique_count"], summed["cross_stage_unique_count"])
        self.assertEqual(aggregate["source_basename_marker_run_id_mismatch_count"], summed["marker_run_id_mismatch_count"])

        for name, circuit in circuits.items():
            self.assertEqual(
                circuit["unique_join_count"],
                circuit["explicit_pass_unique_count"] + circuit["unknown_legacy_status_unique_count"],
                name,
            )
            self.assertEqual(0, circuit["ambiguity_count"], name)

        recomputed = {key: aggregate[key] for key in (
            "explicit_pass_unique_count", "unknown_legacy_status_unique_count")}
        if os.path.isdir(JOIN_ROOT):
            recomputed = {"explicit_pass_unique_count": 0, "unknown_legacy_status_unique_count": 0}
            for circuit in NONBLIND_CIRCUITS:
                path = os.path.join(JOIN_ROOT, circuit + "_join_v2.tsv")
                self.assertTrue(os.path.isfile(path), path)
                counts = {"explicit_pass_unique_count": 0, "unknown_legacy_status_unique_count": 0}
                unique_count = 0
                with open(path, "r", encoding="utf-8", newline="") as stream:
                    for row in csv.DictReader(stream, delimiter="\t"):
                        self.assertEqual(circuit, row["circuit"])
                        if row["join_status"] != "UNIQUE":
                            continue
                        unique_count += 1
                        if row["atpg_status"] == "PASS":
                            self.assertEqual("SUCCESS", row["attempt_outcome_class"])
                            counts["explicit_pass_unique_count"] += 1
                        elif (row["atpg_status"] == "" and
                              row["parse_status"] == "PASS_RUNTIME_OUTCOME_PENDING" and
                              row["attempt_outcome_class"] == "UNKNOWN_LEGACY_STATUS"):
                            counts["unknown_legacy_status_unique_count"] += 1
                        else:
                            self.fail("unexpected UNIQUE runtime status in %s: %r" % (circuit, row))
                self.assertEqual(circuits[circuit]["unique_join_count"], unique_count, circuit)
                for key, count in counts.items():
                    self.assertEqual(circuits[circuit][key], count, circuit + ":" + key)
                    recomputed[key] += count

            for key, count in recomputed.items():
                self.assertEqual(aggregate[key], count, key)
        with open(P0_STATUS, "r", encoding="utf-8") as stream:
            p0_status = stream.read()
        statement = re.search(r"唯一连接中有\s*([\d,]+)\s*条显式 ATPG PASS、([\d,]+)\s*条\s*`UNKNOWN_LEGACY_STATUS`", p0_status)
        self.assertIsNotNone(statement)
        self.assertEqual(recomputed["explicit_pass_unique_count"], int(statement.group(1).replace(",", "")))
        self.assertEqual(recomputed["unknown_legacy_status_unique_count"], int(statement.group(2).replace(",", "")))

        def check_sha_fields(value, location):
            if isinstance(value, dict):
                for key, child in value.items():
                    check_sha_fields(child, location + "." + key)
            elif location.endswith("sha256"):
                self.assertIsInstance(value, str, location)
                self.assertRegex(value, SHA256, location)

        check_sha_fields(audit, "audit")


if __name__ == "__main__":
    unittest.main()
