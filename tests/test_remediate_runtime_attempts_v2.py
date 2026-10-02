import csv
import hashlib
import os
import tempfile
import unittest

from src.data import remediate_runtime_attempts_v2 as remediate
from src.data.runtime_schema import MANIFEST_V2_FIELDS


def log(start, status="PASS", elapsed="0:01", exit_status="0", prefix=""):
    marker = ("MAPPED_INCREMENTAL_ATPG_STATUS=%s\n" % status) if status else ""
    return (prefix + "//  Siemens software executing under x86-64 Linux on %s.\n" % start
            + marker + "User time (seconds): 0.5\nSystem time (seconds): 0.1\n"
            + "Maximum resident set size (kbytes): 10\n"
            + "Elapsed (wall clock) time (h:mm:ss or m:ss): %s\n" % elapsed
            + "Exit status: %s\n" % exit_status).encode("utf-8")


class RemediationTests(unittest.TestCase):
    def row(self, circuit, role, family, attempt, group, path, digest):
        row = dict((field, "") for field in MANIFEST_V2_FIELDS)
        row.update({"attempt_id": attempt, "circuit": circuit, "role": role,
                    "family": family, "retry_group_id": group,
                    "source_log_path": path, "source_log_sha256": digest})
        return row

    def fixture(self, root, special=None):
        roster = [
            ("s13207", "TRAIN", "iscas89_s13207"),
            ("s15850", "TRAIN", "iscas89_s15850"),
            ("s35932", "TRAIN", "iscas89_s35932"),
            ("s38417", "TRAIN", "iscas89_s38417"),
            ("aes_core", "TRAIN", "iwls_aes_core"),
            ("spi", "TRAIN", "iwls_spi"),
            ("s5378", "VALIDATION", "iscas89_s5378"),
            ("tv80", "VALIDATION", "iwls_tv80"),
        ]
        items = []
        for index, (circuit, role, family) in enumerate(roster):
            payload = (special if special is not None and circuit == "s38417" else
                       log("Tue Aug %02d 10:00:00 CST 2026" % (index + 1)))
            path = circuit + ".driver.log"
            with open(os.path.join(root, path), "wb") as stream:
                stream.write(payload)
            digest = hashlib.sha256(payload).hexdigest()
            manifest = os.path.join(root, circuit + ".tsv")
            with open(manifest, "w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=MANIFEST_V2_FIELDS,
                                        delimiter="\t", lineterminator="\n")
                writer.writeheader()
                writer.writerow(self.row(circuit, role, family, "parent_" + circuit,
                                          "group_" + circuit, path, digest))
            items.append({"circuit": circuit, "role": role, "family": family,
                          "manifest": manifest, "evidence_roots": [root]})
        return {"schema_version": "runtime-attempt-remediation-bindings-v2",
                "circuits": items}

    def test_incremental_pass_becomes_known_success(self):
        with tempfile.TemporaryDirectory() as root:
            outputs, aggregate = remediate.remediate(self.fixture(root))
            row = outputs["s13207"]["rows"][0]
            self.assertEqual(("SUCCESS", "NO_TIMEOUT", "1", "KNOWN_ORDER"),
                             tuple(row[key] for key in (
                                 "attempt_outcome_class", "timeout_status",
                                 "retry_order", "retry_order_status")))
            self.assertEqual(8, sum(item["output_attempt_count"] for item in aggregate))

    def test_two_sessions_retain_failure_and_terminal_parent_id(self):
        first = log("Sun Aug 09 00:47:48 CST 2026", status="", elapsed="0:02",
                    exit_status="3", prefix="ERROR: refusing to overwrite path\n")
        second = ("MAPPED_INCREMENTAL_ATPG_STATUS=PASS\n"
                  "User time (seconds): 1\nSystem time (seconds): 1\n"
                  "Maximum resident set size (kbytes): 20\n"
                  "Elapsed (wall clock) time (h:mm:ss or m:ss): 0:03\n"
                  "Exit status: 0\n").encode("utf-8")
        with tempfile.TemporaryDirectory() as root:
            outputs, _aggregate = remediate.remediate(self.fixture(root, first + second))
            rows = outputs["s38417"]["rows"]
            self.assertEqual(2, len(rows))
            self.assertEqual(["FAILURE", "SUCCESS"], [row["attempt_outcome_class"] for row in rows])
            self.assertNotEqual("parent_s38417", rows[0]["attempt_id"])
            self.assertEqual("parent_s38417", rows[1]["attempt_id"])
            self.assertEqual(["1", "2"], [row["retry_order"] for row in rows])
            self.assertEqual("GNU_TIME_FOOTER_EMISSION_ORDER",
                             outputs["s38417"]["lineage"][0]["order_evidence"])

    def test_unrecognized_nonzero_fails_closed(self):
        payload = log("Sun Aug 09 00:47:48 CST 2026", status="", exit_status="9")
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(remediate.RemediationError,
                                        "SESSION_OUTCOME_UNRESOLVED_1"):
                remediate.remediate(self.fixture(root, payload))

    def test_cross_file_group_uses_embedded_start_order(self):
        with tempfile.TemporaryDirectory() as root:
            bindings = self.fixture(root)
            item = bindings["circuits"][0]
            first_path = "s13207.driver.log"
            second_path = "s13207_second.driver.log"
            second_payload = log("Tue Aug 01 09:59:59 CST 2026")
            with open(os.path.join(root, second_path), "wb") as stream:
                stream.write(second_payload)
            rows, _sha = remediate.read_manifest(item["manifest"])
            rows.append(self.row("s13207", "TRAIN", "iscas89_s13207", "second",
                                 "group_s13207", second_path,
                                 hashlib.sha256(second_payload).hexdigest()))
            with open(item["manifest"], "w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=MANIFEST_V2_FIELDS,
                                        delimiter="\t", lineterminator="\n")
                writer.writeheader(); writer.writerows(rows)
            outputs, _aggregate = remediate.remediate(bindings)
            ordered = outputs["s13207"]["rows"]
            self.assertEqual("second", ordered[0]["attempt_id"])
            self.assertEqual("EMBEDDED_SIEMENS_START_ORDER",
                             outputs["s13207"]["lineage"][0]["order_evidence"])


if __name__ == "__main__":
    unittest.main()
