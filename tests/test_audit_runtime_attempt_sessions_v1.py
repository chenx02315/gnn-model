import csv
import hashlib
import json
import os
import tempfile
import unittest

from src.data import audit_runtime_attempt_sessions_v1 as audit
from src.data.runtime_schema import MANIFEST_V2_FIELDS


class SessionAuditTests(unittest.TestCase):
    def write_manifest(self, root, circuit, role, family, log_name, payload):
        log_path = os.path.join(root, log_name)
        with open(log_path, "wb") as stream:
            stream.write(payload)
        digest = hashlib.sha256(payload).hexdigest()
        row = dict((field, "") for field in MANIFEST_V2_FIELDS)
        row.update({"attempt_id": "attempt_" + circuit, "circuit": circuit,
                    "role": role, "family": family, "retry_group_id": "group_" + circuit,
                    "source_log_path": log_name, "source_log_sha256": digest})
        manifest = os.path.join(root, circuit + ".tsv")
        with open(manifest, "w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=MANIFEST_V2_FIELDS,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        return manifest

    def bindings(self, root, payload=None):
        payload = payload or (
            b"//  Siemens software executing under x86-64 Linux on Tue Aug 11 23:02:25 CST 2026.\n"
            b"MAPPED_INCREMENTAL_ATPG_STATUS=PASS\n"
            b"Elapsed (wall clock) time (h:mm:ss or m:ss): 0:01.00\nExit status: 0\n")
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
        for circuit, role, family in roster:
            manifest = self.write_manifest(root, circuit, role, family, circuit + ".driver.log", payload)
            items.append({"circuit": circuit, "role": role, "family": family,
                          "manifest": manifest, "evidence_roots": [root]})
        return {"schema_version": "runtime-attempt-session-bindings-v1", "circuits": items}

    def test_incremental_marker_and_footer_are_counted(self):
        with tempfile.TemporaryDirectory() as root:
            receipt, details = audit.audit(self.bindings(root))
            self.assertEqual("PASS_READ_ONLY_INVENTORY", receipt["status"])
            self.assertEqual(8, receipt["totals"]["incremental_status_count"])
            self.assertEqual(8, receipt["totals"]["effective_session_count"])
            self.assertEqual(0, receipt["totals"]["no_explicit_status_log_count"])
            self.assertEqual(8, len(details))

    def test_multiple_footers_are_not_collapsed(self):
        payload = (
            b"//  Siemens software executing under x86-64 Linux on Sun Aug 09 00:47:48 CST 2026.\n"
            b"ERROR: refusing to overwrite\nElapsed (wall clock) time (h:mm:ss or m:ss): 0:02\nExit status: 3\n"
            b"MAPPED_INCREMENTAL_ATPG_STATUS=PASS\n"
            b"Elapsed (wall clock) time (h:mm:ss or m:ss): 0:03\nExit status: 0\n")
        with tempfile.TemporaryDirectory() as root:
            receipt, details = audit.audit(self.bindings(root, payload))
            self.assertEqual(16, receipt["totals"]["effective_session_count"])
            self.assertEqual(8, receipt["totals"]["multi_elapsed_log_count"])
            self.assertTrue(all(row["elapsed_footer_count"] == 2 for row in details))

    def test_sha_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            bindings = self.bindings(root)
            manifest = bindings["circuits"][0]["manifest"]
            with open(manifest, encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
            rows[0]["source_log_sha256"] = "0" * 64
            with open(manifest, "w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=MANIFEST_V2_FIELDS,
                                        delimiter="\t", lineterminator="\n")
                writer.writeheader(); writer.writerows(rows)
            with self.assertRaisesRegex(audit.AuditError,
                                        "SOURCE_BINDING_MATCH_COUNT_0:s13207:attempt_s13207"):
                audit.audit(bindings)

    def test_path_escape_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            bindings = self.bindings(root)
            manifest = bindings["circuits"][0]["manifest"]
            with open(manifest, encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
            rows[0]["source_log_path"] = "../escape.driver.log"
            with open(manifest, "w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=MANIFEST_V2_FIELDS,
                                        delimiter="\t", lineterminator="\n")
                writer.writeheader(); writer.writerows(rows)
            with self.assertRaisesRegex(audit.AuditError,
                                        "SOURCE_PATH_ESCAPE:s13207:attempt_s13207"):
                audit.audit(bindings)

    def test_multiple_roots_require_exactly_one_digest_match(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as second:
            bindings = self.bindings(root)
            bindings["circuits"][0]["evidence_roots"].append(second)
            source = os.path.join(root, "s13207.driver.log")
            with open(source, "rb") as stream:
                payload = stream.read()
            with open(os.path.join(second, "s13207.driver.log"), "wb") as stream:
                stream.write(payload)
            with self.assertRaisesRegex(audit.AuditError,
                                        "SOURCE_BINDING_MATCH_COUNT_2:s13207:attempt_s13207"):
                audit.audit(bindings)


if __name__ == "__main__":
    unittest.main()
