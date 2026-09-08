from __future__ import print_function

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "src", "data")
SCRIPT = os.path.join(DATA, "recheck_runtime_source_digests.py")
AUDIT = os.path.join(DATA, "audit_runtime_log_inventory.py")
sys.path.insert(0, DATA)
import recheck_runtime_source_digests as recheck


def frozen_spec(work):
    entries = []
    version = "r03-canonical-18-v2"
    for index, logical_id in enumerate(sorted(recheck.CANONICAL_VERSIONS[version])):
        expected = recheck.CANONICAL_DIGESTS[logical_id]
        if logical_id == "phase2.s38584.source":
            source = os.path.join(work, "source.csv")
            with open(source, "wb") as stream:
                stream.write(b"canonical source\n")
            entries.append({"logical_id": logical_id, "kind": "file",
                            "source_path": source, "expected_sha256": expected})
        else:
            source = os.path.join(work, "inventory_%02d" % index)
            os.mkdir(source)
            entries.append({"logical_id": logical_id, "kind": "inventory",
                            "input_path": source, "evidence_root": source,
                            "extra_logs": [], "circuit": "c%02d" % index,
                            "cohort": "frozen", "expected_sha256": expected})
    return {"schema_version": recheck.SPEC_SCHEMA,
            "receipt_version": version, "entries": entries}


def build_with_frozen_digests(specification):
    actual_recheck = recheck.sha256_file(recheck.__file__)

    def fake_file(path):
        if os.path.abspath(path) == os.path.abspath(AUDIT):
            return recheck.AUDIT_TOOL_SHA256
        if os.path.abspath(path) == os.path.abspath(recheck.__file__):
            return actual_recheck
        for entry in specification["entries"]:
            if entry.get("source_path") == path:
                return entry["expected_sha256"]
        raise AssertionError("unexpected file digest request")

    with mock.patch.object(recheck, "sha256_file", side_effect=fake_file), \
            mock.patch.object(recheck, "inventory_digest",
                              side_effect=lambda entry, _tool, _runner: entry["expected_sha256"]):
        return recheck.build_receipt(specification, audit_script=AUDIT)


class CanonicalDigestRecheckTest(unittest.TestCase):
    def test_exact_frozen_set_is_deterministic_and_aggregate_only(self):
        with tempfile.TemporaryDirectory() as work:
            specification = frozen_spec(work)
            first = build_with_frozen_digests(specification)
            reversed_spec = dict(specification)
            reversed_spec["entries"] = list(reversed(specification["entries"]))
            second = build_with_frozen_digests(reversed_spec)
            self.assertEqual(first, second)
            self.assertEqual({"entry_count": 18, "file_count": 1,
                              "inventory_count": 17}, first["counts"])
            self.assertEqual(sorted(recheck.CANONICAL_VERSIONS["r03-canonical-18-v2"]),
                             list(first["artifacts"]))
            serialized = json.dumps(first, sort_keys=True).lower()
            for forbidden in ("path", "run_id", "runtime", "candidate", "source.csv", "frozen"):
                self.assertNotIn(forbidden, serialized)

    def test_unfrozen_version_mapping_missing_and_duplicate_are_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            specification = frozen_spec(work)
            bad = dict(specification)
            bad["receipt_version"] = "candidate_run_id_7"
            with self.assertRaises(ValueError):
                build_with_frozen_digests(bad)
            bad = dict(specification)
            bad["entries"] = [dict(entry) for entry in specification["entries"]]
            bad["entries"][0]["expected_sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                build_with_frozen_digests(bad)
            bad = dict(specification)
            bad["entries"] = specification["entries"][:-1]
            with self.assertRaises(ValueError):
                build_with_frozen_digests(bad)
            bad = dict(specification)
            bad["entries"] = specification["entries"] + [specification["entries"][0]]
            with self.assertRaises(ValueError):
                build_with_frozen_digests(bad)
            with self.assertRaises(ValueError):
                recheck.strict_json_loads('{"entries":[],"entries":[]}')

    def test_inventory_identity_subprocess_failure_and_no_output_on_failure(self):
        with tempfile.TemporaryDirectory() as work:
            root = os.path.join(work, "logs")
            os.mkdir(root)
            entry = {"input_path": root, "evidence_root": root, "extra_logs": [],
                     "circuit": "circuit", "cohort": "cohort"}
            wrong = {"schema_version": "runtime_log_inventory_aggregate_v1",
                     "circuit": "other", "cohort": "cohort",
                     "inventory_manifest_sha256": "0" * 64}
            with self.assertRaises(ValueError):
                recheck.inventory_digest(entry, AUDIT,
                                         runner=lambda _command: json.dumps(wrong).encode("utf-8"))
            with self.assertRaises(ValueError):
                recheck.inventory_digest(entry, AUDIT,
                                         runner=lambda command: (_ for _ in ()).throw(
                                             subprocess.CalledProcessError(1, command)))
            spec_path = os.path.join(work, "bad.json")
            output = os.path.join(work, "receipt.json")
            with open(spec_path, "w") as stream:
                json.dump({"schema_version": recheck.SPEC_SCHEMA,
                           "receipt_version": "not-frozen", "entries": []}, stream)
            self.assertNotEqual(0, subprocess.call([sys.executable, SCRIPT, "--spec", spec_path,
                                                    "--output", output]))
            self.assertFalse(os.path.exists(output))
            with open(output, "wb") as stream:
                stream.write(b"preserve")
            self.assertNotEqual(0, subprocess.call([sys.executable, SCRIPT, "--spec", spec_path,
                                                    "--output", output]))
            with open(output, "rb") as stream:
                self.assertEqual(b"preserve", stream.read())


if __name__ == "__main__":
    unittest.main()
