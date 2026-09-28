import csv
import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "audit" / "audit_common_fault_denominator_v2.py"
CONTRACT_PATH = ROOT / "contracts" / "common_fault_denominator_v2.json"
SPEC = importlib.util.spec_from_file_location("denominator_v2", str(MODULE_PATH))
denominator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(denominator)


def digest(path):
    value = hashlib.sha256()
    with open(str(path), "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


class CommonFaultDenominatorV2Test(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="denominator-v2-"))
        self.evidence = self.temp / "evidence"
        self.evidence.mkdir()

    def tearDown(self):
        shutil.rmtree(str(self.temp), ignore_errors=True)

    def write_text(self, relative, text):
        path = self.evidence / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        return path

    def make_circuit(self, circuit="c1", legacy_header=False,
                     basic_override=None, mapping_override=None,
                     fault_model="stuck-at"):
        directory = Path(circuit)
        if legacy_header:
            header = ["stuck_value", "canonical_path", "F_path", "M_path", "H_path"]
        else:
            header = ["stuck_value", "canonical_core_path", "F_native_path",
                      "M_native_path", "H_native_path"]
        rows = mapping_override or [
            ["0", "/U2/a", "/U1/a", "/U2/a", "/U2/a"],
            ["1", "/U2/b", "/U1/b", "/U2/b", "/U2/b"],
        ]
        mapping = self.evidence / directory / "canonical_fault_mapping.tsv"
        mapping.parent.mkdir(parents=True, exist_ok=True)
        with mapping.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
            writer.writerow(header)
            writer.writerows(rows)
        mode_paths = {}
        native_paths = {}
        for mode, column in (("F", 2), ("M", 3), ("H", 4)):
            lines = ["      %s    CLASS_%s_%d   %s\n" %
                     (row[0], mode, index, row[column])
                     for index, row in enumerate(rows)]
            if basic_override and mode in basic_override:
                lines = basic_override[mode]
            mode_paths[mode] = self.write_text(
                directory / (mode + "_common_initial_faults.basic"), "".join(lines))
            native_lines = [
                '      %s,  UC,        "%s";\n' % (row[0], row[column])
                for row in rows]
            native_lines.append(
                '      0,  UC,        "/%s_only";\n' % mode.lower())
            native_paths[mode] = self.write_text(
                directory / (mode + "_native_faults.mtfi"),
                "FaultInformation {\n FaultList {\n" +
                "".join(native_lines) + " }\n}\n")
        manifest = {
            "schema": "multimode_common_fault_universe_v1",
            "fault_model": fault_model,
            "common_fault_count": len(rows),
            "f_flat_instance_offset": 1,
            "minimum_fraction": 0.50,
            "native_fault_counts": dict((mode, len(rows) + 1)
                                        for mode in ("F", "M", "H")),
            "files": {},
            "mapping": {
                "path": "canonical_fault_mapping.tsv",
                "sha256": digest(mapping),
                "row_count_excluding_header": len(rows),
            },
        }
        for mode in ("F", "M", "H"):
            manifest["files"][mode] = {
                "path": mode + "_common_initial_faults.basic",
                "sha256": digest(mode_paths[mode]),
                "fault_count": len(rows),
            }
        manifest_path = self.write_text(
            directory / "manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        readback_path = self.write_text(
            directory / "readback_validation.json",
            json.dumps({
                "status": "PASS", "errors": [], "expected": len(rows),
                "readback_counts": {"H": len(rows), "M": len(rows),
                                    "F": len(rows)},
            }, sort_keys=True) + "\n")
        return {
            "circuit": circuit,
            "family": "family_" + circuit,
            "role": "TRAIN",
            "manifest": {"path": str(directory / "manifest.json"),
                         "sha256": digest(manifest_path)},
            "mapping": {"path": str(directory / "canonical_fault_mapping.tsv"),
                        "sha256": digest(mapping)},
            "readback": {"path": str(directory / "readback_validation.json"),
                         "sha256": digest(readback_path)},
            "modes": dict((mode, {
                "path": str(directory / (mode + "_common_initial_faults.basic")),
                "sha256": digest(mode_paths[mode]),
            }) for mode in ("H", "M", "F")),
            "native_universes": dict((mode, {
                "path": str(directory / (mode + "_native_faults.mtfi")),
                "sha256": digest(native_paths[mode]),
            }) for mode in ("H", "M", "F")),
        }

    def write_bindings(self, circuits):
        path = self.temp / "bindings.json"
        payload = {
            "schema_version": "common-fault-denominator-bindings-v2",
            "evidence_root": str(self.evidence.resolve()),
            "circuits": circuits,
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path

    def audit(self, circuits):
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        contract["required_roster"] = [
            {"circuit": item["circuit"], "family": item["family"],
             "role": item["role"]} for item in circuits]
        contract_path = self.temp / "contract.json"
        contract_path.write_text(json.dumps(contract, sort_keys=True) + "\n",
                                 encoding="utf-8")
        return denominator.build_receipt(
            str(contract_path), str(self.write_bindings(circuits)))

    def test_passes_arbitrary_set_and_ignores_basic_class(self):
        receipt = self.audit([
            self.make_circuit("alpha"),
            self.make_circuit("beta", legacy_header=True),
        ])
        self.assertEqual("PASS", receipt["status"])
        self.assertEqual(2, receipt["circuit_count"])
        self.assertEqual(4, receipt["aggregate_common_fault_count"])
        self.assertEqual(2, receipt["circuits"]["alpha"]["d95"])
        self.assertEqual({"H": 2, "M": 2, "F": 2},
                         receipt["circuits"]["beta"]["mode_counts"])
        rendered = json.dumps(receipt, sort_keys=True).lower()
        for forbidden in ("/u1/", "/u2/", "candidate_uid",
                          "total_cycles", "detected_faults"):
            self.assertNotIn(forbidden, rendered)
        self.assertFalse(receipt["fault_identities_persisted"])
        self.assertFalse(receipt["candidate_or_outcome_data_read"])
        self.assertTrue(
            receipt["all_intersections_recomputed_from_native_universes"])

    def test_rejects_native_intersection_mismatch(self):
        circuit = self.make_circuit("native-mismatch")
        path = self.evidence / circuit["native_universes"]["H"]["path"]
        text = path.read_text(encoding="utf-8").replace('/U2/b', '/U9/b')
        path.write_text(text, encoding="utf-8")
        circuit["native_universes"]["H"]["sha256"] = digest(path)
        with self.assertRaisesRegex(
                denominator.AuditError, "RECOMPUTED_INTERSECTION_MISMATCH"):
            self.audit([circuit])

    def test_rejects_fault_like_malformed_mtfi_line(self):
        circuit = self.make_circuit("malformed-native")
        path = self.evidence / circuit["native_universes"]["F"]["path"]
        path.write_text(path.read_text(encoding="utf-8") +
                        '  0, UC, "unterminated;\n', encoding="utf-8")
        circuit["native_universes"]["F"]["sha256"] = digest(path)
        with self.assertRaisesRegex(denominator.AuditError,
                                    "MTFI_F_MALFORMED_LINE"):
            self.audit([circuit])

    def test_rejects_exact_roster_drift(self):
        circuit = self.make_circuit("roster")
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        contract_path = self.temp / "fixed-contract.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        with self.assertRaisesRegex(denominator.AuditError,
                                    "BINDINGS_ROSTER_MISMATCH"):
            denominator.build_receipt(
                str(contract_path), str(self.write_bindings([circuit])))

    def test_hash_and_parse_use_the_same_artifact_bytes(self):
        circuit = self.make_circuit("single-read")
        mapping = self.evidence / circuit["mapping"]["path"]
        original_reader = denominator.read_regular_bytes
        changed = {"done": False}

        def mutate_after_read(path, label):
            data = original_reader(path, label)
            if (os.path.normcase(os.path.abspath(path)) ==
                    os.path.normcase(os.path.abspath(str(mapping))) and
                    not changed["done"]):
                changed["done"] = True
                mapping.write_text("corrupted after bound read\n", encoding="utf-8")
            return data

        with mock.patch.object(denominator, "read_regular_bytes",
                               side_effect=mutate_after_read):
            receipt = self.audit([circuit])
        self.assertTrue(changed["done"])
        self.assertEqual("PASS", receipt["status"])

    def test_rejects_mode_set_mismatch_even_when_count_matches(self):
        circuit = self.make_circuit("mismatch", basic_override={
            "H": ["0 X /h/a\n", "1 Y /h/not-b\n"],
        })
        with self.assertRaisesRegex(denominator.AuditError, "MODE_SET_MISMATCH_H"):
            self.audit([circuit])

    def test_rejects_duplicate_basic_identity(self):
        circuit = self.make_circuit("duplicate-basic", basic_override={
            "M": ["0 A /m/a\n", "0 B /m/a\n"],
        })
        with self.assertRaisesRegex(denominator.AuditError, "BASIC_DUPLICATE_M"):
            self.audit([circuit])

    def test_rejects_duplicate_mapping_canonical_identity(self):
        rows = [
            ["0", "/same", "/f/a", "/m/a", "/h/a"],
            ["0", "/same", "/f/b", "/m/b", "/h/b"],
        ]
        circuit = self.make_circuit("duplicate-mapping", mapping_override=rows)
        with self.assertRaisesRegex(denominator.AuditError,
                                    "MAPPING_DUPLICATE_CANONICAL"):
            self.audit([circuit])

    def test_rejects_explicit_sha_mismatch(self):
        circuit = self.make_circuit("sha")
        circuit["mapping"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(denominator.AuditError, "MAPPING_SHA_MISMATCH"):
            self.audit([circuit])

    def test_rejects_manifest_fault_model(self):
        circuit = self.make_circuit("model", fault_model="transition")
        with self.assertRaisesRegex(denominator.AuditError, "MANIFEST_FAULT_MODEL"):
            self.audit([circuit])

    def test_rejects_readback_count_mismatch(self):
        circuit = self.make_circuit("readback")
        path = self.evidence / circuit["readback"]["path"]
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["readback_counts"]["H"] -= 1
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        circuit["readback"]["sha256"] = digest(path)
        with self.assertRaisesRegex(denominator.AuditError,
                                    "READBACK_COUNT_MISMATCH"):
            self.audit([circuit])

    def test_rejects_glob_and_escape_paths(self):
        globbed = self.make_circuit("glob")
        globbed["mapping"]["path"] = "glob/*.tsv"
        with self.assertRaisesRegex(denominator.AuditError, "MAPPING_GLOB"):
            self.audit([globbed])
        escaped = self.make_circuit("escape")
        escaped["mapping"]["path"] = "../outside.tsv"
        with self.assertRaisesRegex(denominator.AuditError, "MAPPING_ESCAPE"):
            self.audit([escaped])

    def test_rejects_reused_artifact_path(self):
        first = self.make_circuit("one")
        second = json.loads(json.dumps(first))
        second["circuit"] = "two"
        with self.assertRaisesRegex(denominator.AuditError, "REUSED_ARTIFACT_PATH"):
            self.audit([first, second])

    def test_rejects_nonregular_artifact(self):
        circuit = self.make_circuit("directory")
        directory = self.evidence / "directory" / "not-a-file"
        directory.mkdir()
        circuit["mapping"] = {"path": "directory/not-a-file",
                              "sha256": "0" * 64}
        with self.assertRaisesRegex(denominator.AuditError, "MAPPING_NOT_REGULAR"):
            self.audit([circuit])

    def test_rejects_symlink_artifact(self):
        circuit = self.make_circuit("link")
        source = self.evidence / circuit["mapping"]["path"]
        link = source.parent / "mapping-link.tsv"
        try:
            os.symlink(str(source), str(link))
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable on this platform")
        circuit["mapping"] = {"path": "link/mapping-link.tsv",
                              "sha256": digest(source)}
        with self.assertRaisesRegex(denominator.AuditError, "MAPPING_SYMLINK"):
            self.audit([circuit])

    def test_cli_writes_canonical_aggregate_receipt_once(self):
        circuit = self.make_circuit("cli")
        bindings = self.write_bindings([circuit])
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        contract["required_roster"] = [{
            "circuit": circuit["circuit"], "family": circuit["family"],
            "role": circuit["role"]}]
        contract_path = self.temp / "cli-contract.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        output = self.temp / "receipt.json"
        self.assertEqual(0, denominator.main([
            "--contract", str(contract_path),
            "--bindings", str(bindings), str(output),
        ]))
        receipt = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual("PASS", receipt["status"])
        with self.assertRaisesRegex(denominator.AuditError, "OUTPUT_ALREADY_EXISTS"):
            denominator.atomic_write_json(str(output), receipt)


if __name__ == "__main__":
    unittest.main()
