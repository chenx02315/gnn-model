import hashlib
import importlib.util
import io
import json
import pathlib
import shutil
import struct
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "audit" / "audit_legacy_graph_topology_v1.py"
SPEC = importlib.util.spec_from_file_location("legacy_topology_v1", str(MODULE_PATH))
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def sha(value):
    return hashlib.sha256(value).hexdigest()


class LegacyGraphTopologyV1Test(unittest.TestCase):
    def setUp(self):
        self.temp = pathlib.Path(tempfile.mkdtemp(prefix="legacy-topology-v1-"))
        self.root = self.temp / "graphs"
        self.root.mkdir()
        self.circuits = ["aes_core", "s13207", "s15850", "s35932",
                         "s38417", "s5378", "spi", "tv80"]

    def tearDown(self):
        shutil.rmtree(str(self.temp), ignore_errors=True)

    def make_graph(self, circuit, pairs=((0, 1), (1, 2))):
        path = self.root / (circuit + ".pt")
        values = ([item[0] for item in pairs] + [item[1] for item in pairs])
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(circuit + "/data/1",
                             struct.pack("<%dq" % len(values), *values))
            archive.writestr(circuit + "/byteorder", "little")
        data = buffer.getvalue()
        path.write_bytes(data)
        return {"circuit": circuit, "path": path.name, "sha256": sha(data),
                "nodes": 3, "edges": len(pairs)}

    def contract(self):
        contract = json.loads((ROOT / "contracts" /
                               "legacy_graph_topology_audit_v1.json").read_text(
                                   encoding="utf-8"))
        path = self.temp / "contract.json"
        path.write_text(json.dumps(contract), encoding="utf-8")
        return path

    def bindings(self, graphs):
        path = self.temp / "bindings.json"
        path.write_text(json.dumps({
            "schema_version": "legacy-graph-topology-bindings-v1",
            "evidence_root": str(self.root.resolve()), "graphs": graphs,
        }), encoding="utf-8")
        return path

    def test_digest_only_receipt_passes(self):
        graphs = [self.make_graph(circuit) for circuit in self.circuits]
        receipt = audit.build_receipt(str(self.contract()),
                                      str(self.bindings(graphs)))
        self.assertEqual("PASS_DIGEST_ONLY", receipt["status"])
        self.assertEqual(8, receipt["graph_count"])
        self.assertFalse(receipt["raw_nodes_or_edges_persisted"])
        self.assertFalse(receipt["pickle_executed"])

    def test_digest_changes_at_same_edge_count(self):
        first = self.make_graph("aes_core", ((0, 1), (1, 2)))
        first_bytes = (self.root / "aes_core.pt").read_bytes()
        second = self.make_graph("aes_core", ((0, 2), (2, 1)))
        second_bytes = (self.root / "aes_core.pt").read_bytes()
        self.assertNotEqual(
            audit.edge_digest(first_bytes, "aes_core", 3, 2),
            audit.edge_digest(second_bytes, "aes_core", 3, 2))
        self.assertNotEqual(first["sha256"], second["sha256"])

    def test_rejects_duplicate_and_out_of_range_edges(self):
        with self.assertRaisesRegex(audit.TopologyAuditError,
                                    "GRAPH_DUPLICATE_EDGE"):
            item = self.make_graph("aes_core", ((0, 1), (0, 1)))
            audit.edge_digest((self.root / "aes_core.pt").read_bytes(),
                              "aes_core", item["nodes"], item["edges"])

    def test_rejects_contract_drift(self):
        graphs = [self.make_graph(circuit) for circuit in self.circuits]
        contract = json.loads((ROOT / "contracts" /
                               "legacy_graph_topology_audit_v1.json").read_text(
                                   encoding="utf-8"))
        contract["input"]["required_circuits"][-1] = "wb_dma"
        path = self.temp / "drifted-contract.json"
        path.write_text(json.dumps(contract), encoding="utf-8")
        with self.assertRaisesRegex(audit.TopologyAuditError,
                                    "CONTRACT_INPUT"):
            audit.build_receipt(str(path), str(self.bindings(graphs)))

    def test_rejects_duplicate_edge_storage_member(self):
        buffer = io.BytesIO()
        values = [0, 1]
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("aes_core/data/1", struct.pack("<2q", *values))
            archive.writestr("aes_core/data/1", struct.pack("<2q", *values))
            archive.writestr("aes_core/byteorder", "little")
        with self.assertRaisesRegex(audit.TopologyAuditError,
                                    "GRAPH_MEMBERS_aes_core"):
            audit.edge_digest(buffer.getvalue(), "aes_core", 2, 1)
        with self.assertRaisesRegex(audit.TopologyAuditError,
                                    "GRAPH_EDGE_RANGE"):
            item = self.make_graph("aes_core", ((0, 3),))
            audit.edge_digest((self.root / "aes_core.pt").read_bytes(),
                              "aes_core", item["nodes"], item["edges"])


if __name__ == "__main__":
    unittest.main()
