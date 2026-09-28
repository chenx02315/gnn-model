import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from src.data import build_runtime_graphs_v1 as graphs


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RuntimeGraphV1Tests(unittest.TestCase):
    def fixture(self, root):
        root = pathlib.Path(root)
        netlist = root / "netlists" / "s13207_mapped.v"
        netlist.parent.mkdir()
        netlist.write_text("""
module top(input a, b, output y);
wire n, alias;
assign alias = n;
AND2_X1 u_b (.A(a), .B(b), .Y(n));
DQV0 u_a (.D(alias), .Q(y));
endmodule
""", encoding="utf-8")
        bindings = {"schema_version":"runtime-graph-netlist-bindings-v1", "bindings":[
            {"circuit":"s13207","role":"TRAIN","family":"iscas89_s13207","path":"netlists/s13207_mapped.v","sha256":sha(netlist)}
        ]}
        parity = root / "historical_graph_manifest.tsv"
        parity.write_text(
            "circuit\tnodes\tedges\tfeature_dim\tgraph_sha256\n"
            "s13207\t2\t1\t16\t%s\n" % ("a" * 64), encoding="utf-8")
        bindings["parity_manifest"] = {
            "path": "historical_graph_manifest.tsv", "sha256": sha(parity)}
        (root / "bindings.json").write_text(json.dumps(bindings, sort_keys=True), encoding="utf-8")
        contract = json.loads(pathlib.Path(graphs.CONTRACT_PATH).read_text(
            encoding="utf-8"))
        contract["required_roster"] = [{
            "circuit": "s13207", "family": "iscas89_s13207",
            "role": "TRAIN"}]
        contract_path = root / "contract.json"
        contract_path.write_text(json.dumps(contract, sort_keys=True),
                                 encoding="utf-8")
        return netlist, bindings, contract_path

    def test_build_is_deterministic_and_assign_union_drives_edge(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "root"; root.mkdir(); _, _, contract = self.fixture(root)
            first = pathlib.Path(directory) / "first"; second = pathlib.Path(directory) / "second"
            receipt = graphs.build("bindings.json", str(root), str(first), str(contract))
            graphs.build("bindings.json", str(root), str(second), str(contract))
            payload = json.loads((first / "graphs" / "s13207.json").read_text(encoding="utf-8"))
            self.assertEqual([{"node_type":"standard_cell_instance","cell_type":"AND2_X1","sequential_flag":False}, {"node_type":"standard_cell_instance","cell_type":"DQV0","sequential_flag":True}], payload["nodes"])
            self.assertEqual([[0, 1]], payload["edge_index"])
            self.assertFalse(receipt["training_execution_allowed"])
            self.assertEqual("BLOCKED_HISTORICAL_TOPOLOGY_DIGEST",
                             receipt["status"])
            self.assertFalse(receipt["historical_topology_parity_pass"])
            self.assertRegex(receipt["source_hashes"]["s13207"]["topology_sha256"],
                             r"^[0-9a-f]{64}$")
            self.assertEqual((first / "graphs" / "s13207.json").read_bytes(), (second / "graphs" / "s13207.json").read_bytes())

    def test_line_comments_do_not_consume_following_instances(self):
        text = "// header\nAND2_X1 u0 (.A(a), .B(b), .Y(n));\n// next\nDQV0 u1 (.D(n), .Q(y));\n"
        nodes, edges = graphs._parse_mapped_verilog(
            text, graphs._json(str(graphs.CONTRACT_PATH)))
        self.assertEqual(2, len(nodes))
        self.assertEqual([[0, 1]], edges)

    def test_hash_glob_duplicate_and_escape_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "root"; root.mkdir(); _, bindings, contract = self.fixture(root)
            bindings["bindings"][0]["sha256"] = "0" * 64
            (root / "bindings.json").write_text(json.dumps(bindings), encoding="utf-8")
            with self.assertRaisesRegex(graphs.GraphBuildError, "BINDING_SHA256_MISMATCH"):
                graphs.build("bindings.json", str(root), str(pathlib.Path(directory) / "out"), str(contract))
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "root"; root.mkdir(); _, bindings, contract = self.fixture(root)
            bindings["bindings"].append(dict(bindings["bindings"][0]))
            (root / "bindings.json").write_text(json.dumps(bindings), encoding="utf-8")
            with self.assertRaisesRegex(graphs.GraphBuildError, "BINDING_CIRCUIT_DUPLICATE"):
                graphs.build("bindings.json", str(root), str(pathlib.Path(directory) / "out"), str(contract))
            bindings["bindings"] = [dict(bindings["bindings"][0], circuit="s15850", path="*.v")]
            (root / "bindings.json").write_text(json.dumps(bindings), encoding="utf-8")
            with self.assertRaisesRegex(graphs.GraphBuildError, "BINDING_GLOB_FORBIDDEN"):
                graphs.build("bindings.json", str(root), str(pathlib.Path(directory) / "out2"), str(contract))

    def test_historical_graph_parity_mismatch_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "root"; root.mkdir(); _, bindings, contract = self.fixture(root)
            parity = root / "historical_graph_manifest.tsv"
            parity.write_text("circuit\tnodes\tedges\tfeature_dim\tgraph_sha256\ns13207\t3\t1\t16\t%s\n" % ("a" * 64), encoding="utf-8")
            bindings["parity_manifest"]["sha256"] = sha(parity)
            (root / "bindings.json").write_text(json.dumps(bindings), encoding="utf-8")
            output = pathlib.Path(directory) / "out"
            with self.assertRaisesRegex(graphs.GraphBuildError,
                                        "HISTORICAL_GRAPH_PARITY_MISMATCH_s13207"):
                graphs.build("bindings.json", str(root), str(output), str(contract))
            self.assertFalse(output.exists())

    def test_non_named_pin_and_output_root_reuse_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "root"; root.mkdir(); netlist, bindings, contract = self.fixture(root)
            netlist.write_text("module t;\nAND2_X1 u(a,b,y);\nendmodule\n", encoding="utf-8")
            bindings["bindings"][0]["sha256"] = sha(netlist)
            (root / "bindings.json").write_text(json.dumps(bindings), encoding="utf-8")
            output = pathlib.Path(directory) / "out"
            with self.assertRaisesRegex(graphs.GraphBuildError, "NON_NAMED_PIN_CONNECTION"):
                graphs.build("bindings.json", str(root), str(output), str(contract))
            self.assertFalse(output.exists())

    def test_hash_and_parse_use_same_netlist_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "root"; root.mkdir()
            netlist, _, contract = self.fixture(root)
            original_reader = graphs._read_regular_bytes
            changed = {"done": False}

            def mutate_after_read(path):
                data = original_reader(path)
                if (pathlib.Path(path) == netlist and not changed["done"]):
                    changed["done"] = True
                    netlist.write_text("corrupted after bound read\n",
                                       encoding="utf-8")
                return data

            output = pathlib.Path(directory) / "out"
            with mock.patch.object(graphs, "_read_regular_bytes",
                                   side_effect=mutate_after_read):
                receipt = graphs.build("bindings.json", str(root), str(output),
                                       str(contract))
            self.assertTrue(changed["done"])
            self.assertEqual(2, receipt["source_hashes"]["s13207"]["nodes"])

    def test_topology_digest_changes_when_adjacency_changes_at_same_counts(self):
        nodes = [{"node_type": "standard_cell_instance", "cell_type": "X",
                  "sequential_flag": False} for _ in range(3)]
        self.assertNotEqual(graphs._topology_sha256(nodes, [[0, 1], [1, 2]]),
                            graphs._topology_sha256(nodes, [[0, 2], [2, 1]]))


if __name__ == "__main__":
    unittest.main()
