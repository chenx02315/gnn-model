import hashlib
import importlib.util
import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "audit" / "audit_runtime_graph_topology_parity_v1.py"
SPEC = importlib.util.spec_from_file_location("topology_parity_v1", str(MODULE_PATH))
parity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(parity)
ROSTER = ["aes_core", "s13207", "s15850", "s35932", "s38417", "s5378", "spi", "tv80"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


class RuntimeGraphTopologyParityV1Test(unittest.TestCase):
    def setUp(self):
        self.temp = pathlib.Path(tempfile.mkdtemp(prefix="topology-parity-v1-"))
        self.evidence = self.temp / "evidence"; self.evidence.mkdir()

    def tearDown(self):
        shutil.rmtree(str(self.temp), ignore_errors=True)

    def receipts(self, mismatch=False):
        digests = dict((name, sha((name + "-edge").encode("ascii"))) for name in ROSTER)
        remote = {"schema_version":"legacy-graph-topology-receipt-v1", "status":"PASS_DIGEST_ONLY", "contract_sha256":parity.REMOTE_AUDITOR_CONTRACT_SHA256, "bindings_sha256":"b" * 64, "graph_count":8, "graphs":{}, "raw_nodes_or_edges_persisted":False, "pickle_executed":False, "torch_imported":False, "training_execution_allowed":False}
        local = {"schema_version":"runtime-graphs-aggregate-receipt-v1", "status":"BLOCKED_HISTORICAL_TOPOLOGY_DIGEST", "bindings_sha256":"c" * 64, "contract_sha256":parity.LOCAL_RUNTIME_GRAPH_CONTRACT_SHA256, "historical_graph_manifest_sha256":"e" * 64, "historical_node_edge_count_parity_pass":True, "historical_topology_parity_pass":False, "historical_topology_blocker":"HISTORICAL_CANONICAL_EDGE_INDEX_SHA256_NOT_BOUND", "source_hashes":{}, "graph_manifest_sha256":"f" * 64, "graph_count":8, "training_execution_allowed":False}
        for name in ROSTER:
            remote["graphs"][name] = {"artifact_sha256": parity.HISTORICAL_ARTIFACT_SHA256[name], "nodes":1, "edges":1, "canonical_edge_index_sha256":digests[name]}
            local_digest = ("0" * 64 if mismatch and name == "spi" else digests[name])
            local["source_hashes"][name] = {"role":"TRAIN", "family":"test", "netlist_path":"netlists/x.v", "netlist_sha256":"2" * 64, "nodes":1, "edges":1, "historical_nodes":1, "historical_edges":1, "historical_feature_dim":16, "historical_graph_sha256":"3" * 64, "topology_sha256":"4" * 64, "edge_index_sha256":local_digest}
        remote_bytes, local_bytes = json.dumps(remote, sort_keys=True).encode("utf-8"), json.dumps(local, sort_keys=True).encode("utf-8")
        (self.evidence / "remote.json").write_bytes(remote_bytes); (self.evidence / "local.json").write_bytes(local_bytes)
        return remote_bytes, local_bytes

    def bindings(self, remote, local):
        path = self.temp / "bindings.json"
        path.write_text(json.dumps({"schema_version":"runtime-graph-topology-parity-bindings-v1", "evidence_root":str(self.evidence.resolve()), "remote_receipt":{"path":"remote.json", "sha256":sha(remote)}, "local_receipt":{"path":"local.json", "sha256":sha(local)}}), encoding="utf-8")
        return path

    def active_contract(self, remote_sha, local_sha):
        value = json.loads((ROOT / "contracts" / "runtime_graph_topology_parity_v1.json").read_text(encoding="utf-8"))
        value["status"] = "ACTIVE_VERIFIED_REMOTE_RECEIPT_SHA"
        value["trust_anchors"]["remote_receipt_sha256"] = remote_sha
        value["trust_anchors"]["local_receipt_sha256"] = local_sha
        path = self.temp / "active-contract.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def pending_contract(self):
        value = json.loads((ROOT / "contracts" / "runtime_graph_topology_parity_v1.json").read_text(encoding="utf-8"))
        value["status"] = "DESIGN_FROZEN_REMOTE_RECEIPT_SHA_PENDING"
        value["trust_anchors"]["remote_receipt_sha256"] = None
        path = self.temp / "pending-contract.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_pending_anchor_refuses_before_any_binding_or_evidence_io(self):
        contract = str(self.pending_contract())
        missing_bindings = str(self.temp / "must-not-be-read.json")
        original = parity.read_regular_bytes
        with mock.patch.object(parity, "read_regular_bytes", wraps=original) as reader:
            with self.assertRaisesRegex(parity.TopologyParityError,
                                        "REMOTE_RECEIPT_TRUST_ANCHOR_PENDING"):
                parity.build_receipt(contract, missing_bindings)
        self.assertEqual([mock.call(contract, "CONTRACT")], reader.call_args_list)

    def test_mismatch_and_bound_hash_drift_fail_closed(self):
        remote, local = self.receipts(mismatch=True)
        with self.assertRaisesRegex(parity.TopologyParityError, "TOPOLOGY_DIGEST_MISMATCH"):
            remote_digests = parity.validate_remote(json.loads(remote.decode("utf-8")))
            local_digests = parity.validate_local(json.loads(local.decode("utf-8")))
            parity.require(all(remote_digests[name] == local_digests[name]
                               for name in ROSTER), "TOPOLOGY_DIGEST_MISMATCH")
        remote, local = self.receipts()
        self.assertEqual(64, len(parity.valid_sha("a" * 64, "TEST_SHA")))
        with self.assertRaisesRegex(parity.TopologyParityError, "TEST_SHA"):
            parity.valid_sha("a" * 63 + "\n", "TEST_SHA")

    def test_contract_and_historical_artifact_substitution_fail_closed(self):
        remote, local = self.receipts()
        remote_value = json.loads(remote.decode("utf-8"))
        remote_value["contract_sha256"] = "0" * 64
        remote = json.dumps(remote_value, sort_keys=True).encode("utf-8")
        with self.assertRaisesRegex(parity.TopologyParityError, "REMOTE_CONTRACT_SHA"):
            parity.validate_remote(json.loads(remote.decode("utf-8")))
        remote, local = self.receipts()
        local_value = json.loads(local.decode("utf-8"))
        local_value["contract_sha256"] = "0" * 64
        local = json.dumps(local_value, sort_keys=True).encode("utf-8")
        with self.assertRaisesRegex(parity.TopologyParityError, "LOCAL_CONTRACT_SHA"):
            parity.validate_local(json.loads(local.decode("utf-8")))
        remote, local = self.receipts()
        remote_value = json.loads(remote.decode("utf-8"))
        remote_value["graphs"]["spi"]["artifact_sha256"] = "0" * 64
        remote = json.dumps(remote_value, sort_keys=True).encode("utf-8")
        with self.assertRaisesRegex(parity.TopologyParityError, "REMOTE_ARTIFACT_SHA_spi"):
            parity.validate_remote(json.loads(remote.decode("utf-8")))

    def test_validators_reject_missing_roster(self):
        remote, local = self.receipts()
        remote_value = json.loads(remote.decode("utf-8")); del remote_value["graphs"]["tv80"]
        remote = json.dumps(remote_value, sort_keys=True).encode("utf-8")
        with self.assertRaisesRegex(parity.TopologyParityError, "REMOTE_ROSTER"):
            parity.validate_remote(json.loads(remote.decode("utf-8")))

    def test_active_contract_binds_actual_remote_and_local_receipt_hashes(self):
        remote, local = self.receipts()
        bindings = self.bindings(remote, local)
        contract = self.active_contract(sha(remote), sha(local))
        with mock.patch.object(parity, "LOCAL_RECEIPT_SHA256", sha(local)):
            receipt = parity.build_receipt(str(contract), str(bindings))
        self.assertEqual("PASS_TOPOLOGY_PARITY_DIGEST_ONLY", receipt["status"])

        contract_value = json.loads(contract.read_text(encoding="utf-8"))
        contract_value["trust_anchors"]["remote_receipt_sha256"] = "0" * 64
        contract.write_text(json.dumps(contract_value), encoding="utf-8")
        with mock.patch.object(parity, "LOCAL_RECEIPT_SHA256", sha(local)):
            with self.assertRaisesRegex(parity.TopologyParityError,
                                        "REMOTE_RECEIPT_TRUST_ANCHOR_MISMATCH"):
                parity.build_receipt(str(contract), str(bindings))

        contract_value["trust_anchors"]["remote_receipt_sha256"] = sha(remote)
        contract.write_text(json.dumps(contract_value), encoding="utf-8")
        changed_local = local + b"\n"
        (self.evidence / "local.json").write_bytes(changed_local)
        bindings_value = json.loads(bindings.read_text(encoding="utf-8"))
        bindings_value["local_receipt"]["sha256"] = sha(changed_local)
        bindings.write_text(json.dumps(bindings_value), encoding="utf-8")
        with mock.patch.object(parity, "LOCAL_RECEIPT_SHA256", sha(local)):
            with self.assertRaisesRegex(parity.TopologyParityError,
                                        "LOCAL_RECEIPT_TRUST_ANCHOR_MISMATCH"):
                parity.build_receipt(str(contract), str(bindings))


if __name__ == "__main__":
    unittest.main()
