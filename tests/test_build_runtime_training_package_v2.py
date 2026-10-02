from __future__ import print_function

import csv
import hashlib
import json
import os
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from src.data import build_runtime_training_package_v2 as package


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tsv(path, fields, rows):
    with Path(path).open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)


class RuntimeTrainingPackageV2Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.candidate = self.root / "candidate"; self.candidate.mkdir()
        self.cost = self.root / "cost"; self.cost.mkdir()
        self.graph = self.root / "graph"; self.graph.mkdir(); (self.graph / "graphs").mkdir()
        circuits = ["c%d" % i for i in range(8)]
        roles = {"TRAIN": circuits[:6], "VALIDATION": circuits[6:]}
        membership = dict((role, [{"circuit": c, "family": "f_" + c} for c in items])
                          for role, items in roles.items())
        membership.update({"PILOT": [], "BLIND_TEST": []})
        canonical = json.dumps(membership, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
        self.split = self.root / "split.json"
        self.split.write_text(json.dumps({"formal_runtime_membership": membership,
                                          "formal_runtime_membership_sha256": hashlib.sha256(canonical).hexdigest()}),
                              encoding="utf-8")
        actions, normalized, costs, denom, graph_rows = [], [], [], {}, []
        for i, circuit in enumerate(circuits):
            uid = circuit + ":HF:h1"; source = circuit + ":source:1"
            actions.append(dict(zip(package.ACTION_FIELDS,
                [uid, circuit, "HF", "H64-F4", "1", "", "1", source, "hf_coarse", "false", ""])))
            normalized.append({"candidate_uid": source, "circuit": circuit, "result_status": "PASS",
                               "eligible_regression": "1", "total_cycles": str(100 + i),
                               "detected_faults": "95"})
            costs.append(dict(zip(package.COST_FIELDS,
                [uid, circuit, "HF", "1", "", "1", "2", "2", "0", "3.5", "0", "3.5", "3.5", "ARITHMETIC_MEAN_ALL_INVOCATIONS"])))
            denom[circuit] = {"common_fault_count": 100, "d95": 95,
                              "role": "TRAIN" if i < 6 else "VALIDATION", "family": "f_" + circuit}
            graph_file = self.graph / "graphs" / (circuit + ".json")
            graph_file.write_text(json.dumps({"circuit": circuit}), encoding="utf-8")
            graph_rows.append({"graph_key": circuit, "circuit": circuit,
                               "graph_path": "graphs/" + circuit + ".json",
                               "graph_sha256": digest(graph_file)})
        tsv(self.candidate / "candidate_space_v2.tsv", package.ACTION_FIELDS, actions)
        fields = ("candidate_uid", "circuit", "result_status", "eligible_regression",
                  "total_cycles", "detected_faults")
        tsv(self.candidate / "formal_candidate_measurements_v2.tsv", fields, normalized)
        candidate_receipt = {"status": "PASS_BUILD_REPEAT_AGGREGATION_PENDING",
                             "sha256": {"candidate_space": digest(self.candidate / "candidate_space_v2.tsv"),
                                        "normalized_measurements": digest(self.candidate / "formal_candidate_measurements_v2.tsv")}}
        (self.candidate / "receipt_v2.json").write_text(json.dumps(candidate_receipt), encoding="utf-8")
        tsv(self.cost / "action_runtime_costs_v1.tsv", package.COST_FIELDS, costs)
        (self.cost / "receipt_v1.json").write_text("{}", encoding="utf-8")
        review = {"status": "PASS_COST_LABEL_GATE", "boundaries": {"training_allowed": False},
                  "verified_sha256": {"action_runtime_costs": digest(self.cost / "action_runtime_costs_v1.tsv"),
                                      "aggregation_receipt": digest(self.cost / "receipt_v1.json")}}
        (self.cost / "independent_review_v1.json").write_text(json.dumps(review), encoding="utf-8")
        self.denom = self.root / "denom.json"
        self.denom.write_text(json.dumps({"status": "PASS", "candidate_or_outcome_data_read": False,
                                          "circuits": denom}), encoding="utf-8")
        tsv(self.graph / "graph_manifest.tsv", package.GRAPH_FIELDS, graph_rows)
        graph_receipt = {"graph_manifest_sha256": digest(self.graph / "graph_manifest.tsv")}
        (self.graph / "runtime_graphs_aggregate_receipt_v1.json").write_text(json.dumps(graph_receipt), encoding="utf-8")
        self.topology = self.root / "topology.json"
        self.topology.write_text(json.dumps({"status": "PASS_TOPOLOGY_PARITY_DIGEST_ONLY",
                                             "graph_count": 8, "raw_nodes_or_edges_persisted": False,
                                             "local_receipt_sha256": digest(self.graph / "runtime_graphs_aggregate_receipt_v1.json")}),
                                 encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def args(self, output):
        return Namespace(candidate_root=str(self.candidate), cost_root=str(self.cost),
                         denominator_receipt=str(self.denom), split_contract=str(self.split),
                         graph_root=str(self.graph), topology_parity_receipt=str(self.topology),
                         output_root=str(output))

    def test_builds_family_isolated_package(self):
        output = self.root / "output"
        manifest = package.build(self.args(output))
        self.assertEqual("PASS_PACKAGE_INDEPENDENT_REVIEW_PENDING", manifest["status"])
        self.assertEqual(8, manifest["counts"]["action_count"])
        self.assertFalse(manifest["training_execution_allowed"])
        with (output / "features.tsv").open(encoding="utf-8", newline="") as stream:
            features = list(csv.DictReader(stream, delimiter="\t"))
        with (output / "outcomes.tsv").open(encoding="utf-8", newline="") as stream:
            outcomes = list(csv.DictReader(stream, delimiter="\t"))
        self.assertEqual({"TRAIN", "VALIDATION"}, {row["role"] for row in features})
        self.assertEqual({"1"}, {row["epsilon_hit"] for row in outcomes})
        self.assertEqual({"3.500000000"}, {row["policy_charged_runtime_s"] for row in outcomes})

    def test_rejects_unreviewed_cost(self):
        path = self.cost / "independent_review_v1.json"
        value = json.loads(path.read_text(encoding="utf-8")); value["status"] = "PENDING"
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(package.BuildError, "COST_REVIEW_STATUS"):
            package.build(self.args(self.root / "bad"))

    def test_rejects_fastest_policy(self):
        path = self.cost / "action_runtime_costs_v1.tsv"
        with path.open(encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))
        rows[0]["aggregation_policy"] = "FASTEST_SUCCESS"
        tsv(path, package.COST_FIELDS, rows)
        review_path = self.cost / "independent_review_v1.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        review["verified_sha256"]["action_runtime_costs"] = digest(path)
        review_path.write_text(json.dumps(review), encoding="utf-8")
        with self.assertRaisesRegex(package.BuildError, "RUNTIME_AGGREGATION_POLICY"):
            package.build(self.args(self.root / "bad"))


if __name__ == "__main__":
    unittest.main()
