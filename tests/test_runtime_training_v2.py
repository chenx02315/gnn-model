from __future__ import annotations

import csv
import importlib.util
import copy
import json
import tempfile
import unittest
from pathlib import Path

from src.models import runtime_training_v2 as v2
from src.models import train_runtime_v2 as trainer
from src.data import split_runtime_v2_outcomes as outcome_splitter


REPO = Path(__file__).resolve().parents[1]


class RuntimeTrainingV2ContractTest(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads((REPO / "contracts/runtime_training_v2.json").read_text(encoding="utf-8"))

    def test_safe_by_construction_contract_has_no_d95_head(self):
        v2.validate_contract(self.contract)
        self.assertFalse(self.contract["safety"]["d95_head_present"])
        self.assertNotIn("d95", " ".join(self.contract["graphsage"]["heads"]).lower())
        self.assertEqual([20260824, 20260825, 20260826], self.contract["determinism"]["seeds"])
        self.assertFalse(self.contract["determinism"]["seed_selection_allowed"])

    def test_candidate_feature_builder_is_allowlisted_and_outcome_free(self):
        rows = [
            {"action_uid": "c:HF:h1", "circuit": "c", "action_scheme": "HF", "h_limit": "1",
             "m_limit": "0", "common_fault_count": "100"},
            {"action_uid": "c:HMF:h3:m2", "circuit": "c", "action_scheme": "HMF", "h_limit": "3",
             "m_limit": "2", "common_fault_count": "100"},
        ]
        names, values = v2.build_scalar_features(rows)
        v2.assert_feature_boundary(names)
        self.assertEqual(list(v2.FEATURE_COLUMNS), names)
        self.assertEqual(2, len(values))
        self.assertEqual(1.0, values[1][4])
        self.assertEqual(1.0, values[1][5])

    def test_feature_boundary_rejects_extra_or_outcome_columns(self):
        with self.assertRaisesRegex(v2.TrainingV2Error, "FEATURE_ALLOWLIST"):
            v2.assert_feature_boundary(list(v2.FEATURE_COLUMNS) + ["total_cycles"])

    def test_protected_root_is_rejected_before_access(self):
        with self.assertRaisesRegex(v2.TrainingV2Error, "PROTECTED_PATH"):
            v2.reject_protected_paths([Path("/ssd/cjc/multimode_ate_gnn_v1/checkpoint.pt")])
        with self.assertRaisesRegex(v2.TrainingV2Error, "PROTECTED_PATH"):
            outcome_splitter.split(Path("/ssd/cjc/multimode_ate_gnn_v1/package"),
                                   Path("/ssd/cjc/safe_output"))

    def test_missing_validation_split_is_rejected_without_reading_it(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "train_outcomes.tsv").write_text("fixture\n", encoding="utf-8")
            (root / "outcome_split_receipt_v2.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(v2.TrainingV2Error, "validation_outcomes.tsv"):
                v2.validate_outcome_split(root, root, self.contract, validation_access_allowed=False)

    def test_exact_role_family_mapping_rejects_pilot_or_family_drift(self):
        rows = []
        for role, mapping in self.contract["scope"]["exact_role_family_mapping"].items():
            rows.extend({"role": role, "circuit": circuit, "family": family}
                        for circuit, family in mapping.items())
        v2.validate_role_family_mapping(rows, self.contract)
        bad = [dict(row) for row in rows]
        bad[0]["family"] = "pilot_family"
        with self.assertRaisesRegex(v2.TrainingV2Error, "EXACT_ROLE_FAMILY_MAPPING"):
            v2.validate_role_family_mapping(bad, self.contract)
        with self.assertRaisesRegex(v2.TrainingV2Error, "EXACT_ROLE_FAMILY_MAPPING"):
            v2.validate_role_family_mapping(rows + [{"role": "PILOT", "circuit": "b20", "family": "pilot"}], self.contract)

    def test_ranking_is_deterministic_and_cost_aware(self):
        rows = [
            {"action_uid": "b", "action_scheme": "HF", "h_limit": "1", "m_limit": "0",
             "predicted_cycles": "10", "cost_aware_score": "0.2"},
            {"action_uid": "a", "action_scheme": "HMF", "h_limit": "2", "m_limit": "1",
             "predicted_cycles": "11", "cost_aware_score": "0.4"},
        ]
        self.assertEqual(["a", "b"], [r["action_uid"] for r in v2.ordered_actions(rows, "fixed_heuristic")])
        self.assertEqual(["b", "a"], [r["action_uid"] for r in v2.ordered_actions(rows, "predicted_cycles")])
        self.assertEqual(["a", "b"], [r["action_uid"] for r in v2.ordered_actions(rows, "cost_aware")])

    def test_train_outcome_reader_materializes_only_train_rows(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "outcomes.tsv"
            with path.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=v2.OUTCOME_COLUMNS, delimiter="\t", lineterminator="\n")
                writer.writeheader()
                writer.writerow({"action_uid": "train", "execution_status": "SUCCESS", "is_d95_feasible": "1",
                                 "total_cycles": "100", "policy_charged_runtime_s": "2", "epsilon_hit": "1"})
                # Deliberately invalid validation values must remain unparsed before ranking freeze.
                writer.writerow({"action_uid": "validation", "execution_status": "SEALED", "is_d95_feasible": "X",
                                 "total_cycles": "SEALED", "policy_charged_runtime_s": "SEALED", "epsilon_hit": "SEALED"})
            loaded = v2.read_training_outcomes_only(path, {"train"})
            self.assertEqual({"train"}, set(loaded))

    def test_ranking_freeze_exists_before_validation_replay(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            package = root / "package"; package.mkdir()
            output = root / "output"; output.mkdir()
            (output / "runtime_training_v2.bound.json").write_text("{}\n", encoding="utf-8")
            (package / "features.tsv").write_text("fixture\n", encoding="utf-8")
            with (package / "outcomes.tsv").open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=v2.OUTCOME_COLUMNS, delimiter="\t", lineterminator="\n")
                writer.writeheader()
                writer.writerow({"action_uid": "v:HF:h1", "execution_status": "SUCCESS",
                                 "is_d95_feasible": "1", "total_cycles": "100",
                                 "policy_charged_runtime_s": "2", "epsilon_hit": "1"})
            features = [{"role": "VALIDATION", "family": "f", "circuit": "v", "action_uid": "v:HF:h1",
                         "action_scheme": "HF", "h_limit": "1", "m_limit": "0"}]
            predictions = {"v:HF:h1": {"predicted_epsilon_hit_probability": 0.5,
                                        "predicted_cycles": 100.0, "predicted_runtime_s": 2.0}}
            split = root / "split"; split.mkdir()
            (split / "validation_outcomes.tsv").write_bytes((package / "outcomes.tsv").read_bytes())
            (split / "train_outcomes.tsv").write_text("\t".join(v2.OUTCOME_COLUMNS) + "\n", encoding="utf-8")
            receipt = {"status": "PASS_OUTCOME_ROLE_SPLIT",
                       "source_outcomes_sha256": self.contract["trust_anchors"]["outcomes_sha256"],
                       "source_features_sha256": self.contract["trust_anchors"]["features_sha256"],
                       "train_outcomes_sha256": v2.sha256_file(split / "train_outcomes.tsv"),
                       "validation_outcomes_sha256": v2.sha256_file(split / "validation_outcomes.tsv"),
                       "train_count": 1706, "validation_count": 815}
            (split / "outcome_split_receipt_v2.json").write_text(json.dumps(receipt), encoding="utf-8")
            contract = copy.deepcopy(self.contract)
            contract["trust_anchors"]["outcome_split_receipt_sha256"] = v2.sha256_file(split / "outcome_split_receipt_v2.json")
            contract["trust_anchors"]["train_outcomes_sha256"] = receipt["train_outcomes_sha256"]
            contract["trust_anchors"]["validation_outcomes_sha256"] = receipt["validation_outcomes_sha256"]
            paths = trainer._freeze_and_replay("fixture", features, predictions, package, split, output, contract)
            self.assertTrue(paths[1].exists())
            self.assertTrue(paths[2].exists())
            freeze = json.loads(paths[1].read_text(encoding="utf-8"))
            self.assertFalse(freeze["validation_outcomes_read"])

    @unittest.skipUnless(importlib.util.find_spec("torch"), "torch not installed in local control environment")
    def test_pure_torch_graphsage_same_seed_is_deterministic(self):
        import numpy as np
        import torch
        graph = (torch.tensor([[1.0, 0.0], [0.0, 1.0], [1.0, 1.0]]),
                 torch.tensor([[0, 1, 2], [1, 2, 0]], dtype=torch.long))
        candidate = torch.tensor([[0.2, 0.3], [0.4, 0.5]], dtype=torch.float32)
        outputs = []
        for _ in range(2):
            v2.seed_everything(20260824, torch, np)
            model = v2.make_graphsage_model(torch, 2, 2, self.contract)
            model.eval()
            with torch.no_grad():
                result = model({"c": graph}, ["c", "c"], candidate)
            outputs.append([item.numpy().tobytes() for item in result])
        self.assertEqual(outputs[0], outputs[1])

    @unittest.skipUnless(importlib.util.find_spec("torch") and importlib.util.find_spec("xgboost")
                         and importlib.util.find_spec("numpy"),
                         "runtime-v2 ML dependencies not installed in local control environment")
    def test_complete_synthetic_training_paths_repeat_same_seed(self):
        import numpy as np
        import torch
        import xgboost as xgb
        contract = copy.deepcopy(self.contract)
        contract["graphsage"]["epochs"] = 3
        contract["xgboost_baseline"]["n_estimators"] = 5
        features = [
            {"action_uid": "a0", "graph_key": "c0", "common_fault_count": "100"},
            {"action_uid": "a1", "graph_key": "c0", "common_fault_count": "100"},
            {"action_uid": "a2", "graph_key": "c1", "common_fault_count": "200"},
            {"action_uid": "a3", "graph_key": "c1", "common_fault_count": "200"},
        ]
        scalar = np.asarray([[1, 0, 0, 0, 0.1, 0, 4], [1, 0, 1, 0, 1, 0, 4],
                             [0, 1, 0, 0, 0.1, 0.1, 5], [0, 1, 1, 1, 1, 1, 5]], dtype=float)
        indices = np.asarray([0, 1, 2, 3], dtype=np.int64)
        targets = (np.asarray([0, 1, 0, 1], dtype=float),
                   np.log1p(np.asarray([2.0, 1.0, 2.0, 1.0])),
                   np.log1p(np.asarray([5.0, 2.0, 6.0, 3.0])))
        edge = torch.tensor([[0, 1, 2], [1, 2, 0]], dtype=torch.long)
        graphs = {"c0": (torch.eye(3), edge), "c1": (torch.eye(3), edge)}
        digests = []
        for _ in range(2):
            _, gp, _, _ = trainer._fit_graphsage(features, scalar, indices, targets, graphs,
                                                  contract, 20260824, np, torch)
            _, xp, _ = trainer._fit_xgboost(features, scalar, indices, targets, contract,
                                             20260824, np, xgb)
            digests.append((v2.canonical_sha256(gp), v2.canonical_sha256(xp)))
        self.assertEqual(digests[0], digests[1])


if __name__ == "__main__":
    unittest.main()
