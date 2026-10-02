from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.models.aggregate_runtime_v2 import aggregate
from src.models.runtime_training_v2 import RANKING_FIELDS, TrainingV2Error, sha256_file, write_tsv


REPO = Path(__file__).resolve().parents[1]


class AggregateRuntimeV2Test(unittest.TestCase):
    def fixture(self, root: Path, environment_drift=False, freeze_model="graphsage"):
        contract = REPO / "contracts/runtime_training_v2.json"
        package = root / "package"; package.mkdir()
        split = root / "split"; split.mkdir()
        (package / "runtime_training_package_manifest_v2.json").write_text("{}\n", encoding="utf-8")
        (split / "outcome_split_receipt_v2.json").write_text("{}\n", encoding="utf-8")
        ranking_row = {"role": "VALIDATION", "family": "f", "circuit": "c", "action_uid": "c:HF:h1",
                       "action_scheme": "HF", "h_limit": 1, "m_limit": 0,
                       "predicted_epsilon_hit_probability": 0.5, "predicted_cycles": 100,
                       "predicted_runtime_s": 2, "cost_aware_score": 0.25}
        roots = []
        for index, seed in enumerate((20260824, 20260825, 20260826)):
            seed_root = root / ("seed_%s" % seed); seed_root.mkdir(); roots.append(seed_root)
            ranking = seed_root / "ranking_graphsage.tsv"
            write_tsv(ranking, RANKING_FIELDS, [ranking_row])
            freeze = seed_root / "ranking_graphsage.freeze.json"
            freeze.write_text(json.dumps({"model": freeze_model, "contract_sha256": sha256_file(contract),
                                          "features_sha256": json.loads(contract.read_text(encoding="utf-8"))["trust_anchors"]["features_sha256"],
                                          "ranking_sha256": sha256_file(ranking), "validation_outcomes_read": False}),
                              encoding="utf-8")
            receipt = {
                "status": "PASS_FIXED_SEED_TRAINING", "seed": seed, "git_commit": "abc",
                "contract_sha256": sha256_file(contract),
                "dataset_manifest_sha256": sha256_file(package / "runtime_training_package_manifest_v2.json"),
                "dependency_lock_sha256": "lock", "independent_review_sha256": "review",
                "environment_preflight_sha256": "different" if environment_drift and index == 2 else "env",
                "outcome_split_receipt_sha256": sha256_file(split / "outcome_split_receipt_v2.json"),
                "artifact_sha256": {ranking.name: sha256_file(ranking), freeze.name: sha256_file(freeze)},
            }
            (seed_root / "seed_receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        return contract, package, split, roots

    def test_environment_drift_refuses_before_ensemble(self):
        with tempfile.TemporaryDirectory() as td:
            contract, package, split, roots = self.fixture(Path(td), environment_drift=True)
            with self.assertRaisesRegex(TrainingV2Error, "environment_preflight_sha256"):
                aggregate(contract, package, split, roots, "graphsage", Path(td) / "out" / "ranking.tsv")

    def test_tampered_seed_freeze_refuses(self):
        with tempfile.TemporaryDirectory() as td:
            contract, package, split, roots = self.fixture(Path(td), freeze_model="xgboost")
            with self.assertRaisesRegex(TrainingV2Error, "SEED_FREEZE_BINDING"):
                aggregate(contract, package, split, roots, "graphsage", Path(td) / "out" / "ranking.tsv")


if __name__ == "__main__":
    unittest.main()
