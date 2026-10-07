import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.data import ranking_v3_real_fold_package as v3
from src.models import ranking_v5_bound_input_reader as reader
from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_package_binding as binding
from src.models.runtime_ranking_v3 import FAMILIES, FEATURES, plan_folds


def sha(number): return "%064x" % number


def release():
    return {"status": v3.RELEASE_STATUS, "source_sha256": boundary.SOURCE_SHA256,
            "independent_review_pass": True, "roles": ["TRAIN"]}


class BoundInputTests(unittest.TestCase):
    def package(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "train_folds"; root.mkdir()
        rows, outcomes = [], {}; counts = (284, 284, 284, 284, 285, 285)
        for (circuit, family), count in zip(FAMILIES.items(), counts):
            for index in range(count):
                uid = "%s:%d" % (circuit, index)
                rows.append(dict(action_uid=uid, circuit=circuit, family=family, role="TRAIN",
                                 **{name: float(index + column + 1) for column, name in enumerate(FEATURES)}))
                outcomes[uid] = {"execution_status":"SUCCESS", "is_d95_feasible":1,
                                 "total_cycles":100 if index == 0 else 200 + index,
                                 "policy_charged_runtime_s":1.0}
        pins = {}
        for fold in plan_folds(rows):
            pins[fold.family] = v3.export_real_fold(root / ("fold_" + fold.family), rows, outcomes, fold,
                                                     release=release(), source_sha256=boundary.SOURCE_SHA256)
        receipt = {"schema_version":"ranking-v3-real-input-export-receipt-v1", "scope":"REAL_TRAIN_ONLY_RELEASED_SIX_FOLD",
          "release_sha256":sha(1), "source_sha256":boundary.SOURCE_SHA256,
          "source_input_sha256":{"features.tsv":sha(2),"train_outcomes.tsv":sha(3),"graph_manifest.tsv":sha(4)},
          "graph_sha256":{circuit:sha(10+i) for i,circuit in enumerate(FAMILIES)}, "family_metadata_sha256":sha(20),
          "train_action_count":1706, "train_outcome_count":1706, "graph_count":6, "fold_manifest_sha256":pins}
        raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(); (root / "receipt.json").write_bytes(raw)
        return root, receipt, hashlib.sha256(raw).hexdigest()

    def call(self, root, raw_sha, family=None, seed=None):
        return reader.load_bound_fold_request(root.as_posix(), family or sorted(FAMILIES.values())[0], seed or boundary.SEEDS[0])

    def patched(self, root, raw_sha):
        return patch.object(binding, "PACKAGE_ROOT_ALLOWLIST", frozenset((root.as_posix(),))), patch.object(binding, "PACKAGE_SHA256", raw_sha)

    def test_reads_bound_fold_and_never_touches_held_outcomes(self):
        root, _, raw_sha = self.package(); family = sorted(FAMILIES.values())[0]
        originals = {name:getattr(Path, name) for name in ("open", "stat", "lstat", "is_symlink", "resolve")}; calls = {name:0 for name in originals}
        def guard(name):
            def wrapped(path, *args, **kwargs):
                if path.name == "heldout_outcomes.json": calls[name] += 1
                return originals[name](path, *args, **kwargs)
            return wrapped
        allow, pinned = self.patched(root, raw_sha)
        with allow, pinned, patch.object(Path, "open", new=guard("open")), patch.object(Path, "stat", new=guard("stat")), \
                patch.object(Path, "lstat", new=guard("lstat")), patch.object(Path, "is_symlink", new=guard("is_symlink")), \
                patch.object(Path, "resolve", new=guard("resolve")):
            result = self.call(root, raw_sha, family)
        self.assertEqual(reader.STATUS, result["status"]); self.assertEqual(1706, len(result["request"]["rows"]))
        self.assertEqual({name:0 for name in calls}, calls)

    def test_bad_family_seed_and_root_reject_before_receipt_path(self):
        root, _, raw_sha = self.package()
        allow, pinned = self.patched(root, raw_sha)
        with allow, pinned, patch.object(reader.safe_loader, "_ordinary_path") as path:
            with self.assertRaisesRegex(ValueError, "FAMILY"):
                self.call(root, raw_sha, "wrong")
            with self.assertRaisesRegex(ValueError, "SEED"):
                self.call(root, raw_sha, sorted(FAMILIES.values())[0], float(boundary.SEEDS[0]))
        path.assert_not_called()

    def test_protected_root_rejects_before_any_path_operation(self):
        names = ("open", "stat", "lstat", "is_symlink", "resolve")
        originals = {name:getattr(Path, name) for name in names}; calls = {name:0 for name in names}
        def guard(name):
            def wrapped(path, *args, **kwargs):
                calls[name] += 1
                return originals[name](path, *args, **kwargs)
            return wrapped
        with patch.object(Path, "open", new=guard("open")), patch.object(Path, "stat", new=guard("stat")), \
                patch.object(Path, "lstat", new=guard("lstat")), patch.object(Path, "is_symlink", new=guard("is_symlink")), \
                patch.object(Path, "resolve", new=guard("resolve")):
            with self.assertRaisesRegex(ValueError, "ROOT"):
                reader.load_bound_fold_request("/ssd/cjc/multimode_ate_gnn_v1/x", sorted(FAMILIES.values())[0], boundary.SEEDS[0])
        self.assertEqual({name:0 for name in names}, calls)

    def test_receipt_tamper_and_manifest_drift_rejected(self):
        root, receipt, raw_sha = self.package(); family = sorted(FAMILIES.values())[0]; allow, pinned = self.patched(root, raw_sha)
        (root / "receipt.json").write_bytes((root / "receipt.json").read_bytes() + b" ")
        with allow, pinned, self.assertRaisesRegex(ValueError, "RECEIPT_SHA"):
            self.call(root, raw_sha, family)
        root, receipt, raw_sha = self.package(); allow, pinned = self.patched(root, raw_sha)
        (root / ("fold_" + family) / "fit_features.json").write_bytes(b"[]")
        with allow, pinned, self.assertRaises(ValueError): self.call(root, raw_sha, family)
        root, receipt, raw_sha = self.package(); allow, pinned = self.patched(root, raw_sha)
        manifest_path = root / ("fold_" + family) / "manifest.json"
        manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
        with allow, pinned, self.assertRaises(ValueError): self.call(root, raw_sha, family)

    def test_receipt_count_must_match_adapter_request(self):
        root, _, raw_sha = self.package(); allow, pinned = self.patched(root, raw_sha)
        fake = {"rows": [object()] * 12}
        with allow, pinned, patch.object(reader.fold_adapter, "adapt_v3_fold", return_value=fake):
            with self.assertRaisesRegex(ValueError, "ROW_COUNT"):
                self.call(root, raw_sha)


if __name__ == "__main__":
    unittest.main()
