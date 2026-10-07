import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.data import ranking_v3_real_fold_package as v3
from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_v3_fold_adapter as adapter
from src.models.runtime_ranking_v3 import plan_folds
from tests.test_runtime_ranking_v3 import fixture


def release():
    return {"status": v3.RELEASE_STATUS, "source_sha256": boundary.SOURCE_SHA256,
            "independent_review_pass": True, "roles": ["TRAIN"]}


class AdapterTests(unittest.TestCase):
    def package(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        rows, outcomes = fixture(); fold = plan_folds(rows)[0]; root = Path(directory.name) / "fold"
        sha = v3.export_real_fold(root, rows, outcomes, fold, release=release(), source_sha256=boundary.SOURCE_SHA256)
        return root, sha, fold

    def read_manifest(self, root):
        return json.loads((root / "manifest.json").read_text())

    def rewrite(self, path, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(); path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def rewrite_manifest(self, root, manifest):
        return self.rewrite(root / "manifest.json", manifest)

    def test_adapts_synthetic_exporter_fold_to_exact_v5_request(self):
        root, sha, fold = self.package()
        request = adapter.adapt_v3_fold(root, sha, fold.family, boundary.SEEDS[0])
        self.assertEqual(adapter.STATUS, "IMPLEMENTATION_ONLY_PENDING_PHYSICAL_CALLER")
        self.assertEqual(boundary.SCOPE, request["scope"]); self.assertEqual(set(fold.fitting), set(request["fit_cycles"]))
        self.assertTrue(set(fold.heldout).isdisjoint(request["fit_cycles"]))
        boundary.prepare_request(request)

    def test_never_opens_or_stats_heldout_outcomes(self):
        root, sha, fold = self.package()
        originals = {name: getattr(Path, name) for name in ("open", "stat", "lstat", "is_symlink", "resolve")}
        calls = {name: 0 for name in originals}
        def guarded_open(path, *args, **kwargs):
            if path.name == "heldout_outcomes.json": calls["open"] += 1
            return originals["open"](path, *args, **kwargs)
        def guarded_stat(path, *args, **kwargs):
            if path.name == "heldout_outcomes.json": calls["stat"] += 1
            return originals["stat"](path, *args, **kwargs)
        def guarded_lstat(path, *args, **kwargs):
            if path.name == "heldout_outcomes.json": calls["lstat"] += 1
            return originals["lstat"](path, *args, **kwargs)
        def guarded_link(path, *args, **kwargs):
            if path.name == "heldout_outcomes.json": calls["is_symlink"] += 1
            return originals["is_symlink"](path, *args, **kwargs)
        def guarded_resolve(path, *args, **kwargs):
            if path.name == "heldout_outcomes.json": calls["resolve"] += 1
            return originals["resolve"](path, *args, **kwargs)
        with patch.object(Path, "open", new=guarded_open), patch.object(Path, "stat", new=guarded_stat), \
                patch.object(Path, "lstat", new=guarded_lstat), patch.object(Path, "is_symlink", new=guarded_link), \
                patch.object(Path, "resolve", new=guarded_resolve):
            adapter.adapt_v3_fold(root, sha, fold.family, boundary.SEEDS[0])
        self.assertEqual({name: 0 for name in calls}, calls)

    def test_shard_sha_drift_rejected(self):
        root, sha, fold = self.package(); (root / "fit_features.json").write_bytes(b"[]")
        with self.assertRaisesRegex(ValueError, "REQUEST_SHA"):
            adapter.adapt_v3_fold(root, sha, fold.family, boundary.SEEDS[0])

    def test_forged_manifest_membership_rejected(self):
        root, sha, fold = self.package(); manifest = self.read_manifest(root); manifest["fitting"] = []
        sha = self.rewrite_manifest(root, manifest)
        with self.assertRaisesRegex(ValueError, "MEMBERSHIP"):
            adapter.adapt_v3_fold(root, sha, fold.family, boundary.SEEDS[0])

    def test_manifest_release_role_drift_rejected_after_rehash(self):
        root, sha, fold = self.package(); manifest = self.read_manifest(root)
        manifest["release"]["roles"] = ["TRAIN", "VALIDATION"]
        sha = self.rewrite_manifest(root, manifest)
        with self.assertRaisesRegex(ValueError, "RELEASE"):
            adapter.adapt_v3_fold(root, sha, fold.family, boundary.SEEDS[0])

    def test_unsafe_outcome_and_nontrain_row_rejected(self):
        root, sha, fold = self.package(); manifest = self.read_manifest(root)
        outcomes = json.loads((root / "fit_outcomes.json").read_text()); outcomes[next(iter(outcomes))]["execution_status"] = "FAILED"
        manifest["sha256"]["fit_outcomes.json"] = self.rewrite(root / "fit_outcomes.json", outcomes); sha = self.rewrite_manifest(root, manifest)
        with self.assertRaisesRegex(ValueError, "FIT_OUTCOMES"):
            adapter.adapt_v3_fold(root, sha, fold.family, boundary.SEEDS[0])
        root, sha, fold = self.package(); manifest = self.read_manifest(root)
        rows = json.loads((root / "fit_features.json").read_text()); rows[0]["role"] = "PILOT"
        manifest["sha256"]["fit_features.json"] = self.rewrite(root / "fit_features.json", rows); sha = self.rewrite_manifest(root, manifest)
        with self.assertRaisesRegex(ValueError, "METADATA"):
            adapter.adapt_v3_fold(root, sha, fold.family, boundary.SEEDS[0])

    def test_float_seed_and_noninteger_cycles_rejected(self):
        root, sha, fold = self.package()
        with self.assertRaisesRegex(ValueError, "ARGUMENTS"):
            adapter.adapt_v3_fold(root, sha, fold.family, float(boundary.SEEDS[0]))
        manifest = self.read_manifest(root); outcomes = json.loads((root / "fit_outcomes.json").read_text())
        outcomes[next(iter(outcomes))]["total_cycles"] = 100.0
        manifest["sha256"]["fit_outcomes.json"] = self.rewrite(root / "fit_outcomes.json", outcomes); sha = self.rewrite_manifest(root, manifest)
        with self.assertRaisesRegex(ValueError, "CYCLES"):
            adapter.adapt_v3_fold(root, sha, fold.family, boundary.SEEDS[0])


if __name__ == "__main__":
    unittest.main()
