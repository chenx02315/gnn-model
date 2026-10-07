import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.data import ranking_v3_real_fold_package as v3
from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_held_replay_reader as held
from src.models import ranking_v5_package_binding as binding
from src.models.runtime_ranking_v3 import Fold, freeze_ranking, plan_folds
from tests.test_runtime_ranking_v3 import fixture


def release():
    return {"status": v3.RELEASE_STATUS, "source_sha256": boundary.SOURCE_SHA256,
            "independent_review_pass": True, "roles": ["TRAIN"]}


class HeldReplayTests(unittest.TestCase):
    def test_protected_root_refused_with_all_filesystem_operations_zero(self):
        # Reject the protected root lexically, not merely before held-shard IO.
        with patch.object(Path, 'open') as op, patch.object(Path, 'stat') as stat, \
             patch.object(Path, 'lstat') as lstat, patch.object(Path, 'is_dir') as is_dir, \
             patch.object(Path, 'is_symlink') as link, patch.object(Path, 'resolve') as resolve:
            with self.assertRaisesRegex(ValueError, 'V5_HELD_ROOT'):
                held.load_frozen_held_outcomes('/ssd/cjc/multimode_ate_gnn_v1/x',
                                             {}, None, (), '0'*64, None)
            for operation in (op, stat, lstat, is_dir, link, resolve):
                operation.assert_not_called()

    def package(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "train_folds"; root.mkdir()
        rows, outcomes = fixture(); fold = plan_folds(rows)[0]
        manifest_sha = v3.export_real_fold(root / ("fold_" + fold.family), rows, outcomes, fold,
                                            release=release(), source_sha256=boundary.SOURCE_SHA256)
        identity = {"package_receipt_sha256":"a" * 64, "source_sha256":boundary.SOURCE_SHA256,
                    "fold_manifest_sha256":manifest_sha, "family":fold.family, "seed":boundary.SEEDS[0]}
        scores = {uid: float(-index) for index, uid in enumerate(fold.heldout)}
        payload, freeze_sha = freeze_ranking(scores, fold)
        return root, fold, identity, payload, freeze_sha

    def patches(self, root):
        return patch.object(binding, "PACKAGE_ROOT_ALLOWLIST", frozenset((root.as_posix(),))), patch.object(binding, "PACKAGE_SHA256", "a" * 64)

    def call(self, root, fold, identity, payload, freeze_sha):
        return held.load_frozen_held_outcomes(root.as_posix(), identity, fold, fold.heldout, freeze_sha, (payload, freeze_sha))

    def test_valid_frozen_readback_returns_exact_held_outcomes(self):
        root, fold, identity, payload, freeze_sha = self.package(); allow, package = self.patches(root)
        with allow, package:
            outcomes = self.call(root, fold, identity, payload, freeze_sha)
        self.assertEqual(set(fold.heldout), set(outcomes)); self.assertTrue(all(value["policy_charged_runtime_s"] > 0 for value in outcomes.values()))

    def test_pre_io_failures_never_touch_heldout_path(self):
        root, fold, identity, payload, freeze_sha = self.package(); allow, package = self.patches(root)
        originals = {name:getattr(Path, name) for name in ("open", "stat", "lstat", "is_symlink", "resolve")}; calls = {name:0 for name in originals}
        def guard(name):
            def wrapped(path, *args, **kwargs):
                if path.name == "heldout_outcomes.json": calls[name] += 1
                return originals[name](path, *args, **kwargs)
            return wrapped
        bad_identity = dict(identity, family="wrong")
        forged_identity = dict(identity, family="unknown_family")
        forged_fold = Fold("unknown_family", fold.fitting, fold.heldout)
        float_seed_identity = dict(identity, seed=float(boundary.SEEDS[0]))
        bool_seed_identity = dict(identity, seed=True)
        bad_payload = dict(payload, order=list(reversed(payload["order"])))
        with allow, package, patch.object(Path, "open", new=guard("open")), patch.object(Path, "stat", new=guard("stat")), \
                patch.object(Path, "lstat", new=guard("lstat")), patch.object(Path, "is_symlink", new=guard("is_symlink")), patch.object(Path, "resolve", new=guard("resolve")):
            for args in ((root.as_posix(), bad_identity, fold, fold.heldout, freeze_sha, (payload, freeze_sha)),
                         (root.as_posix(), forged_identity, forged_fold, forged_fold.heldout, freeze_sha, (payload, freeze_sha)),
                         (root.as_posix(), float_seed_identity, fold, fold.heldout, freeze_sha, (payload, freeze_sha)),
                         (root.as_posix(), bool_seed_identity, fold, fold.heldout, freeze_sha, (payload, freeze_sha)),
                         (root.as_posix(), identity, fold, list(fold.heldout), freeze_sha, (payload, freeze_sha)),
                         (root.as_posix(), identity, fold, tuple(reversed(fold.heldout)), freeze_sha, (payload, freeze_sha)),
                         (root.as_posix(), identity, fold, fold.heldout, freeze_sha, (bad_payload, freeze_sha)),
                         (root.as_posix(), identity, fold, fold.heldout, freeze_sha, (payload,)),
                         ("/ssd/cjc/multimode_ate_gnn_v1/x", identity, fold, fold.heldout, freeze_sha, (payload, freeze_sha))):
                with self.assertRaises(ValueError): held.load_frozen_held_outcomes(*args)
        self.assertEqual({name:0 for name in calls}, calls)

    def test_manifest_pin_and_held_shard_drift_rejected(self):
        root, fold, identity, payload, freeze_sha = self.package(); allow, package = self.patches(root)
        with allow, package, self.assertRaisesRegex(ValueError, "REQUEST_SHA"):
            held.load_frozen_held_outcomes(root.as_posix(), dict(identity, fold_manifest_sha256="0" * 64), fold, fold.heldout, freeze_sha, (payload, freeze_sha))
        root, fold, identity, payload, freeze_sha = self.package(); allow, package = self.patches(root)
        path = root / ("fold_" + fold.family) / "heldout_outcomes.json"; path.write_bytes(b"{}")
        with allow, package, self.assertRaisesRegex(ValueError, "REQUEST_SHA"):
            self.call(root, fold, identity, payload, freeze_sha)

    def test_invalid_runtime_and_cycles_rejected_after_rehashed_shard(self):
        for field, value in (("policy_charged_runtime_s", 0), ("policy_charged_runtime_s", float("nan")),
                             ("total_cycles", 0), ("total_cycles", 100.0), ("total_cycles", True)):
            root, fold, identity, payload, freeze_sha = self.package(); folder = root / ("fold_" + fold.family)
            outcomes = json.loads((folder / "heldout_outcomes.json").read_text()); outcomes[next(iter(outcomes))][field] = value
            raw = json.dumps(outcomes, sort_keys=True, separators=(",", ":")).encode(); (folder / "heldout_outcomes.json").write_bytes(raw)
            manifest = json.loads((folder / "manifest.json").read_text()); manifest["sha256"]["heldout_outcomes.json"] = hashlib.sha256(raw).hexdigest()
            manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(); (folder / "manifest.json").write_bytes(manifest_raw)
            identity["fold_manifest_sha256"] = hashlib.sha256(manifest_raw).hexdigest(); allow, package = self.patches(root)
            with allow, package, self.assertRaisesRegex(ValueError, "HELD_OUTCOMES"):
                self.call(root, fold, identity, payload, freeze_sha)


if __name__ == "__main__":
    unittest.main()
