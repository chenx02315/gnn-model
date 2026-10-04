import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.data.ranking_v3_real_fold_package import (
    RealFoldReader, export_real_fold,
)
from src.models.ranking_v3_freeze_io import persist_freeze
from src.models.runtime_ranking_v3 import freeze_ranking, plan_folds
from tests.test_runtime_ranking_v3 import fixture


SOURCE_SHA = 'a' * 64


def release(source_sha=SOURCE_SHA):
    return {'status': 'PASS_TRAIN_ONLY_DATA_RELEASE', 'source_sha256': source_sha,
            'independent_review_pass': True, 'roles': ['TRAIN']}


class RealFoldPackageTests(unittest.TestCase):
    def test_release_rejected_before_target_io(self):
        rows, outcomes = fixture()
        fold = plan_folds(rows)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'not-created'
            with patch('src.data.ranking_v3_real_fold_package._reject_symlink') as checked:
                with self.assertRaises(ValueError):
                    export_real_fold(root, rows, outcomes, fold, release=None,
                                     source_sha256=SOURCE_SHA)
            checked.assert_not_called()
            self.assertFalse(root.exists())

    def test_release_role_and_source_binding(self):
        rows, outcomes = fixture()
        fold = plan_folds(rows)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'fold'
            bad = release(); bad['roles'] = ['TRAIN', 'VALIDATION']
            with self.assertRaises(ValueError):
                export_real_fold(root, rows, outcomes, fold, release=bad,
                                 source_sha256=SOURCE_SHA)
            bad = release('b' * 64)
            with self.assertRaises(ValueError):
                export_real_fold(root, rows, outcomes, fold, release=bad,
                                 source_sha256=SOURCE_SHA)
            self.assertFalse(root.exists())

    def test_physical_shards_tamper_and_bad_heldout_refuse(self):
        rows, outcomes = fixture()
        fold = plan_folds(rows)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'fold'
            seal = export_real_fold(root, rows, outcomes, fold, release=release(),
                                    source_sha256=SOURCE_SHA)
            self.assertEqual({path.name for path in root.iterdir()}, {
                'manifest.json', 'fit_features.json', 'fit_outcomes.json',
                'heldout_features.json', 'heldout_outcomes.json'})
            reader = RealFoldReader(root, seal, fold)
            with (root / 'fit_outcomes.json').open('ab') as stream:
                stream.write(b' ')
            with self.assertRaises(ValueError):
                reader.fitting(fold.fitting)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'fold'
            bad = dict(outcomes)
            bad[fold.heldout[0]] = dict(bad[fold.heldout[0]], is_d95_feasible=True)
            with self.assertRaises(ValueError):
                export_real_fold(root, rows, bad, fold, release=release(),
                                 source_sha256=SOURCE_SHA)
            self.assertFalse(root.exists())

    def test_held_labels_require_exact_persisted_fold_freeze(self):
        rows, outcomes = fixture()
        fold = plan_folds(rows)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'fold'
            seal = export_real_fold(root, rows, outcomes, fold, release=release(),
                                    source_sha256=SOURCE_SHA)
            reader = RealFoldReader(root, seal, fold)
            names = []
            original = Path.read_bytes
            def spy(path):
                names.append(path.name)
                return original(path)
            with patch.object(Path, 'read_bytes', spy):
                with self.assertRaises(FileNotFoundError):
                    reader.heldout(fold.heldout, root / 'missing-freeze.json', '0' * 64)
            self.assertNotIn('heldout_outcomes.json', names)
            payload, sha = freeze_ranking({uid: 0.0 for uid in fold.heldout}, fold)
            persist_freeze(root / 'freeze.json', payload, sha)
            self.assertEqual(set(reader.heldout(fold.heldout, root / 'freeze.json', sha)),
                             set(fold.heldout))
            wrong_payload, wrong_sha = freeze_ranking(
                {uid: 0.0 for uid in plan_folds(rows)[1].heldout}, plan_folds(rows)[1])
            persist_freeze(root / 'wrong-freeze.json', wrong_payload, wrong_sha)
            with self.assertRaises(ValueError):
                reader.heldout(fold.heldout, root / 'wrong-freeze.json', wrong_sha)


if __name__ == '__main__':
    unittest.main()
