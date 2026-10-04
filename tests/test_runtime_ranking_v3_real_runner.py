import unittest
import tempfile
from pathlib import Path
from unittest.mock import Mock
from tests.test_runtime_ranking_v3 import fixture
from src.models.runtime_ranking_v3 import plan_folds
from src.models.run_runtime_ranking_v3 import SEEDS
from src.models.run_runtime_ranking_v3_real import run_real_fold, aggregate_real

SOURCE = 'a' * 64
RELEASE = dict(status='PASS_TRAIN_ONLY_EXECUTION_RELEASE', independent_review_pass=True,
               data_gate_pass=True, roles=['TRAIN'], source_sha256=SOURCE)

class RealRunnerTests(unittest.TestCase):
    def test_missing_release_refuses_before_reader(self):
        reader = Mock()
        with self.assertRaisesRegex(ValueError, 'RELEASE_REQUIRED'):
            run_real_fold(reader, None, SEEDS[0], 'candidate_mlp', None, None, None)
        reader.feature_rows.assert_not_called()

    def test_order_complete_grid_and_model_binding(self):
        rows, outcomes = fixture(); records = []
        for seed in SEEDS:
            for fold in plan_folds(rows):
                events = []
                reader = Mock()
                reader.manifest = {'source_sha256': SOURCE}
                reader.feature_rows.return_value = rows
                reader.fitting.side_effect = lambda uids: {u: outcomes[u] for u in uids}
                def fit(prepared, seed):
                    self.assertEqual(set(prepared['targets']), set(fold.fitting))
                    events.append('fit')
                def predict(model, uids, x):
                    events.append('predict'); return {u: float(i) for i, u in enumerate(uids)}
                def held(uids, path, sha):
                    self.assertTrue(Path(path).is_file())
                    self.assertEqual(events, ['fit', 'predict'])
                    events.append('held'); return {u: outcomes[u] for u in uids}
                reader.heldout.side_effect = held
                with tempfile.TemporaryDirectory() as folder:
                    records.append(run_real_fold(reader, fold, seed, 'candidate_mlp', fit, predict,
                        Path(folder) / 'freeze.json', release=RELEASE, source_sha256=SOURCE))
        self.assertEqual(aggregate_real(records, 'candidate_mlp', release=RELEASE,
                                      source_sha256=SOURCE)['receipt_count'], 18)
        with self.assertRaisesRegex(ValueError, 'BINDING'):
            aggregate_real(records, 'xgboost', release=RELEASE, source_sha256=SOURCE)
        with self.assertRaisesRegex(ValueError, 'COMPLETE_GRID'):
            aggregate_real(records[:-1], 'candidate_mlp', release=RELEASE, source_sha256=SOURCE)

    def test_noop_persist_refuses_before_held_labels(self):
        from unittest.mock import patch
        rows, outcomes = fixture(); fold = plan_folds(rows)[0]
        reader = Mock(); reader.feature_rows.return_value = rows
        reader.manifest = {'source_sha256': SOURCE}
        reader.fitting.return_value = {u: outcomes[u] for u in fold.fitting}
        with tempfile.TemporaryDirectory() as folder, \
             patch('src.models.run_runtime_ranking_v3_real.persist_freeze', side_effect=lambda p,v,s:s):
            with self.assertRaises(FileNotFoundError):
                run_real_fold(reader, fold, SEEDS[0], 'candidate_mlp', lambda p,s:None,
                    lambda m,u,x:{v:0. for v in u}, Path(folder)/'absent.json',
                    release=RELEASE, source_sha256=SOURCE)
        reader.heldout.assert_not_called()

    def test_invalid_normalizer_is_rejected(self):
        from src.models.runtime_ranking_v3 import transform, FEATURES
        for value in (0., -1., float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                transform([(0.,)*len(FEATURES)], ((0.,)*len(FEATURES), (value,)*len(FEATURES)))

if __name__ == '__main__':
    unittest.main()
