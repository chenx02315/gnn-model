import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.models.ranking_v3_freeze_io import read_freeze
from src.models.runtime_ranking_v3 import FEATURES, digest, plan_folds
from src.models import ranking_v4_training_worker as worker
from tests.test_runtime_ranking_v3 import fixture


def request_for(rows, cycles, fold):
    slim = [{field: row[field] for field in ('action_uid', 'circuit', 'family', 'role', *FEATURES)} for row in rows]
    return {'scope': worker.SCOPE, 'source_sha256': 'a' * 64, 'family': fold.family,
            'seed': 20260824, 'model': worker.MODEL, 'rows': slim,
            'fit_cycles': {uid: cycles[uid]['total_cycles'] for uid in fold.fitting}}


class V4WorkerTests(unittest.TestCase):
    def test_fake_model_schema_recipe_freeze_and_request_binding(self):
        rows, outcomes = fixture(); fold = plan_folds(rows)[0]; request = request_for(rows, outcomes, fold)
        calls = {}
        class FakeModel:
            def state_dict(self): return {'deterministic': 1}
        class FakeTorch:
            @staticmethod
            def save(value, path):
                self.assertEqual({'deterministic': 1}, value)
                Path(path).write_bytes(b'deterministic-model-state')
        def fake_fit(torch, np, prepared, seed):
            calls['prepared'] = prepared; return FakeModel()
        def fake_predict(torch, model, uids, matrix):
            self.assertEqual(tuple(fold.heldout), uids); return {uid: float(index) for index, uid in enumerate(uids)}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(worker, 'fit_neural', side_effect=fake_fit), \
             patch.object(worker, 'predict_neural', side_effect=fake_predict):
            receipt = worker.execute(request, Path(directory) / 'out', FakeTorch(), object(), raw_request_sha256='b' * 64)
            self.assertEqual('b' * 64, receipt['request_sha256'])
            self.assertEqual(digest(request), receipt['canonical_request_sha256'])
            self.assertFalse(receipt['held_labels_supplied'])
            self.assertEqual(b'deterministic-model-state', (Path(directory) / 'out' / 'model.pt').read_bytes())
            self.assertEqual(set(read_freeze(Path(directory) / 'out' / 'freeze.json', receipt['freeze_sha256'])['scores']), set(fold.heldout))
        self.assertEqual(set(calls['prepared']['fit_uids']), set(fold.fitting))
        self.assertEqual(set(calls['prepared']['pairs']), {row['family'] for row in rows if row['family'] != fold.family})

    def test_rejects_extra_held_or_bad_cycles_before_output(self):
        rows, outcomes = fixture(); fold = plan_folds(rows)[0]; request = request_for(rows, outcomes, fold)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'out'
            missing = dict(request, fit_cycles=dict(request['fit_cycles'])); del missing['fit_cycles'][fold.fitting[0]]
            extra = dict(request, fit_cycles=dict(request['fit_cycles'], **{fold.heldout[0]: 1}))
            nested = dict(request, rows=[dict(row, runtime={'held': 1}) if row['action_uid'] == fold.fitting[0] else row
                                         for row in request['rows']])
            for bad in (dict(request, held_cycles={}), missing, extra, nested,
                        dict(request, source_sha256='not-sha'),
                        dict(request, fit_cycles=dict(request['fit_cycles'], **{fold.fitting[0]: True}))):
                with self.assertRaises(ValueError): worker.execute(bad, output, None, None, raw_request_sha256='b' * 64)
            self.assertFalse(output.exists())

    def test_fitting_normalizer_and_pairs_ignore_held_feature_values(self):
        rows, outcomes = fixture(); fold = plan_folds(rows)[0]; request = request_for(rows, outcomes, fold)
        _, prepared, _, packet = worker.prepare_request(request)
        changed = dict(request, rows=[dict(row, scheme_hf=999.0, scheme_hmf=-999.0)
                                      if row['action_uid'] in fold.heldout else row for row in request['rows']])
        _, changed_prepared, _, changed_packet = worker.prepare_request(changed)
        self.assertEqual(prepared['normalizer'], changed_prepared['normalizer'])
        self.assertEqual(prepared['pairs'], changed_prepared['pairs'])
        self.assertEqual(packet['recipe_sha256'], changed_packet['recipe_sha256'])

    def test_cli_tampered_request_stops_before_dependency_or_worker(self):
        with patch.object(worker, '_read_json_once', side_effect=ValueError('V4_WORKER_REQUEST_SHA')) as read, \
             patch.object(worker, 'execute') as execute, \
             patch('sys.argv', ['worker', '--request', 'x', '--request-sha256', '0' * 64, '--output', 'y']):
            with self.assertRaises(ValueError): worker.main()
        read.assert_called_once(); execute.assert_not_called()


if __name__ == '__main__': unittest.main()
