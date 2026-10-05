import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.models.ranking_v3_freeze_io import read_freeze
from src.models.runtime_ranking_v3 import FEATURES, digest, plan_folds
from src.models import ranking_v4_real_worker as real
from scripts import run_ranking_v4_real_experiment as driver
from scripts import launch_ranking_v4_low_memory_experiment as launcher
from tests.test_runtime_ranking_v3 import fixture


def release():
    return {'status': 'PASS_V4_TRAIN_ONLY_EXECUTION', 'source_sha256': real.SOURCE_SHA256,
            'package_receipt_sha256': real.PACKAGE_SHA256, 'roles': ['TRAIN'],
            'seeds': [20260824, 20260825, 20260826], 'model': 'candidate_mlp',
            'training_release': True, 'reviewed_sources': {name: 'a' * 64 for name in real.REVIEWED_FILES}}


def request(rows, outcomes, fold):
    return {'scope': real.SCOPE, 'source_sha256': real.SOURCE_SHA256, 'family': fold.family,
            'seed': 20260824, 'model': 'candidate_mlp',
            'rows': [{key: row[key] for key in ('action_uid', 'circuit', 'family', 'role', *FEATURES)} for row in rows],
            'fit_cycles': {uid: outcomes[uid]['total_cycles'] for uid in fold.fitting}}


class RealV4ExecutionTests(unittest.TestCase):
    def test_release_inventory_and_tamper_refuse(self):
        good = release(); real.check_release(good, real.SOURCE_SHA256)
        bad = copy.deepcopy(good); bad['reviewed_sources'].pop(next(iter(bad['reviewed_sources'])))
        with self.assertRaises(ValueError): real.check_release(bad, real.SOURCE_SHA256)
        bad = copy.deepcopy(good); bad['package_receipt_sha256'] = '0' * 64
        with self.assertRaises(ValueError): real.check_release(bad, real.SOURCE_SHA256)

    def test_fit_cycle_parser_rejects_fraction_nan_bool_and_held_uid(self):
        rows, outcomes = fixture(); fold = plan_folds(rows)[0]; base = request(rows, outcomes, fold)
        for value in (1.5, float('nan'), True, '1'):
            bad = copy.deepcopy(base); bad['fit_cycles'][fold.fitting[0]] = value
            with self.assertRaises(ValueError): real.prepare_real_request(bad)
        bad = copy.deepcopy(base); bad['fit_cycles'][fold.heldout[0]] = 1
        with self.assertRaises(ValueError): real.prepare_real_request(bad)

    def test_fake_fit_freeze_before_real_receipt_and_no_held_labels(self):
        rows, outcomes = fixture(); fold = plan_folds(rows)[0]; req = request(rows, outcomes, fold)
        class Model:
            def state_dict(self): return {'v4': 1}
        class Torch:
            def set_num_threads(self, value): self.threads = value
            def set_num_interop_threads(self, value): self.interop = value
            def save(self, value, path): Path(path).write_bytes(b'checkpoint')
        torch = Torch()
        def predict(unused_torch, unused_model, uids, matrix): return {uid: float(index) for index, uid in enumerate(uids)}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(real, 'verify_reviewed_sources'), \
             patch.object(real, 'fit_neural', return_value=Model()) as fit, \
             patch.object(real, 'predict_neural', side_effect=predict):
            receipt = real.execute(req, release(), Path(directory) / 'out', torch, object(), raw_request_sha256='b' * 64)
            freeze = read_freeze(Path(directory) / 'out' / 'freeze.json', receipt['freeze_sha256'])
            self.assertEqual(set(freeze['scores']), set(fold.heldout))
            self.assertFalse(receipt['held_labels_supplied'])
            self.assertEqual('b' * 64, receipt['request_sha256'])
            self.assertEqual(digest(req), receipt['canonical_request_sha256'])
            self.assertEqual(b'checkpoint', (Path(directory) / 'out' / 'model.pt').read_bytes())
        self.assertEqual(1, torch.threads); self.assertEqual(1, torch.interop); fit.assert_called_once()

    def test_runner_destination_and_summary_are_bounded(self):
        with self.assertRaises(ValueError): driver.validate_destination('/tmp/not-v4')
        records = [{'family': family, 'seed': seed, 'freeze': {'order': list(range(10 if family == 'iwls_aes_core' else 11))},
                    'metrics': {'hit_at_10': 1, 'best_cycle_regret_at_10': 0., 'charged_runtime_s': 2., 'attempt_count': 1}}
                   for family in sorted(__import__('src.models.runtime_ranking_v3', fromlist=['FAMILIES']).FAMILIES.values()) for seed in (20260824, 20260825, 20260826)]
        summary = driver._summary(records)
        self.assertEqual(18, summary['receipt_count']); self.assertEqual(15, summary['nonexhaustive_count'])
        duplicate = list(records); duplicate[-1] = dict(duplicate[-1], family=duplicate[0]['family'], seed=duplicate[0]['seed'])
        with self.assertRaises(ValueError): driver._summary(duplicate)

    def test_destination_policy_and_launcher_output_are_self_consistent(self):
        self.assertEqual(launcher.ROOT / 'experiment', driver.experiment_output(launcher.ROOT))
        # Test the component policy separately from Windows-local resolve semantics.
        self.assertTrue(driver._valid_destination_value('/ssd/cjc/gnn_model_ranking_v4_train_r2/experiment'))
        for value in ('/ssd/cjc/gnn_model_ranking_v4_train_r2',
                      '/ssd/cjc/gnn_model_ranking_v4_train_r2/not-experiment',
                      '/ssd/cjc/gnn_model_ranking_v4_train_r2/experiment/nested',
                      '/ssd/cjc/protected/experiment'):
            self.assertFalse(driver._valid_destination_value(value))
        with self.assertRaises(ValueError): driver.validate_destination('/ssd/cjc/gnn_model_ranking_v4_train_r2/../experiment')

    def test_integer_cycles_rejects_fraction_nan_bool_and_string(self):
        self.assertEqual(7, driver.integer_cycles(7.0))
        for value in (7.1, float('nan'), True, '7', 0, 2 ** 53 + 1):
            with self.assertRaises(ValueError): driver.integer_cycles(value)

    def test_worker_receipt_binds_raw_and_canonical_request_sha(self):
        request = {'source_sha256': 'a', 'family': 'f', 'seed': 1, 'model': 'candidate_mlp'}
        worker_receipt = dict(request, request_sha256='b' * 64,
                              canonical_request_sha256=digest(request), held_labels_supplied=False)
        driver.validate_worker_receipt(worker_receipt, request, 'b' * 64)
        for key, value in (('request_sha256', 'c' * 64), ('canonical_request_sha256', '0' * 64)):
            bad = dict(worker_receipt, **{key: value})
            with self.assertRaises(ValueError): driver.validate_worker_receipt(bad, request, 'b' * 64)


if __name__ == '__main__': unittest.main()
