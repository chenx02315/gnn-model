import ast
import copy
from pathlib import Path
import unittest

from scripts.diagnose_ranking_v4_r4_existing import fitting_metrics, range_metrics
from scripts.summarize_ranking_v4_r4_diagnostic import summarize, verify_model_identity, RELEASE_SHA, PACKAGE_SHA, AUDIT
from src.models.runtime_ranking_v3 import FAMILIES, FEATURES
from tests.test_ranking_v4_r3_comparison import fixtures


def summary_fixture():
    sealed, _ = fixtures()
    payload = {'status': 'PASS_EXISTING_R4_READ_ONLY_DIAGNOSTIC', 'role': 'TRAIN',
        'new_fits': 0, 'optimizer_steps': 0, 'held_outcome_files_read': 0,
        'checkpoint_bytes_exported': 0, 'raw_labels_features_or_scores_exported': False,
        'peak_process_rss_bytes': 100, 'release_sha256': RELEASE_SHA, 'package_sha256': PACKAGE_SHA, 'results': []}
    original = list(sealed['records'].values())
    sealed['records'] = {}
    for item in original:
        evaluation = item['data']; family, seed = evaluation['family'], evaluation['seed']
        prefix = f'experiment/{family}_{seed}_candidate_mlp/'
        sealed['records'][prefix + 'evaluation.json'] = {'sha256': 'eval', 'data': evaluation}
        sealed['records'][prefix + 'worker_receipt.json'] = {'sha256': 'worker', 'data': {'request_sha256': 'req', 'freeze_sha256': 'freeze'}}
        fitting = [{'fitting_family': f, 'pair_accuracy_ties_half': .9, 'selected_pair_softplus_mean': .1,
                    'mean_positive_negative_margin': 2., 'fit_hit_at_10': 1, 'first_positive_rank': 1}
                   for f in FAMILIES.values() if f != family]
        payload['results'].append({'held_family': family, 'seed': seed, 'worker_sha256': 'worker',
            'evaluation_sha256': 'eval', 'request_sha256': 'req', 'freeze_sha256': 'freeze',
            'model_sha256': 'model', 'model_held_scores_exact': True, 'fitting_families': fitting,
            'feature_ranges': [{'feature': f} for f in FEATURES], 'existing_held_metrics': evaluation['metrics']})
    return payload, sealed


class ExistingFitDiagnosticTests(unittest.TestCase):
    def test_fit_margin_direction_and_top_k(self):
        rows = [{'action_uid': str(i), 'family': 'fit'} for i in range(12)]
        cycles = {str(i): 100 if i == 0 else 110 for i in range(12)}
        recipe = {'families': {'fit': {'pairs': [{'positive_uid': '0', 'negative_uid': '1'}]}}}
        good = fitting_metrics(rows, cycles, {str(i): -i for i in range(12)}, recipe)[0]
        bad = fitting_metrics(rows, cycles, {str(i): i for i in range(12)}, recipe)[0]
        self.assertEqual(1, good['pair_accuracy_ties_half'])
        self.assertEqual(0, bad['pair_accuracy_ties_half'])
        self.assertEqual(1, good['fit_hit_at_10'])
        self.assertEqual(0, bad['fit_hit_at_10'])
        self.assertLess(good['selected_pair_softplus_mean'], bad['selected_pair_softplus_mean'])
        tied = fitting_metrics(rows, cycles, {str(i): 0 for i in range(12)}, recipe)[0]
        self.assertEqual(.5, tied['pair_accuracy_ties_half'])
        with self.assertRaises(ValueError): fitting_metrics(rows, cycles, {'0': 1}, recipe)

    def test_extrapolation_count_and_fit_only_standardization(self):
        result = range_metrics([(0.,), (2.,)], [(-1.,), (1.,), (3.,)], ((1.,), (1.,)), ['x'])[0]
        self.assertEqual(2, result['outside_fitting_range_count'])
        self.assertEqual(2 / 3, result['outside_fitting_range_fraction'])
        self.assertEqual(2, result['max_abs_held_standardized'])
        with self.assertRaises(ValueError): range_metrics([], [(1.,)], ((0.,), (1.,)), ['x'])
        with self.assertRaises(ValueError): range_metrics([(1.,)], [(float('nan'),)], ((0.,), (1.,)), ['x'])

    def test_no_fit_optimizer_training_or_held_label_loader_calls(self):
        source = Path('scripts/diagnose_ranking_v4_r4_existing.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        forbidden = {'fit_neural', 'backward', 'step', 'heldout', 'fitting_targets', 'seed_everything'}
        called = {getattr(node.func, 'id', getattr(node.func, 'attr', '')) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        self.assertFalse(forbidden & called)
        self.assertNotIn('torch.save', source)
        self.assertIn('weights_only=True', source)
        self.assertIn('DIAGNOSTIC_MODEL_FREEZE_REPLAY', source)

    def test_summary_exact_grid_bindings_and_repeat_denominators(self):
        payload, sealed = summary_fixture()
        result = summarize(payload, sealed)
        self.assertEqual(60, result['nonexhaustive_primary']['fit_observations'])
        self.assertEqual(6, len(result['family_rows']))
        self.assertTrue(all(r['fit_observations'] == 15 and r['held_observations'] == 3 for r in result['family_rows']))
        self.assertIn('not independent', result['denominator_note'])
        changed = copy.deepcopy(payload); changed['results'].pop()
        with self.assertRaises(ValueError): summarize(changed, sealed)
        changed = copy.deepcopy(payload); changed['results'][0]['request_sha256'] = 'wrong'
        with self.assertRaises(ValueError): summarize(changed, sealed)

    def test_new_fit_or_held_label_access_or_resource_excess_refuses(self):
        payload, sealed = summary_fixture()
        for field, value in (('new_fits', 1), ('held_outcome_files_read', 1), ('peak_process_rss_bytes', 2 ** 31)):
            changed = copy.deepcopy(payload); changed[field] = value
            with self.assertRaises(ValueError): summarize(changed, sealed)

    def test_historical_model_aggregate_and_audit_pin_refuse_tampering(self):
        import json
        summary = json.loads(Path('data/manifests/ranking_v4_r4_fit_transfer_diagnostic_20261006.json').read_text())
        payload = {'release_sha256': RELEASE_SHA, 'package_sha256': PACKAGE_SHA, 'results': []}
        for key, sha in summary['provenance']['models_sha256'].items():
            family, seed = key.rsplit('_', 1)
            payload['results'].append({'held_family': family, 'seed': int(seed), 'model_sha256': sha})
        raw = AUDIT.read_bytes()
        self.assertEqual('58db84f0f4b4ea445208def7963ea5a3c02317833f7a329b474a33f5ed53874b', verify_model_identity(payload, raw))
        changed = copy.deepcopy(payload); changed['results'][0]['model_sha256'] = '0' * 64
        with self.assertRaises(ValueError): verify_model_identity(changed, raw)
        with self.assertRaises(ValueError): verify_model_identity(payload, raw + b' ')
        for field in ('release_sha256', 'package_sha256'):
            changed, sealed = summary_fixture(); changed[field] = 'wrong'
            with self.assertRaises(ValueError): summarize(changed, sealed)


if __name__ == '__main__': unittest.main()
