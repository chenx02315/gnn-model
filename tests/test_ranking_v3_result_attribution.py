import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import analyze_ranking_v3_frozen_results as attribution


FAMILIES = ('f1', 'f2', 'f3', 'f4', 'f5', 'f6')
SEEDS = (1, 2, 3)
MODELS = ('candidate_mlp', 'graphsage', 'xgboost', 'fixed_heuristic')


def fixture():
    records = {}
    for family_index, family in enumerate(FAMILIES):
        for seed in SEEDS:
            for model_index, model in enumerate(MODELS):
                order = [family + ':u' + str(value) for value in range(10 if family == 'f1' else 12)]
                if model != 'fixed_heuristic': order = order[model_index:] + order[:model_index]
                hit = int(model == 'xgboost' or (model == 'fixed_heuristic' and seed == 1))
                records['experiment/%s_%s_%s/evaluation.json' % (family, seed, model)] = {'data': {
                    'family': family, 'seed': seed, 'model': model,
                    'freeze': {'order': order},
                    'metrics': {'hit_at_10': hit, 'hit_found': bool(hit), 'attempt_count': 3 if hit else 10,
                                'charged_runtime_s': float(10 + model_index), 'best_cycle_regret_at_10': .1},
                }}
    return {'records': records}


class AttributionTests(unittest.TestCase):
    def test_hit_nohit_pairing_and_exhaustive_exclusion(self):
        payload = fixture()
        with patch.object(attribution, 'validate'):
            report = attribution.describe(payload, 'a' * 64)
        xgb = report['models']['xgboost']
        self.assertEqual(18, xgb['aggregate']['evaluation_count_all_18'])
        self.assertEqual(15, xgb['aggregate']['nonexhaustive_evaluation_count'])
        self.assertEqual(3, xgb['aggregate']['exhaustive_evaluation_count'])
        self.assertEqual(6, xgb['aggregate']['paired_shared_hit_count'])
        self.assertEqual(5, xgb['aggregate']['paired_nonexhaustive_shared_hit_count'])
        self.assertEqual(18, xgb['aggregate']['all_evaluations_descriptive_joint']['evaluation_count'])
        self.assertEqual(15, xgb['aggregate']['nonexhaustive_evaluations_descriptive_joint']['evaluation_count'])
        self.assertEqual(18, xgb['aggregate']['all_evaluations_descriptive_joint']['hit_count'])
        self.assertEqual(1.0, xgb['aggregate']['nonexhaustive_evaluations_descriptive_joint']['hit_rate'])
        self.assertEqual(10, report['models']['xgboost']['family']['f1']['heldout_action_count'])
        self.assertEqual([3, None, None], report['models']['fixed_heuristic']['family']['f1']['first_hit_ranks'])
        self.assertTrue(xgb['aggregate']['no_hit_lower_cost_is_not_a_gain'])

    def test_order_stability_tamper_and_duplicate_refuse(self):
        payload = fixture()
        with patch.object(attribution, 'validate'):
            report = attribution.describe(payload, 'a' * 64)
        self.assertEqual(1, report['models']['fixed_heuristic']['family']['f1']['unique_full_order_count_across_3_seeds'])
        tampered = copy.deepcopy(payload)
        key = next(key for key in tampered['records'] if key.endswith('f1_1_xgboost/evaluation.json'))
        tampered['records'][key]['data']['freeze']['order'] = ['duplicate', 'duplicate']
        with patch.object(attribution, 'validate'):
            with self.assertRaises(ValueError): attribution.describe(tampered, 'a' * 64)
        duplicate = copy.deepcopy(payload)
        source = next(key for key in duplicate['records'] if key.endswith('f1_1_xgboost/evaluation.json'))
        duplicate['records']['experiment/duplicate/evaluation.json'] = copy.deepcopy(duplicate['records'][source])
        with patch.object(attribution, 'validate'):
            with self.assertRaises(ValueError): attribution.describe(duplicate, 'a' * 64)

    def test_input_hash_and_create_once(self):
        raw = json.dumps(fixture(), sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'frozen.json'; source.write_bytes(raw)
            target = Path(root) / 'out.json'
            with patch.object(attribution, 'validate'):
                attribution.analyze(source, expected_input_sha256=hashlib.sha256(raw).hexdigest(), output_path=target)
            with patch.object(attribution, 'validate'):
                with self.assertRaises(FileExistsError): attribution.analyze(source, expected_input_sha256=hashlib.sha256(raw).hexdigest(), output_path=target)
            with self.assertRaises(ValueError): attribution.analyze(source, expected_input_sha256='0' * 64)


if __name__ == '__main__': unittest.main()
