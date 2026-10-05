import json
from pathlib import Path
import tempfile
import unittest

from scripts import compare_ranking_v4_r3_results as comparison
from src.models.runtime_ranking_v3 import FAMILIES
from src.models.run_runtime_ranking_v3 import SEEDS


def fixtures():
    v4, v3 = {'records': {}}, {'records': {}}
    for family in FAMILIES.values():
        for seed in SEEDS:
            metrics = {'hit_at_10': 1, 'best_cycle_regret_at_10': .1, 'charged_runtime_s': 10., 'attempt_count': 2}
            v4['records'][f'experiment/{family}_{seed}/evaluation.json'] = {'data': dict(family=family, seed=seed, model='candidate_mlp', metrics=metrics)}
            for model, hit, cost in (('candidate_mlp', 1, 9.), ('graphsage', 1, 9.5), ('xgboost', 1, 8.), ('fixed_heuristic', 0, 1.)):
                v3['records'][f'experiment/{family}_{seed}_{model}/evaluation.json'] = {'data': dict(family=family, seed=seed, model=model,
                    metrics=dict(metrics, hit_at_10=hit, charged_runtime_s=cost))}
    return v4, v3


class ComparisonTests(unittest.TestCase):
    def test_exact_grid_nonexhaustive_and_common_hit_cost_only(self):
        result = comparison.compare(*fixtures())
        xgb = result['comparisons']['xgboost']
        self.assertEqual(18, xgb['all_18']['v4']['count']); self.assertEqual(15, xgb['nonexhaustive_15']['v4']['count'])
        self.assertEqual(18, xgb['all_18']['common_hit_paired_cost_count'])
        fixed = result['comparisons']['fixed_heuristic']['all_18']
        self.assertEqual(0, fixed['common_hit_paired_cost_count'])
        self.assertTrue(fixed['miss_cost_is_not_speedup'])

    def test_incomplete_grid_refuses_and_outputs_are_create_once_chinese(self):
        v4, v3 = fixtures(); v4['records'].pop(next(iter(v4['records'])))
        with self.assertRaises(ValueError): comparison.compare(v4, v3)
        result = comparison.compare(*fixtures())
        with tempfile.TemporaryDirectory() as directory:
            json_path, md_path = Path(directory) / 'r.json', Path(directory) / 'r.md'
            comparison.write_outputs(result, json_path, md_path)
            self.assertIn('描述性比较', md_path.read_text(encoding='utf-8'))
            with self.assertRaises(FileExistsError): comparison.write_outputs(result, json_path, md_path)

    def test_v3_retained_manifests_must_agree(self):
        unused, v3 = fixtures(); comparison.verify_v3_manifest_agreement(v3, v3)
        changed = json.loads(json.dumps(v3)); next(iter(changed['records'].values()))['data']['metrics']['attempt_count'] = 99
        with self.assertRaises(ValueError): comparison.verify_v3_manifest_agreement(v3, changed)
        changed = json.loads(json.dumps(v3))
        graph = next(item for item in changed['records'].values() if item['data']['model'] == 'graphsage')
        graph['data']['metrics']['charged_runtime_s'] = 123.
        with self.assertRaises(ValueError): comparison.verify_v3_manifest_agreement(v3, changed)

    def test_duplicate_extra_and_invalid_metric_domains_refuse(self):
        v4, v3 = fixtures()
        duplicate = json.loads(json.dumps(v4)); source = next(iter(duplicate['records']))
        duplicate['records']['experiment/duplicate/evaluation.json'] = duplicate['records'][source]
        with self.assertRaises(ValueError): comparison.compare(duplicate, v3)
        extra = json.loads(json.dumps(v3)); source = next(iter(extra['records']))
        extra['records']['experiment/extra/evaluation.json'] = dict(extra['records'][source], data=dict(extra['records'][source]['data'], model='unknown'))
        with self.assertRaises(ValueError): comparison.compare(v4, extra)
        for value in (float('nan'), float('inf'), -1, True):
            bad_v4 = json.loads(json.dumps(v4)); next(iter(bad_v4['records'].values()))['data']['metrics']['charged_runtime_s'] = value
            with self.assertRaises(ValueError): comparison.compare(bad_v4, v3)
        for field, value in (('hit_at_10', True), ('attempt_count', 0), ('best_cycle_regret_at_10', float('nan'))):
            bad_v4 = json.loads(json.dumps(v4)); next(iter(bad_v4['records'].values()))['data']['metrics'][field] = value
            with self.assertRaises(ValueError): comparison.compare(bad_v4, v3)


if __name__ == '__main__': unittest.main()
