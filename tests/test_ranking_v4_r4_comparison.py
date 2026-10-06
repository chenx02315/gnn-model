import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts import compare_ranking_v4_r4_results as r4
from tests.test_ranking_v4_r3_comparison import fixtures


class R4ComparisonTests(unittest.TestCase):
    def test_version_grid_semantics_and_family_grain(self):
        left, right = fixtures()
        result = r4.build_comparison(left, right, right)
        self.assertIn('r4', result['schema_version'])
        self.assertEqual(24, len(result['family_rows']))
        self.assertEqual(20, sum(row['nonexhaustive'] for row in result['family_rows']))
        self.assertEqual(.01, result['epsilon'])
        self.assertEqual(10, result['top_k'])
        self.assertIn('all top-10', result['regret_semantics'])
        self.assertIn('not model wall', result['runtime_semantics'])
        fixed = result['comparisons']['fixed_heuristic']['nonexhaustive_15']
        self.assertIsNone(fixed['common_hit_mean_charged_runtime_delta_v4_minus_baseline'])
        self.assertTrue(fixed['miss_cost_is_not_speedup'])

    def test_drift_in_any_retained_v3_model_refused(self):
        left, right = fixtures()
        legacy = json.loads(json.dumps(right))
        row = next(item['data'] for item in legacy['records'].values() if item['data']['model'] == 'graphsage')
        row['metrics']['charged_runtime_s'] += 1
        with self.assertRaises(ValueError): r4.build_comparison(left, right, legacy)

    def test_pinned_inputs_hash_and_size_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'a.json'; raw = b'{}'
            path.write_bytes(raw)
            contract = {'x': ('a.json', hashlib.sha256(raw).hexdigest())}
            self.assertEqual({'x': {}}, r4.load_pinned(root, contract))
            path.write_bytes(b'{"changed":true}')
            with self.assertRaises(ValueError): r4.load_pinned(root, contract)
            path.write_bytes(b' ' * (2 * 1024 * 1024 + 1))
            with self.assertRaises(ValueError): r4.load_pinned(root, contract)

    def test_report_rates_denominators_and_no_blind_claim(self):
        left, right = fixtures()
        result = r4.build_comparison(left, right, right)
        artifact = r4.report_artifact(result)
        rows = artifact['snapshot']['datasets']['primary']
        self.assertEqual(4, len(rows))
        self.assertTrue(all(row['count'] == 15 and 0 <= row['hit_rate'] <= 1 for row in rows))
        self.assertEqual('# ' + artifact['manifest']['title'], artifact['manifest']['blocks'][0]['body'])
        self.assertNotIn('color', artifact['manifest']['charts'][0]['encodings'])
        self.assertIn('未访问 VALIDATION/BLIND', str(artifact))

    def test_report_sql_matches_frozen_primary_aggregates(self):
        left, right = fixtures()
        result = r4.build_comparison(left, right, right)
        rows = {row['model']: row for row in r4.report_rows(result)}
        expected = {'v4_r4_candidate_mlp': result['comparisons']['candidate_mlp']['nonexhaustive_15']['v4']}
        expected.update({'v3_' + name: result['comparisons'][name]['nonexhaustive_15']['v3_baseline'] for name in r4.BASELINES})
        for model, values in expected.items():
            for field in ('count', 'hit_count', 'hit_rate', 'mean_best_cycle_regret_at_10', 'mean_charged_runtime_s'):
                self.assertAlmostEqual(values[field], rows[model][field], places=12)

    def test_create_once_preflight_preserves_other_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); first, second = root / 'first.json', root / 'second.json'
            second.write_text('old', encoding='utf-8')
            with self.assertRaises(FileExistsError): r4.write_once({first: {}, second: {}})
            self.assertFalse(first.exists())
            self.assertEqual('old', second.read_text(encoding='utf-8'))


if __name__ == '__main__': unittest.main()
