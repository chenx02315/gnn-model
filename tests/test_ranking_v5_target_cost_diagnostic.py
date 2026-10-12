"""Synthetic-only target/cost tests; never inspect real TRAIN files."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.models import ranking_v5_target_cost_diagnostic as diagnostic
from src.models import ranking_v5_feature_support as base


def fixture(count=24):
    rows, outcomes = [], {}
    families = sorted(base.FAMILIES.items())
    for i in range(count):
        circuit, family = families[i % 6]
        candidate = i // 6
        uid = 'synthetic-secret-%04d' % i
        rows.append({'action_uid': uid, 'circuit': circuit, 'family': family, 'role': 'TRAIN',
                     'scheme_hf': int(candidate % 2 == 0), 'scheme_hmf': int(candidate % 2 != 0),
                     'log1p_h_limit': 0., 'log1p_m_limit': 0.,
                     'h_limit_fraction_of_circuit_max': candidate / count,
                     'm_limit_fraction_of_circuit_max': 0., 'log1p_common_fault_count': 2.})
        outcomes[uid] = {'execution_status': 'SUCCESS', 'is_d95_feasible': 1,
                         'total_cycles': 100 + candidate, 'policy_charged_runtime_s': float(candidate + 1)}
    return sorted(rows, key=lambda r: r['action_uid']), outcomes


def write_json(path, value):
    raw = json.dumps(value, sort_keys=True, allow_nan=False).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def package(root, mutate=None):
    rows, outcomes = fixture()
    inputs = {n: 'a'*64 for n in ('features.tsv', 'train_outcomes.tsv', 'graph_manifest.tsv')}
    graphs = {n: 'b'*64 for n in base.FAMILIES}
    source = base.digest({'source_input_sha256': inputs, 'graph_sha256': graphs})
    receipt = {'schema_version': 'ranking-v3-real-input-export-receipt-v1', 'scope': base.SCOPE,
               'release_sha256': 'c'*64, 'source_sha256': source, 'source_input_sha256': inputs,
               'graph_sha256': graphs, 'family_metadata_sha256': 'd'*64,
               'train_action_count': len(rows), 'train_outcome_count': len(rows), 'graph_count': 6,
               'fold_manifest_sha256': {}}
    for family in base.FAMILY_NAMES:
        directory = root / ('fold_' + family)
        directory.mkdir()
        fit = [r.copy() for r in rows if r['family'] != family]
        held = [r.copy() for r in rows if r['family'] == family]
        shards = {'fit_features.json': fit, 'heldout_features.json': held,
                  'fit_outcomes.json': {r['action_uid']: copy.deepcopy(outcomes[r['action_uid']]) for r in fit},
                  'heldout_outcomes.json': {r['action_uid']: copy.deepcopy(outcomes[r['action_uid']]) for r in held}}
        manifest = {'schema_version': 'ranking-v3-real-train-fold-v1', 'scope': base.SCOPE,
                    'source_sha256': source, 'family': family,
                    'release': {'status': 'PASS_TRAIN_ONLY_DATA_RELEASE', 'source_sha256': source,
                                'independent_review_pass': True, 'roles': ['TRAIN']},
                    'fitting': [r['action_uid'] for r in fit], 'heldout': [r['action_uid'] for r in held],
                    'sha256': {}}
        if mutate:
            mutate(family, manifest, shards)
        manifest['sha256'] = {name: write_json(directory / name, value) for name, value in shards.items()}
        receipt['fold_manifest_sha256'][family] = write_json(directory / 'manifest.json', manifest)
    pin = base.FixturePin(str(root), write_json(root / 'receipt.json', receipt), source, len(rows))
    return pin


class TargetCostTests(unittest.TestCase):
    def test_root_zero_io(self):
        with patch.object(base.os, 'lstat', side_effect=AssertionError('I/O')), \
                patch.object(base.os, 'open', side_effect=AssertionError('I/O')), \
                patch.object(diagnostic, 'Path', side_effect=AssertionError('Path')):
            for root in (None, Path(base.FIXED_ROOT), base.FIXED_ROOT + '/', base.FIXED_ROOT + '/..',
                         '/tmp/local', base.FIXED_ROOT.replace('train_folds', 'BLIND')):
                with self.assertRaisesRegex(ValueError, 'FIXED_ROOT'):
                    diagnostic.analyze_package(root)

    def test_counts_common_oracle_no_uid_or_raw_labels(self):
        rows, outcomes = fixture()
        first = base.FAMILY_NAMES[0]
        selected = [r for r in rows if r['family'] == first]
        for row in selected:
            if row['scheme_hmf']:
                outcomes[row['action_uid']]['total_cycles'] = 200
        result = diagnostic.analyze_rows(rows, outcomes, expected_count=24)
        family = result['families'][first]
        self.assertEqual(family['family_wide_oracle_cycles'], 100)
        self.assertEqual(family['by_scheme']['HMF']['positive_count'], 0)
        self.assertEqual(family['by_scheme']['HMF']['negative_count'], 2)
        self.assertFalse(family['by_scheme']['HMF']['guaranteed_hit_within_k_without_replacement'])
        self.assertFalse(diagnostic._group([], {}, 100)['guaranteed_hit_within_k_without_replacement'])
        self.assertTrue(family['negative_count_lt_k'])
        self.assertFalse(result['primary_online_cost_replay'])
        encoded = json.dumps(result)
        self.assertLessEqual(len(encoded.encode()), 65536)
        for row in rows:
            self.assertNotIn(row['action_uid'], encoded)
        self.assertNotIn('action_uid', encoded)
        self.assertNotIn('execution_status', encoded)
        self.assertNotIn('total_cycles', encoded)

    def test_spearman_average_ties_and_null(self):
        self.assertEqual(diagnostic._ranks([10, 10, 30]), [1.5, 1.5, 3.])
        self.assertAlmostEqual(diagnostic._spearman([1, 1, 3], [2., 2., 6.])['rho'], 1.)
        self.assertAlmostEqual(diagnostic._spearman([1, 1, 3], [6., 6., 2.])['rho'], -1.)
        for x, y, reason in [([1], [2.], 'insufficient_actions'),
                             ([1, 1], [2., 3.], 'constant_cycles'),
                             ([1, 2], [2., 2.], 'constant_cost'),
                             ([1, 1], [2., 2.], 'constant_cycles_and_cost')]:
            self.assertEqual(diagnostic._spearman(x, y)['null_reason'], reason)
            self.assertIsNone(diagnostic._spearman(x, y)['rho'])

    def test_exact_epsilon_integer_and_guarantee(self):
        rows, outcomes = fixture(72)
        family = base.FAMILY_NAMES[0]
        chosen = [r for r in rows if r['family'] == family]
        for index, row in enumerate(chosen):
            outcomes[row['action_uid']]['total_cycles'] = [100, 101, 102][min(index, 2)]
        group = diagnostic.analyze_rows(rows, outcomes, expected_count=72)['families'][family]
        self.assertEqual(group['positive_count'], 2)
        self.assertEqual(group['negative_count'], 10)
        self.assertFalse(group['guaranteed_hit_within_k_without_replacement'])

    def test_direction_flip_and_ambiguous_keys(self):
        rows, outcomes = fixture()
        a, b = base.FAMILY_NAMES[:2]
        for row in rows:
            if row['family'] == b:
                outcomes[row['action_uid']]['total_cycles'] = 300 - outcomes[row['action_uid']]['total_cycles']
        result = diagnostic.analyze_rows(rows, outcomes, expected_count=24)
        pair = result['pairwise_grid_directions'][0]
        self.assertEqual((pair['first_family'], pair['second_family']), (a, b))
        self.assertEqual(pair['directions']['discordant'], 6)
        chosen = [r for r in rows if r['family'] == a]
        chosen[2]['h_limit_fraction_of_circuit_max'] = chosen[0]['h_limit_fraction_of_circuit_max']
        result = diagnostic.analyze_rows(rows, outcomes, expected_count=24)
        grid = result['families'][a]['comparable_grid']
        self.assertEqual(grid['ambiguous_key_count'], 1)
        self.assertEqual(grid['ambiguous_action_count'], 2)
        pair = result['pairwise_grid_directions'][0]
        self.assertEqual(pair['common_unique_key_count'], 2)
        self.assertEqual(pair['second_unmatched_unique_key_count'], 2)
        self.assertEqual(pair['second_unique_key_coverage'], .5)

    def test_rows_outcome_type_schema_and_join_rejections(self):
        changes = [('execution_status', 'FAILURE'), ('is_d95_feasible', True),
                   ('is_d95_feasible', 1.), ('total_cycles', True), ('total_cycles', 0),
                   ('total_cycles', 1.), ('policy_charged_runtime_s', 1),
                   ('policy_charged_runtime_s', True), ('policy_charged_runtime_s', 0.),
                   ('policy_charged_runtime_s', float('inf')), ('policy_charged_runtime_s', float('nan'))]
        for key, value in changes:
            rows, outcomes = fixture()
            outcomes[rows[0]['action_uid']][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                diagnostic.analyze_rows(rows, outcomes, expected_count=24)
        for kind in ('extra', 'missing', 'role', 'uid', 'nonfinite', 'count', 'family'):
            rows, outcomes = fixture()
            if kind == 'extra':
                outcomes[rows[0]['action_uid']]['extra'] = 1
            elif kind == 'missing':
                outcomes.pop(rows[0]['action_uid'])
            elif kind == 'role':
                rows[0]['role'] = 'VALIDATION'
            elif kind == 'uid':
                rows[1]['action_uid'] = rows[0]['action_uid']
            elif kind == 'nonfinite':
                rows[0]['log1p_h_limit'] = float('inf')
            elif kind == 'family':
                rows[0]['family'] = 'other'
            else:
                rows.pop()
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                diagnostic.analyze_rows(rows, outcomes, expected_count=24)

    def test_fixture_authenticates_exactly_31_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin = package(root)
            opened, original = [], base.os.open
            def recording(path, flags, *args):
                opened.append(str(path))
                return original(path, flags, *args)
            with patch.object(base.os, 'open', side_effect=recording):
                result = diagnostic._analyze_fixture_package(str(root), fixture_pin=pin)
            self.assertEqual(len(opened), 31)
            self.assertEqual(len(set(opened)), 31)
            self.assertEqual({Path(p).name for p in opened}, {'receipt.json', 'manifest.json', *base.SHARDS})
            self.assertEqual(result['action_count'], 24)
            self.assertEqual(result['authenticated_file_count'], 31)

    def test_package_release_schema_uid_and_crossfold_drift(self):
        for kind in ('release', 'schema', 'uid', 'features', 'outcomes'):
            def mutate(family, manifest, shards):
                if family != base.FAMILY_NAMES[-1]:
                    return
                if kind == 'release':
                    manifest['release']['roles'] = ['BLIND']
                elif kind == 'schema':
                    manifest['extra'] = 1
                elif kind == 'uid':
                    manifest['fitting'].reverse()
                elif kind == 'features':
                    shards['fit_features.json'][0]['log1p_h_limit'] += .1
                else:
                    next(iter(shards['fit_outcomes.json'].values()))['policy_charged_runtime_s'] += .1
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                pin = package(root, mutate)
                with self.assertRaises(ValueError):
                    diagnostic._analyze_fixture_package(str(root), fixture_pin=pin)

    def test_hash_and_fixture_pins_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin = package(root)
            with self.assertRaisesRegex(ValueError, 'FIXTURE_PIN'):
                diagnostic._analyze_fixture_package(str(root) + '/other', fixture_pin=pin)
            (root / ('fold_' + base.FAMILY_NAMES[0]) / 'heldout_outcomes.json').write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError, 'HASH'):
                diagnostic._analyze_fixture_package(str(root), fixture_pin=pin)

    def test_max_bound_and_no_pooled_correlation(self):
        rows, outcomes = fixture(1706)
        result = diagnostic.analyze_rows(rows, outcomes)
        self.assertEqual(sum(f['action_count'] for f in result['families'].values()), 1706)
        self.assertLessEqual(result['total_unordered_key_pair_comparisons'], 1706**2)
        self.assertNotIn('spearman_cycles_vs_policy_charged_runtime', result)
        self.assertLessEqual(len(json.dumps(result).encode()), 65536)


if __name__ == '__main__':
    unittest.main()
