"""Fabricated six-family fixtures only; no production inputs or training."""
import copy
import math
import unittest
from unittest.mock import patch

from src.models import ranking_v6_materialized_fold as fold


def fabricated():
    rows, outcomes = [], {}
    for c, (circuit, family) in enumerate(fold.FAMILIES.items()):
        for i in range(2):
            uid = f'{circuit}.{i}'
            values = (1-i, i, c+i*.2, .1*c, .2*i, .4, 3.+c)
            rows.append(dict(zip(fold.FEATURES, values), action_uid=uid,
                             circuit=circuit, family=family, role='TRAIN'))
            outcomes[uid] = dict(execution_status='SUCCESS', is_d95_feasible=1,
                                 total_cycles=100+i, policy_charged_runtime_s=1.+i)
    return rows, outcomes


class PoisonMapping:
    def __len__(self):
        raise AssertionError('OUTCOME_LEN')

    def __iter__(self):
        raise AssertionError('OUTCOME_ITER')

    def __getitem__(self, key):
        raise AssertionError('OUTCOME_READ')


class MaterializedFoldTests(unittest.TestCase):
    def setUp(self):
        self.rows, self.all_outcomes = fabricated()
        self.held = 'iwls_spi'
        self.outcomes = {row['action_uid']: self.all_outcomes[row['action_uid']]
                         for row in self.rows if row['family'] != self.held}

    def prepare(self, **kwargs):
        return fold.prepare_fold(self.rows, self.outcomes,
                                 **dict(dict(held_family=self.held, seed=20260824,
                                             implementation_only=True), **kwargs))

    def test_all_six_lofo_exact_membership_and_full_family_macro(self):
        for held in fold.FAMILIES.values():
            outcomes = {r['action_uid']: self.all_outcomes[r['action_uid']]
                        for r in self.rows if r['family'] != held}
            result = fold.prepare_fold(self.rows, outcomes, held_family=held,
                                       seed=20260824, implementation_only=True)
            self.assertEqual(set(result['fit_uids']) | set(result['held_uids']), set(self.all_outcomes))
            self.assertFalse(set(result['fit_uids']) & set(result['held_uids']))
            self.assertEqual(len(result['fit_tasks']), 5)
            self.assertEqual({t['family'] for t in result['fit_tasks']}, set(fold.FAMILIES.values())-{held})
            self.assertTrue(all(t['all_positive'] for t in result['fit_tasks']))
            self.assertTrue(all(t['cost_normalization_B'] == 4 for t in result['fit_tasks']))

    def test_public_feature_split_optin_copy_order_and_no_outcome_surface(self):
        for value in (False, 1, None):
            with self.assertRaisesRegex(ValueError, 'OPT_IN'):
                fold.feature_split(self.rows, held_family=self.held, seed=20260824,
                                   implementation_only=value)
        before = copy.deepcopy(self.rows)
        with patch('builtins.open', side_effect=AssertionError('IO')), \
                patch('random.Random', side_effect=AssertionError('RNG')):
            result = fold.feature_split(self.rows, held_family=self.held, seed=20260824,
                                        implementation_only=True)
        self.assertEqual(result['fit_uids'], self.prepare()['fit_uids'])
        self.assertEqual(result['held_uids'], self.prepare()['held_uids'])
        self.assertEqual(list(result['feature_rows_by_uid']), sorted(self.all_outcomes))
        self.assertEqual(result, fold.feature_split(list(reversed(self.rows)), held_family=self.held,
                                                   seed=20260824, implementation_only=True))
        self.assertEqual(before, self.rows)
        result['feature_rows_by_uid'][result['fit_uids'][0]]['log1p_h_limit'] = 999.
        self.assertEqual(before, self.rows)
        self.assertTrue(all(set(row) == fold._FEATURE_KEYS
                            for row in result['feature_rows_by_uid'].values()))
        with self.assertRaises(TypeError):
            fold.feature_split(self.rows, held_family=self.held, seed=20260824,
                               implementation_only=True, fit_outcomes=PoisonMapping())

    def test_prepare_uses_public_feature_split_barrier(self):
        original = fold.feature_split
        with patch.object(fold, 'feature_split', wraps=original) as barrier:
            self.prepare()
        barrier.assert_called_once_with(self.rows, held_family=self.held, seed=20260824,
                                         implementation_only=True)

    def test_normalizer_fitting_only_population_statistics(self):
        first = self.prepare()
        fit_rows = sorted((r for r in self.rows if r['family'] != self.held), key=lambda r:r['action_uid'])
        for i, name in enumerate(fold.FEATURES):
            mean = math.fsum(r[name] for r in fit_rows)/len(fit_rows)
            scale = max(math.sqrt(math.fsum((r[name]-mean)**2 for r in fit_rows)/len(fit_rows)), 1e-12)
            self.assertEqual(first['normalizer']['mean'][i], mean)
            self.assertEqual(first['normalizer']['std'][i], scale)
        for row in self.rows:
            if row['family'] == self.held:
                row['log1p_h_limit'] = 1e6
        second = self.prepare()
        self.assertEqual(first['normalizer'], second['normalizer'])
        self.assertEqual(first['fit_features'], second['fit_features'])
        self.assertEqual(first['normalizer_sha256'], second['normalizer_sha256'])
        self.assertNotEqual(first['feature_snapshot_sha256'], second['feature_snapshot_sha256'])
        self.assertFalse(second['legacy_vjp_feature_domain_pass'])
        self.assertGreater(second['domain_diagnostics']['max_abs_held_feature'], 2)

    def test_feature_split_barrier_precedes_outcome_container_inspection(self):
        options = dict(held_family=self.held, seed=20260824, implementation_only=True)
        with self.assertRaisesRegex(ValueError, 'HELD_FAMILY'):
            fold.prepare_fold(self.rows, PoisonMapping(), **dict(options, held_family='unknown'))
        with self.assertRaisesRegex(ValueError, 'SEED'):
            fold.prepare_fold(self.rows, PoisonMapping(), **dict(options, seed=True))
        self.rows[-1]['role'] = 'HELDOUT'
        with self.assertRaisesRegex(ValueError, 'TRAIN_ONLY'):
            fold.prepare_fold(self.rows, PoisonMapping(), **options)
        del self.rows[-1]['role']
        with self.assertRaisesRegex(ValueError, 'FEATURE_SCHEMA'):
            fold.prepare_fold(self.rows, PoisonMapping(), **options)

    def test_held_payload_values_never_touched_and_duplicate_uid_rejected(self):
        held_uid = next(uid for uid in self.all_outcomes if uid not in self.outcomes)
        self.outcomes[held_uid] = PoisonMapping()
        with self.assertRaisesRegex(ValueError, 'FIT_ONLY_EXACT_UID_JOIN'):
            self.prepare()
        self.outcomes.pop(held_uid)
        self.rows[-1]['action_uid'] = self.rows[0]['action_uid']
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_UID'):
            fold.prepare_fold(self.rows, PoisonMapping(), held_family=self.held,
                              seed=20260824, implementation_only=True)

    def test_fit_only_outcome_join_and_failure_rejection(self):
        for change in ('held', 'missing', 'extra', 'fail', 'd95', 'extra_field', 'cycles_bool', 'runtime_inf'):
            old = copy.deepcopy(self.outcomes)
            uid = next(iter(self.outcomes))
            if change == 'held':
                self.outcomes.update({u:self.all_outcomes[u] for u in self.all_outcomes if u not in self.outcomes})
            elif change == 'missing': self.outcomes.pop(uid)
            elif change == 'extra': self.outcomes['other'] = dict(self.outcomes[uid])
            elif change == 'fail': self.outcomes[uid]['execution_status'] = 'FAIL'
            elif change == 'd95': self.outcomes[uid]['is_d95_feasible'] = 0
            elif change == 'extra_field': self.outcomes[uid]['leak'] = 1
            elif change == 'cycles_bool': self.outcomes[uid]['total_cycles'] = True
            elif change == 'runtime_inf': self.outcomes[uid]['policy_charged_runtime_s'] = float('inf')
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.prepare()
            self.outcomes = old

    def test_label_cost_isolation_integer_epsilon_and_order_immutability(self):
        old = copy.deepcopy((self.rows, self.outcomes))
        first = self.prepare()
        uid = next(iter(self.outcomes))
        self.outcomes[uid]['policy_charged_runtime_s'] = 9.
        self.outcomes[uid]['total_cycles'] = 103
        second = self.prepare()
        self.assertEqual(first['fit_features'], second['fit_features'])
        self.assertEqual(first['feature_snapshot_sha256'], second['feature_snapshot_sha256'])
        self.assertEqual(first['normalizer_sha256'], second['normalizer_sha256'])
        self.assertNotEqual(first['fit_tasks'], second['fit_tasks'])
        self.rows, self.outcomes = copy.deepcopy(old)
        self.assertEqual(first, self.prepare())
        self.assertEqual(old, (self.rows, self.outcomes))
        self.rows.reverse()
        self.outcomes = dict(reversed(list(self.outcomes.items())))
        self.assertEqual(first, self.prepare())
        task = second['fit_tasks'][0]
        self.assertEqual(len(task['positive_uids']), 1)

    def test_large_exact_integer_epsilon_boundary(self):
        minimum = 990_000_000_000_000
        uids = sorted(self.outcomes)[:2]
        self.outcomes[uids[0]]['total_cycles'] = minimum
        self.outcomes[uids[1]]['total_cycles'] = minimum*101//100
        self.assertEqual(self.prepare()['fit_tasks'][0]['positive_uids'], uids)
        self.outcomes[uids[1]]['total_cycles'] += 1
        self.assertEqual(self.prepare()['fit_tasks'][0]['positive_uids'], uids[:1])

    def test_raw_logs_above_two_and_constant_std_no_clipping(self):
        for row in self.rows:
            row['log1p_common_fault_count'] = 10.
        result = self.prepare()
        index = fold.FEATURES.index('log1p_common_fault_count')
        self.assertEqual(result['normalizer']['std'][index], 1e-12)
        self.assertTrue(all(row[index] == 0 for row in result['fit_features']))
        self.assertGreater(result['domain_diagnostics']['max_abs_raw_feature'], 2)
        self.assertFalse(result['features_clipped'])
        self.assertFalse(result['identity_normalizer_used'])

    def test_domains_types_identifiers_and_caps(self):
        changes = [('log1p_h_limit', v) for v in (True, '1', -1, 1e6+1, float('nan'), float('inf'), 10**1000)]
        changes += [('h_limit_fraction_of_circuit_max', 1.1), ('scheme_hf', .5),
                    ('action_uid', 'bad/id'), ('family', 'wrong'), ('circuit', 'unknown')]
        for field, value in changes:
            old = self.rows[0][field]
            self.rows[0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.prepare()
            self.rows[0][field] = old
        with patch.object(fold, 'MAX_ROWS', 1), self.assertRaisesRegex(ValueError, 'FEATURE_CONTAINER'):
            self.prepare()
        with patch.object(fold, 'MAX_ACTIONS_PER_CIRCUIT', 1), self.assertRaisesRegex(ValueError, 'CIRCUIT_CAP'):
            self.prepare()
        self.rows.pop()
        self.rows.pop()
        with self.assertRaisesRegex(ValueError, 'SIX_TRAIN_FAMILIES'):
            self.prepare()

    def test_optin_flags_and_no_io_rng(self):
        for value in (False, 1, None):
            with self.assertRaisesRegex(ValueError, 'OPT_IN'):
                self.prepare(implementation_only=value)
        with patch('builtins.open', side_effect=AssertionError('IO')), \
                patch('socket.socket', side_effect=AssertionError('NETWORK')), \
                patch('random.Random', side_effect=AssertionError('RNG')):
            result = self.prepare()
        self.assertEqual(result['status'], 'IMPLEMENTATION_ONLY_NO_REAL_DATA_RELEASE')
        for flag in ('real_data_release', 'real_training_release', 'real_data_access',
                     'candidate_lineage_verified', 'fit_failure_support', 'model_ready',
                     'held_outcomes_accessed', 'trainer_implemented', 'optimizer_implemented'):
            self.assertFalse(result[flag])


if __name__ == '__main__':
    unittest.main()
