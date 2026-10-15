"""Generated synthetic fixtures only; no fitting or external data."""
import copy
import itertools
import math
import unittest

from src.models import ranking_v6_multi_positive_complete_cost as kernel
from src.models import ranking_v6_synthetic_real_bridge_adapter as adapter


def fixture(cycles=(100, 101, 102), circuit='task'):
    features, outcomes = [], []
    for i, value in enumerate(cycles):
        uid = f'{circuit}.{i:04d}'
        features.append(dict(zip(adapter.FEATURES, (1, 0, 2., 0., .5, 0., 3.)),
                             action_uid=uid, family='family.' + circuit,
                             circuit=circuit, role='FIT'))
        outcomes.append({'action_uid': uid, 'total_cycles': value,
                         'policy_charged_runtime_s': i + 1.,
                         'is_d95_feasible': 1, 'execution_status': 'SUCCESS'})
    return features, outcomes


class OutcomeTrap:
    def __iter__(self):
        raise AssertionError('Outcome content accessed')

    def __len__(self):
        raise AssertionError('Outcome length accessed')

    def __getitem__(self, key):
        raise AssertionError('Outcome row accessed')


class AdapterTests(unittest.TestCase):
    def prepare(self, features, outcomes):
        return adapter.prepare_fit_fixture(features, outcomes, synthetic_only=True)

    def test_multiple_single_all_positive_and_single_action(self):
        for cycles, expected in (((100, 101, 102), (0, 1)),
                                 ((100, 102, 103), (0,)),
                                 ((100, 100, 101), (0, 1, 2)), ((100,), (0,))):
            with self.subTest(cycles=cycles):
                features, outcomes = fixture(cycles)
                task = self.prepare(features, outcomes)['tasks'][0]
                self.assertEqual(task['positive_uids'], tuple(features[i]['action_uid'] for i in expected))

    def test_exact_large_integer_epsilon_boundary(self):
        minimum = 990_000_000_000_000
        boundary = minimum * 101 // 100
        features, outcomes = fixture((minimum, boundary, boundary + 1))
        task = self.prepare(features, outcomes)['tasks'][0]
        self.assertEqual(task['positive_uids'], tuple(row['action_uid'] for row in features[:2]))
        self.assertEqual(task['oracle_cycles'], minimum)

    def test_metadata_and_costs_do_not_enter_matrix(self):
        features, outcomes = fixture()
        task = self.prepare(features, outcomes)['tasks'][0]
        self.assertEqual(task['features'], ((1, 0, 2., 0., .5, 0., 3.),) * 3)
        self.assertEqual(len(adapter.FEATURES), 7)
        changed = copy.deepcopy(outcomes)
        changed[0]['policy_charged_runtime_s'] = 999.
        other = self.prepare(features, changed)['tasks'][0]
        self.assertEqual(task['features'], other['features'])
        self.assertEqual(task['positive_uids'], other['positive_uids'])
        self.assertNotEqual(task['costs'], other['costs'])
        features2, outcomes2 = fixture(circuit='other_metadata')
        self.assertEqual(task['features'], self.prepare(features2, outcomes2)['tasks'][0]['features'])

    def test_e23_zero_score_matches_all_permutations_without_fitting(self):
        features, outcomes = fixture((100, 101, 102, 104))
        task = self.prepare(features, outcomes)['tasks'][0]
        positives, costs = set(task['positive_uids']), task['costs']
        scores = dict.fromkeys(task['action_uids'], 0.)
        result = kernel.evaluate(scores, task['positive_uids'], costs, synthetic_only=True)
        charges = []
        for order in itertools.permutations(task['action_uids']):
            charge = 0.
            for uid in order:
                charge += costs[uid]
                if uid in positives:
                    break
            charges.append(charge)
        expected = (costs[task['action_uids'][0]] + costs[task['action_uids'][1]]) / 2 + sum(
            costs[uid] / 3 for uid in task['action_uids'][2:])
        self.assertAlmostEqual(result['complete_first_hit_cost'], expected)
        self.assertAlmostEqual(result['complete_first_hit_cost'], math.fsum(charges) / len(charges))

    def test_all_input_permutations_are_deterministic_and_inputs_unchanged(self):
        features, outcomes = fixture()
        original = copy.deepcopy((features, outcomes))
        baseline = self.prepare(features, outcomes)
        for f in itertools.permutations(features):
            for o in itertools.permutations(outcomes):
                self.assertEqual(self.prepare(f, o), baseline)
        self.assertEqual((features, outcomes), original)

    def test_multiple_tasks_sorted_and_grouped(self):
        first, out_first = fixture((100, 102), circuit='z')
        second, out_second = fixture((200, 201), circuit='a')
        tasks = self.prepare(first + second, out_first + out_second)['tasks']
        self.assertEqual(tuple(t['circuit'] for t in tasks), ('a', 'z'))
        self.assertEqual(tuple(t['oracle_cycles'] for t in tasks), (200, 100))

    def test_unsupported_roles_rejected_before_outcome_container_access(self):
        for role in ('HELDOUT', 'VALIDATION', 'BLIND', 'TRAIN', 'fit', None, True):
            features, _ = fixture()
            features[-1]['role'] = role
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'FIT_ONLY'):
                self.prepare(features, OutcomeTrap())

    def test_exact_feature_schema_rejects_leaks_before_outcomes(self):
        for field in ('synthetic_signal', 'cost_fraction', 'policy_charged_runtime_s',
                      'total_cycles', 'epsilon_hit', 'unknown'):
            features, _ = fixture()
            features[-1][field] = 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'FEATURE_SCHEMA'):
                self.prepare(features, OutcomeTrap())
        features, _ = fixture()
        del features[0][adapter.FEATURES[0]]
        with self.assertRaisesRegex(ValueError, 'FEATURE_SCHEMA'):
            self.prepare(features, OutcomeTrap())

    def test_exact_outcome_schema_and_uid_join(self):
        for mutation in ('extra_field', 'missing_field', 'duplicate', 'missing', 'extra_uid'):
            features, outcomes = fixture()
            if mutation == 'extra_field':
                outcomes[0]['unknown'] = 0
            elif mutation == 'missing_field':
                del outcomes[0]['total_cycles']
            elif mutation == 'duplicate':
                outcomes.append(outcomes[0].copy())
            elif mutation == 'missing':
                outcomes.pop()
            else:
                outcomes.append(dict(outcomes[0], action_uid='extra'))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.prepare(features, outcomes)

    def test_gate_and_container_types(self):
        features, outcomes = fixture()
        for gate in (False, 1, 'True', None):
            with self.subTest(gate=gate), self.assertRaises(ValueError):
                adapter.prepare_fit_fixture(features, outcomes, synthetic_only=gate)
        with self.assertRaises(ValueError):
            adapter.prepare_fit_fixture(features, outcomes)
        for bad in ([], {}, iter(features), None):
            with self.subTest(bad=type(bad)), self.assertRaises(ValueError):
                self.prepare(bad, outcomes)
            with self.assertRaises(ValueError):
                self.prepare(features, bad)
        class Row(dict):
            pass
        with self.assertRaises(ValueError):
            self.prepare([Row(features[0])], outcomes[:1])
        with self.assertRaises(ValueError):
            self.prepare(features[:1], [Row(outcomes[0])])

    def test_feature_numeric_domains_and_types(self):
        for name in adapter.FEATURES:
            for bad in (True, '1', None, float('inf'), float('-inf'), float('nan'), 10**1000):
                features, outcomes = fixture()
                features[0][name] = bad
                with self.subTest(name=name, bad_type=type(bad)), self.assertRaises(ValueError):
                    self.prepare(features, outcomes)
        for name, bad in (('scheme_hf', .5), ('scheme_hmf', 1),
                          ('h_limit_fraction_of_circuit_max', -1),
                          ('m_limit_fraction_of_circuit_max', 1.01),
                          ('log1p_h_limit', -1), ('log1p_m_limit', -1),
                          ('log1p_common_fault_count', -1)):
            features, outcomes = fixture()
            features[0][name] = bad
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.prepare(features, outcomes)

    def test_outcome_domains_reject_failures_instead_of_filtering(self):
        invalid = {'total_cycles': (True, 1., 0, -1, 10**15 + 1, '100'),
                   'policy_charged_runtime_s': (True, 0, -1, 1e9 + 1, float('nan'), float('inf'), '2'),
                   'is_d95_feasible': (True, 1., 0, '1'),
                   'execution_status': ('FAILED', 'TIMEOUT', 'success', None)}
        for field, values in invalid.items():
            for value in values:
                features, outcomes = fixture()
                outcomes[0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.prepare(features, outcomes)

    def test_identifiers_unique_uids_and_one_family_per_circuit(self):
        for field in ('action_uid', 'family', 'circuit'):
            for value in ('', 'x' * 65, '../bad', 'has space', '中文', None, 1):
                features, outcomes = fixture()
                features[0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.prepare(features, outcomes)
        features, outcomes = fixture()
        features[1]['action_uid'] = features[0]['action_uid']
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_UID'):
            self.prepare(features, outcomes)
        features, outcomes = fixture()
        features[1]['family'] = 'different'
        with self.assertRaisesRegex(ValueError, 'CIRCUIT_FAMILY'):
            self.prepare(features, outcomes)

    def test_caps_and_exact_cap_acceptance(self):
        features, outcomes = fixture((100,) * 1024)
        self.assertEqual(len(self.prepare(features, outcomes)['tasks'][0]['features']), 1024)
        more_f, more_o = fixture((100,) * 1025)
        with self.assertRaisesRegex(ValueError, 'CIRCUIT_CAP'):
            self.prepare(more_f, more_o)
        all_f, all_o = [], []
        for i in range(4):
            f, o = fixture((100,) * 1024, circuit=f'c{i}')
            all_f.extend(f)
            all_o.extend(o)
        self.assertEqual(len(self.prepare(all_f, all_o)['tasks']), 4)
        f, o = fixture((100,), circuit='extra')
        with self.assertRaisesRegex(ValueError, 'FEATURE_CONTAINER'):
            self.prepare(all_f + f, all_o + o)

    def test_flags_are_fixture_only_and_no_real_training_claim(self):
        result = self.prepare(*fixture())
        self.assertEqual(result['scope'], 'synthetic_fit_fixture_only')
        self.assertEqual(result['schema'], adapter.SCHEMA)
        for key in ('synthetic_declaration_is_provenance_detector', 'features_standardized',
                    'costs_are_features', 'oracle_is_feature', 'actual_training',
                    'real_data_access', 'online_cost_replay'):
            self.assertIs(result[key], False)


if __name__ == '__main__':
    unittest.main()
