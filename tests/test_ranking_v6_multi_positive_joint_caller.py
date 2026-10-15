"""Small generated-only caller tests; never execute the fixed formal probe."""
import copy
import hashlib
import json
import math
import unittest
from unittest.mock import patch

from src.models import ranking_v6_multi_positive_joint_caller as caller


class JointCallerTests(unittest.TestCase):
    def setUp(self):
        self.features, self.outcomes = caller.generated_fixture()
        self.scores = {f'u{i:03d}': (i - 2) * .2 for i in range(6)}
        self.kwargs = dict(k=3, seed=11, pilot_samples=2, samples=3,
                           risk_weight=.5, normalized_cost_weight=1., synthetic_only=True)

    def control(self, **changes):
        return caller.evaluate_control(self.features, self.outcomes, self.scores,
                                       **dict(self.kwargs, **changes))

    def exact(self, **changes):
        options = {name: self.kwargs[name] for name in
                   ('k', 'risk_weight', 'normalized_cost_weight', 'synthetic_only')}
        return caller.evaluate_exact_reference(self.features, self.outcomes, self.scores,
                                               **dict(options, **changes))

    def test_fixture_complete_m2_boundary_singleton_and_feature_lists(self):
        result = self.exact()
        task = result['prepared_task']
        self.assertEqual(task['positive_uids'], ('u000', 'u001'))
        self.assertEqual(task['costs'], dict(zip(self.scores, (.5, 1., 2., 4., 7., 10.))))
        self.assertTrue(all(type(row) is list and len(row) == 7 for row in task['features']))
        self.outcomes[1]['total_cycles'] = 102
        self.assertEqual(self.exact()['prepared_task']['positive_uids'], ('u000',))

    def test_weights_normalization_hash_and_no_mutation(self):
        before = copy.deepcopy((self.features, self.outcomes, self.scores))
        result = self.exact(risk_weight=.7, normalized_cost_weight=1.3)
        self.assertEqual(result['cost_normalization_B'], 60.)
        self.assertEqual(result['gradient_maps']['cost'], result['cost_component']['normalized_cost_score_gradient'])
        self.assertEqual(result['gradient_maps']['risk'], result['risk_component']['miss_score_gradient'])
        self.assertAlmostEqual(result['joint_scalar'], .7 * result['risk_component']['mean_risk']
                               + 1.3 * result['cost_component']['normalized_complete_first_hit_cost'])
        for uid in self.scores:
            self.assertAlmostEqual(result['joint_score_gradient'][uid],
                                   .7 * result['gradient_maps']['risk'][uid]
                                   + 1.3 * result['gradient_maps']['cost'][uid])
        digest = hashlib.sha256(json.dumps(list(self.scores.values()), separators=(',', ':'),
                                          allow_nan=False).encode()).hexdigest()
        self.assertEqual(result['score_snapshot_sha256'], digest)
        self.assertEqual(before, (self.features, self.outcomes, self.scores))
        self.assertAlmostEqual(math.fsum(result['joint_score_gradient'].values()), 0., delta=1e-14)

    def test_invalid_before_risk_or_rng(self):
        changes = [dict(synthetic_only=v) for v in (False, 1, None)]
        changes += [dict(k=v) for v in (True, 0, 7, 11, 1.)]
        changes += [dict(seed=v) for v in (True, -1, 2**32, 1.)]
        for name in ('pilot_samples', 'samples'):
            changes += [{name: v} for v in (True, 0, 65537, 1.)]
        for name in ('risk_weight', 'normalized_cost_weight'):
            changes += [{name: v} for v in (True, -1, 11, float('nan'), float('inf'), 10**1000)]
        changes += [dict(risk_weight=0, normalized_cost_weight=0)]
        with patch.object(caller.risk_control, 'estimate', side_effect=AssertionError('RISK')), \
                patch('random.Random', side_effect=AssertionError('RNG')):
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    self.control(**change)
            with patch.object(caller.risk_control, 'MAX_WORK', 1), self.assertRaisesRegex(ValueError, 'WORK_BOUND'):
                self.control()
            for invalid in ({}, dict(self.scores, extra=0), dict(self.scores, u000=True),
                            dict(self.scores, u000=float('nan')), dict(self.scores, u000=21)):
                with self.assertRaises(ValueError):
                    caller.evaluate_control(self.features, self.outcomes, invalid, **self.kwargs)
            self.features[0]['log1p_common_fault_count'] = 2.1
            with self.assertRaisesRegex(ValueError, 'FEATURE_VJP_BOUND'):
                self.control()

    def test_cost_representability_rejection_precedes_sampling(self):
        self.outcomes[0]['policy_charged_runtime_s'] = 5e-324
        with patch.object(caller.risk_control, 'estimate', side_effect=AssertionError('RISK')), \
                patch('random.Random', side_effect=AssertionError('RNG')):
            with self.assertRaisesRegex(ValueError, 'REPRESENTABILITY'):
                self.control()

    def test_feature_label_cost_isolation_and_no_silent_fallback(self):
        first = self.exact()
        self.outcomes[1]['total_cycles'] = 102
        self.outcomes[0]['policy_charged_runtime_s'] = 8.
        second = self.exact()
        self.assertEqual(first['prepared_task']['features'], second['prepared_task']['features'])
        self.assertNotEqual(first['prepared_task']['positive_uids'], second['prepared_task']['positive_uids'])
        self.assertNotEqual(first['prepared_task']['costs'], second['prepared_task']['costs'])
        with patch.object(caller.exact_risk, 'enumerate_exact_gradient', side_effect=AssertionError('EXACT')):
            result = self.control()
        self.assertFalse(result['exact_risk_reference'])
        self.assertFalse(result['silent_exact_fallback'])

    def test_all_positive_no_rng_but_cost_not_constant(self):
        for row in self.outcomes:
            row['total_cycles'] = 100
        with patch('random.Random', side_effect=AssertionError('RNG')):
            result, exact = self.control(), self.exact()
        self.assertEqual(result['risk_component']['mean_risk'], 0.)
        self.assertEqual(result['gradient_maps']['risk'], dict.fromkeys(self.scores, 0.))
        self.assertTrue(any(g != 0 for g in result['gradient_maps']['cost'].values()))
        self.assertEqual(result['joint_scalar'], exact['joint_scalar'])

    def test_exact_gradient_finite_difference_and_no_rng_io(self):
        with patch('random.Random', side_effect=AssertionError('RNG')), \
                patch('builtins.open', side_effect=AssertionError('IO')), \
                patch('socket.socket', side_effect=AssertionError('NETWORK')):
            result = self.exact()
            for uid in self.scores:
                original = self.scores[uid]
                self.scores[uid] = original + 1e-5
                hi = self.exact()['joint_scalar']
                self.scores[uid] = original - 1e-5
                lo = self.exact()['joint_scalar']
                self.scores[uid] = original
                self.assertAlmostEqual(result['joint_score_gradient'][uid], (hi-lo)/2e-5, delta=2e-10)

    def test_control_validates_fixed_budget_and_orders_cost_before_risk(self):
        expected = self.exact()['risk_component']
        expected = dict(expected, exact_enumeration=False)
        events = []
        original = caller.complete_cost.evaluate
        def cost(*args, **kwargs):
            events.append('cost')
            return original(*args, **kwargs)
        def risk(*args, **kwargs):
            events.append('risk')
            self.assertEqual(kwargs['pilot_samples'], 32)
            self.assertEqual(kwargs['samples'], 480)
            return expected
        with patch.object(caller.complete_cost, 'evaluate', side_effect=cost), \
                patch.object(caller.risk_control, 'estimate', side_effect=risk):
            self.control(pilot_samples=32, samples=480)
        self.assertEqual(events, ['cost', 'risk'])

    def test_exact_size_limit_and_one_circuit(self):
        for i in range(6, 8):
            row, outcome = dict(self.features[0]), dict(self.outcomes[0])
            row['action_uid'] = outcome['action_uid'] = f'u{i:03d}'
            self.features.append(row)
            self.outcomes.append(outcome)
            self.scores[f'u{i:03d}'] = 0.
        with patch('random.Random', side_effect=AssertionError('RNG')):
            with self.assertRaisesRegex(ValueError, 'EXACT_N_BOUND'):
                self.exact()
            self.features[-1]['circuit'] = 'second_circuit'
            with self.assertRaisesRegex(ValueError, 'ONE_CIRCUIT'):
                self.exact()


if __name__ == '__main__':
    unittest.main()
