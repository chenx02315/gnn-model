"""E10 unit checks use <=8 samples per phase, never the formal entry."""
import copy
import inspect
import json
import math
import random
import unittest
from unittest.mock import patch

from src.models import ranking_v6_joint_score_update_reference as joint


class JointScoreUpdateTests(unittest.TestCase):
    def tiny(self, **kwargs):
        return joint._run_fixed_fixtures(**dict(baseline_samples=3, gradient_samples=8, **kwargs))

    def fixture(self):
        case, values, charges = joint.FIXTURES[0]
        scores = {str(i): s for i, s in enumerate(values)}
        costs = {str(i): c for i, c in enumerate(charges)}
        return case, scores, costs, joint._preflight(scores, costs)

    def frozen(self):
        case, scores, costs, prepared = self.fixture()
        return joint._freeze_proposal(case, 11, scores, costs, prepared, 3, 8)

    def oracle(self, risk, normalized_cost):
        return dict(probability_mass=1., expected_miss_probability=risk,
                    expected_truncated_static_cost=normalized_cost * 27.,
                    miss_score_gradient={str(i): 0. for i in range(6)},
                    cost_score_gradient={str(i): 0. for i in range(6)})

    def proposal_record(self):
        record = self.frozen()
        payload = record['payload']
        # A constructed pilot selection is enough for verifier branch testing.
        if payload['selected_candidate'] is None:
            payload['selected_candidate'] = dict(step=.1, direction=[0., 0., 0., 0., 0., .1])
            payload['proposed_scores'] = dict(payload['scores'])
            payload['proposed_scores']['5'] += .01
            payload['proposed_score_state_sha256'] = joint._hash(payload['proposed_scores'])
            payload['proposal_status'] = 'ONE_PROPOSAL'
            record['payload_sha256'] = joint._hash(payload)
        return record

    def test_fixed_contract_fresh_pins_and_compact_reproducibility(self):
        result = self.tiny()
        self.assertEqual(result, self.tiny())
        self.assertEqual(inspect.signature(joint.run_joint_score_update).parameters, {})
        self.assertEqual(result['config']['formal_nominal_pilot_work'], 9216)
        self.assertEqual(result['config']['nominal_pilot_work'], 8 * 6 * 3 * 11)
        self.assertLessEqual(result['exact_oracle_calls'], 16)
        self.assertEqual(len(result['per_case_seed']), 8)
        self.assertLess(len(json.dumps(result, allow_nan=False)), 262144)
        for key in ('train_release', 'actual_parameter_updates', 'trainer_implemented',
                    'optimizer_implemented', 'real_data_access', 'oracle_used_for_selection',
                    'adaptive_sampling', 'trajectories_retained'):
            self.assertFalse(result[key])
        for summary in result['per_case_seed']:
            payload = summary['pilot_freeze_payload']
            self.assertEqual(summary['pilot_freeze_sha256'], joint._hash(payload))
            self.assertEqual(payload['protocol'], result['config'])
            self.assertEqual(payload['protocol']['score_absolute_bound'], 20.)
            self.assertEqual(payload['protocol']['max_coordinate_update'], .2)
            self.assertEqual(payload['seed_case_id'], 'e10-fixed-' + payload['case_id'])
            self.assertNotEqual(payload['derived_seed_sha256']['baseline'],
                                payload['derived_seed_sha256']['gradient'])
            self.assertEqual(len(payload['candidates']), 15)
            self.assertEqual(sorted(c['pilot_rank'] for c in payload['candidates']), list(range(1, 16)))
            self.assertEqual(set(payload['scores']), set(payload['costs']))
            self.assertEqual(set(summary['committed_scores']), set(payload['scores']))
            self.assertEqual(summary['committed_score_state_sha256'], joint._hash(summary['committed_scores']))
            self.assertFalse(summary['fallback_attempted'])
            self.assertTrue(all(abs(m - 1.) <= 1e-12 for m in summary['oracle_probability_mass'].values()))
            if summary['accepted']:
                self.assertLessEqual(summary['committed_risk_delta'], 1e-12)
                self.assertLessEqual(summary['committed_normalized_cost_delta'], -1e-8)

    def test_pilot_only_selection_grid_and_individual_directions(self):
        with patch.object(joint.full_oracle, 'enumerate_exact_gradient', side_effect=AssertionError('oracle')):
            dr, dc, candidates, selected = joint._select_candidate([2., -1.], [1., -3.])
        self.assertEqual(dr, [-2 / 3, 1 / 3])
        self.assertEqual(dc, [-.25, .75])
        feasible = [c for c in candidates if c['feasible']]
        self.assertEqual(selected, min(feasible, key=lambda c: (
            c['predicted_normalized_cost_delta'], c['mixture_lambda'], c['step'])))
        for candidate in candidates:
            self.assertAlmostEqual(sum(abs(d) for d in candidate['direction']), 1.)
            if candidate['feasible']:
                self.assertLessEqual(candidate['predicted_risk_delta'], candidate['predicted_risk_threshold'])
                self.assertLess(candidate['predicted_normalized_cost_delta'], 0.)
        self.assertLess(joint._dot([2., -1.], dr), 0.)
        self.assertLess(joint._dot([1., -3.], dc), 0.)
        # Exact tie between identical directions uses lambda first, then step.
        self.assertEqual(joint._select_candidate([1.], [1.])[3]['mixture_lambda'], 0.)
        self.assertEqual(joint._select_candidate([1.], [1.])[3]['step'], .2)

    def test_zero_opposed_and_nonfinite_fail_closed(self):
        for gr, gc in (([0., 0.], [1., -1.]), ([1., -1.], [0., 0.]), ([1.], [-1.])):
            self.assertIsNone(joint._select_candidate(gr, gc)[3])
        with self.assertRaisesRegex(ValueError, 'NONFINITE_GRADIENT'):
            joint._select_candidate([float('nan')], [1.])
        with patch.object(joint, '_select_candidate', return_value=(
                [0.] * 6, [0.] * 6, [], None)):
            record = self.frozen()
        with patch.object(joint.full_oracle, 'enumerate_exact_gradient', return_value=self.oracle(.4, .4)) as oracle:
            summary = joint._verify_frozen(record)
        self.assertEqual(oracle.call_count, 1)
        self.assertEqual(summary['proposal_status'], 'NO_PROPOSAL')
        self.assertFalse(summary['accepted'])
        self.assertEqual(summary['committed_scores'], record['payload']['scores'])

    def test_all_freezes_before_any_oracle_and_only_selected_map(self):
        events, records = [], []
        real_freeze = joint._freeze_proposal
        real_oracle = joint.full_oracle.enumerate_exact_gradient
        def freeze(*args):
            record = real_freeze(*args)
            events.append('freeze')
            records.append(copy.deepcopy(record))
            return record
        def oracle(scores, positives, costs, *, k):
            self.assertEqual(events.count('freeze'), 8)
            self.assertTrue(any(scores == r['payload']['scores'] or
                                scores == r['payload']['proposed_scores'] for r in records))
            events.append('oracle')
            return real_oracle(scores, positives, costs, k=k)
        with patch.object(joint, '_freeze_proposal', side_effect=freeze), \
                patch.object(joint.full_oracle, 'enumerate_exact_gradient', side_effect=oracle):
            result = self.tiny()
        self.assertEqual(events[:8], ['freeze'] * 8)
        self.assertEqual(events.count('oracle'), 8 + result['proposal_count'])

    def test_independent_frozen_baseline_matches_raw_components(self):
        case, scores, costs, prepared = self.fixture()
        record = self.frozen()
        payload = record['payload']
        baseline_rng = random.Random(int(payload['derived_seed_sha256']['baseline'], 16))
        baseline = [joint.control._components(*prepared[1:], 3, rng=baseline_rng) for _ in range(3)]
        br = math.fsum(p[1] for p in baseline) / 3
        bc = math.fsum(p[2] for p in baseline) / 3
        self.assertEqual(payload['baseline_risk'], br)
        self.assertEqual(payload['baseline_static_cost'], bc)
        gradient_rng = random.Random(int(payload['derived_seed_sha256']['gradient'], 16))
        gradient = [joint.control._controlled(
            joint.control._components(*prepared[1:], 3, rng=gradient_rng), br, bc) for _ in range(8)]
        for i, uid in enumerate(prepared[0]):
            self.assertEqual(payload['pilot_gradient_risk'][uid], math.fsum(p[3][i] for p in gradient) / 8)
            self.assertEqual(payload['pilot_gradient_normalized_cost'][uid],
                             math.fsum(p[4][i] / 27 for p in gradient) / 8)
        self.assertEqual(scores, {str(i): s for i, s in enumerate(joint.FIXTURES[0][1])})
        selected = payload['selected_candidate']
        if selected:
            for i, uid in enumerate(prepared[0]):
                self.assertEqual(payload['proposed_scores'][uid], scores[uid] + selected['step'] * selected['direction'][i])

    def test_finite_verification_not_derivative_and_no_fallback(self):
        record = self.proposal_record()
        for risk_after, cost_after, accepted in ((.399, .39, True), (.401, .39, False),
                                                (.399, .4, False), (.399, .399999999, False)):
            with self.subTest(risk=risk_after, cost=cost_after), patch.object(
                    joint.full_oracle, 'enumerate_exact_gradient', side_effect=[
                        self.oracle(.4, .4), self.oracle(risk_after, cost_after)]) as oracle:
                summary = joint._verify_frozen(record)
            self.assertEqual(oracle.call_count, 2)
            self.assertEqual(summary['accepted'], accepted)
            self.assertEqual(summary['proposed_risk_after'], risk_after)
            self.assertAlmostEqual(summary['proposed_normalized_cost_after'], cost_after)
            expected = record['payload']['proposed_scores' if accepted else 'scores']
            self.assertEqual(summary['committed_scores'], expected)
            self.assertFalse(summary['fallback_attempted'])
            if not accepted:
                self.assertEqual(summary['committed_risk_after'], .4)
                self.assertEqual(summary['committed_risk_delta'], 0.)

    def test_numerical_and_hash_failure_never_commit(self):
        record = self.proposal_record()
        bad = self.oracle(.3, .3)
        bad['cost_score_gradient']['0'] = float('nan')
        for oracle_result in (bad, dict(self.oracle(.3, .3), probability_mass=.9)):
            with patch.object(joint.full_oracle, 'enumerate_exact_gradient', side_effect=[
                    self.oracle(.4, .4), oracle_result]):
                summary = joint._verify_frozen(record)
            self.assertTrue(summary['numerical_guard_failed'])
            self.assertFalse(summary['accepted'])
            self.assertEqual(summary['committed_scores'], record['payload']['scores'])
        damaged = copy.deepcopy(record)
        damaged['payload']['scores']['0'] += .1
        with patch.object(joint.full_oracle, 'enumerate_exact_gradient', side_effect=AssertionError('oracle')):
            summary = joint._verify_frozen(damaged)
        self.assertTrue(summary['numerical_guard_failed'])
        self.assertEqual(summary['exact_oracle_calls'], 0)

    def test_threshold_boundary_uses_recorded_delta_once(self):
        record = self.proposal_record()
        # Binary-exact baseline risk zero tests +/- immediate threshold neighbors.
        for risk_after in (math.nextafter(1e-12, 0.), 1e-12, math.nextafter(1e-12, math.inf)):
            for cost_after in (.4 - 1e-8, math.nextafter(.4 - 1e-8, 0.),
                               math.nextafter(.4 - 1e-8, math.inf)):
                with patch.object(joint.full_oracle, 'enumerate_exact_gradient', side_effect=[
                        self.oracle(0., .4), self.oracle(risk_after, cost_after)]):
                    summary = joint._verify_frozen(record)
                expected = (summary['proposed_risk_delta'] <= 1e-12 and
                            summary['proposed_normalized_cost_delta'] <= -1e-8)
                self.assertEqual(summary['accepted'], expected)

    def test_oracle_inputs_cannot_mutate_frozen_score_state(self):
        record = self.proposal_record()
        original = copy.deepcopy(record)
        def oracle(scores, positives, costs, *, k):
            scores['0'] = 19.
            costs['0'] = 999.
            return self.oracle(.4, .4)
        with patch.object(joint.full_oracle, 'enumerate_exact_gradient', side_effect=oracle):
            summary = joint._verify_frozen(record)
        self.assertEqual(record, original)
        self.assertEqual(summary['committed_scores'], original['payload']['scores'])

    def test_preflight_config_and_raw_epsilon_domain_before_rng(self):
        with patch.object(joint.random, 'Random', side_effect=AssertionError('RNG')):
            for count in (0, True, 33, 1.5, float('inf')):
                with self.assertRaisesRegex(ValueError, 'PILOT_SAMPLES'):
                    joint._run_fixed_fixtures(baseline_samples=count, gradient_samples=2)
            fixture_id, scores, _ = joint.FIXTURES[0]
            for costs, code in (((0.,) * 6, 'ZERO_COST_FIXTURE'),
                                ((5e-324,) + (1.,) * 5, 'BELOW_SUPPORTED_MIN'),
                                ((1e-9,) + (1.,) * 5, 'BELOW_SUPPORTED_MIN'),
                                ((0.,) + (1.,) * 5, 'NONPOSITIVE_COST_FIXTURE')):
                with patch.object(joint, 'FIXTURES', ((fixture_id, scores, costs),)):
                    with self.assertRaisesRegex(ValueError, code):
                        self.tiny()

    def test_status_aggregation_and_false_main_claims(self):
        for count, failure, expected in ((8, False, 'PASS_FIXED_SCORE_SPACE_JOINT_UPDATES_ONLY'),
                                        (1, False, 'PARTIAL_SAFE_REJECTION'),
                                        (0, False, 'NO_ACCEPTED_UPDATE'), (8, True, 'FAIL_NUMERICAL')):
            summaries = [dict(accepted=i < count, numerical_guard_failed=failure and i == 0,
                              selected_candidate={}, exact_oracle_calls=2,
                              committed_risk_delta=-.01, committed_normalized_cost_delta=-.01)
                         for i in range(8)]
            with patch.object(joint, '_verify_frozen', side_effect=summaries):
                result = self.tiny()
            self.assertEqual(result['status'], expected)
            self.assertFalse(result['train_release'])
            self.assertFalse(result['actual_parameter_updates'])


if __name__ == '__main__':
    unittest.main()
