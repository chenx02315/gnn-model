"""Only supplied synthetic interval fixtures; no sampling or training."""
import ast
import copy
import inspect
import unittest

from src.models import ranking_v6_interval_risk_gate as gate


def metric(risk=.1, cost=.6, risk_radius=.01, cost_radius=.01):
    return dict(risk_mean=risk, risk_radius=risk_radius,
                cost_mean=cost, cost_radius=cost_radius)


class IntervalRiskGateTests(unittest.TestCase):
    def test_cheap_point_estimate_with_cost_overlap_is_not_certified(self):
        result = gate.select_certified_update({'a': metric(cost=.5, cost_radius=.1)},
            {'cheap': {'a': metric(cost=.35, cost_radius=.1)}}, {'a': .3}, .1)
        self.assertEqual(result['decision'], 'NO_CERTIFIED_UPDATE')
        self.assertIsNone(result['selected_id'])

    def test_all_miss_and_macro_risk_offset_cannot_pass(self):
        current = {'a': metric(), 'b': metric()}
        candidates = {'all-miss': {'a': metric(1., 0.), 'b': metric(1., 0.)},
                      'offset': {'a': metric(.4, .1), 'b': metric(0., .1)}}
        result = gate.select_certified_update(current, candidates, {'a': .3, 'b': .3}, .05)
        self.assertEqual(result['decision'], 'NO_CERTIFIED_UPDATE')
        self.assertFalse(result['candidate_intervals']['offset']['risk_certified'])

    def test_current_infeasible_and_current_risk_uncertainty(self):
        candidate = {'cheap': {'a': metric(cost=.1)}}
        for risk, expected in [(.4, 'BLOCKED_INFEASIBLE_CURRENT'),
                               (.3, 'INCONCLUSIVE_CURRENT_RISK')]:
            result = gate.select_certified_update({'a': metric(risk)}, candidate, {'a': .3}, .05)
            self.assertEqual(result['decision'], expected)
            self.assertIsNone(result['selected_id'])

    def test_every_radius_precision_gate_has_precedence(self):
        for where in ('current', 'candidate'):
            for field in ('risk_radius', 'cost_radius'):
                current, candidates = {'a': metric(.8)}, {'bad': {'a': metric(1., .1)}}
                (current if where == 'current' else candidates['bad'])['a'][field] = .06
                with self.subTest(where=where, field=field):
                    result = gate.select_certified_update(current, candidates, {'a': .3}, .05)
                    self.assertEqual(result['decision'], 'INCONCLUSIVE_PRECISION')
                    self.assertIsNone(result['selected_id'])

    def test_equal_family_macro_tie_determinism_and_no_mutation(self):
        current = {'b': metric(cost=.8), 'a': metric(cost=.8)}
        candidates = {'z': {'a': metric(cost=.2), 'b': metric(cost=.4)},
                      'a': {'a': metric(cost=.4), 'b': metric(cost=.2)}}
        caps = {'a': .3, 'b': .3}
        before = copy.deepcopy((current, candidates, caps))
        result = gate.select_certified_update(current, candidates, caps, .05)
        self.assertEqual(result['selected_id'], 'a')
        self.assertEqual(result['decision'], 'CERTIFIED_SYNTHETIC_UPDATE')
        self.assertEqual(result, gate.select_certified_update(current,
            dict(reversed(list(candidates.items()))), caps, .05))
        self.assertEqual((current, candidates, caps), before)
        self.assertAlmostEqual(result['candidate_intervals']['a']['macro_normalized_cost_upper'], .31)
        result['current_intervals']['families']['a']['risk_lower'] = 9
        self.assertEqual((current, candidates, caps), before)

    def test_clipping_strict_equality_and_empty_candidates(self):
        result = gate.select_certified_update({'a': metric(0., 1., .1, .1)},
            {'equal': {'a': metric(0., .8, .1, .1)}}, {'a': .1}, .1)
        self.assertEqual(result['decision'], 'NO_CERTIFIED_UPDATE')
        family = result['current_intervals']['families']['a']
        self.assertEqual(family['risk_lower'], 0)
        self.assertEqual(family['normalized_cost_upper'], 1)
        self.assertEqual(gate.select_certified_update({'a': metric()}, {}, {'a': .3}, .05)
                         ['decision'], 'NO_CERTIFIED_UPDATE')

    def test_all_metric_bounds_finite_and_bool_rejections(self):
        for field in gate.METRICS:
            for bad in (True, False, float('nan'), float('inf'), -float('inf'), -.01, 1.01, '0', 10**400):
                for where in ('current', 'candidate'):
                    current, candidates = {'a': metric()}, {'c': {'a': metric()}}
                    (current if where == 'current' else candidates['c'])['a'][field] = bad
                    with self.subTest(field=field, bad=str(bad), where=where), self.assertRaises(ValueError):
                        gate.select_certified_update(current, candidates, {'a': .3}, .05)

    def test_schema_join_count_and_cap_rejections(self):
        bad_states = ({}, {str(i): metric() for i in range(7)}, {'': metric()},
                      {1: metric()}, {'a': dict(metric(), extra=1)}, {'a': {'risk_mean': .1}})
        for state in bad_states:
            with self.subTest(state=state), self.assertRaises(ValueError):
                gate.select_certified_update(state, {}, {'a': .3}, .05)
        for candidates, caps in [({'c': {'b': metric()}}, {'a': .3}), ({}, {'b': .3}),
                                 ({'': {'a': metric()}}, {'a': .3}), ({1: {'a': metric()}}, {'a': .3}),
                                 ({str(i): {'a': metric()} for i in range(9)}, {'a': .3}),
                                 ([], {'a': .3}), ({}, [])]:
            with self.subTest(candidates=candidates, caps=caps), self.assertRaises(ValueError):
                gate.select_certified_update({'a': metric()}, candidates, caps, .05)
        for bad in (True, float('nan'), float('inf'), -.1, 1.1):
            with self.assertRaises(ValueError):
                gate.select_certified_update({'a': metric()}, {}, {'a': bad}, .05)
        for bad in (True, 0., -.1, 1.1, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                gate.select_certified_update({'a': metric()}, {}, {'a': .3}, bad)

    def test_no_io_and_explicit_non_release_claims(self):
        tree = ast.parse(inspect.getsource(gate))
        imports = [node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)]
        self.assertEqual(imports, ['math'])
        self.assertFalse(any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree)))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id in {'open', 'eval', 'exec', '__import__'}
                             for node in ast.walk(tree)))
        result = gate.select_certified_update({'a': metric()}, {}, {'a': .3}, .05)
        self.assertEqual(result['status'], 'SYNTHETIC_INTERVAL_GATE_NOT_TRAIN_RELEASE')
        for flag in ('update_applied', 'confidence_bound_claim', 'sampling_coverage_claim',
                     'global_guarantee_claim', 'training_release_authorized'):
            self.assertFalse(result[flag])


if __name__ == '__main__':
    unittest.main()
