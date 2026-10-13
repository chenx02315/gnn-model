"""Synthetic family fixtures only; no real scales, caps or candidate labels."""
import copy
import unittest

from src.models import ranking_v6_risk_macro_reference as reference


def metric(risk=.1, cost=10., scale=10.):
    return {'risk': risk, 'raw_cost': cost, 'cost_scale': scale}


class RiskMacroTests(unittest.TestCase):
    def test_equal_family_weights_separate_raw_scales_and_gradients(self):
        families = {'small': dict(metric(.2, 100., 100.), risk_gradient={'p': 2., 'q': -1.},
                                  cost_gradient={'p': 100., 'q': 50.}),
                    'large': dict(metric(.4, 1000., 500.), risk_gradient={'p': 4., 'q': 3.},
                                  cost_gradient={'p': 1000., 'q': -500.})}
        result = reference.aggregate_families(families)
        self.assertAlmostEqual(result['macro_risk'], .3)
        self.assertEqual(result['macro_normalized_cost'], 1.5)
        self.assertEqual(result['macro_risk_gradient'], {'p': 3., 'q': 1.})
        self.assertEqual(result['macro_normalized_cost_gradient'], {'p': 1.5, 'q': -.25})
        self.assertEqual(result['family_weight'], .5)
        families['small']['candidate_count'] = 100
        with self.assertRaisesRegex(ValueError, 'FAMILY_SCHEMA'):
            reference.aggregate_families(families)

    def test_individual_caps_reject_macro_offset_and_cheap_allmiss(self):
        current = {'a': metric(.2), 'b': metric(.2)}
        candidates = {'macro-offset': {'a': metric(.4, 1.), 'b': metric(0., 1.)},
                      'cheap-all-miss': {'a': metric(1., .001), 'b': metric(1., .001)}}
        result = reference.select_feasible_update(current, candidates, {'a': .3, 'b': .3})
        self.assertEqual(result['decision'], 'NO_ACCEPTABLE_UPDATE')
        self.assertIs(result['selected_state'], current)

    def test_infeasible_current_blocks_even_feasible_cheaper_candidate(self):
        current = {'a': metric(.4)}
        result = reference.select_feasible_update(current, {'repair': {'a': metric(.1, 1.)}}, {'a': .3})
        self.assertEqual(result['decision'], 'BLOCKED_INFEASIBLE_CURRENT')
        self.assertIsNone(result['selected_id'])
        self.assertIs(result['selected_state'], current)

    def test_strict_improvement_tie_and_determinism(self):
        current = {'a': metric(.1)}
        candidates = {'z': {'a': metric(.1, 5.)}, 'a': {'a': metric(.2, 5.)},
                      'same': {'a': metric(0., 10.)}}
        original = copy.deepcopy((current, candidates))
        result = reference.select_feasible_update(current, candidates, {'a': .2})
        reversed_result = reference.select_feasible_update(current, dict(reversed(list(candidates.items()))), {'a': .2})
        self.assertEqual(result, reversed_result)
        self.assertEqual(result['selected_id'], 'a')
        self.assertEqual((current, candidates), original)
        noop = reference.select_feasible_update(current, {'same': candidates['same']}, {'a': .2})
        self.assertEqual(noop['decision'], 'NO_ACCEPTABLE_UPDATE')
        self.assertFalse(result['update_applied'])
        self.assertFalse(result['global_guarantee_claim'])
        self.assertFalse(result['confidence_bound_claim'])

    def test_metric_nonfinite_bool_and_schema_rejections(self):
        for field, bad in [('risk', True), ('risk', float('nan')), ('risk', 1.1),
                           ('raw_cost', True), ('raw_cost', 0.), ('raw_cost', 1e10+1),
                           ('raw_cost', float('inf')), ('cost_scale', True), ('cost_scale', 0.),
                           ('cost_scale', 1e10+1), ('cost_scale', float('nan'))]:
            current = {'a': metric()}
            current['a'][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                reference.select_feasible_update(current, {}, {'a': .3})
        for state in ({}, {str(i): metric() for i in range(7)}, {'a': dict(metric(), extra=1)}):
            with self.assertRaises(ValueError):
                reference.select_feasible_update(state, {}, {'a': .3})

    def test_exact_joins_scale_and_cap_rejections(self):
        current = {'a': metric()}
        for candidates, caps in [({'c': {'b': metric()}}, {'a': .3}),
                                  ({'c': {'a': metric(scale=20.)}}, {'a': .3}),
                                  ({}, {'b': .3}), ({}, {'a': True}),
                                  ({}, {'a': float('nan')}), ({}, {'a': -1.}),
                                  ({}, {'a': 1.1}), ({'': {'a': metric()}}, {'a': .3})]:
            with self.assertRaises(ValueError):
                reference.select_feasible_update(current, candidates, caps)

    def test_gradient_param_join_bound_and_types(self):
        family = dict(metric(), risk_gradient={'p': 1.}, cost_gradient={'p': 2.})
        for kind in ('missing', 'extra', 'different-family', 'bool', 'nan', 'bound', 'count'):
            families = {'a': copy.deepcopy(family), 'b': copy.deepcopy(family)}
            if kind == 'missing':
                families['a'].pop('cost_gradient')
            elif kind == 'extra':
                families['a']['cost_gradient']['q'] = 1.
            elif kind == 'different-family':
                families['b']['risk_gradient'] = families['b']['cost_gradient'] = {'q': 1.}
            elif kind == 'count':
                families['a']['risk_gradient'] = families['a']['cost_gradient'] = {str(i): 1. for i in range(129)}
            else:
                families['a']['risk_gradient']['p'] = {'bool': True, 'nan': float('nan'), 'bound': 1e10+1}[kind]
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                reference.aggregate_families(families)


if __name__ == '__main__':
    unittest.main()
