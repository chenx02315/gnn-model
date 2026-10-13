"""Pure shared-parameter synthetic fixture checks; no formal gate execution."""
import copy
import unittest
from unittest.mock import patch

from src.models import ranking_v6_linear_update_reference as linear


def fixture():
    return {'small': {'features': {'a': {'w': -1., 'b': .2}, 'hit': {'w': 1., 'b': -.4}},
                      'positives': {'hit'}, 'costs': {'a': 3., 'hit': 1.}, 'cost_scale': 3.},
            'large': {'features': {'x': {'w': .4, 'b': -1.}, 'yes': {'w': -.8, 'b': 1.}},
                      'positives': {'yes'}, 'costs': {'x': 100., 'yes': 20.}, 'cost_scale': 100.}}


class LinearUpdateTests(unittest.TestCase):
    def test_shared_parameter_central_differences(self):
        families, parameters = fixture(), {'w': .3, 'b': -.2}
        result = linear.evaluate_linear(families, parameters, 1)
        for parameter in parameters:
            plus, minus = parameters.copy(), parameters.copy()
            plus[parameter] += 1e-5
            minus[parameter] -= 1e-5
            p = linear.evaluate_linear(families, plus, 1)['macro_metrics']
            m = linear.evaluate_linear(families, minus, 1)['macro_metrics']
            for objective, gradient in [('macro_risk', 'macro_risk_gradient'),
                                        ('macro_normalized_cost', 'macro_normalized_cost_gradient')]:
                self.assertAlmostEqual(result['macro_metrics'][gradient][parameter],
                                       (p[objective]-m[objective])/2e-5, delta=1e-9)

    def test_family_equal_weights_independent_scales(self):
        result = linear.evaluate_linear(fixture(), {'w': 0., 'b': 0.}, 1)
        small, large = result['family_metrics']['small'], result['family_metrics']['large']
        self.assertEqual(small['raw_cost'], 2.)
        self.assertEqual(large['raw_cost'], 60.)
        self.assertAlmostEqual(result['macro_metrics']['macro_normalized_cost'], (2./3.+.6)/2)
        for p in ('w', 'b'):
            expected = (small['cost_gradient'][p]/3.+large['cost_gradient'][p]/100.)/2
            self.assertAlmostEqual(result['macro_metrics']['macro_normalized_cost_gradient'][p], expected)

    def test_risk_cost_conflict_not_automatically_selected(self):
        family = {'f': {'features': {'cheap': {'w': -1.}, 'hit': {'w': 1.}}, 'positives': {'hit'},
                        'costs': {'cheap': 1., 'hit': 10.}, 'cost_scale': 10.}}
        result = linear.propose_cost_steps(family, {'w': 0.}, 1, [.01, .1])
        current = result['current']['macro_metrics']
        self.assertLess(current['macro_risk_gradient']['w'], 0.)
        self.assertGreater(current['macro_normalized_cost_gradient']['w'], 0.)
        proposed = result['candidates']['step_1']['macro_metrics']
        self.assertGreater(proposed['macro_risk'], current['macro_risk'])
        self.assertLess(proposed['macro_normalized_cost'], current['macro_normalized_cost'])
        self.assertFalse(result['candidate_selected'])
        self.assertFalse(result['update_applied'])
        self.assertFalse(result['risk_guarantee_claim'])

    def test_repeat_determinism_preserves_inputs(self):
        families, parameters, steps = fixture(), {'w': .1, 'b': -.1}, [.01, .1]
        snapshot = copy.deepcopy((families, parameters, steps))
        a = linear.propose_cost_steps(families, parameters, 1, steps)
        b = linear.propose_cost_steps(dict(reversed(list(families.items()))), parameters, 1, steps)
        self.assertEqual(a, b)
        self.assertEqual((families, parameters, steps), snapshot)
        self.assertEqual(list(a['candidates']), ['step_0', 'step_1'])

    def test_all_family_bounds_before_exact_and_no_io(self):
        for kind in ('parameter', 'feature', 'cost', 'schema', 'join', 'positive', 'score', 'k'):
            families, parameters, k = fixture(), {'w': 0., 'b': 0.}, 1
            if kind == 'parameter': parameters['w'] = True
            elif kind == 'feature': families['large']['features']['yes']['w'] = float('nan')
            elif kind == 'cost': families['large']['costs']['yes'] = 0.
            elif kind == 'schema': families['large']['extra'] = 1
            elif kind == 'join': families['large']['features']['yes'].pop('b')
            elif kind == 'positive': families['large']['positives'] = ['yes', 'yes']
            elif kind == 'k': k = True
            else:
                parameters = {f'p{i}': 5. for i in range(8)}
                families = {'f': {'features': {'a': {p: 2. for p in parameters}},
                                  'positives': {'a'}, 'costs': {'a': 1.}, 'cost_scale': 1.}}
            with self.subTest(kind=kind), patch.object(linear, 'enumerate_exact_gradient', side_effect=AssertionError('compute')), \
                    patch('builtins.open', side_effect=AssertionError('I/O')), self.assertRaises(ValueError):
                linear.evaluate_linear(families, parameters, k)

    def test_step_bounds_before_compute_and_proposal_reject_not_clip(self):
        for steps in ([], [0.], [True], [float('nan')], [1.1], [.1, .1], [.2, .1], [.1]*5):
            with self.subTest(steps=steps), patch.object(linear, 'evaluate_linear', side_effect=AssertionError('compute')), \
                    self.assertRaises(ValueError):
                linear.propose_cost_steps(fixture(), {'w': 0., 'b': 0.}, 1, steps)
        family = {'f': {'features': {'a': {'w': -2.}, 'hit': {'w': 2.}}, 'positives': {'hit'},
                        'costs': {'a': 1., 'hit': 100.}, 'cost_scale': .001}}
        with self.assertRaisesRegex(ValueError, 'PARAMETER_BOUND'):
            linear.propose_cost_steps(family, {'w': 0.}, 1, [1.])

    def test_dimension_counts_numeric_bounds_and_cost_scales(self):
        families, parameters = fixture(), {'w': 0., 'b': 0.}
        cases = [(families, {}), (families, {str(i): 0. for i in range(9)}),
                 (families, {'w': 5.1, 'b': 0.}), (families, {'w': float('inf'), 'b': 0.}),
                 ({}, parameters), ({str(i): families['small'] for i in range(7)}, parameters)]
        for field, value in [('cost_scale', True), ('cost_scale', 0.), ('cost_scale', float('nan'))]:
            changed = copy.deepcopy(families)
            changed['large'][field] = value
            cases.append((changed, parameters))
        changed = copy.deepcopy(families)
        changed['large']['features']['yes']['w'] = 2.1
        cases.append((changed, parameters))
        changed = copy.deepcopy(families)
        changed['large']['features'] = {str(i): {'w': 0., 'b': 0.} for i in range(8)}
        changed['large']['costs'] = {str(i): 1. for i in range(8)}
        cases.append((changed, parameters))
        with patch.object(linear, 'enumerate_exact_gradient', side_effect=AssertionError('compute')):
            for family_case, parameter_case in cases:
                with self.subTest(parameter_case=parameter_case), self.assertRaises(ValueError):
                    linear.evaluate_linear(family_case, parameter_case, 1)

    def test_all_negative_oracle_mass_roundoff_adapter(self):
        family = {'f': {'features': {'0': {'w': 1.917633233107046},
                                    '1': {'w': -1.0796542224703654},
                                    '2': {'w': .6944044719294027}},
                        'positives': set(), 'costs': {'0': 1., '1': 1., '2': 1.}, 'cost_scale': 3.}}
        result = linear.evaluate_linear(family, {'w': 1.}, 3)
        self.assertEqual(result['family_metrics']['f']['risk'], 1.)
        self.assertAlmostEqual(result['family_metrics']['f']['raw_cost'], 3., delta=1e-14)
        self.assertAlmostEqual(result['macro_metrics']['macro_risk_gradient']['w'], 0., delta=1e-14)
        plus = linear.evaluate_linear(family, {'w': 1. + 1e-5}, 3)['macro_metrics']
        minus = linear.evaluate_linear(family, {'w': 1. - 1e-5}, 3)['macro_metrics']
        for objective, gradient in [('macro_risk', 'macro_risk_gradient'),
                                    ('macro_normalized_cost', 'macro_normalized_cost_gradient')]:
            self.assertAlmostEqual(result['macro_metrics'][gradient]['w'],
                                   (plus[objective] - minus[objective]) / 2e-5, delta=1e-9)


if __name__ == '__main__':
    unittest.main()
