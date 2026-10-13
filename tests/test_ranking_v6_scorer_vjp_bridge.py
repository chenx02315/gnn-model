"""Local refusal/schema evidence only: NOT_REAL_VJP_PROOF (no torch run)."""
import copy
import unittest

from src.models import ranking_v6_scorer_vjp_bridge as bridge


class NoAPI:
    def __getattr__(self, name):
        raise AssertionError('API called: ' + name)


def inputs():
    return [[.1] * 7, [.2] * 7], ['synthetic_a', 'synthetic_b'], {
        'risk': {'synthetic_a': .1, 'synthetic_b': -.1},
        'cost': {'synthetic_a': -.2, 'synthetic_b': .2}}


class ScorerBridgeTests(unittest.TestCase):
    def test_scope_gate_before_any_api(self):
        for scope in (None, 'TRAIN', True, bridge.SCOPE + ' '):
            with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, 'SCOPE'):
                bridge.tensor_scores_to_parameter_gradients(NoAPI(), NoAPI(), *inputs(), scope=scope)

    def test_sorted_uid_schema_and_gradient_exact_joins(self):
        for kind in ('duplicate', 'reverse', 'length', 'extra-map', 'missing-gradient', 'uid-string'):
            features, uids, maps = inputs()
            if kind == 'duplicate': uids[1] = uids[0]
            elif kind == 'reverse': uids.reverse()
            elif kind == 'length': features.pop()
            elif kind == 'extra-map': maps['labels'] = {}
            elif kind == 'missing-gradient': maps['risk'].pop(uids[0])
            else: uids[0] = 'x' * 129
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                bridge.tensor_scores_to_parameter_gradients(NoAPI(), NoAPI(), features, uids, maps, scope=bridge.SCOPE)

    def test_feature_gradient_nonfinite_boolean_bounds(self):
        for value in (True, float('nan'), float('inf'), 2.1, '1', 10**1000):
            features, uids, maps = inputs()
            features[0][0] = value
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError):
                bridge.tensor_scores_to_parameter_gradients(NoAPI(), NoAPI(), features, uids, maps, scope=bridge.SCOPE)
        for value in (True, float('nan'), float('inf'), 20.1, '1'):
            features, uids, maps = inputs()
            maps['cost'][uids[0]] = value
            with self.assertRaises(ValueError):
                bridge.tensor_scores_to_parameter_gradients(NoAPI(), NoAPI(), features, uids, maps, scope=bridge.SCOPE)

    def test_row_column_and_action_count_bounds(self):
        for features, uids, maps in [([], [], {'risk': {}, 'cost': {}}),
                                    ([[0.] * 6], ['a'], {'risk': {'a': 0.}, 'cost': {'a': 0.}}),
                                    ([[0.] * 7] * 1025, [str(i) for i in range(1025)], {'risk': {}, 'cost': {}})]:
            with self.assertRaises(ValueError):
                bridge.tensor_scores_to_parameter_gradients(NoAPI(), NoAPI(), features, uids, maps, scope=bridge.SCOPE)

    def test_valid_plain_inputs_not_mutated(self):
        values = inputs()
        snapshot = copy.deepcopy(values)
        bridge._inputs(*values)
        self.assertEqual(values, snapshot)

    def test_parameter_count_rejection_before_tensor_creation(self):
        class TooLarge:
            def numel(self):
                return 4097
        class Model:
            def __init__(self, parameters):
                self.values = parameters
            def parameters(self):
                return iter(self.values)
        for parameters in ([], [TooLarge()]):
            with self.assertRaisesRegex(ValueError, 'PARAMETER_COUNT'):
                bridge.tensor_scores_to_parameter_gradients(NoAPI(), Model(parameters), *inputs(), scope=bridge.SCOPE)

    def test_active_coordinate_is_nonzero_and_deterministic(self):
        index, norm = bridge._active_coordinate((0., -.3, .3, .01))
        self.assertEqual(index, 1)
        self.assertGreater(norm, .3)
        for gradient in ((), (0., 0.), (1e-14,), (float('nan'),), (float('inf'),)):
            with self.subTest(gradient=gradient), self.assertRaises(ValueError):
                bridge._active_coordinate(gradient)

    @unittest.skip('NOT_REAL_VJP_PROOF: local environment has no authorized torch execution; B runner owns proof')
    def test_actual_factory_vjp_owned_by_authorized_runner(self):
        pass


if __name__ == '__main__':
    unittest.main()
