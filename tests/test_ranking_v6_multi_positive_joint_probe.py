"""Local implementation checks, never a replacement for the real Torch probe."""
import ast
import inspect
import math
import unittest
from src.models import ranking_v6_multi_positive_joint_probe as probe


class NoTorch:
    def __getattr__(self, key):
        raise AssertionError('unexpected Torch access '+key)


class MultiJointProbeTests(unittest.TestCase):
    def test_scope_precedes_any_torch_api(self):
        for scope in (None, True, 'TRAIN', [], probe.SCOPE+' '):
            with self.assertRaisesRegex(ValueError, 'SCOPE'):
                probe.verify(NoTorch(), scope)

    def test_threads_gate_before_model_and_rng(self):
        class BadThreads(NoTorch):
            def get_num_threads(self):
                return 4
        with self.assertRaisesRegex(ValueError, 'THREADS'):
            probe.verify(BadThreads(), probe.SCOPE)

    def test_plain_top_level_and_no_optimizer(self):
        source = inspect.getsource(probe)
        tree = ast.parse(source)
        imports = [alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names]
        self.assertEqual(imports, ['hashlib', 'json', 'math'])
        self.assertNotIn('torch.optim', source)
        self.assertNotIn('.backward(', source)
        self.assertEqual(source.count('caller.evaluate_control('), 1)
        self.assertIn("mc_finite_difference_is_frozen_linear_surrogate_only", source)

    def test_linear_component_combination_all_coordinates(self):
        values = probe._combine({'risk_parameter_gradient': tuple([.1]*1345),
                                 'cost_parameter_gradient': tuple([-.2]*1345)})
        self.assertEqual(len(values['joint']), 1345)
        self.assertTrue(all(v == -.15 or math.isclose(v, -.15) for v in values['joint']))
        with self.assertRaisesRegex(ValueError, 'PARAMETER_JOIN'):
            probe._combine({'risk_parameter_gradient': [1], 'cost_parameter_gradient': [2]})

    def test_predeclared_fd_rule_and_degenerate_rejection(self):
        self.assertEqual(probe._select([-.1, .3, -.2])[0], 1)
        with self.assertRaisesRegex(ValueError, 'DEGENERATE'):
            probe._select([0., 0.])
        with self.assertRaisesRegex(ValueError, 'DEGENERATE'):
            probe._select([1e-8, -2e-8])
        with self.assertRaisesRegex(ValueError, 'FINITE_DIFFERENCE'):
            probe._check(1., 2.)
        self.assertTrue(probe._check(.01, .01+1e-10)['pass'])
        self.assertEqual((probe.EPSILON, probe.ATOL, probe.RTOL), (1e-6, 1e-8, 1e-5))


if __name__ == '__main__':
    unittest.main()
