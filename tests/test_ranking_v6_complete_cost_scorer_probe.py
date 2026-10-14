"""Local contract/objective tests only: NOT_REAL_PROOF (no local Torch run)."""
import ast
import contextlib
import copy
import inspect
import math
import unittest

from src.models import ranking_v6_complete_cost_scorer_probe as probe
from src.models.ranking_v6_complete_first_hit_reference import evaluate
from src.models.ranking_v6_first_hit_exact_gradient import enumerate_exact_gradient


class NoAPI:
    def __getattr__(self, name):
        raise AssertionError('Torch API called: ' + name)


class CompleteCostScorerProbeTests(unittest.TestCase):
    def test_scope_gate_before_any_torch_api(self):
        for scope in (None, True, 1, 'TRAIN', probe.SCOPE + ' ', []):
            with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, 'SCOPE'):
                probe.verify(NoAPI(), scope)

    def test_stdlib_only_top_level_imports(self):
        tree = ast.parse(inspect.getsource(probe))
        imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual([alias.name for node in imports for alias in node.names],
                         ['hashlib', 'json', 'math'])

    def test_cpu_single_thread_gate(self):
        class WrongThreads(NoAPI):
            def get_num_threads(self):
                return 4

        with self.assertRaisesRegex(ValueError, 'THREADS'):
            probe.verify(WrongThreads(), probe.SCOPE)

    def test_fixed_handwritten_fixture_and_fresh_copies(self):
        fixed = probe.fixture()
        self.assertEqual((len(fixed['features']), fixed['k'], fixed['seed']), (6, 3, 11))
        self.assertTrue(all(len(row) == 7 for row in fixed['features']))
        self.assertEqual(fixed['uids'], sorted(set(fixed['uids'])))
        self.assertEqual(fixed['positive_uids'], ['synthetic_2'])
        self.assertEqual(list(fixed['costs'].values()), [.5, 1., 2., 4., 7., 10.])
        self.assertTrue(fixed['synthetic_only'])
        self.assertEqual(fixed['features'][0], [0., 1., .2, -.4, .1, .8, -.2])
        snapshot = copy.deepcopy(fixed)
        fixed['features'][0][0] = 1.5
        fixed['positive_uids'].clear()
        fixed['costs'].clear()
        self.assertEqual(probe.fixture(), snapshot)
        self.assertEqual(len(probe._digest(snapshot)), 64)

    def test_exact_separate_objective_maps_not_truncated_cost(self):
        fixed = probe.fixture()
        scores = dict(zip(fixed['uids'], [-.2, .3, -.1, .4, .1, -.3]))
        snapshot = copy.deepcopy(scores)
        result = probe.objective_maps(scores)
        risk = enumerate_exact_gradient(scores, fixed['positive_uids'], fixed['costs'], k=3)
        full = evaluate(scores, fixed['positive_uids'], fixed['costs'], synthetic_only=True)
        self.assertEqual(result['risk'], risk['expected_miss_probability'])
        self.assertEqual(result['cost'], full['normalized_complete_first_hit_cost'])
        self.assertEqual(result['maps']['risk'], risk['miss_score_gradient'])
        self.assertEqual(result['maps']['cost'], full['normalized_cost_score_gradient'])
        self.assertNotAlmostEqual(result['cost'], risk['expected_truncated_static_cost'] / 60.)
        self.assertEqual(result['cost_normalization_B'], 60.)
        self.assertAlmostEqual(result['probability_mass'], 1., places=12)
        self.assertEqual(scores, snapshot)
        self.assertTrue(all(abs(math.fsum(mapping.values())) < 1e-12
                            for mapping in result['maps'].values()))

    def test_full_nonlinear_score_finite_differences_each_phase(self):
        scores = dict(zip(probe.fixture()['uids'], [-.2, .3, -.1, .4, .1, -.3]))
        result = probe.objective_maps(scores)
        proofs = probe._score_proofs(scores, result)
        self.assertEqual(set(proofs), {'risk', 'cost'})
        for proof in proofs.values():
            self.assertGreater(abs(proof['analytic_coordinate']), 1e-12)
            self.assertGreater(proof['gradient_norm'], 1e-12)
            self.assertLess(proof['absolute_error'], 1e-8)

    def test_bad_score_join_or_domain_rejected(self):
        for kind in ('missing', 'extra', 'nonfinite', 'boolean'):
            scores = dict.fromkeys(probe.fixture()['uids'], 0.)
            if kind == 'missing':
                scores.pop('synthetic_0')
            elif kind == 'extra':
                scores['extra'] = 0.
            else:
                scores['synthetic_0'] = float('nan') if kind == 'nonfinite' else True
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                probe.objective_maps(scores)

    def test_active_coordinate_maxabs_and_degenerate_refusal(self):
        index, norm = probe._active_coordinate((0., -.3, .3, .01))
        self.assertEqual(index, 1)
        self.assertGreater(norm, .3)
        for values in ((), (0., 0.), (1e-14,), (float('nan'),), (float('inf'),)):
            with self.assertRaises(ValueError):
                probe._active_coordinate(values)

    def test_rng_and_threads_restored_when_setup_fails(self):
        class State:
            def clone(self):
                return self

        class SetupFailureTorch:
            def __init__(self):
                self.threads = 1
                self.rng = State()
                self.restored_rng = None

            def get_num_threads(self):
                return self.threads

            def set_num_threads(self, number):
                self.threads = number

            def get_rng_state(self):
                return self.rng

            def set_rng_state(self, state):
                self.restored_rng = state

            def manual_seed(self, seed):
                self.assert_seed = seed
                raise RuntimeError('injected setup failure')

            def no_grad(self):
                return contextlib.nullcontext()

        torch = SetupFailureTorch()
        with self.assertRaisesRegex(RuntimeError, 'injected setup failure'):
            probe.verify(torch, probe.SCOPE)
        self.assertIs(torch.restored_rng, torch.rng)
        self.assertEqual(torch.threads, 1)
        self.assertEqual(torch.assert_seed, 11)

    @unittest.skip('NOT_REAL_PROOF: no local Torch; authorized external runner owns actual E17 VJP proof')
    def test_actual_injected_torch_factory_proof(self):
        pass


if __name__ == '__main__':
    unittest.main()
