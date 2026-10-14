"""E11 tiny/mocked checks only: never import Torch or run formal 32+32."""
import copy
import inspect
import unittest
from unittest.mock import patch

from src.models import ranking_v6_joint_parameter_probe as probe


class FakeState:
    def clone(self):
        return self


class FakeTorch:
    def __init__(self):
        self.restored = False

    def get_num_threads(self):
        return 1

    def get_rng_state(self):
        return FakeState()

    def set_rng_state(self, state):
        self.restored = True


class FakeSession:
    instances = []

    def __init__(self, torch, inputs, seed):
        self.inputs = inputs
        self.initial_hash = 'initial'
        self.layout = [{'name': 'fake', 'shape': [2]}]
        self.changed = False
        self.forward_calls = 0
        self.restore_calls = 0
        self.instances.append(self)

    def scores(self):
        self.forward_calls += 1
        return {str(i): i * .1 + (.03 if self.changed and i == 5 else 0.) for i in range(6)}

    def weight_hash(self):
        return 'proposed' if self.changed else self.initial_hash

    def vjp(self, maps):
        return dict(weights_sha256=self.initial_hash, weights_unchanged=True,
                    parameter_count=2, risk_parameter_gradient=(1., 2.),
                    cost_parameter_gradient=(2., 1.))

    def apply(self, selected):
        assert selected is not None
        self.changed = True
        return self.weight_hash()

    def restore(self):
        self.changed = False
        self.restore_calls += 1
        return True


class ParameterProbeTests(unittest.TestCase):
    def setUp(self):
        FakeSession.instances = []

    def oracle(self, risk=.4, cost=.4, bound=27.):
        return dict(probability_mass=1., expected_miss_probability=risk,
                    expected_truncated_static_cost=cost * bound,
                    miss_score_gradient={str(i): 0. for i in range(6)},
                    cost_score_gradient={str(i): 0. for i in range(6)})

    def fixture(self):
        case, values, charges = probe.FIXTURES[0]
        inputs = probe._inputs(case, values, charges)
        session = FakeSession(None, inputs, 11)
        record = probe._freeze(session, inputs, 11, 2, 3)
        return session, record

    def test_formal_entry_fixed_and_lazy_torch(self):
        self.assertEqual(list(inspect.signature(probe.run_joint_parameter_probe).parameters), ['torch'])
        self.assertEqual(probe.SEEDS, (11, 29, 47, 83))
        self.assertEqual((probe.BASELINE_SAMPLES, probe.GRADIENT_SAMPLES), (32, 32))
        source = inspect.getsource(probe)
        self.assertNotIn('import torch', source)

    def test_parameter_grid_and_zero_opposed_guards(self):
        grid, selected, _, _ = probe._select_parameter_candidate([1., 2.], [2., 1.])
        self.assertEqual(len(grid), 15)
        self.assertTrue(all('direction' not in candidate for candidate in grid))
        self.assertAlmostEqual(sum(abs(v) for v in selected['direction']), 1.)
        for risk, cost in (([0.], [1.]), ([1.], [-1.])):
            self.assertIsNone(probe._select_parameter_candidate(risk, cost)[1])
        for risk, cost in (([1.], [1., 2.]), ([], [])):
            with self.assertRaisesRegex(ValueError, 'GRADIENT_SHAPE'):
                probe._select_parameter_candidate(risk, cost)
        with self.assertRaisesRegex(ValueError, 'NONFINITE_GRADIENT'):
            probe._select_parameter_candidate([float('nan')], [1.])

    def test_freeze_pins_hashes_vjp_and_synthetic_graph_metadata(self):
        session, record = self.fixture()
        payload = record['payload']
        self.assertEqual(record['payload_sha256'], probe._hash(payload))
        self.assertFalse(payload['graph_consumed_by_model'])
        self.assertEqual(payload['scores'], session.scores())
        self.assertEqual(payload['features_sha256'], probe._hash(payload['features']))
        self.assertEqual(payload['graph_sha256'], probe._hash(payload['graph']))
        self.assertNotEqual(payload['derived_seed_sha256']['pilot'], payload['derived_seed_sha256']['main'])
        self.assertEqual(payload['pilot_seed_namespace'], probe.joint.control.SEED_NAMESPACE)
        self.assertNotEqual(payload['pilot_seed_namespace'], probe.SEED_NAMESPACE)
        self.assertTrue(payload['baselines_frozen_before_gradient'])
        self.assertFalse(payload['baseline_derivative_taken'])

    def test_eight_freezes_before_oracle_actual_forward_and_restore(self):
        events, records = [], []
        original = probe._freeze
        def freeze(*args):
            record = original(*args)
            records.append(record)
            events.append('freeze')
            return record
        def oracle(scores, positives, costs, *, k):
            self.assertEqual(events.count('freeze'), 8)
            events.append('oracle')
            # Proposed forward in the fake scorer is deliberately not the
            # parameter direction, proving verifier never injects score deltas.
            is_proposed = abs(scores['5'] - .53) < 1e-12
            return self.oracle(.39 if is_proposed else .4,
                               .39 if is_proposed else .4, 3 * max(costs.values()))
        torch = FakeTorch()
        with patch.object(probe, '_TorchSession', FakeSession), \
                patch.object(probe, '_freeze', side_effect=freeze), \
                patch.object(probe.joint.full_oracle, 'enumerate_exact_gradient', side_effect=oracle):
            result = probe._run_fixed_fixtures(torch, baseline_samples=2, gradient_samples=3)
        self.assertEqual(events[:8], ['freeze'] * 8)
        self.assertEqual(result['accepted_count'], 8)
        self.assertEqual(result['exact_oracle_calls'], 16)
        self.assertTrue(torch.restored)
        self.assertTrue(all(not s.changed and s.restore_calls >= 2 for s in FakeSession.instances))
        for summary in result['per_case_seed']:
            self.assertEqual(summary['restored_parameter_sha256'], 'initial')
            self.assertEqual(summary['committed_parameter_sha256'], 'proposed')
            self.assertTrue(summary['parameters_restored_exactly'])
        self.assertFalse(result['train_release'])
        self.assertFalse(result['persistent_parameter_updates'])

    def test_rejection_no_fallback_and_hash_failure(self):
        for risk, cost, accepted in ((.39, .39, True), (.41, .39, False), (.39, .4, False)):
            session, record = self.fixture()
            with patch.object(probe.joint.full_oracle, 'enumerate_exact_gradient', side_effect=[
                    self.oracle(), self.oracle(risk, cost)]) as oracle:
                result = probe._verify(session, record)
            self.assertEqual(oracle.call_count, 2)
            self.assertEqual(result['accepted'], accepted)
            self.assertFalse(result['fallback_attempted'])
            self.assertFalse(session.changed)
        session, record = self.fixture()
        record['payload']['seed'] = 999
        with patch.object(probe.joint.full_oracle, 'enumerate_exact_gradient', side_effect=AssertionError('oracle')):
            result = probe._verify(session, record)
        self.assertEqual(result['exact_oracle_calls'], 0)
        self.assertTrue(result['numerical_guard_failed'])
        self.assertFalse(result['accepted'])

    def test_restore_on_unexpected_oracle_exception_and_no_proposal(self):
        session, record = self.fixture()
        with patch.object(probe.joint.full_oracle, 'enumerate_exact_gradient', side_effect=[
                self.oracle(), RuntimeError('injected')]):
            with self.assertRaisesRegex(RuntimeError, 'injected'):
                probe._verify(session, record)
        self.assertFalse(session.changed)
        self.assertEqual(session.restore_calls, 1)
        session, record = self.fixture()
        record = copy.deepcopy(record)
        record['payload']['selected_candidate'] = None
        record['payload_sha256'] = probe._hash(record['payload'])
        with patch.object(probe.joint.full_oracle, 'enumerate_exact_gradient', return_value=self.oracle()) as oracle:
            result = probe._verify(session, record)
        self.assertEqual(oracle.call_count, 1)
        self.assertFalse(result['accepted'])

    def test_preflight_counts_before_session_and_rng(self):
        with patch.object(probe, '_TorchSession', side_effect=AssertionError('session')):
            for count in (0, True, 33, 1.5):
                with self.assertRaisesRegex(ValueError, 'PILOT_SAMPLES'):
                    probe._run_fixed_fixtures(FakeTorch(), baseline_samples=count)

    def test_outer_finally_restores_models_and_rng_on_pilot_exception(self):
        torch = FakeTorch()
        original = probe._freeze
        calls = []
        def freeze(*args):
            calls.append(True)
            if len(calls) == 2:
                args[0].changed = True
                raise RuntimeError('pilot injected')
            return original(*args)
        with patch.object(probe, '_TorchSession', FakeSession), \
                patch.object(probe, '_freeze', side_effect=freeze), \
                patch.object(probe.joint.full_oracle, 'enumerate_exact_gradient', side_effect=AssertionError('oracle')):
            with self.assertRaisesRegex(RuntimeError, 'pilot injected'):
                probe._run_fixed_fixtures(torch, baseline_samples=2, gradient_samples=3)
        self.assertTrue(torch.restored)
        self.assertEqual(len(FakeSession.instances), 2)
        self.assertTrue(all(not s.changed and s.restore_calls == 1 for s in FakeSession.instances))


if __name__ == '__main__':
    unittest.main()
