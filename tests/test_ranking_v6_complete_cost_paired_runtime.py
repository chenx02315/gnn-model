"""E20 local adapter evidence: fake sessions/RNG only; never imports Torch."""
import copy
import unittest
from unittest.mock import patch

from src.models import ranking_v6_complete_cost_paired_runtime as runtime


class FakeSession:
    def __init__(self, seed):
        self.weights = [seed/1000 + i*.03 for i in range(6)]
        self.initial = self.weights[:]
        self.initial_hash = self.weight_hash()
        self.steps = 0
        self.restored = False

    def weight_hash(self):
        return runtime.e19._hash(self.weights)

    def scores(self, task):
        return dict(zip(task['uids'], self.weights))

    def vjp(self, task, maps):
        return dict(weights_unchanged=True, weights_sha256=self.weight_hash(),
                    risk_parameter_gradient=list(maps['risk'].values())+[0.]*1339,
                    cost_parameter_gradient=list(maps['cost'].values())+[0.]*1339)

    def step(self, gradient):
        self.weights = [v-.2*g for v, g in zip(self.weights, gradient)]
        self.steps += 1

    def restore(self):
        self.weights = self.initial[:]
        self.restored = True
        return True


class RuntimeTests(unittest.TestCase):
    def factory(self, alter=None):
        sessions = []

        def make(seed):
            self.assertTrue(all(s.restored for s in sessions), 'one live session')
            session = FakeSession(seed)
            sessions.append(session)
            if alter:
                alter(session, len(sessions))
            return session
        make.mock_only = True
        return make, sessions

    def test_public_source_lock_cannot_be_overridden(self):
        class NoAPI:
            def __getattribute__(self, name):
                raise AssertionError('API accessed: '+name)
        self.assertFalse(runtime.EXECUTION_RELEASED)
        for released in (False, True, 'authorized'):
            with patch.object(runtime, 'EXECUTION_RELEASED', released):
                for release in (None, True, {}, runtime.SCOPE):
                    with self.assertRaisesRegex(ValueError, 'RUNTIME_EXECUTION_LOCKED'):
                        runtime.run(NoAPI(), release=release)
                with self.assertRaisesRegex(ValueError, 'RUNTIME_EXECUTION_LOCKED'):
                    runtime._run_released(NoAPI())
                with self.assertRaisesRegex(ValueError, 'RUNTIME_EXECUTION_LOCKED'):
                    runtime._collect(lambda seed: self.fail('factory called'), real_execution=True)
        self.assertIs(runtime._TorchSession, runtime.e14._TorchSession)

    def test_mock_guard_before_factory(self):
        def forbidden(seed):
            self.fail('factory called')
        for mock_only in (True, False, None, 1):
            with self.assertRaisesRegex(ValueError, 'MOCK_FACTORY_REQUIRED'):
                runtime._run_core(forbidden, mock_only=mock_only)
        forbidden.mock_only = True
        for mock_only in (False, None, 1):
            with self.assertRaisesRegex(ValueError, 'MOCK_FACTORY_REQUIRED'):
                runtime._run_core(forbidden, mock_only=mock_only)
        with self.assertRaisesRegex(ValueError, 'MOCK_FACTORY_REQUIRED'):
            runtime._run_core(runtime._TorchSession)
        with self.assertRaisesRegex(ValueError, 'MOCK_FACTORY_REQUIRED'):
            runtime._collect(lambda seed: self.fail('factory called'), real_execution=False)

    def test_144_mock_steps_six_restored_sessions_and_helper_reuse(self):
        make, sessions = self.factory()
        evaluate = runtime.e19._evaluate

        def verified_evaluate(records, config):
            self.assertEqual(len(records), 6)
            self.assertEqual(sum(s.steps for s in sessions), 144)
            self.assertTrue(all(s.restored for s in sessions))
            self.assertTrue(all(r['freeze_sha256'] == runtime.e19._hash(r['payload'])
                                for r in records))
            return evaluate(records, config)

        with patch.object(runtime.e19, '_collect_for_test', side_effect=AssertionError('old collector')), \
                patch.object(runtime.e19, '_fit_step', wraps=runtime.e19._fit_step) as fit, \
                patch.object(runtime.e19, '_scores', wraps=runtime.e19._scores) as scores, \
                patch.object(runtime.e19, '_evaluate', side_effect=verified_evaluate) as metrics:
            result = runtime._run_core(make)
        self.assertEqual(result['status'], 'PASS_MOCK_IMPLEMENTATION_ONLY', result.get('failure'))
        self.assertEqual([s.steps for s in sessions], [24]*6)
        self.assertEqual(fit.call_count, 144)
        self.assertEqual(scores.call_count, 336)
        metrics.assert_called_once()
        self.assertEqual(result['mock_steps'], 144)
        for key in ('real_optimizer_steps', 'optimizer_steps', 'synthetic_fitting_runs',
                    'checkpoint_reads', 'checkpoint_writes', 'real_label_reads', 'retry_count'):
            self.assertEqual(result[key], 0, key)
        for key in ('fitting_executed', 'actual_torch_proof', 'protocol_completed',
                    'execution_released', 'train_release', 'remote_execution'):
            self.assertIs(result[key], False, key)
        self.assertTrue(result['all_parameters_restored'])
        self.assertTrue(result['all_snapshots_frozen_before_comparative_evaluation'])
        self.assertEqual(result['restored_sessions'], 6)
        self.assertEqual(len(result['paired_rows']), 12)
        envelope = result['runtime_freeze_envelope']
        self.assertEqual(envelope['runtime_scope'], runtime.SCOPE)
        self.assertEqual(envelope['inner_schema_scope'], runtime.e19.SCOPE)
        self.assertEqual(envelope['execution_kind'], 'mock')
        self.assertEqual(envelope['freeze_sha256'], [r['freeze_sha256'] for r in result['records']])
        self.assertEqual(result['runtime_freeze_envelope_sha256'], runtime.e19._hash(envelope))

    def test_pair_hash_and_score_mismatch_before_treatment_update(self):
        def hash_mismatch(session, index):
            if index == 2:
                session.weights[0] += .1
                session.initial = session.weights[:]
                session.initial_hash = session.weight_hash()

        def score_mismatch(session, index):
            if index == 2:
                original = session.scores

                def scores(task):
                    result = original(task)
                    result['0'] += .01
                    return result
                session.scores = scores

        for alter, code in ((hash_mismatch, 'PAIRED_INITIAL_HASH'),
                            (score_mismatch, 'PAIRED_INITIAL_SCORES')):
            make, sessions = self.factory(alter)
            with patch.object(runtime.e19, '_evaluate', side_effect=AssertionError('too soon')):
                result = runtime._run_core(make)
            self.assertEqual(result['status'], 'FAIL_CLOSED')
            self.assertIn(code, result['failure'])
            self.assertEqual([s.steps for s in sessions], [24, 0])
            self.assertTrue(all(s.restored for s in sessions))

    def test_partial_step_failure_restore_and_no_retry(self):
        def alter(session, index):
            original = session.step

            def partial(gradient):
                original(gradient)
                raise RuntimeError('PARTIAL_STEP_FAILURE')
            session.step = partial
        make, sessions = self.factory(alter)
        result = runtime._run_core(make)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].steps, 1)
        self.assertEqual(result['status'], 'FAIL_CLOSED')
        self.assertIn('PARTIAL_STEP_FAILURE', result['failure'])
        self.assertTrue(result['all_parameters_restored'])
        self.assertEqual(result['mock_steps'], 0)  # No completed verified helper call.
        self.assertEqual(result['real_optimizer_steps'], 0)
        self.assertEqual(result['retry_count'], 0)
        self.assertFalse(result['protocol_completed'])

    def test_cleanup_false_cannot_report_discard_or_continue(self):
        def alter(session, index):
            session.restore = lambda: False
        make, sessions = self.factory(alter)
        result = runtime._run_core(make)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(result['status'], 'FAIL_CLOSED')
        self.assertIn('RESTORE_FAILED', result['failure'])
        self.assertFalse(result['all_parameters_restored'])
        self.assertFalse(result['final_weights_discarded'])
        self.assertFalse(result['protocol_completed'])

    def test_rng_restoration_with_fake_rng_success_and_exception(self):
        class State:
            def clone(self):
                return copy.copy(self)

        class FakeRNG:
            def __init__(self):
                self.state = State()
                self.saved = self.state
                self.restores = 0

            def get_rng_state(self):
                return self.state

            def set_rng_state(self, state):
                self.state = state
                self.restores += 1

        for fail in (False, True):
            rng = FakeRNG()

            def callback():
                rng.state = None
                if fail:
                    raise ValueError('CALLBACK_FAILURE')
                return {}
            if fail:
                with self.assertRaisesRegex(ValueError, 'CALLBACK_FAILURE'):
                    runtime._with_rng_restored(rng, callback)
            else:
                self.assertTrue(runtime._with_rng_restored(rng, callback)['rng_restored'])
            self.assertIsInstance(rng.state, State)
            self.assertEqual(rng.restores, 1)


if __name__ == '__main__':
    unittest.main()
