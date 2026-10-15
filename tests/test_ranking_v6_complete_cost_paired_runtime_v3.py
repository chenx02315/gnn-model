"""E22 local adapter evidence: fake sessions/RNG only; never imports Torch."""
import copy
import unittest
from unittest.mock import patch

from src.models import ranking_v6_complete_cost_paired_runtime_v3 as runtime


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

    @staticmethod
    def release():
        return dict(authorization_id=runtime.AUTHORIZATION_ID,
                    execution_authorized=True, formal_runs=1, automatic_retries=0,
                    scope=runtime.SCOPE, planned_models=6,
                    planned_optimizer_steps_total=144, memory_bytes=1073741824,
                    workers=1, cpus=1, swap_extra_bytes=0,
                    protocol_sha256=runtime.PROTOCOL_SHA256)

    def test_invalid_release_never_touches_torch_even_with_mutable_flags(self):
        class NoAPI:
            def __getattribute__(self, name):
                raise AssertionError('API accessed: ' + name)
        self.assertIs(runtime.EXECUTION_RELEASED, True)
        invalid = [None, True, {}, runtime.SCOPE]
        good = self.release()
        for key in good:
            missing = good.copy()
            del missing[key]
            invalid.append(missing)
            bad = good.copy()
            bad[key] = None
            invalid.append(bad)
            if type(good[key]) is int:
                for replacement in (True, False, float(good[key]), good[key] + 1):
                    bad = good.copy()
                    bad[key] = replacement
                    invalid.append(bad)
        for flag in (True, False, 'authorized'):
            with patch.object(runtime, 'EXECUTION_RELEASED', flag):
                for release in invalid:
                    with self.assertRaisesRegex(ValueError, 'RELEASE_CONTRACT'):
                        runtime.run(NoAPI(), release=release)
        with patch.object(runtime, 'EXECUTION_RELEASED', False):
            with self.assertRaisesRegex(ValueError, 'RUNTIME_EXECUTION_LOCKED'):
                runtime.run(NoAPI(), release=good)

    def test_valid_release_calls_released_path_without_executing_it(self):
        torch = object()
        sentinel = object()
        with patch.object(runtime, '_run_released', return_value=sentinel) as run:
            self.assertIs(runtime.run(torch, release=self.release()), sentinel)
        run.assert_called_once_with(torch)

    def test_protocol_drift_rejected_before_api(self):
        with patch.object(runtime.e19, '_hash', return_value='drift'):
            with self.assertRaisesRegex(ValueError, 'PROTOCOL_DIGEST'):
                runtime.run(object(), release=self.release())

    def test_future_wiring_with_trusted_mock_binding_not_actual_torch(self):
        # Patching both bindings tests the real-path orchestration only.
        # The output's proof fields below are simulated; no Torch is imported.
        sessions = []

        class State:
            def clone(self):
                return copy.copy(self)

        class FakeTorch:
            def __init__(self):
                self.state = State()
                self.restores = 0

            def get_num_threads(self):
                return 1

            def get_rng_state(self):
                return self.state

            def set_rng_state(self, state):
                self.state = state
                self.restores += 1

        class BoundMockSession(FakeSession):
            def __init__(self, torch, seed):
                self_test.assertTrue(all(s.restored for s in sessions))
                super().__init__(seed)
                sessions.append(self)

            @property
            def optimizer_steps(self):
                return self.steps

        self_test = self
        torch = FakeTorch()
        with patch.object(runtime.e14, '_TorchSession', BoundMockSession), \
                patch.object(runtime, '_TorchSession', BoundMockSession):
            result = runtime.run(torch, release=self.release())
        self.assertEqual(result['status'], 'COMPLETE_PAIRED_SYNTHETIC_FIT_DIAGNOSTIC_ONLY',
                         result.get('failure'))
        self.assertEqual([s.steps for s in sessions], [24]*6)
        self.assertTrue(all(s.restored for s in sessions))
        self.assertEqual(result['real_optimizer_steps'], 144)
        self.assertEqual(result['optimizer_steps'], 144)
        self.assertEqual(result['synthetic_fitting_runs'], 6)
        self.assertEqual(result['mock_steps'], 0)
        self.assertEqual(result['restored_sessions'], 6)
        self.assertEqual(result['retry_count'], 0)
        for key in ('fitting_executed', 'actual_torch_proof', 'protocol_completed',
                    'execution_released', 'all_parameters_restored',
                    'final_weights_discarded', 'rng_restored'):
            self.assertIs(result[key], True, key)
        self.assertEqual(torch.restores, 1)
        self.assertEqual(result['runtime_freeze_envelope']['execution_kind'], 'injected_torch')

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
