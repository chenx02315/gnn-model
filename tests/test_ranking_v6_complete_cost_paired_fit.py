"""E18 mock-only evidence: no Torch import, fitting, remote access or files."""
import copy
import math
import unittest
from unittest.mock import patch

from src.models import ranking_v6_complete_cost_paired_fit as pair


class FakeSession:
    def __init__(self, seed, events, *, mismatch=False, fail_step=False, mutate_vjp=False):
        self.events = events
        self.weights = [seed/1000 + i*.03 + (.1 if mismatch else 0.) for i in range(6)]
        self.initial = self.weights[:]
        self.initial_hash = self.weight_hash()
        self.steps = 0
        self.restored = False
        self.fail_step = fail_step
        self.mutate_vjp = mutate_vjp
        self.gradients = []
        events.append(('create', seed))

    def weight_hash(self):
        return pair._hash(self.weights)

    def scores(self, task):
        self.events.append(('scores', task['split'], self.steps))
        return dict(zip(task['uids'], self.weights))

    def vjp(self, task, maps):
        before = self.weight_hash()
        self.events.append(('vjp', task['case_id'], before, copy.deepcopy(maps)))
        if self.mutate_vjp:
            self.weights[0] += .01
        return {'weights_unchanged': True, 'weights_sha256': before,
                'risk_parameter_gradient': [maps['risk'][str(i)] for i in range(6)]+[0.]*1339,
                'cost_parameter_gradient': [maps['cost'][str(i)] for i in range(6)]+[0.]*1339}

    def step(self, gradient):
        if self.fail_step:
            raise RuntimeError('INJECTED_STEP_FAILURE')
        self.gradients.append(gradient[:])
        self.weights = [v-.2*g for v, g in zip(self.weights, gradient)]
        self.steps += 1
        self.events.append(('step', self.steps))

    def restore(self):
        self.weights = self.initial[:]
        self.restored = True
        self.events.append(('restore', self.steps))
        return True


class PairedFitTests(unittest.TestCase):
    def factory(self, *, mismatch_at=None, fail_step=False, mutate_vjp=False):
        sessions, events = [], []

        def make(seed):
            self.assertTrue(all(s.restored for s in sessions), 'one active model only')
            session = FakeSession(seed, events, mismatch=len(sessions) == mismatch_at,
                                  fail_step=fail_step, mutate_vjp=mutate_vjp)
            sessions.append(session)
            return session
        make.mock_only = True
        return make, sessions, events

    def test_public_entry_always_fails_before_any_api(self):
        class NoAPI:
            def __getattribute__(self, name):
                raise AssertionError('Torch API accessed: '+name)
        for scope in (None, pair.SCOPE, 'authorized'):
            with self.assertRaisesRegex(ValueError, 'EXECUTION_NOT_RELEASED'):
                pair.run_synthetic_pair(NoAPI(), scope=scope)
        self.assertIs(pair._TorchSession, pair.e14._TorchSession)

    def test_scope_and_bounds_before_factory(self):
        def forbidden(seed):
            self.fail('factory invoked before input guard')
        with self.assertRaisesRegex(ValueError, 'MOCK_FACTORY_REQUIRED'):
            pair._collect_for_test(forbidden, scope=pair.SCOPE)
        forbidden.mock_only = True
        for scope in (None, True, '', 'synthetic'):
            with self.assertRaisesRegex(ValueError, 'MOCK_SCOPE_REQUIRED'):
                pair._collect_for_test(forbidden, scope=scope)
        for steps in (0, 25, True, 1., '1'):
            with self.assertRaisesRegex(ValueError, 'BOUNDED_STEPS'):
                pair._collect_for_test(forbidden, scope=pair.SCOPE, steps=steps)
        with self.assertRaisesRegex(ValueError, 'MOCK_FACTORY_REQUIRED'):
            pair._collect_for_test(pair._TorchSession, scope=pair.SCOPE)
        with patch.object(pair.protocol, 'plan', return_value={}):
            # validate() compares against its own fixed plan, so ensure the
            # invalid plan is rejected independently at the seam boundary.
            with patch.object(pair.protocol, 'validate', side_effect=ValueError('PROTOCOL_MISMATCH')):
                with self.assertRaisesRegex(ValueError, 'PROTOCOL_MISMATCH'):
                    pair._collect_for_test(forbidden, scope=pair.SCOPE)

    def test_all_144_mock_steps_weights_freezes_and_no_unseen_objective(self):
        make, sessions, events = self.factory()
        evaluation_started = False
        original_evaluate = pair._evaluate
        original_exact = pair.exact.enumerate_exact_gradient
        original_complete = pair.complete.evaluate

        def gated_exact(scores, positives, costs, k=3):
            if '4' in positives:
                self.assertTrue(evaluation_started, 'unseen objective before all freezes')
            return original_exact(scores, positives, costs, k=k)

        def gated_complete(scores, positives, costs, *, synthetic_only=False):
            if '4' in positives:
                self.assertTrue(evaluation_started)
            return original_complete(scores, positives, costs, synthetic_only=synthetic_only)

        def evaluate(records, config):
            nonlocal evaluation_started
            self.assertEqual(len(records), 6)
            self.assertEqual(sum(s.steps for s in sessions), 144)
            self.assertTrue(all(s.restored for s in sessions))
            self.assertTrue(all(r['freeze_sha256'] == pair._hash(r['payload']) for r in records))
            evaluation_started = True
            return original_evaluate(records, config)

        with patch.object(pair, '_evaluate', side_effect=evaluate), \
                patch.object(pair.exact, 'enumerate_exact_gradient', side_effect=gated_exact), \
                patch.object(pair.complete, 'evaluate', side_effect=gated_complete):
            result = pair._collect_for_test(make, scope=pair.SCOPE)
        self.assertEqual(result['status'], 'PASS_MOCK_IMPLEMENTATION_ONLY', result.get('failure'))
        self.assertEqual(result['mock_steps'], 144)
        self.assertEqual(result['restored_sessions'], 6)
        self.assertTrue(result['all_parameters_restored'])
        self.assertFalse(result['fitting_executed'])
        self.assertFalse(result['actual_torch_proof'])
        self.assertFalse(result['train_release'])
        self.assertEqual(result['optimizer_steps'], 0)
        self.assertFalse(result['protocol_completed'])
        self.assertTrue(result['mock_window_completed'])
        self.assertTrue(result['planned_mock_budget_completed'])
        for i in range(0, 6, 2):
            self.assertEqual(sessions[i].initial_hash, sessions[i+1].initial_hash)
        for event in events:
            if event[:2] == ('scores', 'unseen'):
                self.assertIn(event[2], (0, 24))
        for arm in (pair.CONTROL, pair.TREATMENT):
            self.assertEqual(len(result['arms'][arm]['rows']), 12)
            self.assertEqual(result['arms'][arm]['summary']['fit']['rows'], 6)
            self.assertEqual(result['arms'][arm]['summary']['unseen']['rows'], 6)
        self.assertEqual(len(result['paired_rows']), 12)
        # Every applied gradient is the correctly weighted mean of both VJPs.
        cursor = 0
        vjps = [e for e in events if e[0] == 'vjp']
        for index, session in enumerate(sessions):
            weight = .5 if index % 2 == 0 else 1.
            for gradient in session.gradients:
                first, second = vjps[cursor:cursor+2]
                cursor += 2
                self.assertEqual(first[2], second[2])
                for uid in range(6):
                    expected = math.fsum(.5*e[3]['risk'][str(uid)] +
                                         weight*e[3]['cost'][str(uid)] for e in (first, second))/2
                    self.assertAlmostEqual(gradient[uid], expected, places=15)
        self.assertEqual(cursor, 288)

    def test_initial_hash_mismatch_before_first_treatment_step_and_cleanup(self):
        make, sessions, _ = self.factory(mismatch_at=1)
        result = pair._collect_for_test(make, scope=pair.SCOPE, steps=1)
        self.assertEqual(result['status'], 'FAIL_CLOSED')
        self.assertIn('PAIRED_INITIAL_HASH', result['failure'])
        self.assertEqual([s.steps for s in sessions], [1, 0])
        self.assertTrue(all(s.restored for s in sessions))
        self.assertTrue(result['all_parameters_restored'])

    def test_initial_score_mismatch_even_when_weight_hash_matches(self):
        make, sessions, _ = self.factory()

        def altered(seed):
            session = make(seed)
            if len(sessions) == 2:
                original = session.scores

                def scores(task):
                    values = original(task)
                    values['0'] += .01
                    return values
                session.scores = scores
            return session
        altered.mock_only = True
        result = pair._collect_for_test(altered, scope=pair.SCOPE, steps=1)
        self.assertIn('PAIRED_INITIAL_SCORES', result['failure'])
        self.assertEqual(sessions[1].steps, 0)
        self.assertTrue(all(s.restored for s in sessions))

    def test_mutating_vjp_and_failure_restore_no_retry(self):
        for args, failure in (({'mutate_vjp': True}, 'SHARED_PREUPDATE_STATE'),
                              ({'fail_step': True}, 'INJECTED_STEP_FAILURE')):
            make, sessions, _ = self.factory(**args)
            result = pair._collect_for_test(make, scope=pair.SCOPE, steps=1)
            self.assertEqual(result['status'], 'FAIL_CLOSED')
            self.assertIn(failure, result['failure'])
            self.assertEqual(len(sessions), 1)
            self.assertTrue(result['all_parameters_restored'])
            self.assertEqual(result['retry_count'], 0)
            self.assertFalse(result['protocol_completed'])

    def test_altered_or_incomplete_freeze_rejects_before_metrics(self):
        make, _, _ = self.factory()
        result = pair._collect_for_test(make, scope=pair.SCOPE, steps=1)
        self.assertTrue(result['mock_window_completed'])
        self.assertFalse(result['planned_mock_budget_completed'])
        altered = copy.deepcopy(result['records'])
        altered[-1]['payload']['score_states']['unseen_cheap']['final']['0'] += .1
        for records, code in ((altered, 'FREEZE_HASH'), (result['records'][:-1], 'FREEZE_COUNT')):
            with patch.object(pair, '_metrics', side_effect=AssertionError('metrics too soon')):
                with self.assertRaisesRegex(ValueError, code):
                    pair._evaluate(records, result['protocol'])

    def test_rehashed_invalid_freezes_reject_all_before_metrics(self):
        make, _, _ = self.factory()
        result = pair._collect_for_test(make, scope=pair.SCOPE, steps=1)
        mutations = (
            (lambda p: p['score_states']['unseen_cheap']['final'].update({'0': 21.}), 'SCORE_DOMAIN'),
            (lambda p: p['score_states']['unseen_cheap']['final'].pop('0'), 'SCORE_JOIN'),
            (lambda p: p['score_states']['unseen_cheap']['uniform_PL'].update({'0': .1}), 'FREEZE_BASELINES'),
            (lambda p: p['score_states']['fit_cheap']['cost_prior_PL'].update({'0': 0.}), 'FREEZE_BASELINES'),
            (lambda p: p.update(initial_parameter_sha256='not-a-hash'), 'FREEZE_WEIGHT_HASH'),
            (lambda p: p['fit_step_logs'][0].update(step=True), 'FREEZE_LOG_CHAIN'),
            (lambda p: p['fit_step_logs'][0].update(parameter_before_sha256='0'*64), 'FREEZE_LOG_CHAIN'),
            (lambda p: p['fit_step_logs'][0]['tasks'][1].update(preupdate_sha256='0'*64), 'FREEZE_LOG_TASKS'),
            (lambda p: p.update(final_parameter_sha256='0'*64), 'FREEZE_LOG_ENDPOINT'),
        )
        for mutate, code in mutations:
            altered = copy.deepcopy(result['records'])
            mutate(altered[-1]['payload'])
            altered[-1]['freeze_sha256'] = pair._hash(altered[-1]['payload'])
            with patch.object(pair, '_metrics', side_effect=AssertionError('metrics too soon')):
                with self.assertRaisesRegex(ValueError, code):
                    pair._evaluate(altered, result['protocol'])

    def test_both_objective_gradients_independent_finite_difference(self):
        task = pair.protocol.plan()['tasks'][0]
        scores = {str(i): (i-2)*.17 for i in range(6)}
        eps = 1e-5

        def scalar(values, arm):
            # Full enumeration for C6 independently checks the pairwise kernel.
            old = pair.exact.enumerate_exact_gradient(values, task['positive_uids'], task['costs'], k=3)
            horizon = 3 if arm == pair.CONTROL else 6
            cost = pair.exact.enumerate_exact_gradient(values, task['positive_uids'], task['costs'], k=horizon)
            weight = .5 if arm == pair.CONTROL else 1.
            return .5*old['expected_miss_probability'] + weight*cost['expected_truncated_static_cost']/(horizon*max(task['costs'].values()))

        for arm in (pair.CONTROL, pair.TREATMENT):
            maps = pair._score_maps(task, scores, arm)
            weight = .5 if arm == pair.CONTROL else 1.
            for uid in scores:
                plus, minus = dict(scores), dict(scores)
                plus[uid] += eps
                minus[uid] -= eps
                finite_difference = (scalar(plus, arm)-scalar(minus, arm))/(2*eps)
                self.assertAlmostEqual(.5*maps['risk'][uid]+weight*maps['cost'][uid],
                                       finite_difference, delta=2e-10)

    def test_failed_rows_cannot_be_overridden_and_exact_tolerance(self):
        reference = {'risk': .2, 'raw_C6': 5.}
        self.assertTrue(pair._guard(reference, {'risk': .2+1e-8, 'raw_C6': 5.-2e-8}))
        self.assertFalse(pair._guard(reference, {'risk': .2+2e-8, 'raw_C6': 1.}))
        self.assertFalse(pair._guard(reference, {'risk': 0., 'raw_C6': 5.-1e-8}))
        rows = [{'split': 'fit' if i < 6 else 'unseen', 'pass': i != 11} for i in range(12)]
        summary = pair._summary(rows)
        self.assertTrue(summary['fit']['all_pass'])
        self.assertFalse(summary['unseen']['all_pass'])
        self.assertFalse(summary['all']['all_pass'])
        self.assertEqual(summary['all']['passing_rows'], 11)


if __name__ == '__main__':
    unittest.main()
