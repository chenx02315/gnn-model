"""Pure helpers / tiny mocked E12 orchestration; never run a Torch fit."""
import inspect
import math
import unittest
from unittest.mock import patch

from src.models import ranking_v6_synthetic_fit as fit


class FakeState:
    def clone(self):
        return self


class FakeTorch:
    restored = False

    def get_num_threads(self):
        return 1

    def get_rng_state(self):
        return FakeState()

    def set_rng_state(self, state):
        self.restored = True


class FakeSession:
    instances, events = [], []

    def __init__(self, torch, seed):
        self.seed, self.steps = seed, 0
        self.initial_hash = 'initial-' + str(seed)
        self.restored = False
        self.instances.append(self)

    def weight_hash(self):
        return self.initial_hash + '-step-' + str(self.steps)

    def scores(self, task):
        self.events.append(('score', task['split'], sum(s.steps for s in self.instances)))
        return {u: task['features'][int(u)][0] * .1 + task['offsets'][u] +
                (self.steps * .05 if u in task['positive_uids'] else 0.) for u in task['uids']}

    def vjp(self, task, maps):
        self.events.append(('vjp', task['split']))
        return dict(risk_parameter_gradient=(1.,)*1345, cost_parameter_gradient=(3.,)*1345,
                    score_sha256='raw-score', weights_sha256=self.weight_hash(), weights_unchanged=True)

    def step(self, gradient):
        assert gradient == [2.]*1345
        self.events.append(('step', self.seed))
        self.steps += 1

    def restore(self):
        self.restored = True
        self.steps = 0
        return True


class SyntheticFitTests(unittest.TestCase):
    def setUp(self):
        FakeSession.instances, FakeSession.events = [], []

    def test_fixed_protocol_and_feature_split(self):
        self.assertEqual(list(inspect.signature(fit.run_synthetic_fit).parameters), ['torch'])
        config = fit._protocol(24, 32, 32)
        self.assertEqual(config['seeds'], [11, 29, 47])
        self.assertEqual(config['nominal_sampling_work'], 165888)
        self.assertEqual(config['learning_rate'], .2)
        self.assertEqual(config['resources']['memory_bytes'], 1073741824)
        self.assertNotIn('import torch', inspect.getsource(fit))
        tasks = config['tasks']
        self.assertEqual(len(tasks), 4)
        self.assertEqual([t['positive_uids'] for t in tasks], [['5'], ['5'], ['4'], ['4']])
        self.assertTrue(all(abs(v) <= 2 for t in tasks for row in t['features'] for v in row))
        self.assertEqual(len({fit._hash(t['features']) for t in tasks}), 4)
        # Ignore UID and absolute cost scale: genuinely different tasks must
        # remain distinct under the same feature/cost/label/prior alignment.
        signatures = [sorted((tuple(t['features'][i]), t['costs'][u]/max(t['costs'].values()),
                              int(u in t['positive_uids']), t['offsets'][u])
                             for i, u in enumerate(t['uids'])) for t in tasks]
        self.assertEqual(len({fit._hash(signature) for signature in signatures}), 4)
        self.assertTrue(all(sum(t['offsets'].values()) == -3 for t in tasks))

    def test_constant_prior_has_zero_parameter_derivative(self):
        task = fit._tasks()[0]
        features, offsets = task['features'], dict(task['offsets'])
        theta = [.07, -.03, .02, .04, -.01, .05, .06]
        upstream = [.2, -.1, .07, -.04, .09, -.21]
        def objective(parameters, with_prior):
            return math.fsum(upstream[i]*(math.fsum(x*p for x, p in zip(row, parameters))+
                              (offsets[str(i)] if with_prior else 0.)) for i, row in enumerate(features))
        analytic = [math.fsum(upstream[i]*row[j] for i, row in enumerate(features)) for j in range(7)]
        for j in range(7):
            plus, minus = list(theta), list(theta)
            plus[j] += 1e-6
            minus[j] -= 1e-6
            shifted = (objective(plus, True)-objective(minus, True))/2e-6
            raw = (objective(plus, False)-objective(minus, False))/2e-6
            self.assertAlmostEqual(shifted, analytic[j], places=8)
            self.assertAlmostEqual(raw, analytic[j], places=8)
            self.assertAlmostEqual(shifted, raw, places=8)
        self.assertEqual(offsets, task['offsets'])

    def test_comparisons_share_prior_and_cost_controls_ignore_labels(self):
        task = fit._tasks()[0]
        states = fit._comparison_scores(task, dict(task['offsets']), dict(task['offsets']))
        self.assertEqual(set(states), set(fit._protocol(1, 1, 1)['comparison_states']))
        self.assertEqual(states['PRIOR_ONLY_PL'], task['offsets'])
        self.assertEqual(states['UNIFORM_PL'], {u: 0. for u in task['uids']})
        for u in task['uids']:
            self.assertEqual(states['COST_PLUS_PRIOR_PL'][u], states['COST_PRIOR_PL'][u]+task['offsets'][u])
        other = dict(task, positive_uids=['0'])
        self.assertEqual(fit._comparison_scores(other, {}, {})['COST_PRIOR_PL'], states['COST_PRIOR_PL'])

    def test_shared_model_raw_average_and_offset_chain(self):
        session = FakeSession(None, 11)
        tasks = fit._tasks()[:2]
        # A constant offset does not alter ds/dtheta: VJP consumes features and
        # score-gradient maps, not the total shifted score hash.
        maps_seen = []
        original = session.vjp
        def vjp(task, maps):
            maps_seen.append(maps)
            return original(task, maps)
        session.vjp = vjp
        log = fit._fit_step(session, tasks, 11, 0, 1, 2)
        self.assertEqual(session.steps, 1)
        self.assertEqual(len(maps_seen), 2)
        self.assertAlmostEqual(log['gradient_norm'], math.sqrt(1345*4))
        for task_log in log['tasks']:
            self.assertEqual(task_log['raw_model_score_sha256'], 'raw-score')
            self.assertNotEqual(task_log['raw_model_score_sha256'], task_log['total_score_with_prior_sha256'])
            self.assertTrue(task_log['baselines_frozen'])
        self.assertNotEqual(log['tasks'][0]['derived_seed_sha256']['pilot'], log['tasks'][0]['derived_seed_sha256']['main'])
        with self.assertRaisesRegex(ValueError, 'UNSEEN_FIT_FORBIDDEN'):
            fit._fit_step(session, fit._tasks()[2:], 11, 0, 1, 1)

    def test_all_freezes_before_oracle_and_no_unseen_during_fit(self):
        torch = FakeTorch()
        def oracle(scores, positives, costs, *, k):
            self.assertEqual(sum(s.steps for s in FakeSession.instances), 6)
            return dict(probability_mass=1., expected_miss_probability=.95,
                        expected_truncated_static_cost=.4*k*max(costs.values()))
        with patch.object(fit, '_TorchSession', FakeSession), patch.object(fit.oracle, 'enumerate_exact_gradient', side_effect=oracle) as exact:
            result = fit._run_synthetic_fit(torch, steps=2, baseline_samples=1, main_samples=2)
        self.assertEqual(exact.call_count, 72)
        self.assertEqual(result['optimizer_steps'], 6)
        self.assertEqual(result['synthetic_fitting_runs'], 3)
        self.assertTrue(result['protocol_completed'])
        self.assertEqual(result['scientific_status'], 'NO_JOINT_IMPROVEMENT')
        self.assertTrue(result['rare_initial_guard_pass'])
        self.assertTrue(torch.restored)
        self.assertTrue(all(s.restored for s in FakeSession.instances))
        unseen = [event for event in FakeSession.events if event[:2] == ('score', 'unseen')]
        self.assertEqual([e[2] for e in unseen], [0]*6+[6]*6)
        self.assertTrue(all(e[1] == 'fit' for e in FakeSession.events if e[0] == 'vjp'))
        for record in result['fit_freezes']:
            self.assertEqual(record['freeze_sha256'], fit._hash(record['payload']))
            self.assertEqual(len(record['payload']['fit_step_logs']), 2)
        self.assertFalse(result['real_data_access'])
        self.assertEqual(result['checkpoint_writes'], 0)
        self.assertEqual(result['formal_training_runs'], 0)

    def test_numerical_failure_stops_whole_run_no_retry_or_oracle(self):
        torch = FakeTorch()
        with patch.object(fit, '_TorchSession', FakeSession), patch.object(fit, '_fit_step', side_effect=ValueError('domain')) as step, patch.object(fit.oracle, 'enumerate_exact_gradient') as exact:
            result = fit._run_synthetic_fit(torch, steps=2, baseline_samples=1, main_samples=1)
        self.assertEqual(step.call_count, 1)
        exact.assert_not_called()
        self.assertEqual(result['numerical_guard_failures'], 1)
        self.assertFalse(result['protocol_completed'])
        self.assertEqual(result['retry_count'], 0)
        self.assertTrue(torch.restored)
        self.assertTrue(all(s.restored for s in FakeSession.instances))

    def test_unique_step_seed_pins_and_invalid_bounds(self):
        session = FakeSession(None, 11)
        first = fit._fit_step(session, fit._tasks()[:2], 11, 0, 1, 1)
        second = fit._fit_step(session, fit._tasks()[:2], 11, 1, 1, 1)
        self.assertNotEqual(first['tasks'][0]['derived_seed_sha256'], second['tasks'][0]['derived_seed_sha256'])
        for kwargs in ({'steps': 25}, {'steps': True}, {'baseline_samples': 0}, {'main_samples': 33}):
            with self.assertRaisesRegex(ValueError, 'BOUNDED_TEST_SEAM'):
                fit._run_synthetic_fit(FakeTorch(), **kwargs)

    def test_scientific_status_is_separate_and_freeze_tamper_rejected(self):
        config = fit._protocol(1, 1, 1)
        records = []
        for seed in fit.SEEDS:
            states = {}
            for task in config['tasks']:
                # Marker is only a mocked oracle input, not injected model output.
                initial = {u: 0. for u in task['uids']}
                final = {u: 1. if task['split'] == 'fit' else 2. for u in task['uids']}
                states[task['case_id']] = fit._comparison_scores(task, initial, final)
            payload = dict(seed=seed, score_states=states)
            records.append(dict(payload=payload, freeze_sha256=fit._hash(payload)))
        for improve_unseen, initial_risk, expected in ((True, .95, 'PASS_TRANSFER'),
                (False, .95, 'PASS_FIT_ONLY'), (True, .85, 'FAIL_RARE_DESIGN')):
            def oracle(scores, positives, costs, *, k):
                marker = next(iter(scores.values()))
                improved = marker == 1. or (marker == 2. and improve_unseen)
                return dict(probability_mass=1., expected_miss_probability=initial_risk-(.1 if improved else 0.),
                            expected_truncated_static_cost=(.4 if improved else .5)*k*max(costs.values()))
            with patch.object(fit.oracle, 'enumerate_exact_gradient', side_effect=oracle):
                result = fit._evaluate(records, config)
            self.assertEqual(result['scientific_status'], expected)
        records[0]['payload']['seed'] = 99
        with patch.object(fit.oracle, 'enumerate_exact_gradient') as exact:
            with self.assertRaisesRegex(ValueError, 'FREEZE_HASH'):
                fit._evaluate(records, config)
            exact.assert_not_called()


if __name__ == '__main__':
    unittest.main()
