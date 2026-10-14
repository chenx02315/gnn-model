"""E14 no-prior paired synthetic SGD diagnostic; injected Torch, no data/checkpoint I/O.

The seven-feature factory is an MLP, not a graph model. This derivative removes E12's label-conditioned -3 offset; all offsets are
zero. Tasks, initialization, estimator RNG case IDs, objective and budget
remain fixed for a paired comparison, not a rare-start validation.
Unseen snapshots precede/follow the entire fit window; they never enter fit.
All model states freeze before any full-original-PL oracle. No oracle rollback,
early stopping, retries, clipping, best checkpoint, or production TRAIN release.
"""
import hashlib
import inspect
import json
import math
import sys

from . import ranking_v6_conditional_control_reference as control
from . import ranking_v6_first_hit_exact_gradient as oracle
from . import ranking_v6_scorer_vjp_bridge as bridge
from .runtime_ranking_v3 import make_candidate_ranker

SEEDS = (11, 29, 47)
STEPS, BASELINE_SAMPLES, MAIN_SAMPLES = 24, 32, 32
N, K, LR = 6, 3, .2
NAMESPACE = 'v6-e12-synthetic-fit-v1'
TASK_VECTORS = (
    ('fit_cheap', [-.8, -.4, .1, .3, .6, 1.], [9., 4., 7., 2., 6., .5], [0, 1, 2, 3, 4, 5], 1.),
    ('fit_expensive', [-.7, -.3, 0., .2, .55, 1.1], [.5, 2., 4., 6., 8., 10.], [0, 1, 2, 3, 4, 5], 1.),
    ('unseen_cheap', [.55, -.65, .2, -.2, 1.05, -.85], [4., 8., 1.5, 6., .7, 3.], [3, 0, 5, 1, 4, 2], .8),
    ('unseen_expensive', [.2, -.75, .65, -.15, .95, .1], [.6, 5., 2., 8., 11., 3.], [2, 5, 0, 4, 1, 3], .8),
)


def _require(ok, code):
    if not ok:
        raise ValueError('SYNTHETIC_FIT_' + code)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode('ascii')).hexdigest()


def _tasks():
    tasks = []
    for name, signals, charges, perm, last in TASK_VECTORS:
        uids = [str(i) for i in range(N)]
        designated = '5' if name.startswith('fit_') else '4'
        features = [[signals[i], charges[i] / 12., perm[i] / 5., 1 - perm[i] / 5.,
                     (-1.) ** perm[i] * .25, (perm[i] % 3) / 2., last] for i in range(N)]
        _require([u for u, s in zip(uids, signals) if s > .8] == [designated], 'PRESET_LABEL')
        tasks.append(dict(case_id=name, split='fit' if name.startswith('fit_') else 'unseen',
                          uids=uids, features=features, costs=dict(zip(uids, charges)),
                          positive_uids=[designated], offsets={u: 0. for u in uids},
                          row_permutation=perm, feature_names=['synthetic_signal', 'cost_fraction',
                          'permuted_row_fraction', 'reverse_row_fraction', 'alternating', 'mod_three', 'constant']))
    return tasks


def _protocol(steps, baseline, main):
    tasks = _tasks()
    return dict(namespace=NAMESPACE, seeds=list(SEEDS), tasks=tasks, n=N, k=K,
                steps=steps, baseline_samples=baseline, main_samples=main,
                learning_rate=LR, optimizer='SGD', momentum=0., weight_decay=0.,
                scalar_objective='0.5*risk+0.5*cost/(K*max_cost)',
                task_reduction='mean_of_two_fit_task_raw_parameter_gradients',
                initialization='torch.manual_seed(seed); existing_factory CPU float64',
                parameter_count=1345, graph_consumed=False, production_preprocessing=False,
                prior='none; all offsets zero; E14 paired with frozen E12',
                experiment_id='E14_NO_PRIOR_PAIRED_FIT', rare_guard_required=False,
                paired_sampling_case_ids_preserved=True,
                nominal_sampling_work=len(SEEDS)*steps*2*N*K*(baseline+main),
                control_seed_namespace=control.SEED_NAMESPACE,
                comparison_states=['initial_prior', 'final_prior', 'UNIFORM_PL', 'COST_PRIOR_PL',
                                   'PRIOR_ONLY_PL', 'COST_PLUS_PRIOR_PL'],
                cost_control='-cost/max_cost; temperature 1; stochastic PL, not deterministic',
                rare_initial_miss_min=.9, joint_improvement_threshold=1e-8,
                resources={'cpu': 1, 'memory_bytes': 1073741824, 'workers': 1, 'auto_retry': 0},
                no_early_stop=True, no_grid=True, no_accept_rollback=True, no_checkpoint=True,
                source_sha256={name: hashlib.sha256(inspect.getsource(obj).encode()).hexdigest()
                               for name, obj in [('factory', make_candidate_ranker), ('vjp', bridge),
                                                 ('control', control), ('oracle', oracle),
                                                 ('diagnostic', sys.modules[__name__])]})


class _TorchSession:
    def __init__(self, torch, seed):
        self.torch = torch
        torch.manual_seed(seed)
        self.model = make_candidate_ranker(torch).double().cpu().eval()
        self.parameters = tuple(self.model.parameters())
        self.initial = tuple(p.detach().clone() for p in self.parameters)
        self.initial_grads = tuple(p.grad for p in self.parameters)
        self.initial_hash = self.weight_hash()
        self.optimizer_steps = 0
        _require(sum(p.numel() for p in self.parameters) == 1345, 'FACTORY_COUNT')
        self.optimizer = torch.optim.SGD(self.parameters, lr=LR, momentum=0., weight_decay=0.)

    def weight_hash(self):
        return bridge._digest([p.detach().reshape(-1).tolist() for p in self.parameters])

    def scores(self, task):
        with self.torch.no_grad():
            result = self.model(self.torch.tensor(task['features'], dtype=self.torch.float64, device='cpu'))
        _require(tuple(result.shape) == (N,), 'SCORE_SHAPE')
        scores = {u: v + task['offsets'][u] for u, v in zip(task['uids'], result.detach().tolist())}
        _require(all(math.isfinite(v) and abs(v) <= 20 for v in scores.values()), 'SCORE_DOMAIN')
        return scores

    def vjp(self, task, maps):
        result = bridge.tensor_scores_to_parameter_gradients(self.torch, self.model, task['features'],
                  task['uids'], maps, scope=bridge.SCOPE)
        _require(result['weights_unchanged'] and result['weights_sha256'] == self.weight_hash(), 'VJP_STATE')
        return result

    def step(self, gradient):
        _require(len(gradient) == 1345 and all(math.isfinite(v) for v in gradient), 'GRADIENT_DOMAIN')
        self.optimizer.zero_grad(set_to_none=True)
        offset = 0
        for p in self.parameters:
            count = p.numel()
            p.grad = self.torch.tensor(gradient[offset:offset+count], dtype=self.torch.float64,
                                       device='cpu').reshape(p.shape).detach()
            offset += count
        self.optimizer.step()
        self.optimizer_steps += 1
        _require(all(bool(self.torch.isfinite(p).all().item()) for p in self.parameters), 'WEIGHT_DOMAIN')

    def restore(self):
        with self.torch.no_grad():
            for p, value, grad in zip(self.parameters, self.initial, self.initial_grads):
                p.copy_(value)
                p.grad = grad
        _require(self.weight_hash() == self.initial_hash, 'RESTORE_HASH')
        _require(all(self.torch.equal(p.detach(), value) and p.grad is grad
                     for p, value, grad in zip(self.parameters, self.initial, self.initial_grads)), 'RESTORE_EQUAL')
        return True


def _fit_step(session, fit_tasks, seed, step, baseline, main):
    gradients, logs = [], []
    before = session.weight_hash()
    for task in fit_tasks:
        _require(task['split'] == 'fit', 'UNSEEN_FIT_FORBIDDEN')
        scores = session.scores(task)
        case_id = 'e12-' + task['case_id'] + '-step-' + str(step)
        estimate = control.estimate(scores, set(task['positive_uids']), task['costs'], k=K,
                                   seed=seed, case_id=case_id, pilot_samples=baseline, main_samples=main)
        maps = {'risk': estimate['miss_score_gradient'], 'cost': estimate['normalized_cost_score_gradient']}
        vjp = session.vjp(task, maps)
        gradient = [.5 * (r+c) for r, c in zip(vjp['risk_parameter_gradient'], vjp['cost_parameter_gradient'])]
        _require(len(gradient) == 1345 and all(math.isfinite(v) for v in gradient), 'VJP_DOMAIN')
        gradients.append(gradient)
        risk, cost = estimate['expected_miss_probability'], estimate['expected_truncated_static_cost'] / (K*max(task['costs'].values()))
        _require(all(math.isfinite(v) and 0 <= v <= 1+1e-12 for v in (risk, cost)), 'ESTIMATE_DOMAIN')
        logs.append(dict(case_id=case_id, task_id=task['case_id'], derived_seed_sha256=estimate['derived_seed_sha256'],
                         risk_mean=risk, normalized_cost_mean=cost, objective_mean=.5*(risk+cost),
                         gradient_norm=math.sqrt(math.fsum(v*v for v in gradient)),
                         total_score_with_prior_sha256=_hash(scores), raw_model_score_sha256=vjp['score_sha256'],
                         fixed_offset_sha256=_hash(task['offsets']), baselines_frozen=True))
    average = [math.fsum(values)/2. for values in zip(*gradients)]
    _require(len(gradients) == 2 and session.weight_hash() == before, 'SHARED_PREUPDATE_STATE')
    session.step(average)
    # Only fit forwards are allowed while the optimization window is open.
    for task in fit_tasks:
        session.scores(task)
    return dict(step=step, parameter_before_sha256=before, parameter_after_sha256=session.weight_hash(),
                gradient_sha256=_hash(average), gradient_norm=math.sqrt(math.fsum(v*v for v in average)), tasks=logs)


def _comparison_scores(task, initial, final):
    cost = {u: -task['costs'][u]/max(task['costs'].values()) for u in task['uids']}
    return dict(initial_prior=initial, final_prior=final, UNIFORM_PL={u: 0. for u in task['uids']},
                COST_PRIOR_PL=cost, PRIOR_ONLY_PL=dict(task['offsets']),
                COST_PLUS_PRIOR_PL={u: cost[u]+task['offsets'][u] for u in task['uids']})


def _evaluate(records, config, progress=None):
    results = []
    for record in records:
        _require(record['freeze_sha256'] == _hash(record['payload']), 'FREEZE_HASH')
        payload = record['payload']
        task_results = []
        for task in config['tasks']:
            metrics = {}
            for name, scores in payload['score_states'][task['case_id']].items():
                if progress is not None:
                    progress['exact_oracle_calls'] += 1
                result = oracle.enumerate_exact_gradient(scores, set(task['positive_uids']), task['costs'], k=K)
                _require(abs(result['probability_mass']-1.) <= 1e-10, 'ORACLE_MASS')
                risk = result['expected_miss_probability']
                cost = result['expected_truncated_static_cost']/(K*max(task['costs'].values()))
                _require(all(math.isfinite(v) and 0 <= v <= 1+1e-12 for v in (risk, cost)), 'ORACLE_DOMAIN')
                order = sorted(scores, key=lambda u: (-scores[u], u))
                position = order.index(task['positive_uids'][0])+1
                metrics[name] = dict(risk=risk, normalized_cost=cost, raw_static_cost=result['expected_truncated_static_cost'],
                                     objective=.5*(risk+cost), probability_mass=result['probability_mass'],
                                     deterministic_positive_position=position, deterministic_top_k_hit=int(position <= K))
            initial, final = metrics['initial_prior'], metrics['final_prior']
            dr, dc = final['risk']-initial['risk'], final['normalized_cost']-initial['normalized_cost']
            task_results.append(dict(task_id=task['case_id'], split=task['split'], metrics=metrics,
                risk_delta=dr, normalized_cost_delta=dc, jointly_improved=dr < -1e-8 and dc < -1e-8,
                rare_initial_guard_pass=initial['risk'] >= .9))
        _require(record['freeze_sha256'] == _hash(payload), 'FREEZE_MUTATED')
        results.append(dict(seed=payload['seed'], tasks=task_results))
    flat = [t for r in results for t in r['tasks']]
    fit = all(t['jointly_improved'] for t in flat if t['split'] == 'fit')
    unseen = all(t['jointly_improved'] for t in flat if t['split'] == 'unseen')
    rare = all(t['rare_initial_guard_pass'] for t in flat)
    return dict(per_seed=results, exact_oracle_calls=len(flat)*6, rare_initial_guard_pass=rare, rare_guard_required=False,
                fit_all_jointly_improved=fit, unseen_all_jointly_improved=unseen,
                scientific_status='PASS_TRANSFER' if fit and unseen
                else 'PASS_FIT_ONLY' if fit else 'NO_JOINT_IMPROVEMENT')


def _run_synthetic_fit(torch, *, steps=STEPS, baseline_samples=BASELINE_SAMPLES, main_samples=MAIN_SAMPLES):
    for value, maximum in ((steps, STEPS), (baseline_samples, BASELINE_SAMPLES), (main_samples, MAIN_SAMPLES)):
        _require(type(value) is int and 1 <= value <= maximum, 'BOUNDED_TEST_SEAM')
    _require(torch.get_num_threads() == 1, 'CPU_THREADS')
    config = _protocol(steps, baseline_samples, main_samples)
    config_hash = _hash(config)
    rng = torch.get_rng_state().clone()
    sessions, records, initial_states, logs = [], [], [], []
    result = dict(config=config, config_sha256=config_hash, protocol_complete=False, synthetic_only=True,
                  real_data_access=False, checkpoint_access=False, checkpoint_writes=0, train_release=False,
                  persistent_parameter_updates=False, retry_count=0, optimizer_calls=0, exact_oracle_calls=0,
                  graph_consumed=False, prediction_snapshots_frozen_before_oracle=False,
                  protocol_completed=False, numerical_guard_failures=0, synthetic_fitting_runs=0,
                  optimizer_steps=0, formal_training_runs=0, checkpoint_reads=0, real_label_reads=0,
                  final_parameters_finite=False)
    try:
        # All initial unseen forwards occur before the first optimizer update.
        for seed in SEEDS:
            session = _TorchSession(torch, seed)
            sessions.append(session)
            initial_states.append({t['case_id']: session.scores(t) for t in config['tasks']})
        fit_tasks = [t for t in config['tasks'] if t['split'] == 'fit']
        for seed, session in zip(SEEDS, sessions):
            result['synthetic_fitting_runs'] += 1
            seed_logs = []
            logs.append(seed_logs)
            for step in range(steps):
                seed_logs.append(_fit_step(session, fit_tasks, seed, step, baseline_samples, main_samples))
                result['optimizer_calls'] += 1
                result['optimizer_steps'] += 1
        # All final unseen forwards occur after the last optimizer update.
        for seed, session, initial, seed_logs in zip(SEEDS, sessions, initial_states, logs):
            states = {t['case_id']: _comparison_scores(t, initial[t['case_id']], session.scores(t)) for t in config['tasks']}
            payload = dict(seed=seed, initialization_seed=seed, config_sha256=config_hash, score_states=states,
                           initial_parameter_sha256=session.initial_hash, final_parameter_sha256=session.weight_hash(),
                           fit_step_logs=seed_logs, updates_completed=steps, frozen_before_any_full_oracle=True)
            records.append(dict(payload=payload, freeze_sha256=_hash(payload)))
        _require(_hash(config) == config_hash, 'CONFIG_MUTATED')
        result.update(fit_freezes=records, prediction_snapshots_frozen_before_oracle=True,
                      final_parameters_finite=True)
        result.update(_evaluate(records, config, result))
        result.update(protocol_complete=True, protocol_completed=True,
                      status='COMPLETE_SYNTHETIC_FIT_DIAGNOSTIC_ONLY')
    except (ValueError, ArithmeticError) as exc:
        result.update(status='FAIL_NUMERICAL_OR_DOMAIN', scientific_status='NOT_EVALUATED_OR_INCOMPLETE',
                      failure=str(exc), fit_step_logs=logs, fit_freezes=records, numerical_guard_failures=1)
    finally:
        try:
            if sessions and all(hasattr(s, 'optimizer_steps') for s in sessions):
                result['optimizer_steps'] = sum(s.optimizer_steps for s in sessions)
                result['optimizer_calls'] = result['optimizer_steps']
            restored = [s.restore() for s in sessions]
            result['all_parameters_restored'] = all(restored)
            result['final_weights_discarded'] = True
        finally:
            torch.set_rng_state(rng)
            result['rng_restored'] = True
    return result


def run_synthetic_fit(torch):
    """Fixed formal synthetic entry. Caller enforces 1 GiB/1 CPU/one worker."""
    return _run_synthetic_fit(torch)
