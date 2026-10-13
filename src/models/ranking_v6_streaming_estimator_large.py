"""Bounded synthetic-only large-domain estimator, NOT_TRAINER.

Derived from ranking_v6_streaming_estimator.py (n<=256) without modifying it.
Only the domain and explicit v2-large-domain RNG namespace differ; independent
pilot/main math, bounds, normalization and streaming sampling are preserved.
No readers, models, optimizers, global RNG, trajectories or online replay.
"""
import hashlib
import json
import math
import random
import re

from .ranking_v6_streaming_estimator import _finite, _require, _sample

STATUS = 'DRAFT_SYNTHETIC_STREAMING_ESTIMATOR_NOT_TRAINER'
MAX_ACTIONS = 1024
MAX_WORK = 20_000_000
RNG_NAMESPACE = 'v6-synthetic-stream-v2-large-domain'


def _seed_pin(seed, case_id, phase):
    raw = json.dumps([RNG_NAMESPACE, seed, case_id, phase],
                     separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return hashlib.sha256(raw).hexdigest()


def estimate(scores, positive_uids, costs, *, k, seed, case_id,
             pilot_samples=256, main_samples=16384):
    """Synthetic UID->score/cost maps only; n<=1024, temperature 1.

    Locally validate the larger domain before RNG or softmax; never call the
    old n<=256 entrypoint or change its globals. All other bounds and math
    match that source: costs [1e-6,1e9], scores [-20,20], K 1..10,
    samples 1..65536 per phase, and n*min(K,n)*(pilot+main)<=20,000,000.
    Pilot means freeze before independent main samples. Separate risk and
    normalized-cost gradients use B=min(K,n)*max(cost); raw cost gradients
    are restored by multiplying B. No trajectories are retained.
    """
    _require(type(scores) is dict and 1 <= len(scores) <= MAX_ACTIONS
             and all(type(u) is str and bool(u) for u in scores), 'SCORES_SCHEMA')
    _require(type(costs) is dict and set(costs) == set(scores), 'COST_EXACT_JOIN')
    _require(type(positive_uids) in (set, frozenset, list, tuple)
             and all(type(u) is str and bool(u) for u in positive_uids), 'POSITIVES')
    _require(len(positive_uids) == len(set(positive_uids))
             and set(positive_uids) <= set(scores), 'POSITIVE_JOIN')
    _require(type(k) is int and 1 <= k <= 10, 'K')
    _require(type(seed) is int and 0 <= seed <= 2**32 - 1, 'SEED')
    _require(type(case_id) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', case_id) is not None,
             'CASE_ID')
    for count in (pilot_samples, main_samples):
        _require(type(count) is int and 1 <= count <= 65536, 'SAMPLES')
    n = len(scores)
    work = n * min(k, n) * (pilot_samples + main_samples)
    _require(work <= MAX_WORK, 'WORK_BOUND')
    for score in scores.values():
        _finite(score, 'SCORE')
        _require(abs(score) <= 20, 'SCORE_BOUND')
    for cost in costs.values():
        _finite(cost, 'COST')
        _require(1e-6 <= cost <= 1e9, 'COST_BOUND')
    uids = sorted(scores)
    values, charges = [scores[u] for u in uids], [costs[u] for u in uids]
    positives = [u in positive_uids for u in uids]
    bound = min(k, n) * max(charges)
    pins = {phase: _seed_pin(seed, case_id, phase) for phase in ('pilot', 'main')}
    pilot_rng, main_rng = (random.Random(int(pins[phase], 16)) for phase in ('pilot', 'main'))
    pilot_risk = pilot_cost = 0.
    for _ in range(pilot_samples):
        risk, cost, _ = _sample(values, positives, charges, k, pilot_rng, False)
        pilot_risk += risk
        pilot_cost += cost / bound
    baseline_risk, baseline_cost = pilot_risk / pilot_samples, pilot_cost / pilot_samples
    risk_sum = cost_sum = 0.
    risk_gradient, cost_gradient = [0.] * n, [0.] * n
    for _ in range(main_samples):
        risk, cost, gradient = _sample(values, positives, charges, k, main_rng, True)
        risk_sum += risk
        cost_sum += cost
        risk_residual, cost_residual = risk - baseline_risk, cost / bound - baseline_cost
        for index in range(n):
            risk_gradient[index] += risk_residual * gradient[index]
            cost_gradient[index] += cost_residual * gradient[index]
    risk_gradient = [g / main_samples for g in risk_gradient]
    cost_gradient = [g / main_samples for g in cost_gradient]
    result = {'status': STATUS, 'synthetic_only': True, 'action_count': n, 'k': k,
              'temperature': 1, 'seed': seed, 'case_id': case_id,
              'pilot_samples': pilot_samples, 'main_samples': main_samples,
              'derived_seed_sha256': pins, 'seed_derivation': 'sha256_json_' + RNG_NAMESPACE,
              'work_bound': work, 'max_work': MAX_WORK, 'cost_normalization_B': bound,
              'baseline_risk': baseline_risk, 'baseline_normalized_cost': baseline_cost,
              'baselines_frozen_before_main': True,
              'expected_miss_probability': risk_sum / main_samples,
              'expected_truncated_static_cost': cost_sum / main_samples,
              'miss_score_gradient': dict(zip(uids, risk_gradient)),
              'normalized_cost_score_gradient': dict(zip(uids, cost_gradient)),
              'cost_score_gradient': dict(zip(uids, (g * bound for g in cost_gradient))),
              'scalar_loss_implemented': False, 'trainer_implemented': False,
              'real_data_access': False, 'online_cost_replay': False, 'trajectories_retained': False}
    _require(all(math.isfinite(v) for v in [baseline_risk, baseline_cost, bound,
             result['expected_miss_probability'], result['expected_truncated_static_cost'],
             *risk_gradient, *cost_gradient, *result['cost_score_gradient'].values()]), 'NONFINITE_RESULT')
    return result
