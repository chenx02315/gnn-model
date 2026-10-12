"""Bounded synthetic-only streaming score-function estimator, NOT_TRAINER.

No readers, models, optimizers, global RNG, trajectories or online replay.
Independent pilot/main streams freeze separate risk/normalized-cost baselines.
"""
import hashlib
import json
import math
import random
import re

STATUS = 'DRAFT_SYNTHETIC_STREAMING_ESTIMATOR_NOT_TRAINER'
MAX_WORK = 20_000_000


def _require(ok, code):
    if not ok:
        raise ValueError('STREAMING_ESTIMATOR_' + code)


def _finite(value, code):
    _require(type(value) in (int, float), code)
    try:
        _require(math.isfinite(value), code)
    except OverflowError as exc:
        raise ValueError('STREAMING_ESTIMATOR_' + code) from exc


def _seed_pin(seed, case_id, phase):
    raw = json.dumps(['v6-synthetic-stream-v1', seed, case_id, phase],
                     separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return hashlib.sha256(raw).hexdigest()


def _sample(values, positives, costs, k, rng, gradients):
    n = len(values)
    remaining, gradient = list(range(n)), [0.] * n
    charged, hit = 0., False
    for _ in range(min(k, n)):
        shift = max(values[i] for i in remaining)
        weights = [math.exp(values[i] - shift) for i in remaining]
        denominator = math.fsum(weights)
        probabilities = [w / denominator for w in weights]
        draw, cumulative, position = rng.random(), 0., len(remaining) - 1
        for j, probability in enumerate(probabilities):
            cumulative += probability
            if draw < cumulative:
                position = j
                break
        chosen = remaining[position]
        if gradients:
            for index, probability in zip(remaining, probabilities):
                gradient[index] -= probability
            gradient[chosen] += 1.
        charged += costs[chosen]
        remaining.pop(position)
        if positives[chosen]:
            hit = True
            break
    return int(not hit), charged, gradient


def estimate(scores, positive_uids, costs, *, k, seed, case_id,
             pilot_samples=256, main_samples=16384):
    """Synthetic UID->score/cost maps only; n<=256, fixed temperature 1.

    Reject work bounds before creating RNGs or computing softmax. Costs are
    [1e-6,1e9], scores [-20,20], K 1..10, samples 1..65536 per phase.
    UID order is sorted. Case IDs are 1..64 ASCII letters/digits/underscore/dot/
    hyphen. Pilot means are frozen before independent main samples. Risk and
    cost gradients are never scalarized; cost baseline/gradient use C/B with
    B=min(K,n)*max(cost), with raw cost gradient restored by multiplying B.
    """
    _require(type(scores) is dict and 1 <= len(scores) <= 256
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
              'derived_seed_sha256': pins, 'seed_derivation': 'sha256_json_v6-synthetic-stream-v1',
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
