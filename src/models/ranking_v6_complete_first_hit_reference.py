"""Bounded synthetic singleton PL complete-first-hit arithmetic, NOT_TRAINER.

Under a full Plackett-Luce ordering, stop at the sole positive and charge its
action too. Pairwise precedence gives C = c_p + sum_i c_i sigmoid(s_i-s_p).
The negative score derivative is c_i*q_i*(1-q_i); the positive derivative is
minus their sum. We evaluate the equivalent stable derivative expression to
avoid cancellation at score gaps of +/-40. There is no cutoff, miss penalty,
sampler, fitting, Torch, RNG, file access, remote access, or real-data reader.

The frozen normalization B_N = N*max(costs) depends ONLY on supplied fixed
costs, not scores. No derivative through costs or B_N is taken. Raw C lies in
[c_p, sum(costs)], normalized C in [0,1]. Negative raw gradient lies in
[0,c_i/4], positive raw gradient in [-sum_negative_costs/4,0]; divide by B_N
for normalized bounds. O(N) arithmetic and O(N) output memory, N<=1024.

Finite scores have abs<=20; fixed costs are strictly positive and <=1e9.
Additional fail-closed representability checks reject derivative underflow
for a negative coordinate (including normalized underflow), and underflow of
any mathematically nonzero gradient-bound endpoint. Subnormal double-rounding
that puts a derivative outside its represented bound is also rejected.
Conservatively, every negative raw/normalized derivative and every nonzero
bound endpoint must be a normal float (>= sys.float_info.min in magnitude).
This rejects some mathematically representable subnormal cases too, avoiding
claims of reliable derivative rounding in the subnormal region.
A structurally
zero gradient for the supported N=1 case is not an underflow error.
The explicit synthetic_only=True declaration is a caller scope gate, not a
provenance detector. Results establish objective arithmetic, not online cost.
This is a deterministic analytic kernel, not the historical stochastic
estimator. No R@K is computed or guaranteed and no fit/update is performed.
"""
import math
import re
import sys

STATUS = 'DRAFT_SYNTHETIC_COMPLETE_FIRST_HIT_NOT_TRAINER'
MAX_ACTIONS = 1024
_UID = re.compile(r'[A-Za-z0-9_.-]{1,64}')


def _require(ok, code):
    if not ok:
        raise ValueError('COMPLETE_FIRST_HIT_' + code)


def _number(value, *, score):
    _require(type(value) in (int, float), 'SCORE' if score else 'COST')
    try:
        valid = math.isfinite(value) and (abs(value) <= 20 if score else 0 < value <= 1e9)
    except OverflowError:
        valid = False
    _require(valid, 'SCORE_DOMAIN' if score else 'COST_DOMAIN')


def evaluate(scores, positive_uids, costs, *, synthetic_only=False):
    """Exact expected full first-hit charge and raw/normalized score gradients.

    UID dictionaries must join exactly; insertion order is preserved without
    sorting, so the entire kernel remains O(N). Inputs are never modified.
    """
    _require(synthetic_only is True, 'SYNTHETIC_ONLY_GATE')
    _require(type(scores) is dict and 1 <= len(scores) <= MAX_ACTIONS, 'SCORES_SCHEMA')
    _require(all(type(u) is str and _UID.fullmatch(u) is not None for u in scores), 'UID')
    _require(type(costs) is dict and set(costs) == set(scores), 'COST_JOIN')
    _require(type(positive_uids) in (set, frozenset, tuple, list), 'POSITIVES_SCHEMA')
    _require(len(positive_uids) == 1 and all(type(u) is str and u in scores for u in positive_uids),
             'SINGLETON_POSITIVE_JOIN')
    for value in scores.values():
        _number(value, score=True)
    for value in costs.values():
        _number(value, score=False)
    positive = next(iter(positive_uids))
    n = len(scores)
    bound = n * max(costs.values())
    gradient, normalized_gradient, contributions = {}, {}, [float(costs[positive])]
    negative_costs = []
    for uid, score in scores.items():
        if uid == positive:
            continue
        delta = score - scores[positive]
        z = math.exp(-abs(delta))
        probability = 1 / (1 + z) if delta >= 0 else z / (1 + z)
        factor = z / ((1 + z) ** 2)
        gradient[uid] = costs[uid] * factor
        # Compute in normalized units directly: first rounding the raw
        # gradient then dividing can hide true normalized underflow.
        normalized_gradient[uid] = (costs[uid] / bound) * factor
        _require(gradient[uid] > 0, 'NUMERIC_UNDERFLOW')
        contributions.append(costs[uid] * probability)
        negative_costs.append(costs[uid])
    gradient[positive] = -math.fsum(gradient.values())
    normalized_gradient[positive] = -math.fsum(normalized_gradient.values())
    # Restore caller coordinate order without an O(N log N) sort.
    gradient = {uid: gradient[uid] for uid in scores}
    normalized_gradient = {uid: normalized_gradient[uid] for uid in scores}
    _require(all(normalized_gradient[u] > 0 for u in scores if u != positive),
             'NORMALIZED_NUMERIC_UNDERFLOW')
    _require(all(gradient[u] >= sys.float_info.min and normalized_gradient[u] >= sys.float_info.min
                 for u in scores if u != positive), 'GRADIENT_SUBNORMAL_REPRESENTABILITY')
    raw = math.fsum(contributions)
    normalized = raw / bound
    negative_sum = math.fsum(negative_costs)
    raw_bounds = {u: [-negative_sum / 4, 0.] if u == positive else
                  [0., costs[u] / 4] for u in scores}
    normalized_bounds = {u: [-negative_sum / (4 * bound), 0.] if u == positive else
                         [0., (costs[u] / bound) / 4] for u in scores}
    if n > 1:
        _require(raw_bounds[positive][0] < 0 and normalized_bounds[positive][0] < 0
                 and all(raw_bounds[u][1] > 0 and normalized_bounds[u][1] > 0
                         for u in scores if u != positive), 'GRADIENT_BOUND_NUMERIC_UNDERFLOW')
        _require(all(abs(endpoint) >= sys.float_info.min
                     for bounds in (raw_bounds, normalized_bounds)
                     for endpoints in bounds.values() for endpoint in endpoints if endpoint != 0),
                 'GRADIENT_BOUND_SUBNORMAL_REPRESENTABILITY')
    _require(all(raw_bounds[u][0] <= gradient[u] <= raw_bounds[u][1]
                 and normalized_bounds[u][0] <= normalized_gradient[u] <= normalized_bounds[u][1]
                 for u in scores), 'GRADIENT_BOUND_REPRESENTABILITY')
    return {
        'status': STATUS, 'scope': 'synthetic_singleton_fixed_additive_costs_only',
        'synthetic_only': True, 'n': n, 'positive_uid': positive,
        'complete_first_hit_cost': raw, 'normalized_complete_first_hit_cost': normalized,
        'cost_score_gradient': gradient, 'normalized_cost_score_gradient': normalized_gradient,
        'cost_normalization_B': bound, 'normalization_depends_on_scores': False,
        'normalization_derivative_taken': False,
        'raw_cost_bounds': [float(costs[positive]), math.fsum(costs.values())],
        'normalized_cost_bounds': [0., 1.],
        'raw_score_gradient_bounds': raw_bounds,
        'normalized_score_gradient_bounds': normalized_bounds,
        'pairwise_terms': n - 1, 'work_bound': n, 'time_complexity': 'O(n)',
        'memory_complexity': 'O(n)', 'positive_cost_is_unavoidable_constant': True,
        'exact_score_gradient': True, 'online_cost_replay': False,
        'training_estimator_implemented': False, 'model_fitting_implemented': False,
        'stochastic_estimator_implemented': False, 'r_at_k_computed': False,
    }
