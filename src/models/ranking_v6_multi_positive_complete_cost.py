"""Synthetic-only complete-first-positive PL cost arithmetic; NOT_TRAINER.

Let w_i=exp(s_i-max(s)), P=sum_positive(w_i), and a=sum_positive(c_i*w_i)/P.
An exponential race gives Pr(negative i precedes every positive)=w_i/(w_i+P)
and Pr(j is the first positive)=w_j/P. Therefore the full charge, including
the first positive, is C=a+sum_negative(c_i*w_i/(w_i+P)). Its score derivative
is t_i=c_i*w_i*P/(w_i+P)^2 for a negative i and
(w_j/P)*(c_j-a-sum_negative(t_i)) for a positive j. Positive derivatives
can have EITHER sign when positive costs differ. Costs and B=N*max(c) are
fixed, so normalized derivatives are raw derivatives divided by B.

O(N) time and memory, 1<=N<=1024; no enumeration, I/O, Torch, RNG, optimizer,
trainer, remote access or data loading. synthetic_only=True is a declaration,
not a provenance detector. No online cost, fit quality or R@K claim is made.
Scores are finite builtin numbers in [-20,20], costs in (0,1e9]. The weight
range is safe in binary64, but arbitrary tiny costs need not be. Conservatively
reject subnormal weighted-cost terms and negative derivatives, including in
normalized units. Floating point still rounds, particularly when positive
derivatives cancel; a returned zero positive derivative is NOT proof of a
mathematical zero, and this is not an all-underflow/all-cancellation guarantee.
"""
import math
import re
import sys

STATUS = 'DRAFT_SYNTHETIC_MULTI_POSITIVE_COMPLETE_COST_NOT_TRAINER'
MAX_ACTIONS = 1024
_UID = re.compile(r'[A-Za-z0-9_.-]{1,64}')


def _require(condition, code):
    if not condition:
        raise ValueError('MULTI_POSITIVE_COMPLETE_COST_' + code)


def _number(value, *, score):
    _require(type(value) in (int, float), 'SCORE' if score else 'COST')
    try:
        valid = math.isfinite(value) and (abs(value) <= 20 if score else 0 < value <= 1e9)
    except OverflowError:
        valid = False
    _require(valid, 'SCORE_DOMAIN' if score else 'COST_DOMAIN')


def _normal_positive(value):
    _require(math.isfinite(value) and value >= sys.float_info.min,
             'NUMERIC_REPRESENTABILITY')


def evaluate(scores, positive_uids, costs, *, synthetic_only=False):
    """Return deterministic cost and analytic score gradients; never mutate input.

    Exact builtin dictionaries and builtin positive containers are required.
    Coordinate order follows scores, not positive-container iteration order.
    No scope parameter exists: unknown keyword/scope arguments fail closed.
    """
    _require(synthetic_only is True, 'SYNTHETIC_ONLY_GATE')
    _require(type(scores) is dict and 1 <= len(scores) <= MAX_ACTIONS, 'SCORES_SCHEMA')
    _require(all(type(u) is str and _UID.fullmatch(u) is not None for u in scores), 'UID')
    _require(type(costs) is dict and set(costs) == set(scores), 'COST_JOIN')
    _require(type(positive_uids) in (set, frozenset, tuple, list), 'POSITIVES_SCHEMA')
    _require(1 <= len(positive_uids) <= len(scores) and
             all(type(u) is str and u in scores for u in positive_uids), 'POSITIVE_JOIN')
    positives = set(positive_uids)
    _require(len(positives) == len(positive_uids), 'DUPLICATE_POSITIVE')
    for value in scores.values():
        _number(value, score=True)
    for value in costs.values():
        _number(value, score=False)
    n = len(scores)
    bound = n * max(costs.values())
    _normal_positive(bound)
    max_score = max(scores.values())
    weights = {u: math.exp(s - max_score) for u, s in scores.items()}
    positive_weight = math.fsum(weights[u] for u in scores if u in positives)
    shares = {u: weights[u] / positive_weight for u in scores if u in positives}
    raw_positive_terms = [costs[u] * shares[u] for u in shares]
    norm_positive_terms = [(costs[u] / bound) * shares[u] for u in shares]
    for value in raw_positive_terms + norm_positive_terms:
        _normal_positive(value)
    # An anchored mean makes equal-cost positives exactly constant, and avoids
    # rounding a weighted mean just below its minimum supplied cost.
    minimum_positive = min(costs[u] for u in positives)
    positive_mean = minimum_positive + math.fsum(
        (costs[u] - minimum_positive) * shares[u] for u in shares)
    normalized_positive_mean = minimum_positive / bound + math.fsum(
        ((costs[u] - minimum_positive) / bound) * shares[u] for u in shares)
    raw_terms, norm_terms = [positive_mean], [normalized_positive_mean]
    gradient, normalized_gradient = {}, {}
    for u in scores:
        if u in positives:
            continue
        denominator = weights[u] + positive_weight
        probability = weights[u] / denominator
        factor = probability * (positive_weight / denominator)
        raw_term, norm_term = costs[u] * probability, (costs[u] / bound) * probability
        gradient[u] = costs[u] * factor
        normalized_gradient[u] = (costs[u] / bound) * factor
        for value in (raw_term, norm_term, gradient[u], normalized_gradient[u]):
            _normal_positive(value)
        raw_terms.append(raw_term)
        norm_terms.append(norm_term)
    negative_derivative = math.fsum(gradient.values())
    normalized_negative_derivative = math.fsum(normalized_gradient.values())
    # Center on the dominant positive's cost before summing. Subtracting the
    # already rounded positive_mean can erase a small, genuine derivative
    # when that positive has almost all the mass (e.g. scores -20/+20).
    # Cost differences are formed BEFORE normalization, not from two rounded
    # cost/B values. This stays O(N), without a quadratic pairwise expansion.
    anchor = costs[max(shares, key=shares.get)]
    centered_mean = math.fsum((costs[u] - anchor) * shares[u] for u in shares)
    normalized_centered_mean = math.fsum(
        ((costs[u] - anchor) / bound) * shares[u] for u in shares)
    for u in shares:
        gradient[u] = shares[u] * math.fsum(
            (costs[u] - anchor, -centered_mean, -negative_derivative))
        normalized_gradient[u] = shares[u] * math.fsum(
            ((costs[u] - anchor) / bound, -normalized_centered_mean,
             -normalized_negative_derivative))
    raw, normalized = math.fsum(raw_terms), math.fsum(norm_terms)
    lower = float(min(costs[u] for u in positives))
    upper = math.fsum(costs.values())
    _require(all(math.isfinite(v) for v in (raw, normalized, upper, *gradient.values(),
                                          *normalized_gradient.values())), 'NONFINITE_RESULT')
    _require(all(v == 0. or abs(v) >= sys.float_info.min
                 for values in (gradient, normalized_gradient) for v in values.values()),
             'GRADIENT_SUBNORMAL_REPRESENTABILITY')
    _require(lower <= raw <= upper and 0 < normalized <= 1, 'COST_BOUND_REPRESENTABILITY')
    return {
        'status': STATUS, 'scope': 'synthetic_multi_positive_fixed_additive_costs_only',
        'synthetic_only': True, 'n': n, 'positive_uids': tuple(u for u in scores if u in positives),
        'positive_count': len(positives), 'complete_first_hit_cost': raw,
        'normalized_complete_first_hit_cost': normalized,
        'cost_score_gradient': {u: gradient[u] for u in scores},
        'normalized_cost_score_gradient': {u: normalized_gradient[u] for u in scores},
        'cost_normalization_B': bound, 'normalization_depends_on_scores': False,
        'normalization_derivative_taken': False, 'raw_cost_bounds': [lower, upper],
        'normalized_cost_bounds': [lower / bound, upper / bound],
        'negative_precedence_terms': n - len(positives), 'work_bound': n,
        'time_complexity': 'O(n)', 'memory_complexity': 'O(n)',
        'positive_cost_is_unavoidable_constant': len(positives) == 1,
        'exact_score_gradient': True, 'online_cost_replay': False,
        'training_estimator_implemented': False, 'model_fitting_implemented': False,
        'stochastic_estimator_implemented': False, 'r_at_k_computed': False,
    }
