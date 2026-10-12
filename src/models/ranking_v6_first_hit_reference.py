"""DRAFT_DESIGN_NOT_TRAINER: pure synthetic first-hit reference arithmetic.

Inputs must be synthetic fixtures, never real labels or model predictions.
Static additive fixture costs do not establish online wall-clock replay.
No reader, scorer, optimization, sampling or training implementation is here.
"""
import math

STATUS = 'DRAFT_DESIGN_NOT_TRAINER'
WEIGHT_SUM_ABS_TOL = 1e-12


def _require(ok, code):
    if not ok:
        raise ValueError('FIRST_HIT_REFERENCE_' + code)


def _positive_number(value, code):
    _require(type(value) in (int, float), code)
    try:
        _require(math.isfinite(value) and value > 0, code)
    except OverflowError as exc:
        raise ValueError('FIRST_HIT_REFERENCE_' + code) from exc


def evaluate_order(order, positive_uids, costs, k=10):
    """Evaluate a full synthetic permutation; include the hit action's cost.

    Costs join exactly to the full permutation; positives are a subset of its
    universe. An exhausted/no-hit list charges all actions tried up to k.
    Compare objective_key lexicographically, never cost alone or a scalar sum.
    """
    _require(type(order) in (list, tuple) and bool(order)
             and all(type(uid) is str and bool(uid) for uid in order), 'ORDER')
    _require(len(order) == len(set(order)), 'DUPLICATE_UID')
    _require(type(positive_uids) in (set, frozenset, list, tuple)
             and all(type(uid) is str and bool(uid) for uid in positive_uids), 'POSITIVES')
    _require(len(positive_uids) == len(set(positive_uids))
             and set(positive_uids) <= set(order), 'POSITIVE_JOIN')
    _require(type(costs) is dict and set(costs) == set(order), 'COST_EXACT_JOIN')
    _require(type(k) is int and k > 0, 'K')
    for value in costs.values():
        _positive_number(value, 'COST')
    positives, tried, hit_rank = set(positive_uids), [], None
    for rank, uid in enumerate(order[:k], 1):
        tried.append(costs[uid])
        if uid in positives:
            hit_rank = rank
            break
    try:
        cost = math.fsum(tried)
    except OverflowError as exc:
        raise ValueError('FIRST_HIT_REFERENCE_COST_OVERFLOW') from exc
    _require(math.isfinite(cost), 'COST_OVERFLOW')
    miss = int(hit_rank is None)
    return {'status': STATUS, 'hit': not bool(miss), 'miss_indicator': miss,
            'first_hit_rank': hit_rank, 'tried_count': len(tried), 'k': k,
            'truncated_static_cost': cost, 'objective_key': (miss, cost),
            'online_cost_replay': False}


def aggregate_distribution(weighted_orders, positive_uids, costs, k=10):
    """Exact finite expectation over supplied (weight, synthetic order) pairs.

    Weights must already sum to one within fixed absolute tolerance 1e-12.
    This is arithmetic over a fixture, not a stochastic training estimator.
    Each order must be a complete permutation of the same costs universe.
    """
    _require(type(weighted_orders) in (list, tuple) and bool(weighted_orders), 'DISTRIBUTION')
    weights, results = [], []
    for item in weighted_orders:
        _require(type(item) in (list, tuple) and len(item) == 2, 'WEIGHTED_ORDER')
        weight, order = item
        _positive_number(weight, 'WEIGHT')
        _require(weight <= 1, 'WEIGHT')
        weights.append(weight)
        results.append(evaluate_order(order, positive_uids, costs, k=k))
    total = math.fsum(weights)
    _require(math.isclose(total, 1., rel_tol=0., abs_tol=WEIGHT_SUM_ABS_TOL), 'WEIGHT_SUM')
    # Only correct the already validated floating-point sum; do not accept
    # unnormalized distributions or select a data-dependent tolerance.
    try:
        risk = math.fsum(w*r['miss_indicator'] for w, r in zip(weights, results)) / total
        try:
            # Preserve small weighted terms across widely separated scales.
            cost = math.fsum(w*r['truncated_static_cost'] for w, r in zip(weights, results)) / total
        except OverflowError:
            cost = math.inf
        if not math.isfinite(cost) or cost <= 0:
            # Recover overflowing convex sums or products rounded down to zero.
            maximum = max(r['truncated_static_cost'] for r in results)
            scaled_mean = math.fsum(w*(r['truncated_static_cost'] / maximum)
                                    for w, r in zip(weights, results)) / total
            _require(math.isfinite(scaled_mean) and 0 <= scaled_mean <= 1, 'EXPECTATION_OVERFLOW')
            cost = maximum * scaled_mean
    except OverflowError as exc:
        raise ValueError('FIRST_HIT_REFERENCE_EXPECTATION_OVERFLOW') from exc
    _require(math.isfinite(risk) and math.isfinite(cost) and cost > 0, 'EXPECTATION_OVERFLOW')
    return {'status': STATUS, 'distribution_size': len(results), 'weight_sum': total, 'k': k,
            'expected_miss_probability': risk, 'expected_truncated_static_cost': cost,
            'objective_key': (risk, cost), 'comparison': 'lexicographic_miss_then_cost',
            'online_cost_replay': False, 'training_estimator_implemented': False}
