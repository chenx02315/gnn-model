"""DRAFT_SYNTHETIC_GRADIENT_NOT_TRAINER: bounded exact small-n oracle.

Synthetic scores/labels/costs only. Enumerates full Plackett-Luce permutations
at fixed temperature 1, reusing the frozen first-hit evaluation contract.
This is not an estimator for the real 1706-candidate task, a scalar loss,
an optimizer, a model, a data reader or online cost replay.
"""
import itertools
import math

from src.models.ranking_v6_first_hit_reference import evaluate_order

STATUS = 'DRAFT_SYNTHETIC_GRADIENT_NOT_TRAINER'
MAX_ACTIONS = 7
MAX_ABS_SCORE = 20
MAX_COST = 1e9
TEMPERATURE = 1


def _require(ok, code):
    if not ok:
        raise ValueError('FIRST_HIT_EXACT_GRADIENT_' + code)


def _number(value, code):
    _require(type(value) in (int, float), code)
    try:
        _require(math.isfinite(value), code)
    except OverflowError as exc:
        raise ValueError('FIRST_HIT_EXACT_GRADIENT_' + code) from exc


def enumerate_exact_gradient(scores, positive_uids, costs, k=10):
    """Return separate expected miss/cost and their score-gradient maps.

    scores and costs join exactly on 1..7 nonempty string UIDs. Positive UIDs
    are a unique subset. Scores have absolute value <=20, costs are positive
    and <=1e9, and k is an integer in 1..10. Each permutation contributes
    probability times objective times the log-probability score gradient.
    No risk/cost scalarization, update, prediction sorting or sampling occurs.
    """
    _require(type(scores) is dict and 1 <= len(scores) <= MAX_ACTIONS
             and all(type(uid) is str and uid for uid in scores), 'SCORES_SCHEMA')
    _require(type(costs) is dict and set(costs) == set(scores), 'COST_EXACT_JOIN')
    _require(type(k) is int and 1 <= k <= 10, 'K')
    for score in scores.values():
        _number(score, 'SCORE')
        _require(abs(score) <= MAX_ABS_SCORE, 'SCORE_BOUND')
    for cost in costs.values():
        _number(cost, 'COST')
        _require(0 < cost <= MAX_COST, 'COST_BOUND')
    uids = tuple(sorted(scores))
    # Validate the shared synthetic universe/positive subset before enumeration.
    evaluate_order(uids, positive_uids, costs, k=k)
    positives = frozenset(positive_uids)
    shift = max(scores.values())
    weights = {uid: math.exp(scores[uid] - shift) for uid in uids}
    # Bounded by 7e9; scale cost moments so positive subnormal fixture costs
    # are not rounded to zero by permutation probability multiplication.
    cost_scale = math.fsum(costs.values())
    probability_terms, miss_terms, cost_terms = [], [], []
    miss_gradient_terms = {uid: [] for uid in uids}
    cost_gradient_terms = {uid: [] for uid in uids}
    for order in itertools.permutations(uids):
        remaining = list(uids)
        probability = 1.
        log_gradient = {uid: [] for uid in uids}
        for chosen in order:
            denominator = math.fsum(weights[uid] for uid in remaining)
            probability *= weights[chosen] / denominator
            for uid in remaining:
                log_gradient[uid].append(int(uid == chosen) - weights[uid] / denominator)
            remaining.remove(chosen)
        evaluated = evaluate_order(order, positives, costs, k=k)
        miss = evaluated['miss_indicator']
        cost = evaluated['truncated_static_cost']
        probability_terms.append(probability)
        miss_terms.append(probability * miss)
        scaled_cost = cost / cost_scale
        cost_terms.append(probability * scaled_cost)
        for uid in uids:
            gradient = math.fsum(log_gradient[uid])
            miss_gradient_terms[uid].append(probability * miss * gradient)
            cost_gradient_terms[uid].append(probability * scaled_cost * gradient)
    mass = math.fsum(probability_terms)
    _require(math.isclose(mass, 1., rel_tol=0., abs_tol=1e-12), 'PROBABILITY_MASS')
    result = {'status': STATUS, 'action_count': len(uids), 'k': k, 'temperature': TEMPERATURE,
              'permutation_count': len(probability_terms), 'probability_mass': mass,
              'expected_miss_probability': math.fsum(miss_terms),
              'expected_truncated_static_cost': math.fsum(cost_terms) * cost_scale,
              'miss_score_gradient': {uid: math.fsum(miss_gradient_terms[uid]) for uid in uids},
              'cost_score_gradient': {uid: math.fsum(cost_gradient_terms[uid]) * cost_scale for uid in uids},
              'scalar_loss_implemented': False, 'training_estimator_implemented': False,
              'online_cost_replay': False}
    _require(all(math.isfinite(v) for v in [result['expected_miss_probability'],
             result['expected_truncated_static_cost'], *result['miss_score_gradient'].values(),
             *result['cost_score_gradient'].values()]), 'NONFINITE_RESULT')
    _require(result['expected_truncated_static_cost'] > 0, 'NONPOSITIVE_RESULT')
    return result
