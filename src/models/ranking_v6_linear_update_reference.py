"""Synthetic shared-linear Jacobian and user-specified cost-step proposals.

NOT_TRAINER / NOT_AUTOMATIC_OPTIMIZER: no readers, actual model, training,
step search, threshold selection, candidate selection or update application.
"""
import math

from src.models.ranking_v6_first_hit_exact_gradient import enumerate_exact_gradient
from src.models.ranking_v6_risk_macro_reference import aggregate_families

STATUS = 'SYNTHETIC_LINEAR_UPDATE_REFERENCE_NOT_TRAINER'
SCHEMA = {'features', 'positives', 'costs', 'cost_scale'}


def _require(ok, code):
    if not ok:
        raise ValueError('LINEAR_UPDATE_REFERENCE_' + code)


def _number(value, code):
    _require(type(value) in (int, float), code)
    try:
        _require(math.isfinite(value), code)
    except OverflowError as exc:
        raise ValueError('LINEAR_UPDATE_REFERENCE_' + code) from exc


def _validated_scores(families, parameters, k):
    _require(type(parameters) is dict and 1 <= len(parameters) <= 8
             and all(type(p) is str and p for p in parameters), 'PARAMETERS')
    for value in parameters.values():
        _number(value, 'PARAMETER')
        _require(abs(value) <= 5, 'PARAMETER_BOUND')
    _require(type(k) is int and 1 <= k <= 10, 'K')
    _require(type(families) is dict and 1 <= len(families) <= 6
             and all(type(f) is str and f for f in families), 'FAMILIES')
    scores = {}
    for name in sorted(families):
        family = families[name]
        _require(type(family) is dict and set(family) == SCHEMA, 'FAMILY_SCHEMA')
        features, costs, positives = family['features'], family['costs'], family['positives']
        _require(type(features) is dict and 1 <= len(features) <= 7
                 and all(type(uid) is str and uid for uid in features), 'FEATURES')
        _require(type(costs) is dict and set(costs) == set(features), 'COST_JOIN')
        _require(type(positives) in (set, frozenset, list, tuple)
                 and all(type(uid) is str and uid for uid in positives)
                 and len(positives) == len(set(positives)) and set(positives) <= set(features), 'POSITIVE_JOIN')
        _number(family['cost_scale'], 'COST_SCALE')
        _require(0 < family['cost_scale'] <= 1e10, 'COST_SCALE_BOUND')
        scores[name] = {}
        for uid in sorted(features):
            vector = features[uid]
            _require(type(vector) is dict and set(vector) == set(parameters), 'PARAMETER_JOIN')
            for value in vector.values():
                _number(value, 'FEATURE')
                _require(abs(value) <= 2, 'FEATURE_BOUND')
            _number(costs[uid], 'COST')
            # Preserve the frozen exact-gradient domain, not a wider promise.
            _require(0 < costs[uid] <= 1e9, 'COST_BOUND')
            score = math.fsum(parameters[p] * vector[p] for p in sorted(parameters))
            _require(math.isfinite(score) and abs(score) <= 20, 'SCORE_BOUND')
            scores[name][uid] = score
    return scores


def evaluate_linear(families, parameters, k):
    """Map exact synthetic score gradients into common linear parameters.

    Validate every family and derived score before any exact enumeration.
    Inputs use finite real int/float values (never bool), frozen synthetic
    fitting cost scales, and 1..7 candidate fixtures per family.
    """
    scores = _validated_scores(families, parameters, k)
    metrics = {}
    for name in sorted(families):
        family = families[name]
        evaluated = enumerate_exact_gradient(scores[name], family['positives'], family['costs'], k=k)
        # The frozen exact oracle validates mass within 1e-12 of one. Correct
        # only its floating-point accumulation, for all moments consistently;
        # this does not change the mathematical PL target or fit a normalizer.
        mass = evaluated['probability_mass']
        _require(math.isfinite(mass) and mass > 0
                 and math.isclose(mass, 1., rel_tol=0., abs_tol=1e-12), 'ORACLE_MASS')
        risk_gradient, cost_gradient = {}, {}
        for parameter in sorted(parameters):
            risk_gradient[parameter] = math.fsum((evaluated['miss_score_gradient'][uid] / mass)
                                                * family['features'][uid][parameter] for uid in scores[name])
            cost_gradient[parameter] = math.fsum((evaluated['cost_score_gradient'][uid] / mass)
                                                * family['features'][uid][parameter] for uid in scores[name])
        metrics[name] = {'risk': evaluated['expected_miss_probability'] / mass,
                         'raw_cost': evaluated['expected_truncated_static_cost'] / mass,
                         'cost_scale': family['cost_scale'], 'risk_gradient': risk_gradient,
                         'cost_gradient': cost_gradient}
    macro = aggregate_families(metrics)
    return {'status': STATUS, 'parameters': dict(parameters), 'family_metrics': metrics,
            'macro_metrics': macro, 'synthetic_only': True, 'trainer_implemented': False,
            'automatic_optimizer_implemented': False, 'update_applied': False}


def propose_cost_steps(families, parameters, k, steps):
    """Return all fixed user-provided steps, without choosing/applying any.

    Steps must be 1..4 unique strictly ascending positive values <=1. A proposal
    is parameters-step*macro_normalized_cost_gradient. Any parameter/score
    domain violation is rejected, never clipped. This is not a risk guarantee.
    """
    _require(type(steps) is list and 1 <= len(steps) <= 4, 'STEPS')
    for step in steps:
        _number(step, 'STEP')
        _require(0 < step <= 1, 'STEP_BOUND')
    _require(all(a < b for a, b in zip(steps, steps[1:])), 'STEP_ORDER')
    current = evaluate_linear(families, parameters, k)
    gradient = current['macro_metrics']['macro_normalized_cost_gradient']
    proposals = [{p: parameters[p] - step * gradient[p] for p in sorted(parameters)} for step in steps]
    # Check all derived bounds before enumerating any proposed candidate.
    for proposal in proposals:
        _validated_scores(families, proposal, k)
    candidates = {f'step_{index}': evaluate_linear(families, proposal, k)
                  for index, proposal in enumerate(proposals)}
    return {'status': STATUS, 'current': current, 'candidates': candidates,
            'synthetic_only': True, 'steps': list(steps), 'steps_user_provided': True,
            'candidate_selected': False, 'update_applied': False,
            'trainer_implemented': False, 'automatic_optimizer_implemented': False,
            'risk_guarantee_claim': False}
