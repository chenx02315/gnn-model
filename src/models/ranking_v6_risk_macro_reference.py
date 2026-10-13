"""Synthetic family-macro and risk-constrained candidate selection reference.

No readers, real caps, candidate evaluation, confidence bounds, optimization,
recovery or training. Fixture cost scales and family risk caps are predeclared.
"""
import math

STATUS = 'SYNTHETIC_RISK_CONSTRAINED_REFERENCE_NOT_OPTIMIZER'
METRICS = {'risk', 'raw_cost', 'cost_scale'}
FULL = METRICS | {'risk_gradient', 'cost_gradient'}


def _require(ok, code):
    if not ok:
        raise ValueError('RISK_MACRO_REFERENCE_' + code)


def _finite(value, code):
    _require(type(value) in (int, float), code)
    try:
        _require(math.isfinite(value), code)
    except OverflowError as exc:
        raise ValueError('RISK_MACRO_REFERENCE_' + code) from exc


def _mean(values):
    # Preserve small signed residuals; divide first only for sum overflow.
    try:
        return math.fsum(values) / len(values)
    except OverflowError:
        return math.fsum(v / len(values) for v in values)


def _validate(families, *, gradients_required):
    _require(type(families) is dict and 1 <= len(families) <= 6
             and all(type(name) is str and name for name in families), 'FAMILIES')
    parameters = None
    for family in families.values():
        _require(type(family) is dict and (set(family) == FULL if gradients_required
                 else set(family) in (METRICS, FULL)), 'FAMILY_SCHEMA')
        for field in METRICS:
            _finite(family[field], 'METRIC')
        _require(0 <= family['risk'] <= 1, 'RISK')
        _require(0 < family['raw_cost'] <= 1e10 and 0 < family['cost_scale'] <= 1e10, 'COST_SCALE')
        normalized = family['raw_cost'] / family['cost_scale']
        _require(math.isfinite(normalized) and normalized > 0, 'NORMALIZED_COST')
        if set(family) == FULL:
            risk, cost = family['risk_gradient'], family['cost_gradient']
            _require(type(risk) is dict and type(cost) is dict and 1 <= len(risk) <= 128
                     and set(risk) == set(cost) and all(type(p) is str and p for p in risk), 'GRADIENT_JOIN')
            if parameters is None:
                parameters = set(risk)
            _require(set(risk) == parameters, 'PARAMETER_JOIN')
            for value in (*risk.values(), *cost.values()):
                _finite(value, 'GRADIENT')
                _require(abs(value) <= 1e10, 'GRADIENT_BOUND')
            _require(all(math.isfinite(v / family['cost_scale']) for v in cost.values()),
                     'NORMALIZED_GRADIENT')
    return parameters


def _metrics(families):
    return {'macro_risk': _mean([v['risk'] for v in families.values()]),
            'macro_normalized_cost': _mean([v['raw_cost'] / v['cost_scale'] for v in families.values()])}


def aggregate_families(families):
    """Equal family weights, separate risk/raw-cost-scale-normalized gradients.

    Fixed full schema; parameter maps join exactly across every family.
    Cost scales are frozen synthetic fitting scales, not candidate counts or
    a post-hoc normalizer. Raw cost gradients are divided by the family scale.
    """
    parameters = _validate(families, gradients_required=True)
    result = {'status': STATUS, 'family_count': len(families), 'family_weight': 1 / len(families),
              **_metrics(families),
              'macro_risk_gradient': {p: _mean([f['risk_gradient'][p] for f in families.values()])
                                      for p in sorted(parameters)},
              'macro_normalized_cost_gradient': {
                  p: _mean([f['cost_gradient'][p] / f['cost_scale'] for f in families.values()])
                  for p in sorted(parameters)},
              'synthetic_only': True, 'optimizer_implemented': False,
              'confidence_bound_claim': False, 'global_guarantee_claim': False}
    return result


def select_feasible_update(current, candidates, risk_caps):
    """Choose an evaluated synthetic candidate, never evaluate or apply it.

    States are family->metrics dictionaries (optionally full gradient schema).
    Candidates are nonempty-string-ID->state dictionaries; empty is allowed.
    All scales/family sets must match current. Caps are predeclared fixture
    numbers, not confidence bounds. Strict macro-cost improvement and every
    individual family risk cap are required. Current infeasibility blocks
    selection, not an authorization to recover or optimize it.
    """
    _validate(current, gradients_required=False)
    _require(type(candidates) is dict and all(type(c) is str and c for c in candidates), 'CANDIDATES')
    _require(type(risk_caps) is dict and set(risk_caps) == set(current), 'CAP_JOIN')
    for cap in risk_caps.values():
        _finite(cap, 'CAP')
        _require(0 <= cap <= 1, 'CAP')
    for state in candidates.values():
        _validate(state, gradients_required=False)
        _require(set(state) == set(current), 'CANDIDATE_FAMILY_JOIN')
        _require(all(state[f]['cost_scale'] == current[f]['cost_scale'] for f in current),
                 'FROZEN_SCALE')
    current_metrics = _metrics(current)
    selected_id, selected, decision = None, current, 'NO_ACCEPTABLE_UPDATE'
    if any(current[f]['risk'] > risk_caps[f] for f in current):
        decision = 'BLOCKED_INFEASIBLE_CURRENT'
    else:
        best = None
        for candidate_id, state in candidates.items():
            if any(state[f]['risk'] > risk_caps[f] for f in current):
                continue
            cost = _metrics(state)['macro_normalized_cost']
            if cost >= current_metrics['macro_normalized_cost']:
                continue
            key = (cost, candidate_id)
            if best is None or key < best:
                best, selected_id, selected = key, candidate_id, state
        if selected_id is not None:
            decision = 'ACCEPTABLE_SYNTHETIC_CANDIDATE'
    return {'status': STATUS, 'decision': decision, 'selected_id': selected_id,
            'selected_state': selected, 'current_metrics': current_metrics,
            'selected_metrics': _metrics(selected), 'synthetic_only': True,
            'optimizer_implemented': False, 'update_applied': False,
            'confidence_bound_claim': False, 'global_guarantee_claim': False}
