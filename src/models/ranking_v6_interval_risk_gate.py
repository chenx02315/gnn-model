"""Pure, bounded synthetic gate over externally supplied normalized intervals.

No sampling, interval estimation, I/O, model evaluation, or update application.
Radii are inputs, not evidence of coverage or confidence. Fixed normalization
scales belong upstream; normalized cost is not a claim about real fees.
"""
import math

STATUS = 'SYNTHETIC_INTERVAL_GATE_NOT_TRAIN_RELEASE'
METRICS = {'risk_mean', 'risk_radius', 'cost_mean', 'cost_radius'}


def _require(condition, code):
    if not condition:
        raise ValueError('INTERVAL_RISK_GATE_' + code)


def _unit(value, code):
    _require(type(value) in (int, float), code)
    try:
        valid = math.isfinite(value) and 0 <= value <= 1
    except OverflowError:
        valid = False
    _require(valid, code)


def _validate_state(state):
    _require(type(state) is dict and 1 <= len(state) <= 6
             and all(type(name) is str and name for name in state), 'FAMILIES')
    for metrics in state.values():
        _require(type(metrics) is dict and set(metrics) == METRICS, 'METRIC_SCHEMA')
        for field in METRICS:
            _unit(metrics[field], 'METRIC_' + field.upper())


def _intervals(state, risk_caps, max_radius):
    families = {}
    for name in sorted(state):
        metrics = state[name]
        risk_lower = max(0., metrics['risk_mean'] - metrics['risk_radius'])
        risk_upper = min(1., metrics['risk_mean'] + metrics['risk_radius'])
        families[name] = {
            'risk_lower': risk_lower, 'risk_upper': risk_upper,
            'normalized_cost_lower': max(0., metrics['cost_mean'] - metrics['cost_radius']),
            'normalized_cost_upper': min(1., metrics['cost_mean'] + metrics['cost_radius']),
            'risk_cap': risk_caps[name],
            'risk_certified': risk_upper <= risk_caps[name],
            'risk_proven_infeasible': risk_lower > risk_caps[name],
            'precision_sufficient': all(metrics[field] <= max_radius
                                        for field in ('risk_radius', 'cost_radius')),
        }
    return {
        'families': families,
        'macro_normalized_cost_lower': math.fsum(
            f['normalized_cost_lower'] for f in families.values()) / len(families),
        'macro_normalized_cost_upper': math.fsum(
            f['normalized_cost_upper'] for f in families.values()) / len(families),
        'risk_certified': all(f['risk_certified'] for f in families.values()),
        'risk_proven_infeasible': any(f['risk_proven_infeasible'] for f in families.values()),
        'precision_sufficient': all(f['precision_sufficient'] for f in families.values()),
    }


def select_certified_update(current, candidates, risk_caps, max_radius):
    """Select only a per-family-safe, strictly interval-separated candidate.

    States map 1..6 nonempty family names to exactly risk_mean, risk_radius,
    cost_mean, cost_radius, all finite normalized numbers in [0, 1]. Candidate
    maps contain at most eight nonempty string IDs (an empty map is a no-op).
    All family sets and caps join exactly. Any excessive input radius prevents
    selection, including for otherwise rejected candidates. Current infeasible
    or unresolved risk also prevents selection; this is not a recovery helper.

    Equal-family macro cost upper must be strictly below current macro cost
    lower. Risk is never macro-averaged or offset across families. Selection
    minimizes (macro cost upper, candidate ID), without applying any update.
    NO_CERTIFIED_UPDATE does not prove absence of a true improvement.
    """
    _validate_state(current)
    _require(type(candidates) is dict and len(candidates) <= 8
             and all(type(name) is str and name for name in candidates), 'CANDIDATES')
    _require(type(risk_caps) is dict and set(risk_caps) == set(current), 'CAP_JOIN')
    for cap in risk_caps.values():
        _unit(cap, 'CAP')
    _unit(max_radius, 'MAX_RADIUS')
    _require(max_radius > 0, 'MAX_RADIUS')
    for state in candidates.values():
        _validate_state(state)
        _require(set(state) == set(current), 'CANDIDATE_FAMILY_JOIN')

    current_summary = _intervals(current, risk_caps, max_radius)
    candidate_summaries = {}
    for name in sorted(candidates):
        summary = _intervals(candidates[name], risk_caps, max_radius)
        summary['strict_cost_improvement_certified'] = (
            summary['macro_normalized_cost_upper']
            < current_summary['macro_normalized_cost_lower'])
        summary['candidate_certified'] = (summary['risk_certified']
                                          and summary['strict_cost_improvement_certified']
                                          and summary['precision_sufficient'])
        candidate_summaries[name] = summary

    selected_id = None
    if not all(s['precision_sufficient'] for s in
               (current_summary, *candidate_summaries.values())):
        decision = 'INCONCLUSIVE_PRECISION'
    elif current_summary['risk_proven_infeasible']:
        decision = 'BLOCKED_INFEASIBLE_CURRENT'
    elif not current_summary['risk_certified']:
        decision = 'INCONCLUSIVE_CURRENT_RISK'
    else:
        certified = [(s['macro_normalized_cost_upper'], name)
                     for name, s in candidate_summaries.items() if s['candidate_certified']]
        if certified:
            selected_id = min(certified)[1]
            decision = 'CERTIFIED_SYNTHETIC_UPDATE'
        else:
            decision = 'NO_CERTIFIED_UPDATE'
    return {
        'status': STATUS, 'decision': decision, 'selected_id': selected_id,
        'current_intervals': current_summary, 'candidate_intervals': candidate_summaries,
        'family_count': len(current), 'family_weight': 1 / len(current),
        'max_radius': max_radius, 'synthetic_only': True, 'update_applied': False,
        'confidence_bound_claim': False, 'sampling_coverage_claim': False,
        'global_guarantee_claim': False, 'training_release_authorized': False,
    }
