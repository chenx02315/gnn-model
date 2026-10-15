"""Generated FIT fixture joint objective wiring only, never a trainer.

Risk is miss by K; cost is complete additive charge including the first
positive, divided by fixed B=N*max(cost). Weights are mandatory and explicit.
The adapter's feature tuples are copied to lists for the existing VJP shape;
values are neither standardized nor clipped. No model or Torch is used here.
"""
import math

from . import ranking_v6_multi_positive_complete_cost as complete_cost
from . import ranking_v6_multi_positive_conditional_risk as exact_risk
from . import ranking_v6_multi_positive_risk_control as risk_control
from . import ranking_v6_synthetic_real_bridge_adapter as adapter
from .ranking_v6_scorer_vjp_bridge import _digest


def _require(condition, code):
    if not condition:
        raise ValueError('MULTI_POSITIVE_JOINT_CALLER_' + code)


def _bounded_number(value, lower, upper, code):
    _require(type(value) in (int, float) and lower <= value <= upper
             and math.isfinite(value), code)


def _prepare(feature_rows, outcome_rows, scores, k, risk_weight,
             normalized_cost_weight, synthetic_only, *, exact):
    _require(synthetic_only is True, 'SYNTHETIC_ONLY')
    _bounded_number(risk_weight, 0, 10, 'RISK_WEIGHT')
    _bounded_number(normalized_cost_weight, 0, 10, 'COST_WEIGHT')
    _require(risk_weight > 0 or normalized_cost_weight > 0, 'ZERO_WEIGHTS')
    _require(type(k) is int and 1 <= k <= 10, 'K')
    prepared = adapter.prepare_fit_fixture(feature_rows, outcome_rows, synthetic_only=True)
    _require(len(prepared['tasks']) == 1, 'EXACTLY_ONE_CIRCUIT')
    original = prepared['tasks'][0]
    uids = list(original['action_uids'])
    _require(k <= len(uids), 'K_EXCEEDS_N')
    _require(not exact or len(uids) <= 7, 'EXACT_N_BOUND')
    _require(type(scores) is dict and set(scores) == set(uids), 'SCORE_EXACT_UID_JOIN')
    for value in scores.values():
        _bounded_number(value, -20, 20, 'SCORE')
    features = [list(row) for row in original['features']]
    _require(all(abs(value) <= 2 for row in features for value in row), 'FEATURE_VJP_BOUND')
    task = dict(original, action_uids=uids, features=features,
                costs=dict(original['costs']), positive_uids=tuple(original['positive_uids']))
    return task, {uid: scores[uid] for uid in uids}


def _finish(task, scores, k, risk, cost, risk_weight, normalized_cost_weight):
    risk_gradient = dict(risk['miss_score_gradient'])
    cost_gradient = dict(cost['normalized_cost_score_gradient'])
    joint = math.fsum((risk_weight * risk['expected_miss_probability'],
                       normalized_cost_weight * cost['normalized_complete_first_hit_cost']))
    gradient = {uid: math.fsum((risk_weight * risk_gradient[uid],
                               normalized_cost_weight * cost_gradient[uid])) for uid in scores}
    _require(math.isfinite(joint) and all(math.isfinite(v) for v in gradient.values()),
             'NONFINITE_JOINT')
    return dict(status='SYNTHETIC_MULTI_POSITIVE_JOINT_CALLER_NOT_TRAINER',
                prepared_task=task, scores=scores,
                score_snapshot_sha256=_digest(list(scores.values())),
                risk_component=risk, cost_component=cost,
                gradient_maps={'risk': risk_gradient, 'cost': cost_gradient},
                risk_weight=risk_weight, normalized_cost_weight=normalized_cost_weight,
                joint_scalar=joint, joint_score_gradient=gradient, k=k,
                cost_normalization_B=cost['cost_normalization_B'],
                cost_normalization='fixed_N_times_max_cost',
                normalization_derivative_taken=False,
                features_standardized=False, features_clipped=False,
                feature_tuple_to_list_conversion_only=True,
                costs_are_features=False, oracle_is_feature=False,
                exact_risk_reference=risk['exact_enumeration'],
                silent_exact_fallback=False, synthetic_only=True,
                synthetic_declaration_is_provenance_detector=False,
                trainer_implemented=False, optimizer_implemented=False,
                model_fitting_implemented=False, real_data_access=False,
                online_cost_replay=False, trajectories_retained=False,
                risk_nonincrease_guaranteed=False)


def evaluate_control(feature_rows, outcome_rows, scores, *, k, seed,
                     pilot_samples, samples, risk_weight, normalized_cost_weight,
                     synthetic_only=False):
    """Validate all inputs/work and deterministic cost before any risk sampling."""
    _require(synthetic_only is True, 'SYNTHETIC_ONLY')
    _require(type(seed) is int and 0 <= seed <= 2**32 - 1, 'SEED')
    _require(type(pilot_samples) is int and 1 <= pilot_samples <= 65536, 'PILOT_SAMPLES')
    _require(type(samples) is int and 1 <= samples <= 65536, 'SAMPLES')
    task, ordered_scores = _prepare(feature_rows, outcome_rows, scores, k,
                                   risk_weight, normalized_cost_weight,
                                   synthetic_only, exact=False)
    work = len(ordered_scores) * k * (pilot_samples + samples)
    _require(work <= risk_control.MAX_WORK, 'WORK_BOUND')
    cost = complete_cost.evaluate(ordered_scores, task['positive_uids'], task['costs'],
                                  synthetic_only=True)
    risk = risk_control.estimate(ordered_scores, task['positive_uids'], k=k, seed=seed,
                                 pilot_samples=pilot_samples, samples=samples, synthetic_only=True)
    return _finish(task, ordered_scores, k, risk, cost, risk_weight, normalized_cost_weight)


def evaluate_exact_reference(feature_rows, outcome_rows, scores, *, k,
                             risk_weight, normalized_cost_weight, synthetic_only=False):
    """Small N<=7 Decimal80 risk reference plus the same completecost, no RNG."""
    task, ordered_scores = _prepare(feature_rows, outcome_rows, scores, k,
                                   risk_weight, normalized_cost_weight,
                                   synthetic_only, exact=True)
    cost = complete_cost.evaluate(ordered_scores, task['positive_uids'], task['costs'],
                                  synthetic_only=True)
    risk = exact_risk.enumerate_exact_gradient(ordered_scores, task['positive_uids'],
                                              k=k, synthetic_only=True)
    return _finish(task, ordered_scores, k, risk, cost, risk_weight, normalized_cost_weight)


def generated_fixture():
    """Fresh deterministic six-action probe fixture, not inherited train inputs.

    Probe choices seed=11, K=3, pilot/main=32/480 and weights=.5/1 belong
    in the separately frozen launcher contract, never implicit API defaults.
    """
    features, outcomes = [], []
    for i, (cost, cycles) in enumerate(zip((.5, 1., 2., 4., 7., 10.),
                                          (100, 101, 130, 150, 175, 200))):
        uid = f'u{i:03d}'
        values = (1 - i % 2, i % 2, .3 * i, .2 * i, i / 5, (5 - i) / 5, .36 * i)
        features.append(dict(zip(adapter.FEATURES, values), action_uid=uid,
                             family='synthetic_family', circuit='synthetic_circuit', role='FIT'))
        outcomes.append(dict(action_uid=uid, total_cycles=cycles,
                             policy_charged_runtime_s=cost,
                             is_d95_feasible=1, execution_status='SUCCESS'))
    return features, outcomes
