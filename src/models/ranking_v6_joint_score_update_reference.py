"""Fixed E10 synthetic score-space joint update; never a trainer.

Independent baseline and gradient pilots use analytic positive stopping. With
frozen b, E[dF+(F-b)dlogq]=dE[F]; no derivative through b is taken. Negative
L1 gradients define a fixed 15-point mixture/step grid. Pilot predictions
select ONE finite score proposal before any full-original-PL enumeration.
An exact derivative is not a finite-change certificate: only the later raw
finite risk/cost comparison can accept that proposal. Rejection commits the
original scores, with no alternative or fallback. The 1e-12 risk tolerance
is a practical numerical guard, not a formal IEEE floating-point proof.
Stdlib only, no I/O, Torch, model parameters, optimizer or real data.
"""
import hashlib
import json
import math
import random

from . import ranking_v6_conditional_control_reference as control
from . import ranking_v6_first_hit_exact_gradient as full_oracle
from . import ranking_v6_nonuniform_precision_v3 as fixed
from . import ranking_v6_prior_cost_ranges as cost_domain

SEED_NAMESPACE = 'v6-synthetic-joint-score-v1'
SEEDS, FIXTURES = fixed.SEEDS, fixed.FIXTURES
N, K = 6, 3
BASELINE_SAMPLES, GRADIENT_SAMPLES = 32, 32
LAMBDAS, STEPS = (0., .25, .5, .75, 1.), (.05, .1, .2)
RISK_TOLERANCE, COST_DECREASE_MIN = 1e-12, 1e-8


def _require(ok, code):
    if not ok:
        raise ValueError('JOINT_SCORE_UPDATE_' + code)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()


def _pin(seed, case_id, phase):
    return _hash([SEED_NAMESPACE, seed, case_id, phase])


def _direction(gradient):
    _require(all(math.isfinite(g) for g in gradient), 'NONFINITE_GRADIENT')
    norm = math.fsum(abs(g) for g in gradient)
    _require(math.isfinite(norm), 'NONFINITE_NORM')
    return ([-g / norm for g in gradient], True) if norm > 0 else ([0.] * len(gradient), False)


def _dot(a, b):
    return math.fsum(x * y for x, y in zip(a, b))


def _select_candidate(gr, gc):
    """Pure pilot-only grid: zero directions fail closed, ties lambda then step."""
    dr, vr = _direction(gr)
    dc, vc = _direction(gc)
    candidates = []
    for mix in LAMBDAS:
        combined = [mix * r + (1 - mix) * c for r, c in zip(dr, dc)]
        norm = math.fsum(abs(v) for v in combined)
        direction = [v / norm for v in combined] if norm else [0.] * len(gr)
        for step in STEPS:
            risk_delta, cost_delta = step * _dot(gr, direction), step * _dot(gc, direction)
            threshold = -.1 * step * abs(_dot(gr, dr))
            feasible = vr and vc and norm > 0 and risk_delta <= threshold and cost_delta < 0
            candidates.append(dict(mixture_lambda=mix, step=step, direction=direction,
                                   predicted_risk_delta=risk_delta,
                                   predicted_normalized_cost_delta=cost_delta,
                                   predicted_risk_threshold=threshold, feasible=feasible))
    ranked = sorted(candidates, key=lambda c: (not c['feasible'],
                    c['predicted_normalized_cost_delta'], c['mixture_lambda'], c['step']))
    for rank, candidate in enumerate(ranked, 1):
        candidate['pilot_rank'] = rank
    selected = ranked[0] if ranked[0]['feasible'] else None
    return dr, dc, candidates, selected


def _preflight(scores, costs):
    cost_domain.prior_normalized_cost_gradient_ranges(
        scores, {'5'}, costs, k=K, normalized_cost_baseline=0.)
    prepared = control.frozen._validate(scores, {'5'}, costs, K, 7)
    _require(len(scores) == N and K == 3, 'FIXED_SHAPE')
    _require(K * max(costs.values()) > 0, 'ZERO_COST_FIXTURE')
    # Full-original oracle requires every cost strictly positive.
    _require(all(c > 0 for c in costs.values()), 'NONPOSITIVE_COST_FIXTURE')
    return prepared


def _protocol(baseline_samples, gradient_samples):
    """Entire fixed decision protocol, frozen before verification, not post hoc."""
    return dict(n=N, k=K, seeds=list(SEEDS), seed_namespace=SEED_NAMESPACE,
                seed_case_id_prefix='e10-fixed-', baseline_samples=baseline_samples,
                gradient_samples=gradient_samples, total_pilot_samples=baseline_samples + gradient_samples,
                mixtures=list(LAMBDAS), steps=list(STEPS), candidate_count_per_case_seed=15,
                risk_tolerance=RISK_TOLERANCE, normalized_cost_decrease_min=COST_DECREASE_MIN,
                risk_tolerance_is_formal_ieee_proof=False, min_positive_cost=cost_domain.MIN_POSITIVE_COST,
                cost_normalization='fixed_K_times_max_cost',
                selection_rule='pilot_feasible_min_cost_delta_then_lambda_then_step',
                direction_rule='negative_objective_gradient_L1_then_L1_normalized_mixture',
                risk_feasibility_rule='predicted_risk_delta<=-0.1*step*abs(pilot_gr_dot_dRisk)',
                cost_feasibility_rule='predicted_normalized_cost_delta<0',
                acceptance_rule='risk_after_minus_before<=1e-12_and_normalized_cost_delta<=-1e-8',
                zero_direction_rule='NO_PROPOSAL_failclosed', score_absolute_bound=20.,
                max_coordinate_update=.2, oracle_selection=False, no_fallback=True,
                nominal_pilot_work_per_case_seed=N * K * (baseline_samples + gradient_samples),
                nominal_pilot_work=8 * N * K * (baseline_samples + gradient_samples),
                formal_nominal_pilot_work=9216, full_original_pl_permutations_per_call=720,
                max_exact_oracle_calls=16)


def _freeze_proposal(case_id, seed, scores, costs, prepared, baseline_samples, gradient_samples):
    uids = prepared[0]
    bound = K * max(costs.values())
    seed_case_id = 'e10-fixed-' + case_id
    pins = {phase: _pin(seed, seed_case_id, phase) for phase in ('baseline', 'gradient')}
    baseline_rng = random.Random(int(pins['baseline'], 16))
    baseline_parts = [control._components(*prepared[1:], K, rng=baseline_rng)
                      for _ in range(baseline_samples)]
    br = math.fsum(p[1] for p in baseline_parts) / baseline_samples
    bc = math.fsum(p[2] for p in baseline_parts) / baseline_samples
    baseline_hash = _hash([[p[1], p[2]] for p in baseline_parts])
    # The baseline is a scalar constant before this independent RNG exists.
    gradient_rng = random.Random(int(pins['gradient'], 16))
    parts = [control._controlled(control._components(*prepared[1:], K, rng=gradient_rng), br, bc)
             for _ in range(gradient_samples)]
    gr = [math.fsum(p[3][i] for p in parts) / gradient_samples for i in range(N)]
    gc = [math.fsum(p[4][i] / bound for p in parts) / gradient_samples for i in range(N)]
    dr, dc, candidates, selected = _select_candidate(gr, gc)
    proposed = ({u: scores[u] + selected['step'] * selected['direction'][i]
                 for i, u in enumerate(uids)} if selected else None)
    _require(proposed is None or all(math.isfinite(v) and abs(v) <= 20 for v in proposed.values()),
             'PROPOSED_SCORE_DOMAIN')
    payload = dict(case_id=case_id, seed=seed, seed_case_id=seed_case_id,
                   protocol=_protocol(baseline_samples, gradient_samples),
                   seed_namespace=SEED_NAMESPACE, derived_seed_sha256=pins,
                   uids=list(uids), positive_uids=['5'], scores=dict(scores), costs=dict(costs),
                   n=N, k=K, temperature=1, cost_normalization_B=bound,
                   baseline_samples=baseline_samples, gradient_samples=gradient_samples,
                   baseline_risk=br, baseline_static_cost=bc, baseline_normalized_cost=bc / bound,
                   baselines_frozen_before_gradient=True, baseline_derivative_taken=False,
                   baseline_observation_sha256=baseline_hash,
                   gradient_observation_sha256=_hash([[p[3], p[4]] for p in parts]),
                   pilot_gradient_risk=dict(zip(uids, gr)),
                   pilot_gradient_normalized_cost=dict(zip(uids, gc)),
                   risk_direction=dict(zip(uids, dr)), normalized_cost_direction=dict(zip(uids, dc)),
                   candidates=candidates, candidate_count=len(candidates), selected_candidate=selected,
                   proposal_status='ONE_PROPOSAL' if selected else 'NO_PROPOSAL',
                   proposed_scores=proposed, base_score_state_sha256=_hash(scores),
                   proposed_score_state_sha256=_hash(proposed) if proposed else None,
                   oracle_used_for_selection=False, frozen_before_any_full_oracle=True)
    # Canonical JSON roundtrip detaches all caller dictionaries and selection aliases.
    payload = json.loads(json.dumps(payload, allow_nan=False))
    return dict(payload=payload, payload_sha256=_hash(payload))


def _oracle_values(result, bound):
    values = [result['probability_mass'], result['expected_miss_probability'],
              result['expected_truncated_static_cost'], *result['miss_score_gradient'].values(),
              *result['cost_score_gradient'].values()]
    _require(all(math.isfinite(v) for v in values), 'NONFINITE_ORACLE')
    _require(abs(result['probability_mass'] - 1.) <= 1e-12, 'ORACLE_MASS')
    _require(0 <= result['expected_miss_probability'] <= 1. + RISK_TOLERANCE
             and 0 <= result['expected_truncated_static_cost'] / bound <= 1. + RISK_TOLERANCE,
             'ORACLE_OBJECTIVE_DOMAIN')
    return result['expected_miss_probability'], result['expected_truncated_static_cost'] / bound


def _verify_frozen(frozen):
    payload, digest = frozen['payload'], frozen['payload_sha256']
    summary = dict(payload, pilot_freeze_payload=payload, pilot_freeze_sha256=digest,
                   accepted=False, numerical_guard_failed=False, exact_oracle_calls=0,
                   fallback_attempted=False, committed_scores=dict(payload['scores']),
                   committed_score_state_sha256=payload['base_score_state_sha256'],
                   risk_before=None, normalized_cost_before=None, proposed_risk_after=None,
                   proposed_normalized_cost_after=None, committed_risk_after=None,
                   committed_normalized_cost_after=None, proposed_risk_delta=None,
                   proposed_normalized_cost_delta=None, committed_risk_delta=None,
                   committed_normalized_cost_delta=None, oracle_probability_mass={})
    try:
        _require(_hash(payload) == digest, 'FREEZE_HASH')
        summary['exact_oracle_calls'] += 1
        base = full_oracle.enumerate_exact_gradient(dict(payload['scores']), {'5'}, dict(payload['costs']), k=K)
        rb, cb = _oracle_values(base, payload['cost_normalization_B'])
        summary.update(risk_before=rb, normalized_cost_before=cb,
                       committed_risk_after=rb, committed_normalized_cost_after=cb,
                       committed_risk_delta=0., committed_normalized_cost_delta=0.)
        summary['oracle_probability_mass']['base'] = base['probability_mass']
        if payload['selected_candidate'] is not None:
            summary['exact_oracle_calls'] += 1
            after = full_oracle.enumerate_exact_gradient(dict(payload['proposed_scores']), {'5'}, dict(payload['costs']), k=K)
            ra, ca = _oracle_values(after, payload['cost_normalization_B'])
            summary['oracle_probability_mass']['proposed'] = after['probability_mass']
            risk_delta, cost_delta = ra - rb, ca - cb
            summary.update(proposed_risk_after=ra, proposed_normalized_cost_after=ca,
                           proposed_risk_delta=risk_delta, proposed_normalized_cost_delta=cost_delta)
            accepted = risk_delta <= RISK_TOLERANCE and cost_delta <= -COST_DECREASE_MIN
            summary['accepted'] = accepted
            if accepted:
                summary.update(committed_scores=dict(payload['proposed_scores']),
                               committed_score_state_sha256=payload['proposed_score_state_sha256'],
                               committed_risk_after=ra, committed_normalized_cost_after=ca,
                               committed_risk_delta=risk_delta, committed_normalized_cost_delta=cost_delta)
        _require(_hash(payload) == digest, 'FREEZE_MUTATED')
    except (ValueError, OverflowError, ArithmeticError) as exc:
        summary.update(accepted=False, numerical_guard_failed=True, numerical_guard_error=str(exc),
                       committed_scores=dict(payload['scores']),
                       committed_score_state_sha256=payload['base_score_state_sha256'],
                       committed_risk_after=summary['risk_before'],
                       committed_normalized_cost_after=summary['normalized_cost_before'],
                       committed_risk_delta=0. if summary['risk_before'] is not None else None,
                       committed_normalized_cost_delta=0. if summary['normalized_cost_before'] is not None else None)
    return summary


def run_joint_score_update():
    """Formal fixed entry: no overrides, exactly eight case/seed pilots."""
    return _run_fixed_fixtures()


def _run_fixed_fixtures(*, baseline_samples=32, gradient_samples=32):
    """Private count-only seam for tiny tests; no adaptive or fixture overrides."""
    for count in (baseline_samples, gradient_samples):
        _require(type(count) is int and 1 <= count <= 32, 'PILOT_SAMPLES')
    prepared_cases = []
    for case_id, score_values, cost_values in FIXTURES:
        scores = {str(i): s for i, s in enumerate(score_values)}
        costs = {str(i): c for i, c in enumerate(cost_values)}
        prepared_cases.append((case_id, scores, costs, _preflight(scores, costs)))
    records = [_freeze_proposal(case_id, seed, scores, costs, prepared,
                               baseline_samples, gradient_samples)
               for case_id, scores, costs, prepared in prepared_cases for seed in SEEDS]
    # All eight pilot selections and hashes exist before even baseline enumeration.
    summaries = [_verify_frozen(record) for record in records]
    accepted = sum(s['accepted'] for s in summaries)
    failed = any(s['numerical_guard_failed'] for s in summaries)
    status = ('FAIL_NUMERICAL' if failed else 'PASS_FIXED_SCORE_SPACE_JOINT_UPDATES_ONLY'
              if accepted == 8 else 'PARTIAL_SAFE_REJECTION' if accepted else 'NO_ACCEPTED_UPDATE')
    config = _protocol(baseline_samples, gradient_samples)
    return dict(status=status, train_release=False, actual_parameter_updates=False,
                trainer_implemented=False, optimizer_implemented=False, synthetic_only=True,
                real_data_access=False, adaptive_sampling=False, trajectories_retained=False,
                oracle_used_for_selection=False, no_fallback=True, no_grid_expansion=True,
                config=config, config_sha256=_hash(config), per_case_seed=summaries,
                accepted_count=accepted, rejected_count=8 - accepted,
                proposal_count=sum(s['selected_candidate'] is not None for s in summaries),
                numerical_guard_failures=sum(s['numerical_guard_failed'] for s in summaries),
                exact_oracle_calls=sum(s['exact_oracle_calls'] for s in summaries),
                total_work=config['nominal_pilot_work'],
                all_committed_updates_safe=not failed and all(not s['accepted'] or (
                    s['committed_risk_delta'] <= RISK_TOLERANCE and
                    s['committed_normalized_cost_delta'] <= -COST_DECREASE_MIN) for s in summaries))
