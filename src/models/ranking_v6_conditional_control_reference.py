"""Independent-pilot control variates for synthetic analytic positive stopping.

Exactly one positive; negative-only PL q. For F=R or C, use
g = dF + (F-b)*dlogq, where pilot b is frozen before independent main draws.
Conditioning on that pilot, b is a constant and E_q[dlogq]=0, so the original
score-gradient expectation is unchanged. No derivative through b is taken.
Positive coordinates have dlogq=0 and are unchanged on every trajectory.

R,b_R in [0,1]. C,b_C in [0,B], B=K*max_cost; normalization uses B if B>0,
otherwise 1 with exactly zero costs/gradients. Consequently residuals are
bounded by 1 (risk/normalized cost); each proposal coordinate is bounded by
K. Direct survival derivatives satisfy |dR_i|<=K and |dC_i|<=2*K*B, hence
|g_R,i|<=2*K and |g_C,i|<=3*K*B (conservative, not CI claims). No universal
variance reduction claim, adaptive experiment, reader, Torch, or training.

Reported safe coordinate ranges use L_i=dlogq_i in [-K,1] for negatives
and L_positive=0. Since |dS_t,i| <= S_t*sum_{j<=t}(1-r_j) <= 1,
the form C=cpos*(1-S_K)+sum_t c_negative,t*S_t bounds each direct
normalized negative cost derivative in [-1,1] and positive in [-1,1].
Combining bounded residuals with L yields negative risk [-K-1,K+1],
negative normalized cost [-K-2,K+1], positive risk [-K,0], and positive
normalized cost [-K,1]. These are safe loose ranges, not measured intervals.

O(n*K*(pilot+main)) time and O(n+K) memory; nominal work counts both phases,
including pilot component derivatives. No extra full estimator is rerun.
Small fixed-baseline enumeration streams <=720 negative trajectories.
"""
import hashlib
import itertools
import json
import math
import random
import re

from src.models import ranking_v6_conditional_survival_reference as frozen

STATUS = 'DRAFT_SYNTHETIC_CONDITIONAL_CONTROL_NOT_TRAINER'
MAX_WORK = 20_000_000
SEED_NAMESPACE = 'v6-synthetic-conditional-control-v1'


def _require(ok, code):
    if not ok:
        raise ValueError('CONDITIONAL_CONTROL_' + code)


def _pin(seed, case_id, phase):
    return hashlib.sha256(json.dumps([SEED_NAMESPACE, seed, case_id, phase],
                                    separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()


def _baseline(value, bound, code):
    _require(type(value) in (int, float), code)
    try:
        valid = math.isfinite(value) and 0 <= value <= bound
    except OverflowError:
        valid = False
    _require(valid, code)


def _components(weights, charges, positive, negative, k, rng=None, order=None):
    """Return q,R,C,dR,dC,dlogq separately; one auditable trajectory pass."""
    n = len(weights)
    pos = positive[0]
    p, cpos = weights[pos], charges[pos]
    remaining = list(negative)
    survival, cost, probability = 1., 0., 1.
    ds, dc, logq = [0.] * n, [0.] * n, [0.] * n
    for t in range(k):
        a = math.fsum(weights[i] for i in remaining)
        r, hit = a / (a + p), p / (a + p)
        if order is None:
            draw, cumulative, chosen = rng.random(), 0., remaining[-1]
            for i in remaining:
                cumulative += weights[i] / a
                if draw < cumulative:
                    chosen = i
                    break
        else:
            chosen = order[t]
        probability *= weights[chosen] / a
        dr = [0.] * n
        for i in remaining:
            fraction = weights[i] / a
            dr[i] = r * hit * fraction
            logq[i] -= fraction
        dr[pos] = -r * hit
        logq[chosen] += 1.
        step_cost = hit * cpos + r * charges[chosen]
        cost += survival * step_cost
        for i in range(n):
            dc[i] += ds[i] * step_cost + survival * dr[i] * (charges[chosen] - cpos)
            ds[i] = ds[i] * r + survival * dr[i]
        survival *= r
        remaining.remove(chosen)
    return probability, survival, cost, ds, dc, logq


def _controlled(parts, risk_baseline, cost_baseline):
    q, risk, cost, dr, dc, logq = parts
    return q, risk, cost, [dr[i] + (risk - risk_baseline) * logq[i] for i in range(len(dr))], [
        dc[i] + (cost - cost_baseline) * logq[i] for i in range(len(dc))]


def _finish(prepared, k, count, total, mass, work, exact, br, bc, bound):
    result = frozen._result(prepared, k, count, total, mass, work, exact)
    scale = bound if bound > 0 else 1.
    result.update(status=STATUS, baseline_risk=br, baseline_static_cost=bc,
                  baseline_normalized_cost=bc / scale, cost_normalization_B=scale,
                  cost_upper_bound=bound, all_zero_costs=bound == 0,
                  baselines_frozen_before_main=True, baseline_derivative_taken=False,
                  normalized_cost_score_gradient={u: g / scale for u, g in
                                                  result['cost_score_gradient'].items()},
                  positive_proposal_gradient_zero=True,
              gradient_absolute_bounds={'risk': 2 * k, 'raw_cost': 3 * k * bound},
              safe_gradient_ranges={'negative_risk': [-k - 1, k + 1],
                                    'negative_normalized_cost': [-k - 2, k + 1],
                                    'positive_risk': [-k, 0],
                                    'positive_normalized_cost': [-k, 1]},
                  confidence_interval_implemented=False)
    return result


def estimate(scores, positive_uids, costs, *, k, seed, case_id,
             pilot_samples=64, main_samples=1024):
    """Independent SHA-pinned streams, frozen pilot means; all rejects pre-RNG."""
    _require(type(seed) is int and 0 <= seed <= 2**32 - 1, 'SEED')
    _require(type(case_id) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', case_id) is not None,
             'CASE_ID')
    for count in (pilot_samples, main_samples):
        _require(type(count) is int and 1 <= count <= 65536, 'SAMPLES')
    prepared = frozen._validate(scores, positive_uids, costs, k, 1024)
    work = len(scores) * k * (pilot_samples + main_samples)
    _require(work <= MAX_WORK, 'WORK_BOUND')
    bound = k * max(prepared[2])
    scale = bound if bound > 0 else 1.
    pins = {phase: _pin(seed, case_id, phase) for phase in ('pilot', 'main')}
    pilot_rng = random.Random(int(pins['pilot'], 16))
    risk_total = cost_total = 0.
    for _ in range(pilot_samples):
        parts = _components(*prepared[1:], k, rng=pilot_rng)
        risk_total += parts[1]
        cost_total += parts[2] / scale
    br, bc = risk_total / pilot_samples, cost_total / pilot_samples * scale
    # Only create the main RNG once baselines have been frozen.
    main_rng = random.Random(int(pins['main'], 16))
    total = [0., 0., [0.] * len(scores), [0.] * len(scores)]
    for _ in range(main_samples):
        frozen._accumulate(total, _controlled(_components(*prepared[1:], k, rng=main_rng), br, bc), 1.)
    result = _finish(prepared, k, main_samples, total, None, work, False, br, bc, bound)
    result.update(seed=seed, case_id=case_id, pilot_samples=pilot_samples,
                  main_samples=main_samples, derived_seed_sha256=pins, seed_namespace=SEED_NAMESPACE)
    return result


def enumerate_exact_gradient(scores, positive_uids, costs, *, k,
                             risk_baseline, cost_baseline):
    """n<=7 exact expectation for externally fixed finite valid baselines."""
    prepared = frozen._validate(scores, positive_uids, costs, k, 7)
    bound = k * max(prepared[2])
    _baseline(risk_baseline, 1., 'RISK_BASELINE')
    _baseline(cost_baseline, bound, 'COST_BASELINE')
    total = [0., 0., [0.] * len(scores), [0.] * len(scores)]
    count, mass = 0, 0.
    for order in itertools.permutations(prepared[4], k):
        values = _controlled(_components(*prepared[1:], k, order=order), risk_baseline, cost_baseline)
        frozen._accumulate(total, values, values[0])
        count += 1
        mass += values[0]
    return _finish(prepared, k, count, total, mass, len(scores) * k * count, True,
                   risk_baseline, cost_baseline, bound)
