"""Synthetic PRIOR normalized-cost gradient ranges, exactly one positive.

On a negative-only PL prefix, C=cpos*(1-S_K)+sum_t c_z[t]*S_t,
S_t=prod_{j<t} A_j/(A_j+P), H_t=sum_{j<t} P/(A_j+P).
Subset sums bound each A_j, and hence S_t,H_t before any main sampling.
For a negative i, 0<=dS_t,i<=D_it, where
D_it=Smax_t*Hmax_t*min(1,w_i/Amin_(t-1)). Thus direct dC_i/B lies in
[-cpos*D_iK/B, cmaxneg*sum_t D_it/B]. The proposal derivative lies in
[-Q_i,1], Q_i=sum_j min(1,w_i/Amin_j). Bounds on C/B minus the externally
frozen normalized baseline, multiplied by all four proposal endpoints,
and added to the direct interval bound the controlled gradient.
For the positive coordinate L=0 and dC/B=(cpos*S_K*H_K-
sum_t c_z[t]*S_t*H_t)/B; separate product envelopes bound both terms.

Only scores, costs, K and a known frozen baseline enter the API. No RNG,
observations, moments, training or CI release. Fixed absolute +/-1e-12
endpoint padding is a practical guard, not a formal floating-point proof.
If all costs vanish, the valid frozen cost baseline must be zero; gradients
are exactly zero and normalization uses scale 1 rather than dividing by 0.
This helper supports charges that are zero or in [1e-6,1e9]. Smaller positive
charges are rejected before exponentiation: raw-cost control arithmetic may
underflow before normalization (e.g. cpos=0,cneg=5e-324,N=2,K=1), which
fixed endpoint padding cannot repair. This numerical domain restriction is
not fitted to experiment results and does not alter the frozen validator.
"""
import math

from src.models import ranking_v6_conditional_survival_reference as frozen

STATUS = 'SYNTHETIC_PRIOR_COST_RANGES_NOT_CI_RELEASE'
NUMERICAL_PADDING = 1e-12
MIN_POSITIVE_COST = 1e-6
MAX_COST = 1e9


def prior_normalized_cost_gradient_ranges(scores, positive_uids, costs, *, k,
                                          normalized_cost_baseline):
    """Return UID ranges for d(C/B)+(C/B-bc)*dlogq, B=K*max(cost).

    Baseline validation precedes any softmax. Frozen validation bounds scores
    by 20, costs by 1e9, actions by 1024, K by 10 and requires one positive.
    This helper additionally requires positive costs >=1e-6 before softmax.
    Caller is responsible for independent-pilot freezing; no such provenance
    can be verified by this deterministic helper.
    """
    valid = type(normalized_cost_baseline) in (int, float)
    if valid:
        try:
            valid = math.isfinite(normalized_cost_baseline) and 0 <= normalized_cost_baseline <= 1
        except OverflowError:
            valid = False
    if not valid:
        raise ValueError('PRIOR_COST_RANGES_NORMALIZED_COST_BASELINE')
    if type(costs) is not dict:
        raise ValueError('PRIOR_COST_RANGES_COST_SCHEMA')
    for value in costs.values():
        valid = type(value) in (int, float)
        if valid:
            try:
                valid = math.isfinite(value) and 0 <= value <= MAX_COST
            except OverflowError:
                valid = False
        if not valid:
            raise ValueError('PRIOR_COST_RANGES_COST_BOUND')
        if 0 < value < MIN_POSITIVE_COST:
            raise ValueError('PRIOR_COST_RANGES_POSITIVE_COST_BELOW_SUPPORTED_MIN')
    uids, weights, charges, positive, negative = frozen._validate(
        scores, positive_uids, costs, k, frozen.MAX_ACTIONS)
    bound = k * max(charges)
    if bound == 0 and normalized_cost_baseline != 0:
        raise ValueError('PRIOR_COST_RANGES_ZERO_COST_BASELINE')
    scale = bound if bound > 0 else 1.
    pos = positive[0]
    p, cpos = weights[pos], charges[pos]
    cmin, cmax = min(charges[i] for i in negative), max(charges[i] for i in negative)
    # Normalize charges before multiplication to avoid helper-side underflow.
    # This does not certify floating artifacts in a separate raw-cost engine.
    cposn, cminn, cmaxn = cpos / scale, cmin / scale, cmax / scale
    ordered = sorted(weights[i] for i in negative)
    m = len(negative)
    amin = [math.fsum(ordered[:m - t]) for t in range(k)]
    amax = [math.fsum(ordered[t:]) for t in range(k)]
    hmin = [p / (a + p) for a in amax]
    hmax = [p / (a + p) for a in amin]
    smin_prefix, smax_prefix, Hmin_prefix, Hmax_prefix = [], [], [], []
    smin = smax = 1.
    for t in range(k):
        # A/(A+P) avoids cancellation when h is close to 1.
        smin *= amin[t] / (amin[t] + p)
        smax *= amax[t] / (amax[t] + p)
        smin_prefix.append(smin)
        smax_prefix.append(smax)
        Hmin_prefix.append(math.fsum(hmin[:t + 1]))
        Hmax_prefix.append(math.fsum(hmax[:t + 1]))
    shmin = [s * h for s, h in zip(smin_prefix, Hmin_prefix)]
    shmax = [s * h for s, h in zip(smax_prefix, Hmax_prefix)]
    flo = max(0., min(1., cposn * (1. - smax) + cminn * math.fsum(smin_prefix)))
    fhi = max(0., min(1., cposn * (1. - smin) + cmaxn * math.fsum(smax_prefix)))
    residual = [flo - normalized_cost_baseline, fhi - normalized_cost_baseline]
    analytic, details = {}, {}
    for i, uid in enumerate(uids):
        if i == pos:
            direct = [cposn * shmin[-1] - cmaxn * math.fsum(shmax),
                      cposn * shmax[-1] - cminn * math.fsum(shmin)]
            analytic[uid] = direct
            details[uid] = {'role': 'positive', 'direct_derivative_range': direct,
                            'proposal_gradient_range': [0., 0.]}
        else:
            qi = math.fsum(min(1., weights[i] / a) for a in amin)
            di = [shmax[t] * min(1., weights[i] / amin[t]) for t in range(k)]
            direct = [-cposn * di[-1], cmaxn * math.fsum(di)]
            products = [r * ell for r in residual for ell in (-qi, 1.)]
            analytic[uid] = [direct[0] + min(products), direct[1] + max(products)]
            details[uid] = {'role': 'negative', 'direct_derivative_range': direct,
                            'proposal_gradient_range': [-qi, 1.], 'Q_i': qi, 'D_it': di}
    ranges = ({uid: [0., 0.] for uid in uids} if bound == 0 else
              {uid: [lo - NUMERICAL_PADDING, hi + NUMERICAL_PADDING]
               for uid, (lo, hi) in analytic.items()})
    return {
        'status': STATUS, 'synthetic_only': True, 'does_not_release_ci': True,
        'confidence_interval_implemented': False, 'range_source': 'PRIOR_ANALYTIC',
        'k': k, 'action_count': len(uids), 'positive_count': 1,
        'baseline_normalized_cost': float(normalized_cost_baseline),
        'baseline_derivative_taken': False, 'baseline_independence_verified': False,
        'cost_upper_bound': bound, 'cost_normalization_B': scale, 'all_zero_costs': bound == 0,
        'min_positive_cost': MIN_POSITIVE_COST,
        'supported_cost_domain': {'zero_allowed': True,
                                  'min_positive_cost': MIN_POSITIVE_COST, 'max_cost': MAX_COST},
        'normalized_cost_score_gradient_ranges': ranges,
        'unpadded_analytic_ranges': analytic, 'coordinate_derivation': details,
        'constants': {'Amin_t': amin, 'Amax_t': amax, 'positive_weight': p,
                      'positive_cost': cpos, 'negative_cost_min': cmin,
                      'negative_cost_max': cmax, 'hmin_t': hmin, 'hmax_t': hmax,
                      'Smin_prefix': smin_prefix, 'Smax_prefix': smax_prefix,
                      'Hmin_prefix': Hmin_prefix, 'Hmax_prefix': Hmax_prefix,
                      'normalized_cost_range': [flo, fhi], 'residual_range': residual,
                      'numerical_padding': NUMERICAL_PADDING,
                      'padding_applied': bound > 0},
        'derivation': 'C=cpos*(1-S_K)+sum cneg*S_t; direct subset-sum '
                      'envelopes + [Flo-bc,Fhi-bc]*[-Q_i,1] (four endpoint products)',
        'rounding_guard_is_formal_proof': False,
    }
