"""Deterministic PRIOR ranges for one-positive controlled risk gradients.

For negative-only PL prefixes, R=prod_t A_t/(A_t+P), H=sum_t P/(A_t+P).
Every A_t lies between sums of the m-t smallest/largest negative weights.
Therefore Smin<=R<=Smax and Hmin<=H<=Hmax. The positive proposal
derivative is zero and dR_positive=-R*H. For negative i,
dR_i=R*sum_{t:i remaining} h_t*w_i/A_t is in [0,D_i], where
D_i=Smax*Hmax*min(1,w_i/Amin_last). Its proposal derivative is
L_i=1_{i selected}-sum_{t:i remaining} w_i/A_t in [-Q_i,1],
Q_i=sum_t min(1,w_i/Amin_t). Bounding (R-br)*L_i by all four
interval endpoint products and adding [0,D_i] bounds the controlled
gradient. Bounds depend only on scores, K and the externally frozen br.

Stdlib, no RNG, outcomes, moments, cost bounds, training or CI release.
Public endpoints include fixed absolute 1e-12 numerical padding. This is
a practical rounding guard, NOT an exact formal floating-point proof.
Unpadded analytic endpoints are diagnostics, not the operational ranges.
Exactly one positive is required; no multiple-positive universality claim.
"""
import math

from src.models import ranking_v6_conditional_survival_reference as frozen

STATUS = 'SYNTHETIC_PRIOR_RISK_RANGES_NOT_CI_RELEASE'
NUMERICAL_PADDING = 1e-12


def prior_risk_gradient_ranges(scores, positive_uids, *, k, risk_baseline):
    """Validate before softmax; return UID-joined deterministic risk ranges.

    The baseline is a known finite constant in [0,1], supplied after freezing
    an independent pilot. This helper cannot verify pilot independence.
    Frozen validation enforces 2..1024 actions, |score|<=20, 1<=K<=10,
    one positive and at least K negatives. Dummy costs validate that contract
    without adding any raw-cost dependency to this risk-only API.
    """
    valid = type(risk_baseline) in (int, float)
    if valid:
        try:
            valid = math.isfinite(risk_baseline) and 0 <= risk_baseline <= 1
        except OverflowError:
            valid = False
    if not valid:
        raise ValueError('PRIOR_RISK_RANGES_RISK_BASELINE')
    dummy_costs = {uid: 1. for uid in scores} if type(scores) is dict else {}
    uids, weights, _, positive, negative = frozen._validate(
        scores, positive_uids, dummy_costs, k, frozen.MAX_ACTIONS)
    p = weights[positive[0]]
    ordered = sorted(weights[i] for i in negative)
    m = len(negative)
    amin = [math.fsum(ordered[:m - t]) for t in range(k)]
    amax = [math.fsum(ordered[t:]) for t in range(k)]
    hmin = [p / (a + p) for a in amax]
    hmax = [p / (a + p) for a in amin]
    # A/(A+P) is algebraically 1-h but avoids cancellation near h=1.
    smin = math.prod(a / (a + p) for a in amin)
    smax = math.prod(a / (a + p) for a in amax)
    Hmin, Hmax = math.fsum(hmin), math.fsum(hmax)
    residual = [smin - risk_baseline, smax - risk_baseline]
    analytic, details = {}, {}
    for i, uid in enumerate(uids):
        if i == positive[0]:
            analytic[uid] = [-smax * Hmax, -smin * Hmin]
            details[uid] = {'role': 'positive', 'proposal_gradient_range': [0., 0.]}
        else:
            qi = math.fsum(min(1., weights[i] / a) for a in amin)
            di = smax * Hmax * min(1., weights[i] / amin[-1])
            products = [r * ell for r in residual for ell in (-qi, 1.)]
            analytic[uid] = [min(products), max(products) + di]
            details[uid] = {'role': 'negative', 'direct_derivative_range': [0., di],
                            'proposal_gradient_range': [-qi, 1.], 'Q_i': qi, 'D_i': di}
    ranges = {uid: [lo - NUMERICAL_PADDING, hi + NUMERICAL_PADDING]
              for uid, (lo, hi) in analytic.items()}
    return {
        'status': STATUS, 'synthetic_only': True, 'does_not_release_ci': True,
        'confidence_interval_implemented': False, 'range_source': 'PRIOR_ANALYTIC',
        'k': k, 'action_count': len(uids), 'positive_count': 1,
        'baseline_risk': float(risk_baseline), 'baseline_derivative_taken': False,
        'baseline_independence_verified': False,
        'risk_score_gradient_ranges': ranges, 'unpadded_analytic_ranges': analytic,
        'coordinate_derivation': details,
        'constants': {'Amin_t': amin, 'Amax_t': amax, 'positive_weight': p,
                      'hmin_t': hmin, 'hmax_t': hmax, 'Smin': smin, 'Smax': smax,
                      'Hmin': Hmin, 'Hmax': Hmax, 'residual_range': residual,
                      'numerical_padding': NUMERICAL_PADDING},
        'derivation': 'A subset-sum envelopes; -R*H positive; [0,D_i] + '
                      '[Smin-br,Smax-br]*[-Q_i,1] negative (four endpoint products)',
        'rounding_guard_is_formal_proof': False,
    }
