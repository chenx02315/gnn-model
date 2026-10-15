"""Synthetic-only multi-positive PL miss-risk reference; NOT_TRAINER.

For a negative-only PL prefix z, A_t is remaining negative mass and P is
total positive mass. S(z)=prod_t A_t/(A_t+P), and risk=E_q[S]. Scores
also change q: the unbiased gradient is dS + S*dlog(q), including BOTH
terms. Positive stopping is integrated, not sampled. This is not a
universal variance-reduction guarantee and supplies no confidence interval.

Stdlib only; no costs, I/O, training, online replay, or global RNG use.
Time O(samples*n*k), working memory O(n+k); trajectories are not retained.
Exact enumeration streams negative prefixes and is limited to n<=7.
IEEE-754 rounding still applies (risk may round to one at extreme scores);
positive derivatives use explicit positive mass, never rounded 1-S or
total-minus-negative subtraction, preserving tiny nonzero derivatives.
Exact sums are normalized by their computed proposal mass (checked within
1e-12 of one) to keep rounded probabilities in [0,1].
The small exact reference uses Decimal80 arithmetic; the Monte Carlo path
uses binary64, where near-zero negative derivatives can still cancel.
Neither path claims arbitrary precision for Monte Carlo sample gradients.
"""
import itertools
from decimal import Decimal, localcontext
import math
import random
import re

STATUS = 'SYNTHETIC_MULTI_POSITIVE_CONDITIONAL_RISK_NOT_TRAINER'
MAX_ACTIONS = 1024
MAX_WORK = 20_000_000
_UID = re.compile(r'[A-Za-z0-9_.-]{1,64}', re.ASCII)


def _require(ok, code):
    if not ok:
        raise ValueError('MULTI_POSITIVE_CONDITIONAL_RISK_' + code)


def _validate(scores, positive_uids, k, synthetic_only, limit):
    _require(synthetic_only is True, 'SYNTHETIC_ONLY')
    _require(type(scores) is dict and 1 <= len(scores) <= limit, 'SCORES_SCHEMA')
    _require(all(type(u) is str and _UID.fullmatch(u) for u in scores), 'UID')
    _require(type(positive_uids) in (set, frozenset, tuple, list), 'POSITIVES')
    _require(all(type(u) is str and _UID.fullmatch(u) for u in positive_uids), 'POSITIVES')
    positives = frozenset(positive_uids)
    _require(len(positives) == len(positive_uids) and len(positives) > 0
             and positives <= set(scores), 'POSITIVE_JOIN')
    _require(type(k) is int and 1 <= k <= 10, 'K')
    for value in scores.values():
        _require(type(value) in (int, float), 'SCORE')
        try:
            valid = math.isfinite(value) and abs(value) <= 20
        except OverflowError:
            valid = False
        _require(valid, 'SCORE_BOUND')
    uids = tuple(sorted(scores))
    shift = max(scores.values())
    weights = [math.exp(scores[u] - shift) for u in uids]
    positive = [i for i, u in enumerate(uids) if u in positives]
    negative = [i for i, u in enumerate(uids) if u not in positives]
    return uids, weights, positive, negative


def _trajectory(weights, positive, negative, k, rng=None, order=None):
    n = len(weights)
    p = math.fsum(weights[i] for i in positive)
    remaining = list(negative)
    survival, probability, inverse_sum = 1., 1., 0.
    # Keep dS separate: combining it into 1-w/(A+P) can erase the
    # tiny but nonzero positive mass. The chosen proposal derivative
    # similarly uses explicit OTHER mass rather than 1-w/A.
    ds, logq = [0.] * n, [0.] * n
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
        other_mass = math.fsum(weights[i] for i in remaining if i != chosen)
        for i in range(n):
            ds[i] *= r
        for i in remaining:
            fraction = weights[i] / a
            ds[i] += survival * r * hit * fraction
            logq[i] += other_mass / a if i == chosen else -fraction
        inverse_sum += 1. / (a + p)
        survival *= r
        remaining.remove(chosen)
    for i in positive:
        ds[i] = -survival * weights[i] * inverse_sum
    return probability, survival, [ds[i] + survival * logq[i] for i in range(n)]


def _result(prepared, k, count, total, work, exact, guaranteed, mass=None):
    uids, _, positive, _ = prepared
    if exact:
        _require(math.isclose(mass, 1., rel_tol=0., abs_tol=1e-12), 'PROBABILITY_MASS')
    divisor = mass if exact else (1 if guaranteed else count)
    raw_risk = total[0] / divisor
    _require(math.isfinite(raw_risk) and 0 <= raw_risk <= 1, 'RISK_RANGE')
    if exact and not guaranteed:
        _require(all(total[1][i].is_finite() and total[1][i] < 0
                     for i in positive), 'EXACT_POSITIVE_GRADIENT_SIGN')
        _require(all(total[1][i].is_finite() and total[1][i] > 0
                     for i in prepared[3]), 'EXACT_NEGATIVE_GRADIENT_SIGN')
    risk = float(raw_risk)
    gradient = dict(zip(uids, (float(v / divisor) for v in total[1])))
    _require(math.isfinite(risk) and 0 <= risk <= 1, 'RISK_RANGE')
    _require(all(math.isfinite(v) for v in gradient.values()), 'NONFINITE_GRADIENT')
    result = dict(status=STATUS, synthetic_only=True, action_count=len(uids),
                  positive_count=len(positive), k=k, temperature=1,
                  mean_risk=risk, uid_gradient=gradient,
                  expected_miss_probability=risk, miss_score_gradient=gradient.copy(),
                  trajectory_count=count, nominal_work=work, work_bound=work,
                  max_work=MAX_WORK, guaranteed_hit=guaranteed,
                  positive_stopping_integrated=True, proposal_score_term_included=True,
                  exact_enumeration=exact, trajectories_retained=False,
                  arithmetic='decimal80_reference' if exact else 'binary64_monte_carlo',
                  trainer_implemented=False, scalar_loss_implemented=False,
                  real_data_access=False, online_cost_replay=False)
    if exact:
        result['probability_mass'] = float(mass)
    return result


def estimate(scores, positive_uids, *, k, seed, samples=256, synthetic_only=False):
    """Estimate miss risk and score gradient; all checks precede local RNG.

    n=1..1024, k=1..10, samples=1..65536, seed=0..2**32-1; exact
    builtin int/float scores finite within [-20,20]. n*k*samples<=20M.
    If negatives<k, risk and gradient are structurally zero, no RNG is
    constructed, and trajectory_count=0; nominal planning still uses samples.
    """
    _require(synthetic_only is True, 'SYNTHETIC_ONLY')
    _require(type(samples) is int and 1 <= samples <= 65536, 'SAMPLES')
    _require(type(seed) is int and 0 <= seed <= 2**32 - 1, 'SEED')
    prepared = _validate(scores, positive_uids, k, synthetic_only, MAX_ACTIONS)
    work = len(scores) * k * samples
    _require(work <= MAX_WORK, 'WORK_BOUND')
    total = [0., [0.] * len(scores)]
    guaranteed = len(prepared[3]) < k
    if not guaranteed:
        rng = random.Random(seed)
        for _ in range(samples):
            _, risk, gradient = _trajectory(*prepared[1:], k, rng=rng)
            total[0] += risk
            for i, value in enumerate(gradient):
                total[1][i] += value
    result = _result(prepared, k, 0 if guaranteed else samples, total, work,
                     False, guaranteed)
    result.update(seed=seed, samples=samples)
    return result


def enumerate_exact_gradient(scores, positive_uids, *, k, synthetic_only=False):
    """Stream negative prefixes using Decimal80 (n<=7, at most 720).

    This small numerical reference is not the binary64 sampling kernel.
    """
    prepared = _validate(scores, positive_uids, k, synthetic_only, 7)
    guaranteed = len(prepared[3]) < k
    with localcontext() as context:
        context.prec = 80
        zero, one = Decimal(0), Decimal(1)
        n = len(scores)
        total = [zero, [zero] * n]
        mass, count = (one, 0) if guaranteed else (zero, 0)
        if not guaranteed:
            uids, _, positive, negative = prepared
            shift = Decimal(str(max(scores.values())))
            weights = [(Decimal(str(scores[u])) - shift).exp() for u in uids]
            p = sum((weights[i] for i in positive), zero)
            for order in itertools.permutations(negative, k):
                remaining = list(negative)
                probability, survival, inverse_sum = one, one, zero
                # dlog(q*S); unlike binary64 this small high-precision
                # reference can retain tiny terms across prefix cancellation.
                joint = [zero] * n
                for chosen in order:
                    a = sum((weights[i] for i in remaining), zero)
                    denominator = a + p
                    probability *= weights[chosen] / a
                    survival *= a / denominator
                    other = sum((weights[i] for i in remaining if i != chosen), zero)
                    for i in remaining:
                        joint[i] += ((other + p) / denominator if i == chosen
                                     else -weights[i] / denominator)
                    inverse_sum += one / denominator
                    remaining.remove(chosen)
                for i in positive:
                    joint[i] = -weights[i] * inverse_sum
                contribution = probability * survival
                total[0] += contribution
                for i, value in enumerate(joint):
                    total[1][i] += contribution * value
                mass += probability
                count += 1
        work = n * k * count
        _require(work <= MAX_WORK, 'WORK_BOUND')
        return _result(prepared, k, count, total, work, True, guaranteed, mass)
