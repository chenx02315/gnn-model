"""Synthetic-only negative-PL conditional survival reference; NOT_TRAINER.

For a negative-only PL prefix z of length K, let A_t be its remaining
negative weight and P the (unchanged) total positive weight. Under the full
PL process, continuation without a hit has probability r_t=A_t/(A_t+P).
Thus R(z)=prod(r_t), and C(z)=sum_t S_(t-1)*[(1-r_t)*cbar_P+r_t*c_z[t]],
where S_0=1 and cbar_P is the sole positive's cost. The hit is charged.
E_q[R], E_q[C] equal the full PL first-hit objectives for exactly one positive.
Multi-positive universes are deliberately rejected in this first prototype.

Crucially, scores also change the negative proposal q. The unbiased score
gradient is dF(z)+F(z)*dlog(q(z)), NOT just dF(z). This implementation includes
both terms. It analytically integrates positive stopping, but is not a
Rao-Blackwell or universal variance reduction claim
for cost/gradients relative to every other estimator.

Stdlib only: no data access, Torch, training, online replay, or global RNG.
Time O(samples*n*K), working memory O(n+K); no trajectories retained. Exact
enumeration is restricted to n<=7 and streams at most 6!=720 trajectories.
"""
import itertools
import math
import random

STATUS = 'DRAFT_SYNTHETIC_CONDITIONAL_SURVIVAL_NOT_TRAINER'
MAX_ACTIONS = 1024
MAX_WORK = 20_000_000


def _require(ok, code):
    if not ok:
        raise ValueError('CONDITIONAL_SURVIVAL_' + code)


def _validate(scores, positive_uids, costs, k, max_actions):
    _require(type(scores) is dict and 2 <= len(scores) <= max_actions
             and all(type(u) is str and u for u in scores), 'SCORES_SCHEMA')
    _require(type(costs) is dict and set(costs) == set(scores), 'COST_JOIN')
    _require(type(positive_uids) in (set, frozenset, tuple, list)
             and all(type(u) is str and u for u in positive_uids), 'POSITIVES')
    positives = frozenset(positive_uids)
    _require(len(positives) == len(positive_uids) and len(positives) == 1
             and positives <= set(scores), 'POSITIVE_JOIN')
    _require(type(k) is int and 1 <= k <= 10, 'K')
    _require(len(scores) - len(positives) >= k, 'NEGATIVE_COUNT')
    for mapping, bound, code in ((scores, 20., 'SCORE'), (costs, 1e9, 'COST')):
        for value in mapping.values():
            _require(type(value) in (int, float), code)
            try:
                finite = math.isfinite(value)
            except OverflowError:
                finite = False
            _require(finite, code)
            _require(abs(value) <= bound if code == 'SCORE' else 0 <= value <= bound,
                     code + '_BOUND')
    uids = tuple(sorted(scores))
    shift = max(scores.values())
    weights = [math.exp(scores[u] - shift) for u in uids]
    charges = [float(costs[u]) for u in uids]
    positive = [i for i, u in enumerate(uids) if u in positives]
    negative = [i for i, u in enumerate(uids) if u not in positives]
    return uids, weights, charges, positive, negative


def _trajectory(weights, charges, positive, negative, k, rng=None, order=None):
    n = len(weights)
    p = math.fsum(weights[i] for i in positive)
    cbar = charges[positive[0]]
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
        for i in positive:
            dr[i] = -r * hit * weights[i] / p
        logq[chosen] += 1.
        step_cost = hit * cbar + r * charges[chosen]
        cost += survival * step_cost
        for i in range(n):
            dc[i] += ds[i] * step_cost + survival * (
                dr[i] * (charges[chosen] - cbar))
            ds[i] = ds[i] * r + survival * dr[i]
        survival *= r
        remaining.remove(chosen)
    return probability, survival, cost, [ds[i] + survival * logq[i] for i in range(n)], [
        dc[i] + cost * logq[i] for i in range(n)]


def _result(prepared, k, count, total, mass, work, exact):
    uids = prepared[0]
    divisor = 1. if exact else count
    result = {'status': STATUS, 'synthetic_only': True, 'action_count': len(uids),
              'positive_count': len(prepared[3]), 'k': k, 'temperature': 1,
              'trajectory_count': count, 'work_bound': work, 'max_work': MAX_WORK,
              'expected_miss_probability': total[0] / divisor,
              'expected_truncated_static_cost': total[1] / divisor,
              'miss_score_gradient': dict(zip(uids, (v / divisor for v in total[2]))),
              'cost_score_gradient': dict(zip(uids, (v / divisor for v in total[3]))),
              'proposal_score_term_included': True, 'positive_stopping_integrated': True,
              'exact_enumeration': exact, 'trajectories_retained': False,
              'scalar_loss_implemented': False, 'trainer_implemented': False,
              'real_data_access': False, 'online_cost_replay': False}
    if exact:
        result['probability_mass'] = mass
        _require(math.isclose(mass, 1., abs_tol=1e-12, rel_tol=0.), 'PROBABILITY_MASS')
    _require(all(math.isfinite(v) for v in [result['expected_miss_probability'],
             result['expected_truncated_static_cost'], *result['miss_score_gradient'].values(),
             *result['cost_score_gradient'].values()]), 'NONFINITE_RESULT')
    return result


def _accumulate(total, values, factor):
    _, risk, cost, dr, dc = values
    total[0] += factor * risk
    total[1] += factor * cost
    for i in range(len(dr)):
        total[2][i] += factor * dr[i]
        total[3][i] += factor * dc[i]


def estimate(scores, positive_uids, costs, *, k, seed, samples=1024):
    """Estimate two objectives/score gradients; n<=1024, |score|<=20.

    Costs are finite [0,1e9], samples 1..65536, seed integer [0,2**32-1].
    Exactly one positive and >=K negatives are required. All schema and
    work bounds are rejected before RNG construction. K<=10; n*K*s<=20M.
    """
    _require(type(samples) is int and 1 <= samples <= 65536, 'SAMPLES')
    _require(type(seed) is int and 0 <= seed <= 2**32 - 1, 'SEED')
    prepared = _validate(scores, positive_uids, costs, k, MAX_ACTIONS)
    work = len(scores) * k * samples
    _require(work <= MAX_WORK, 'WORK_BOUND')
    rng = random.Random(seed)
    total = [0., 0., [0.] * len(scores), [0.] * len(scores)]
    for _ in range(samples):
        _accumulate(total, _trajectory(*prepared[1:], k, rng=rng), 1.)
    result = _result(prepared, k, samples, total, None, work, False)
    result.update(seed=seed, samples=samples)
    return result


def enumerate_exact_gradient(scores, positive_uids, costs, *, k):
    """Stream exact negative-only prefixes (n<=7), for synthetic unit oracles."""
    prepared = _validate(scores, positive_uids, costs, k, 7)
    total = [0., 0., [0.] * len(scores), [0.] * len(scores)]
    mass, count = 0., 0
    for order in itertools.permutations(prepared[4], k):
        values = _trajectory(*prepared[1:], k, order=order)
        _accumulate(total, values, values[0])
        mass += values[0]
        count += 1
    return _result(prepared, k, count, total, mass, len(scores) * k * count, True)
