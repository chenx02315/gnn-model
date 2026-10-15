"""Synthetic-only pilot-frozen score control variate; NOT_TRAINER.

Negative-only PL proposal q yields survival S, its derivative dS and dlogq.
The main gradient is dS + (S-b)*dlogq, NOT a reconstruction from an
already-cancelled gradient. b is the mean S of ALL independent pilot paths,
frozen before constructing the main RNG, with no derivative through b.
Risk itself remains the main mean S (no baseline subtraction).

Streams are modeled as independent PRNG streams: distinct Random objects
with seeds seed ^ 0x9E3779B9 and seed. This is not empirical certification
of PRNG independence, a universal variance guarantee, or a confidence interval.
Stdlib only, no I/O/model/optimizer/training/real data/remote operations.
O(n*k*(pilot_samples+samples)) time, O(n+k) working memory, no retained paths.
Binary64 rounding and near-zero negative-derivative cancellation still apply.
"""
import math
import random
import re

STATUS = 'SYNTHETIC_MULTI_POSITIVE_RISK_CONTROL_NOT_TRAINER'
MAX_ACTIONS = 1024
MAX_WORK = 20_000_000
PILOT_SEED_XOR = 0x9E3779B9
_UID = re.compile(r'[A-Za-z0-9_.-]{1,64}', re.ASCII)


def _require(ok, code):
    if not ok:
        raise ValueError('MULTI_POSITIVE_RISK_CONTROL_' + code)


def _validate(scores, positive_uids, k, synthetic_only, limit=MAX_ACTIONS):
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
    """Private binary64 path: return (q, S, dS, dlogq), not an exact oracle."""
    n = len(weights)
    p = math.fsum(weights[i] for i in positive)
    remaining = list(negative)
    survival, probability, inverse_sum = 1., 1., 0.
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
    return probability, survival, ds, logq


def _kahan_add(totals, corrections, i, value):
    adjusted = value - corrections[i]
    updated = totals[i] + adjusted
    corrections[i] = (updated - totals[i]) - adjusted
    totals[i] = updated


def estimate(scores, positive_uids, *, k, seed, pilot_samples=32,
             samples=480, synthetic_only=False):
    """Independent pilot baseline; all validation/budget gates precede RNG.

    Exact builtin types only. Pilot and main counts each 1..65536; seed
    0..2**32-1; n<=1024, k<=10; nominal n*k*(pilot+main)<=20M even when
    negatives<k gives structural zero without constructing either RNG.
    """
    _require(synthetic_only is True, 'SYNTHETIC_ONLY')
    _require(type(pilot_samples) is int and 1 <= pilot_samples <= 65536, 'PILOT_SAMPLES')
    _require(type(samples) is int and 1 <= samples <= 65536, 'SAMPLES')
    _require(type(seed) is int and 0 <= seed <= 2**32 - 1, 'SEED')
    prepared = _validate(scores, positive_uids, k, synthetic_only)
    uids, weights, positive, negative = prepared
    total_samples = pilot_samples + samples
    work = len(uids) * k * total_samples
    _require(work <= MAX_WORK, 'WORK_BOUND')
    guaranteed = len(negative) < k
    pilot_seed = seed ^ PILOT_SEED_XOR
    baseline = 0.
    totals, corrections = [0.] * (len(uids) + 1), [0.] * (len(uids) + 1)
    if not guaranteed:
        pilot_rng = random.Random(pilot_seed)
        baseline = math.fsum(_trajectory(weights, positive, negative, k,
                                         rng=pilot_rng)[1]
                             for _ in range(pilot_samples)) / pilot_samples
        # No main RNG or main path exists before this baseline is frozen.
        main_rng = random.Random(seed)
        for _ in range(samples):
            _, survival, ds, logq = _trajectory(weights, positive, negative, k,
                                                rng=main_rng)
            _kahan_add(totals, corrections, 0, survival)
            for i in range(len(uids)):
                _kahan_add(totals, corrections, i + 1,
                           ds[i] + (survival - baseline) * logq[i])
    divisor = 1 if guaranteed else samples
    risk = totals[0] / divisor
    gradient = dict(zip(uids, (v / divisor for v in totals[1:])))
    _require(math.isfinite(risk) and 0 <= risk <= 1, 'RISK_RANGE')
    _require(all(math.isfinite(v) for v in gradient.values()), 'NONFINITE_GRADIENT')
    return dict(status=STATUS, synthetic_only=True, action_count=len(uids),
                positive_count=len(positive), k=k, temperature=1,
                mean_risk=risk, uid_gradient=gradient,
                expected_miss_probability=risk, miss_score_gradient=gradient.copy(),
                seed=seed, main_seed=seed, pilot_seed=pilot_seed,
                samples=samples, pilot_samples=pilot_samples, total_samples=total_samples,
                trajectory_count=0 if guaranteed else samples,
                main_trajectory_count=0 if guaranteed else samples,
                pilot_trajectory_count=0 if guaranteed else pilot_samples,
                total_trajectory_count=0 if guaranteed else total_samples,
                pilot_baseline=baseline, baseline_frozen_before_main=True,
                baseline_main_adaptation=False, baseline_derivative_included=False,
                pilot_uses_all_samples=True, independent_prng_stream_model=True,
                prng_independence_empirically_certified=False,
                nominal_work=work, work_bound=work, max_work=MAX_WORK,
                guaranteed_hit=guaranteed, structural_zero_baseline=guaranteed,
                positive_stopping_integrated=True, proposal_score_term_included=True,
                exact_enumeration=False, trajectories_retained=False,
                arithmetic='binary64_monte_carlo', trainer_implemented=False,
                scalar_loss_implemented=False, real_data_access=False,
                online_cost_replay=False, confidence_interval_implemented=False,
                universal_variance_reduction_claim=False)
