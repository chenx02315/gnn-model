"""Fixed-sample uniform-single-positive synthetic precision reference only.

No reader, training, ML, real labels, online costs, adaptive sampling or I/O.
Closed forms apply ONLY to equal scores, one positive, all costs exactly one.
Main observations are IID conditional on an independent, frozen pilot.
The empirical Bernstein bound uses unbiased sample variance and a known
observation range; log(4*M/alpha) conservatively unions all fixed comparisons.
Neither a passing synthetic fixture nor its CI generalizes to nonuniform
weights, variable costs, actual task data, or learned scorers.
"""
import hashlib
import json
import math
import random

from . import ranking_v6_streaming_estimator_large as streaming

SEEDS = (11, 29, 47, 83)
MAX_WORK = 20_000_000
MAX_TOTAL_WORK = 80_000_000


def _require(ok, code):
    if not ok:
        raise ValueError('LARGE_PRECISION_' + code)


def _domain(n, k):
    _require(type(n) is int and 2 <= n <= 1024, 'N')
    _require(type(k) is int and 1 <= k <= min(n, 10), 'K')


def _fixture(n):
    uids = sorted(str(i) for i in range(n))
    positive_uid = '17' if n >= 18 else '0'
    return uids, positive_uid


def uniform_closed_form(n, k):
    """Complete UID gradient maps at the equal-score/unit-cost fixture.

    Survival after j draws is (n-j)/n. Differentiate survival for a single
    positive score; symmetry and shift invariance give every negative's
    derivative as -positive_derivative/(n-1). Cost is the survival sum for
    j=0..K-1. Valid also at K=n: miss and its gradient are zero, but expected
    first-hit cost can still have a nonzero score derivative.
    """
    _domain(n, k)
    uids, positive_uid = _fixture(n)
    harmonic = math.fsum(1. / (n-t) for t in range(k))
    risk = (n-k) / n
    risk_pos = -risk * harmonic
    cost = k - k*(k-1) / (2*n)
    cost_pos = -math.fsum((n-j) / n * math.fsum(1. / (n-t) for t in range(j))
                          for j in range(1, k))
    risk_neg, cost_neg = -risk_pos / (n-1), -cost_pos / (n-1)
    return {'action_count': n, 'k': k, 'positive_uid': positive_uid,
            'survival_probability_by_draw': [(n-j) / n for j in range(k+1)],
            'expected_miss_probability': risk, 'expected_truncated_static_cost': cost,
            'expected_normalized_cost': cost / k, 'cost_normalization_B': k,
            'miss_score_gradient': {u: risk_pos if u == positive_uid else risk_neg for u in uids},
            'cost_score_gradient': {u: cost_pos if u == positive_uid else cost_neg for u in uids},
            'normalized_cost_score_gradient': {
                u: (cost_pos if u == positive_uid else cost_neg) / k for u in uids}}


class _Welford:
    """O(dimension) state: count, means and unnormalized second moments."""
    def __init__(self, dimension):
        self.count = 0
        self.mean = [0.] * dimension
        self.m2 = [0.] * dimension

    def add(self, values):
        _require(len(values) == len(self.mean), 'MOMENT_DIMENSION')
        self.count += 1
        for i, value in enumerate(values):
            delta = value - self.mean[i]
            self.mean[i] += delta / self.count
            self.m2[i] += delta * (value - self.mean[i])

    def sample_variance(self, index):
        _require(self.count >= 2, 'VARIANCE_COUNT')
        return max(0., self.m2[index] / (self.count-1))


def _radius(variance, width, count, log_term):
    return math.sqrt(2*variance*log_term / count) + 7*width*log_term / (3*(count-1))


def run_uniform_precision(n=736, k=10, *, seeds=SEEDS, pilot_samples=64,
                          main_samples=2304, alpha=.01, max_radius=.05):
    """Fixed four-seed gate, with caller preregistration and no retry/extension.

    n/counts can be smaller for tests. Fixture scores=0, one positive UID17
    (UID0 for n<18), costs=1 are not caller-overridable. Every UID in both
    gradient vectors and both scalar objectives is checked for each seed.
    Precision is in normalized cost units, not raw cost units. No normal
    approximation: two-sided empirical Bernstein, fixed N, union bound over
    M=4*(2+2*n). Interpretation is conditional on frozen pilot, independent
    main IID draws and bounded observations under this uniform fixture.
    """
    _domain(n, k)
    _require(type(seeds) in (tuple, list) and tuple(seeds) == SEEDS
             and all(type(seed) is int for seed in seeds), 'FIXED_SEEDS')
    _require(type(pilot_samples) is int and 1 <= pilot_samples <= 65536, 'PILOT_SAMPLES')
    _require(type(main_samples) is int and 2 <= main_samples <= 65536, 'MAIN_SAMPLES')
    for value, name in ((alpha, 'ALPHA'), (max_radius, 'MAX_RADIUS')):
        _require(type(value) in (int, float) and 0 < value <= 1 and math.isfinite(value), name)
    work = n*k*(pilot_samples + main_samples)
    _require(work <= MAX_WORK, 'WORK_BOUND')
    _require(len(SEEDS)*work <= MAX_TOTAL_WORK, 'TOTAL_WORK_BOUND')
    # All bounds/config checks precede seed hashing, RNGs or softmax.
    oracle = uniform_closed_form(n, k)
    uids, positive_uid = _fixture(n)
    values, charges = [0.] * n, [1.] * n
    positives = [u == positive_uid for u in uids]
    comparison_count = len(SEEDS)*(2+2*n)
    # Difference of logs also supports finite positive subnormal alpha without
    # overflowing the otherwise equivalent quotient 4*M/alpha.
    log_term = math.log(4*comparison_count) - math.log(alpha)
    q = min(k / (n-k+1), k)
    gradient_width = 2*max(q, 1.)
    labels = [('miss_probability', None), ('normalized_cost', None)]
    labels += [('miss_score_gradient', u) for u in uids]
    labels += [('normalized_cost_score_gradient', u) for u in uids]
    exact = [oracle['expected_miss_probability'], oracle['expected_normalized_cost']]
    exact += [oracle['miss_score_gradient'][u] for u in uids]
    exact += [oracle['normalized_cost_score_gradient'][u] for u in uids]
    widths = [1., 1.] + [gradient_width] * (2*n)
    negative_uid = next(u for u in uids if u != positive_uid)
    case_id = 'uniform-precision-v1-n%d-k%d' % (n, k)
    summaries = []
    total_errors = total_precision = total_checked = 0
    all_comparisons_digest = hashlib.sha256()
    for seed in SEEDS:
        pins = {phase: streaming._seed_pin(seed, case_id, phase) for phase in ('pilot', 'main')}
        pilot_rng, main_rng = (random.Random(int(pins[phase], 16)) for phase in ('pilot', 'main'))
        pilot_risk = pilot_cost = 0.
        for _ in range(pilot_samples):
            risk, cost, _ = streaming._sample(values, positives, charges, k, pilot_rng, False)
            pilot_risk += risk
            pilot_cost += cost / k
        baseline_risk, baseline_cost = pilot_risk / pilot_samples, pilot_cost / pilot_samples
        moments = _Welford(2+2*n)
        for _ in range(main_samples):
            risk, cost, gradient = streaming._sample(values, positives, charges, k, main_rng, True)
            normalized_cost = cost / k
            observations = [risk, normalized_cost]
            observations += [(risk-baseline_risk)*g for g in gradient]
            observations += [(normalized_cost-baseline_cost)*g for g in gradient]
            moments.add(observations)
        groups = {name: {'comparison_count': 0, 'max_absolute_error': 0., 'max_radius': 0.,
                         'error_bound_violations': 0, 'precision_violations': 0}
                  for name in ('miss_probability', 'normalized_cost', 'miss_score_gradient',
                               'normalized_cost_score_gradient')}
        rows = []
        worst_error = worst_radius = None
        digest = hashlib.sha256()
        for i, (metric, uid) in enumerate(labels):
            variance = moments.sample_variance(i)
            radius = _radius(variance, widths[i], main_samples, log_term)
            error = abs(moments.mean[i]-exact[i])
            _require(all(math.isfinite(v) for v in (moments.mean[i], variance, radius, error)), 'NONFINITE')
            row = {'metric': metric, 'uid': uid, 'estimate': moments.mean[i], 'exact': exact[i],
                   'sample_variance': variance, 'range_width': widths[i], 'radius': radius,
                   'absolute_error': error, 'inside_error_bound': error <= radius,
                   'precision_sufficient': radius <= max_radius}
            encoded = json.dumps([seed, row], sort_keys=True, separators=(',', ':'),
                                 allow_nan=False).encode('ascii')
            digest.update(encoded)
            all_comparisons_digest.update(encoded)
            group = groups[metric]
            group['comparison_count'] += 1
            group['max_absolute_error'] = max(group['max_absolute_error'], error)
            group['max_radius'] = max(group['max_radius'], radius)
            group['error_bound_violations'] += int(error > radius)
            group['precision_violations'] += int(radius > max_radius)
            if worst_error is None or error-radius > worst_error['absolute_error']-worst_error['radius']:
                worst_error = row
            if worst_radius is None or radius > worst_radius['radius']:
                worst_radius = row
            if uid is None or uid in (positive_uid, negative_uid):
                rows.append(row)
        errors = sum(g['error_bound_violations'] for g in groups.values())
        insufficient = sum(g['precision_violations'] for g in groups.values())
        checked = sum(g['comparison_count'] for g in groups.values())
        total_errors += errors
        total_precision += insufficient
        total_checked += checked
        summaries.append({'seed': seed, 'derived_seed_sha256': pins, 'case_id': case_id,
                          'baseline_risk': baseline_risk, 'baseline_normalized_cost': baseline_cost,
                          'baselines_frozen_before_main': True, 'main_observation_count': moments.count,
                          'comparison_count': checked, 'comparison_sha256': digest.hexdigest(),
                          'expected_truncated_static_cost_estimate': moments.mean[1]*k,
                          'groups': groups, 'scalar_and_named_positive_negative_rows': rows,
                          'worst_error_minus_radius': worst_error, 'worst_radius': worst_radius})
    _require(total_checked == comparison_count, 'COMPARISON_COUNT')
    status = 'FAIL' if total_errors else ('INCONCLUSIVE_PRECISION' if total_precision else 'PASS')
    return {'status': status, 'synthetic_only': True, 'fixture': 'uniform_single_positive_unit_cost',
            'config': {'n': n, 'k': k, 'seeds': list(SEEDS), 'pilot_samples': pilot_samples,
                       'main_samples': main_samples, 'alpha': alpha, 'max_radius': max_radius,
                       'positive_uid': positive_uid, 'temperature': 1, 'uniform_score': 0,
                       'unit_cost': 1, 'cost_normalization_B': k, 'case_id': case_id},
            'work_per_seed': work, 'total_work': work*len(SEEDS), 'max_work_per_seed': MAX_WORK,
            'max_total_work': MAX_TOTAL_WORK, 'comparison_count': total_checked,
            'comparison_sha256': all_comparisons_digest.hexdigest(), 'log_term': log_term,
            'gradient_q_bound': q, 'gradient_range_width': gradient_width,
            'error_bound_violations': total_errors, 'precision_violations': total_precision,
            'all_comparisons_inside_error_bound': total_errors == 0,
            'all_comparisons_precision_sufficient': total_precision == 0,
            'oracle_summary': {key: oracle[key] for key in ('expected_miss_probability',
                               'expected_normalized_cost', 'expected_truncated_static_cost')},
            'per_seed': summaries, 'fixed_sample_iid_conditional_on_independent_pilot': True,
            'ci_method': 'empirical_Bernstein_unbiased_s2_log4M_over_alpha',
            'adaptive_sampling': False, 'trajectories_retained': False, 'real_data_access': False,
            'trainer_implemented': False, 'generalizes_to_nonuniform_or_real_data': False}
