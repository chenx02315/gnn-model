"""Fixed small nonuniform synthetic precision/direction gate, never TRAIN.

Main IID observations condition on an independent frozen pilot. Baselines
and negative-L1 pilot-gradient directions are constants, not differentiated.
Every scalar, UID gradient and four projections gets a two-sided empirical
Bernstein CI, with known conservative ranges and one fixed global M=144.
V3 retains v2 risk PRIOR ranges and changes ONLY cost coordinate ranges to
score/cost/K/frozen-baseline PRIOR bounds; raw-cost sampling is unchanged.
Costs must be zero or >=1e-6. Fixed budget remains v1/v2; fresh case-ID pins
prevent replay. Full bound payloads appear only in the pre-main freeze record.
Risk endpoint padding is fixed 1e-12, not a formal floating-point proof.
Precision and same-objective descent certification are separate decisions.
No adaptive samples, optimizer, real data, Torch, external I/O or trajectories.
"""
import hashlib
import json
import math
import random

from . import ranking_v6_conditional_control_reference as control
from . import ranking_v6_first_hit_exact_gradient as full_oracle
from . import ranking_v6_prior_risk_ranges as prior
from . import ranking_v6_prior_cost_ranges as cost_prior

SEEDS = (11, 29, 47, 83)
N, K = 6, 3
PILOT_SAMPLES, MAIN_SAMPLES = 64, 16384
ALPHA, MAX_RADIUS = .01, .02
COMPARISON_COUNT = 144
MAX_WORK = 20_000_000
MAX_TOTAL_WORK = 80_000_000
FIXTURES = (
    ('mixed', (-.7, .4, 1.2, -1.1, .2, -.2), (1., 9., .2, 2., 4., 5.)),
    ('rare', (-.4, .3, .8, -.9, .2, -3.), (.5, 3., 8., 1., 2., 10.)),
)


def _require(ok, code):
    if not ok:
        raise ValueError('NONUNIFORM_PRECISION_' + code)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode('ascii')).hexdigest()


def _observe_hash(digest, values):
    """Frame each vector with a newline; hash observations without retaining them."""
    digest.update(json.dumps(values, separators=(',', ':'), allow_nan=False).encode('ascii'))
    digest.update(b'\n')


def _verify_oracles(scores, costs, full):
    conditional = control.enumerate_exact_gradient(
        scores, {'5'}, costs, k=K, risk_baseline=0., cost_baseline=0.)
    errors = [abs(full[key] - conditional[key]) for key in
              ('expected_miss_probability', 'expected_truncated_static_cost')]
    errors += [abs(full[key][u] - conditional[key][u]) for key in
               ('miss_score_gradient', 'cost_score_gradient') for u in sorted(scores)]
    maximum = max(errors)
    _require(math.isfinite(maximum) and maximum <= 1e-10, 'EXACT_ORACLE_MISMATCH')
    return dict(paths=['full_original_PL', 'conditional_control_fixed_zero_baselines'],
                max_absolute_error=maximum, absolute_tolerance=1e-10,
                comparison_count=len(errors), passed=True,
                verified_before_pilot_and_main=True)


class _Welford:
    """Streaming vector means and unbiased variances; O(n) retained state."""
    def __init__(self, dimension):
        self.count = 0
        self.mean = [0.] * dimension
        self.m2 = [0.] * dimension

    def add(self, values):
        _require(len(values) == len(self.mean), 'MOMENT_DIMENSION')
        _require(all(math.isfinite(v) for v in values), 'NONFINITE_OBSERVATION')
        self.count += 1
        for i, value in enumerate(values):
            delta = value - self.mean[i]
            self.mean[i] += delta / self.count
            self.m2[i] += delta * (value - self.mean[i])

    def sample_variance(self, index):
        _require(self.count >= 2, 'VARIANCE_COUNT')
        return max(0., self.m2[index] / (self.count - 1))


def _radius(variance, width, count, log_term):
    return math.sqrt(2 * variance * log_term / count) + 7 * width * log_term / (3 * (count - 1))


def _direction(gradient):
    norm = math.fsum(abs(g) for g in gradient)
    _require(math.isfinite(norm), 'DIRECTION_NONFINITE')
    # Zero pilot gradient cannot certify a search direction.
    return ([-g / norm for g in gradient], True) if norm > 0 else ([0.] * len(gradient), False)


def _dot(vector, direction):
    return math.fsum(g * d for g, d in zip(vector, direction))


def _projection_range(ranges, direction):
    """Conservative linear-interval image; correlation cannot invalidate it."""
    lower = math.fsum(min(lo * d, hi * d) for (lo, hi), d in zip(ranges, direction))
    upper = math.fsum(max(lo * d, hi * d) for (lo, hi), d in zip(ranges, direction))
    return lower, upper


def _validate_config(pilot_samples, main_samples, alpha, max_radius):
    _require(type(pilot_samples) is int and 1 <= pilot_samples <= 65536, 'PILOT_SAMPLES')
    _require(type(main_samples) is int and 2 <= main_samples <= 65536, 'MAIN_SAMPLES')
    for value, name in ((alpha, 'ALPHA'), (max_radius, 'MAX_RADIUS')):
        _require(type(value) in (int, float) and 0 < value <= 1 and math.isfinite(value), name)
    work = N * K * (pilot_samples + main_samples)
    _require(work <= MAX_WORK, 'WORK_BOUND')
    _require(2 * len(SEEDS) * work <= MAX_TOTAL_WORK, 'TOTAL_WORK_BOUND')
    return work


def run_nonuniform_precision_v3():
    """Formal fixed entry: no fixture, count, alpha or tolerance overrides."""
    return _run_fixed_fixtures(pilot_samples=PILOT_SAMPLES, main_samples=MAIN_SAMPLES)


def _run_fixed_fixtures(*, pilot_samples=64, main_samples=16384, alpha=.01, max_radius=.02):
    """Private small-count test seam; fixtures/seeds/global M never change."""
    work = _validate_config(pilot_samples, main_samples, alpha, max_radius)
    log_term = math.log(4 * COMPARISON_COUNT) - math.log(alpha)
    summaries, all_rows, fixtures = [], [], []
    exact_by_case, checks_by_case = {}, {}
    # Validate both fixed oracle pairs before constructing ANY pilot/main RNG.
    for fixture_id, score_values, cost_values in FIXTURES:
        scores = {str(i): s for i, s in enumerate(score_values)}
        costs = {str(i): c for i, c in enumerate(cost_values)}
        # Numerical-domain preflight before ANY pilot/main RNG. The fixed
        # precision experiment requires positive B; the standalone helper
        # separately supports the exact all-zero cost branch.
        preflight = cost_prior.prior_normalized_cost_gradient_ranges(
            scores, {'5'}, costs, k=K, normalized_cost_baseline=0.)
        _require(preflight['cost_upper_bound'] > 0, 'ZERO_COST_FIXTURE')
        exact_by_case[fixture_id] = full_oracle.enumerate_exact_gradient(scores, {'5'}, costs, k=K)
        checks_by_case[fixture_id] = _verify_oracles(scores, costs, exact_by_case[fixture_id])
    for fixture_id, score_values, cost_values in FIXTURES:
        scores = {str(i): s for i, s in enumerate(score_values)}
        costs = {str(i): c for i, c in enumerate(cost_values)}
        prepared = control.frozen._validate(scores, {'5'}, costs, K, 7)
        uids = prepared[0]
        bound = K * max(cost_values)
        exact = exact_by_case[fixture_id]
        oracle_check = checks_by_case[fixture_id]
        truth = [exact['expected_miss_probability'], exact['expected_truncated_static_cost'] / bound]
        truth += [exact['miss_score_gradient'][u] for u in uids]
        truth += [exact['cost_score_gradient'][u] / bound for u in uids]
        payload = dict(case_id=fixture_id, scores=scores, costs=costs, positive_uids=['5'],
                       n=N, k=K, temperature=1, cost_normalization_B=bound)
        fixtures.append(dict(payload, fixture_sha256=_hash(payload), exact_original_pl=exact,
                             exact_normalized_cost=truth[1], exact_oracle_crosscheck=oracle_check))
        for seed in SEEDS:
            case_id = 'nonuniform-precision-v3-' + fixture_id
            pins = {phase: control._pin(seed, case_id, phase) for phase in ('pilot', 'main')}
            pilot_rng = random.Random(int(pins['pilot'], 16))
            pilot = _Welford(2 + 2 * N)
            pilot_digest = hashlib.sha256()
            for _ in range(pilot_samples):
                _, risk, cost, gr, gc = control._controlled(
                    control._components(*prepared[1:], K, rng=pilot_rng), 0., 0.)
                pilot_values = [risk, cost / bound] + gr + [g / bound for g in gc]
                pilot.add(pilot_values)
                _observe_hash(pilot_digest, pilot_values)
            br, bc = pilot.mean[0], pilot.mean[1] * bound
            risk_direction, risk_valid = _direction(pilot.mean[2:2 + N])
            cost_direction, cost_valid = _direction(pilot.mean[2 + N:])
            directions = {'risk': risk_direction, 'normalized_cost': cost_direction}
            freeze_payload = dict(case_id=fixture_id, seed=seed, pilot_samples=pilot_samples,
                                  pilot_seed_sha256=pins['pilot'], cost_normalization_B=bound,
                                  baseline_risk=br, baseline_static_cost=bc,
                                  baseline_normalized_cost=bc / bound,
                                  directions={name: dict(zip(uids, d)) for name, d in directions.items()},
                                  direction_valid={'risk': risk_valid, 'normalized_cost': cost_valid},
                                  pilot_observation_sha256=pilot_digest.hexdigest())
            labels = [('miss_probability', None, None), ('normalized_cost', None, None)]
            labels += [('miss_score_gradient', u, None) for u in uids]
            labels += [('normalized_cost_score_gradient', u, None) for u in uids]
            # Scores/K/frozen br only: no main outcomes or moments exist yet.
            risk_prior = prior.prior_risk_gradient_ranges(
                scores, {'5'}, k=K, risk_baseline=br)
            risk_prior_hash = _hash(risk_prior)
            risk_ranges = [risk_prior['risk_score_gradient_ranges'][u] for u in uids]
            cost_bound_prior = cost_prior.prior_normalized_cost_gradient_ranges(
                scores, {'5'}, costs, k=K, normalized_cost_baseline=bc / bound)
            cost_prior_hash = _hash(cost_bound_prior)
            cost_ranges = [cost_bound_prior['normalized_cost_score_gradient_ranges'][u] for u in uids]
            freeze_payload.update(risk_prior_bound_payload=risk_prior,
                                  risk_prior_bound_sha256=risk_prior_hash,
                                  risk_range_source='PRIOR_ANALYTIC_SCORES_K_FROZEN_BR_V2',
                                  cost_prior_bound_payload=cost_bound_prior,
                                  cost_prior_bound_sha256=cost_prior_hash,
                                  cost_range_source='PRIOR_ANALYTIC_SCORES_COSTS_K_FROZEN_BC_V3')
            ranges = [(0., 1.), (0., 1.)] + risk_ranges + cost_ranges
            projected_truth = []
            for objective, vector, coordinate_ranges in (
                    ('risk', truth[2:2 + N], risk_ranges),
                    ('normalized_cost', truth[2 + N:], cost_ranges)):
                for direction_name, direction in directions.items():
                    labels.append((objective + '_projection', None, direction_name))
                    ranges.append(_projection_range(coordinate_ranges, direction))
                    projected_truth.append(_dot(vector, direction))
            exact_values = truth + projected_truth
            freeze_payload.update(comparison_labels=labels, comparison_ranges=ranges)
            freeze_hash = _hash(freeze_payload)
            # No main RNG exists until every pilot-dependent quantity is frozen.
            main_rng = random.Random(int(pins['main'], 16))
            moments = _Welford(len(labels))
            main_digest = hashlib.sha256()
            for _ in range(main_samples):
                _, risk, cost, gr, gc_raw = control._controlled(
                    control._components(*prepared[1:], K, rng=main_rng), br, bc)
                gc = [g / bound for g in gc_raw]
                observations = [risk, cost / bound] + gr + gc
                observations += [_dot(vector, direction) for vector in (gr, gc)
                                 for direction in directions.values()]
                moments.add(observations)
                _observe_hash(main_digest, observations)
            rows = []
            for i, (metric, uid, direction_name) in enumerate(labels):
                variance = moments.sample_variance(i)
                width = ranges[i][1] - ranges[i][0]
                radius = _radius(variance, width, main_samples, log_term)
                estimate, target = moments.mean[i], exact_values[i]
                error = abs(estimate - target)
                _require(all(math.isfinite(v) for v in (variance, radius, estimate, target, error)),
                         'NONFINITE_RESULT')
                same = metric == direction_name + '_projection' if direction_name else False
                row = dict(case_id=fixture_id, seed=seed, metric=metric, uid=uid,
                           direction=direction_name, estimate=estimate, exact=target,
                           sample_variance=variance, range_lower=ranges[i][0],
                           range_upper=ranges[i][1], range_width=width, radius=radius,
                           ci_lower=estimate - radius, ci_upper=estimate + radius,
                           absolute_error=error, inside_error_bound=error <= radius,
                           precision_sufficient=radius <= max_radius,
                           same_objective_projection=same,
                           upper_strictly_negative=estimate + radius < 0)
                rows.append(row)
            descent = risk_valid and cost_valid and all(
                row['upper_strictly_negative'] for row in rows if row['same_objective_projection'])
            summaries.append(dict(case_id=fixture_id, seed=seed, derived_seed_sha256=pins,
                                  seed_case_id=case_id, baseline_risk=br,
                                  baseline_normalized_cost=bc / bound, baseline_static_cost=bc,
                                  baselines_frozen_before_main=True, directions_frozen_before_main=True,
                                  baseline_derivative_taken=False, direction_derivative_taken=False,
                                  pilot_gradient_risk=dict(zip(uids, pilot.mean[2:2 + N])),
                                  pilot_gradient_normalized_cost=dict(zip(uids, pilot.mean[2 + N:])),
                                  frozen_directions={name: dict(zip(uids, d)) for name, d in directions.items()},
                                  direction_valid={'risk': risk_valid, 'normalized_cost': cost_valid},
                                  risk_ranges_frozen_before_main=True,
                                  risk_prior_bound_sha256=risk_prior_hash,
                                  cost_ranges_frozen_before_main=True,
                                  cost_prior_bound_sha256=cost_prior_hash,
                                  pilot_freeze_payload=freeze_payload, pilot_freeze_sha256=freeze_hash,
                                  pilot_observation_sha256=pilot_digest.hexdigest(),
                                  main_observation_sha256=main_digest.hexdigest(),
                                  pilot_observation_count=pilot.count,
                                  raw_same_objective_ucb_negative=descent,
                                  same_objective_direction_certified=descent,
                                  main_observation_count=moments.count, comparison_count=len(rows), rows=rows))
            all_rows.extend(rows)
    _require(len(all_rows) == COMPARISON_COUNT, 'COMPARISON_COUNT')
    errors = sum(not r['inside_error_bound'] for r in all_rows)
    insufficient = sum(not r['precision_sufficient'] for r in all_rows)
    status = ('FAIL_NUMERICAL' if errors else 'INCONCLUSIVE_PRECISION' if insufficient
              else 'PASS_FIXED_SYNTHETIC_PRECISION_ONLY')
    if errors:
        for summary in summaries:
            summary['same_objective_direction_certified'] = False
    certified = not errors and all(s['same_objective_direction_certified'] for s in summaries)
    config = dict(method_version=3, freshnamespace='nonuniform-precision-v3-',
                  freshnamespace_type='SHA_PIN_CASE_ID_PREFIX',
                  seed_derivation_namespace_changed=False,
                  seed_case_id_prefix='nonuniform-precision-v3-',
                  risk_range_source='PRIOR_ANALYTIC_SCORES_K_FROZEN_BR_V2',
                  cost_range_source='PRIOR_ANALYTIC_SCORES_COSTS_K_FROZEN_BC_V3',
                  cost_numerical_padding=cost_prior.NUMERICAL_PADDING,
                  min_positive_cost=cost_prior.MIN_POSITIVE_COST,
                  supported_cost_domain={'zero_allowed': True,
                                         'min_positive_cost': cost_prior.MIN_POSITIVE_COST,
                                         'max_cost': cost_prior.MAX_COST},
                  cost_padding_is_formal_floating_point_proof=False,
                  risk_numerical_padding=prior.NUMERICAL_PADDING,
                  risk_padding_is_formal_floating_point_proof=False,
                  n=N, k=K, seeds=list(SEEDS), positive_uid='5', temperature=1,
                  pilot_samples=pilot_samples, main_samples=main_samples, alpha=alpha,
                  max_radius=max_radius, comparison_count=COMPARISON_COUNT,
                  nominal_work_per_seed=work, nominal_total_work=2 * len(SEEDS) * work,
                  max_work=MAX_WORK, max_total_work=MAX_TOTAL_WORK,
                  seed_namespace=control.SEED_NAMESPACE, pilot_gradient_baselines=[0., 0.],
                  exact_oracle_absolute_tolerance=1e-10,
                  observation_hash_encoding='JSON_vector_ASCII_compact_newline_SHA256',
                  direction_rule='negative_pilot_gradient_L1_unit_zero_failclosed')
    return dict(status=status, precision_status=status, train_release=False,
                direction_status=('BLOCKED_NUMERICAL_FAILURE' if errors else
                                  'PASS_FIXED_SYNTHETIC_DIRECTION_ONLY' if certified
                                  else 'INCONCLUSIVE_DIRECTION'),
                config=config, config_sha256=_hash(config), fixtures=fixtures,
                per_case_seed=summaries, rows=all_rows, comparison_count=len(all_rows),
                comparison_sha256=_hash(all_rows), total_work=config['nominal_total_work'],
                log_term=log_term, error_bound_violations=errors, precision_violations=insufficient,
                all_comparisons_inside_error_bound=errors == 0,
                all_comparisons_precision_sufficient=insufficient == 0,
                same_objective_direction_certified=certified, cross_objective_sign_report_only=True,
                synthetic_only=True, adaptive_sampling=False, trajectories_retained=False,
                real_data_access=False, trainer_implemented=False, optimizer_implemented=False,
                fixed_sample_iid_conditional_on_independent_pilot=True,
                ci_method='empirical_Bernstein_unbiased_s2_log4M_over_alpha',
                generalizes_to_other_fixtures_or_real_data=False)
