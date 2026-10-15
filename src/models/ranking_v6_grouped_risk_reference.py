"""Independent Decimal60 full-PL miss reference for three synthetic classes.

The surviving prefix contains only negatives. A layer records the number of
negative-A selections; negative-B selections are implied by the layer index.
Group-logit derivatives move every score in a class together. Exchangeability
then gives a single individual's derivative by dividing by the class size.
This is bounded numerical reference arithmetic, not symbolic exact arithmetic.
No sampling, external I/O, action permutation enumeration or training is used.
"""
from decimal import Decimal, localcontext
import math


GROUPS = ('positive', 'negative_a', 'negative_b')
DECIMAL_PRECISION = 60


def _require(condition, code):
    if not condition:
        raise ValueError('GROUPED_RISK_REFERENCE_' + code)


def _validate(counts, scores, k, synthetic_only):
    _require(synthetic_only is True, 'SYNTHETIC_OPT_IN_REQUIRED')
    _require(all(type(value) is int and value >= 1 for value in counts), 'COUNTS')
    n = sum(counts)
    _require(n <= 1024, 'N_BOUND')
    _require(type(k) is int and 1 <= k <= 10 and k <= n, 'K_BOUND')
    # Bound before isfinite: arbitrary-size built-in integers must fail closed
    # without conversion overflow. bool and user-defined numeric hooks fail too.
    _require(all(type(value) in (int, float) and abs(value) <= 20
                 and math.isfinite(value) for value in scores), 'SCORES')
    return n


def reference(positive_count, negative_a_count, negative_b_count,
              positive_score, negative_a_score, negative_b_score, *, k,
              synthetic_only=False):
    """Return miss risk and group/per-individual derivatives, with Decimal text.

    Counts are exact built-in positive integers, total <=1024. Scores are finite
    built-in int/float values with magnitude <=20; 1<=k<=min(10,N). All inputs
    are checked before Decimal work. Opt-in is deliberately mandatory.
    """
    counts = (positive_count, negative_a_count, negative_b_count)
    scores = (positive_score, negative_a_score, negative_b_score)
    n = _validate(counts, scores, k, synthetic_only)
    structural_zero = negative_a_count + negative_b_count < k
    state_visits = transition_count = 0
    max_live_states = 0
    with localcontext() as ctx:
        ctx.prec = DECIMAL_PRECISION
        zero, one = Decimal(0), Decimal(1)
        risk, gradient = zero, (zero, zero, zero)
        if not structural_zero:
            weights = tuple(Decimal(str(value)).exp() for value in scores)
            states = {0: (one, (zero, zero, zero))}
            max_live_states = 1
            for selected in range(k):
                next_states = {}
                for chosen_a, (probability, sensitivity) in states.items():
                    state_visits += 1
                    chosen_b = selected - chosen_a
                    masses = (positive_count * weights[0],
                              (negative_a_count - chosen_a) * weights[1],
                              (negative_b_count - chosen_b) * weights[2])
                    denominator = sum(masses, zero)
                    for group in (1, 2):
                        if not masses[group]:
                            continue
                        transition_count += 1
                        transition = masses[group] / denominator
                        branch_probability = probability * transition
                        # dT/ds_h = T * (1[group=h] - mass_h / total).
                        branch_gradient = tuple(
                            sensitivity[h] * transition + branch_probability *
                            ((one if h == group else zero) - masses[h] / denominator)
                            for h in range(3))
                        destination = chosen_a + (group == 1)
                        previous_p, previous_g = next_states.get(
                            destination, (zero, (zero, zero, zero)))
                        next_states[destination] = (
                            previous_p + branch_probability,
                            tuple(previous_g[h] + branch_gradient[h] for h in range(3)))
                        max_live_states = max(max_live_states,
                                              len(states) + len(next_states))
                states = next_states
            risk = sum((state[0] for state in states.values()), zero)
            gradient = tuple(sum((state[1][h] for state in states.values()), zero)
                             for h in range(3))
        individual = tuple(gradient[h] / counts[h] for h in range(3))
        return dict(
            expected_miss_probability=float(risk),
            miss_group_score_gradient=dict(zip(GROUPS, map(float, gradient))),
            miss_per_individual_score_gradient=dict(zip(GROUPS, map(float, individual))),
            decimal_expected_miss_probability=str(risk),
            decimal_miss_group_score_gradient=dict(zip(GROUPS, map(str, gradient))),
            counts=dict(zip(GROUPS, counts)), scores=dict(zip(GROUPS, scores)),
            n=n, k=k, decimal_precision=DECIMAL_PRECISION,
            method='Decimal60_full_PL_two_negative_class_survival_DP',
            derivative_parameterization='class_shared_logit_temperature_1',
            state_visits=state_visits, transition_count=transition_count,
            max_live_states=max_live_states, structural_zero=structural_zero,
            synthetic_only=True, real_data_access=False,
            optimizer_implemented=False, trainer_implemented=False,
            trajectories_retained=False)
