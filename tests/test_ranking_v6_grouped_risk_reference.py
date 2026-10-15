"""Small-only independent full-permutation and finite-difference checks."""
from decimal import Decimal, getcontext, localcontext
import importlib
import itertools
import math
import unittest
from unittest.mock import patch

from src.models import ranking_v6_grouped_risk_reference as grouped


def permutation_reference(counts, scores, k):
    """Explicit UID permutation sum, not the grouped recurrence under test."""
    with localcontext() as context:
        context.prec = 75
        classes = [g for g, count in enumerate(counts) for _ in range(count)]
        weights = [Decimal(str(scores[g])).exp() for g in classes]
        risk = Decimal(0)
        gradient = [Decimal(0)] * 3
        individual_gradient = [Decimal(0)] * sum(counts)
        for order in itertools.permutations(range(sum(counts)), k):
            if any(classes[uid] == 0 for uid in order):
                continue
            remaining = set(range(sum(counts)))
            probability = Decimal(1)
            log_gradient = [Decimal(0)] * 3
            individual_log_gradient = [Decimal(0)] * sum(counts)
            for uid in order:
                denominator = sum(weights[u] for u in remaining)
                probability *= weights[uid] / denominator
                for group in range(3):
                    mass = sum((weights[u] for u in remaining if classes[u] == group), Decimal(0))
                    log_gradient[group] += Decimal(classes[uid] == group) - mass / denominator
                for coordinate in remaining:
                    individual_log_gradient[coordinate] += (Decimal(uid == coordinate)
                                                            - weights[coordinate] / denominator)
                remaining.remove(uid)
            risk += probability
            for group in range(3):
                gradient[group] += probability * log_gradient[group]
            for coordinate in range(sum(counts)):
                individual_gradient[coordinate] += probability * individual_log_gradient[coordinate]
        return risk, gradient, individual_gradient


class GroupedRiskReferenceTests(unittest.TestCase):
    CASES = (((1, 2, 2), (-2., -1., 1.), 2),
             ((2, 1, 2), (0., -1., 1.), 3),
             ((1, 2, 1), (2., -1., 1.), 2))

    def ref(self, counts=(1, 2, 2), scores=(0., -1., 1.), k=2):
        return grouped.reference(*counts, *scores, k=k, synthetic_only=True)

    def test_independent_permutation_decimal_and_individual_symmetry(self):
        for counts, scores, k in self.CASES:
            result = self.ref(counts, scores, k)
            risk, gradient, individual_gradient = permutation_reference(counts, scores, k)
            self.assertLess(abs(Decimal(result['decimal_expected_miss_probability']) - risk), Decimal('1e-57'))
            for index, name in enumerate(grouped.GROUPS):
                self.assertLess(abs(Decimal(result['decimal_miss_group_score_gradient'][name])
                                    - gradient[index]), Decimal('1e-57'))
                self.assertAlmostEqual(result['miss_per_individual_score_gradient'][name] * counts[index],
                                       float(gradient[index]), delta=1e-16)
            classes = [g for g, count in enumerate(counts) for _ in range(count)]
            for coordinate, group in enumerate(classes):
                self.assertAlmostEqual(
                    result['miss_per_individual_score_gradient'][grouped.GROUPS[group]],
                    float(individual_gradient[coordinate]), delta=1e-16)

    def test_finite_difference_every_group_logit_and_shift(self):
        for counts, scores, k in self.CASES:
            result = self.ref(counts, scores, k)
            for index, name in enumerate(grouped.GROUPS):
                hi, lo = list(scores), list(scores)
                hi[index] += 1e-5
                lo[index] -= 1e-5
                finite_difference = (self.ref(counts, hi, k)['expected_miss_probability'] -
                                     self.ref(counts, lo, k)['expected_miss_probability']) / 2e-5
                self.assertAlmostEqual(result['miss_group_score_gradient'][name], finite_difference, delta=2e-10)
            shifted = self.ref(counts, tuple(value + 3. for value in scores), k)
            self.assertEqual(result['expected_miss_probability'], shifted['expected_miss_probability'])
            for name in grouped.GROUPS:
                self.assertEqual(result['miss_group_score_gradient'][name], shifted['miss_group_score_gradient'][name])
            self.assertAlmostEqual(math.fsum(result['miss_group_score_gradient'].values()), 0., delta=1e-16)

    def test_equal_scores_closed_form_and_small_state_bound(self):
        result = self.ref((2, 3, 4), (0., 0., 0.), 5)
        risk = math.prod((7-t)/(9-t) for t in range(5))
        self.assertAlmostEqual(result['expected_miss_probability'], risk, delta=1e-16)
        self.assertLessEqual(result['max_live_states'], 2*5+1)
        self.assertLessEqual(result['state_visits'], 5*6//2)
        self.assertLessEqual(result['transition_count'], 5*6)

    def test_structural_zero_and_extreme_bounded_scores(self):
        result = self.ref((2, 1, 1), (20., -20., 20.), 3)
        self.assertTrue(result['structural_zero'])
        self.assertEqual(result['decimal_expected_miss_probability'], '0')
        self.assertEqual(result['transition_count'], 0)
        self.assertTrue(all(value == 0 for value in result['miss_group_score_gradient'].values()))
        for scores in ((-20., 20., -20.), (20., -20., 20.)):
            result = self.ref((1, 2, 2), scores, 4)
            self.assertTrue(0 <= result['expected_miss_probability'] <= 1)
            self.assertTrue(all(math.isfinite(value) for value in result['miss_group_score_gradient'].values()))

    def test_invalid_before_decimal_work_and_explicit_optin(self):
        valid = dict(positive_count=1, negative_a_count=2, negative_b_count=2,
                     positive_score=0., negative_a_score=-1., negative_b_score=1.,
                     k=2, synthetic_only=True)
        changes = [dict(synthetic_only=value) for value in (False, 1, 'true', None)]
        for name in ('positive_count', 'negative_a_count', 'negative_b_count'):
            changes += [{name: value} for value in (True, 0, -1, 1., '2', 1024)]
        changes += [dict(k=value) for value in (True, 0, 6, 11, 1., '2')]
        for name in ('positive_score', 'negative_a_score', 'negative_b_score'):
            changes += [{name: value} for value in
                        (True, '0', Decimal(0), float('nan'), float('inf'), -21, 21, 10**1000)]
        with patch.object(grouped, 'localcontext', side_effect=AssertionError('DECIMAL_WORK')):
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    grouped.reference(**dict(valid, **change))
            omitted = dict(valid)
            del omitted['synthetic_only']
            with self.assertRaisesRegex(ValueError, 'OPT_IN'):
                grouped.reference(**omitted)

    def test_no_io_rng_or_context_mutation(self):
        precision_before = getcontext().prec
        with patch('builtins.open', side_effect=AssertionError('IO')), \
                patch('os.open', side_effect=AssertionError('IO')), \
                patch('socket.socket', side_effect=AssertionError('NETWORK')), \
                patch('subprocess.Popen', side_effect=AssertionError('PROCESS')), \
                patch('random.Random', side_effect=AssertionError('RNG')):
            importlib.reload(grouped)
            first, second = self.ref(), self.ref()
        self.assertEqual(first, second)
        self.assertEqual(getcontext().prec, precision_before)
        self.assertEqual(first['decimal_precision'], 60)
        for key in ('real_data_access', 'optimizer_implemented', 'trainer_implemented', 'trajectories_retained'):
            self.assertFalse(first[key])


if __name__ == '__main__':
    unittest.main()
