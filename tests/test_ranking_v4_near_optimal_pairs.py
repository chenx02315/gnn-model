import unittest

from scripts.ranking_v4_near_optimal_pairs import (
    PAIR_CAP_PER_FAMILY, build_near_optimal_pair_recipe, family_macro_pairwise_softplus,
)


def row(uid, family, cycles):
    return {'action_uid': uid, 'family': family, 'total_cycles': cycles}


class NearOptimalPairTests(unittest.TestCase):
    def test_deterministic_permutation_and_exact_epsilon_boundary(self):
        rows = [row('a', 'fit_a', 100), row('b', 'fit_a', 101), row('c', 'fit_a', 102),
                row('d', 'fit_b', 10), row('e', 'fit_b', 12)]
        first = build_near_optimal_pair_recipe(rows, heldout_family='held')
        second = build_near_optimal_pair_recipe(list(reversed(rows)), heldout_family='held')
        self.assertEqual(first, second)
        self.assertEqual(2, first['recipe']['families']['fit_a']['positive_count'])
        self.assertEqual(1, first['recipe']['families']['fit_a']['negative_count'])

    def test_rejects_allowlist_numeric_duplicate_and_heldout_errors(self):
        bad = row('a', 'fit', 1); bad['policy_charged_runtime_s'] = 1.0
        for rows in ([bad], [row('a', 'fit', '1')], [row('a', 'fit', True)],
                     [row('a', 'fit', 1), row('a', 'fit', 2)], [row('a', 'held', 1)]):
            with self.assertRaises(ValueError): build_near_optimal_pair_recipe(rows, heldout_family='held')

    def test_missing_class_and_cap_refuse_or_bound(self):
        with self.assertRaises(ValueError):
            build_near_optimal_pair_recipe([row('a', 'fit', 100), row('b', 'fit', 101)], heldout_family='held')
        rows = [row('p%d' % index, 'fit', 100) for index in range(65)]
        rows += [row('n%d' % index, 'fit', 102) for index in range(65)]
        packet = build_near_optimal_pair_recipe(rows, heldout_family='held')
        self.assertEqual(packet, build_near_optimal_pair_recipe(list(reversed(rows)), heldout_family='held'))
        family = packet['recipe']['families']['fit']
        self.assertGreater(family['candidate_pair_count'], PAIR_CAP_PER_FAMILY)
        self.assertEqual(PAIR_CAP_PER_FAMILY, family['selected_pair_count'])

    def test_family_macro_weight_is_independent_of_action_count(self):
        rows = [row('a+', 'a', 100), row('a-', 'a', 102)]
        rows += [row('b+', 'b', 100)] + [row('b-%d' % index, 'b', 102) for index in range(100)]
        packet = build_near_optimal_pair_recipe(rows, heldout_family='held')
        recipe = packet['recipe']
        self.assertEqual(.5, recipe['families']['a']['family_macro_weight'])
        self.assertEqual(.5, recipe['families']['b']['family_macro_weight'])
        scores = {uid: (1.0 if '+' in uid else 0.0) for family in recipe['families'].values()
                  for pair in family['pairs'] for uid in (pair['positive_uid'], pair['negative_uid'])}
        self.assertAlmostEqual(family_macro_pairwise_softplus(scores, recipe),
                               0.31326168751822286)
        reversed_scores = {uid: 1.0 - score for uid, score in scores.items()}
        self.assertLess(family_macro_pairwise_softplus(scores, recipe),
                        family_macro_pairwise_softplus(reversed_scores, recipe))


if __name__ == '__main__': unittest.main()
