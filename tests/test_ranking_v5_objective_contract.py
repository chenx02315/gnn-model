"""Source-contract and mathematical counterexamples; synthetic labels only.

No torch, fit, optimizer, real labels, models, filesystem data or network.
"""
import math
import unittest

from src.models.ranking_v5_head_objective import build_recipe, family_logs, loss_reference
from src.models.runtime_ranking_v3 import FEATURES, fit_normalizer


def family_rows(family, negatives=10):
    return [{'action_uid': family + ':p', 'family': family, 'total_cycles': 100}] + [
        {'action_uid': '%s:n%02d' % (family, index), 'family': family, 'total_cycles': 102}
        for index in range(negatives)]


class ObjectiveContractTests(unittest.TestCase):
    def test_same_hit_and_head_loss_different_first_positive_rank(self):
        rows = family_rows('synthetic')
        recipe = build_recipe(rows, heldout_family='held-sentinel')
        first_scores = {r['action_uid']: -1. for r in rows}
        first_scores['synthetic:p'] = 0.
        tenth_scores = dict(first_scores)
        for index in range(9):
            tenth_scores['synthetic:n%02d' % index] = 1.
        first = family_logs(first_scores, recipe)[0]
        tenth = family_logs(tenth_scores, recipe)[0]
        self.assertEqual((first['hit_at_10'], tenth['hit_at_10']), (1, 1))
        self.assertEqual((first['first_positive_rank'], tenth['first_positive_rank']), (1, 10))
        self.assertEqual(first['head_gap'], tenth['head_gap'])
        self.assertEqual(loss_reference(first_scores, recipe), loss_reference(tenth_scores, recipe))

    def test_runtime_cost_is_external_and_not_an_objective_input(self):
        rows = family_rows('synthetic')
        recipe = build_recipe(rows, heldout_family='held-sentinel')
        scores = {r['action_uid']: -1. for r in rows}
        scores.update({'synthetic:n00': 2., 'synthetic:n01': 1., 'synthetic:p': 0.})
        log = family_logs(scores, recipe)[0]
        order = sorted(scores, key=lambda uid: (-scores[uid], uid))
        prefix = order[:log['first_positive_rank']]
        # Explicit external synthetic cost, including execution of the first hit.
        cheap = {uid: 1. for uid in scores}
        costly = dict(cheap, **{'synthetic:n00': 1000., 'synthetic:n01': 2000.})
        self.assertEqual(log['first_positive_rank'], 3)
        self.assertEqual(log['hit_at_10'], 1)
        self.assertEqual(sum(cheap[u] for u in prefix), 3.)
        self.assertEqual(sum(costly[u] for u in prefix), 3001.)
        before = loss_reference(scores, recipe)
        # The recipe/log/loss is exactly unchanged by external cost reassignment.
        self.assertEqual(family_logs(scores, recipe)[0], log)
        self.assertEqual(loss_reference(scores, recipe), before)
        polluted = [dict(row, policy_charged_runtime_s=cheap[row['action_uid']]) for row in rows]
        with self.assertRaisesRegex(ValueError, 'HEAD_ROW_ALLOWLIST'):
            build_recipe(polluted, heldout_family='held-sentinel')

    def test_identical_cross_family_vectors_can_have_opposite_preferences(self):
        x = (1., 0., 1., 0., .25, 0., 2.)
        y = (1., 0., 2., 0., .5, 0., 2.)
        self.assertEqual(len(x), len(FEATURES))
        rows = family_rows('A') + family_rows('B')
        vectors = {}
        for row in rows:
            family, positive = row['family'], row['total_cycles'] == 100
            vectors[row['action_uid']] = x if (family == 'A') == positive else y
        # Pure hypothetical cycle labels: A prefers x, B prefers y.
        recipe = build_recipe(rows, heldout_family='held-sentinel')
        self.assertEqual(vectors['A:p'], vectors['B:n00'])
        self.assertEqual(vectors['B:p'], vectors['A:n00'])
        self.assertNotEqual(vectors['A:p'], vectors['B:p'])
        for score_x, score_y in ((2., 1.), (1., 2.), (1., 1.)):
            scores = {uid: score_x if vector == x else score_y for uid, vector in vectors.items()}
            logs = family_logs(scores, recipe)
            self.assertEqual(logs[0]['head_gap'], -logs[1]['head_gap'])
            self.assertFalse(all(log['strict_score_hit_certificate'] for log in logs))
        # No actual collision labels or trained model are consulted in this proof.

    def test_macro_family_loss_is_not_candidate_weighted_normalization(self):
        small, large = family_rows('small', negatives=1), family_rows('large', negatives=10)
        rows = small + large
        recipe = build_recipe(rows, heldout_family='held-sentinel')
        scores = {r['action_uid']: 2. for r in rows}
        scores['large:p'] = 0.
        logs = {log['family']: log for log in family_logs(scores, recipe)}
        self.assertTrue(logs['small']['guaranteed_hit_by_size'])
        self.assertEqual(logs['small']['head_softplus'], 0.)
        macro = loss_reference(scores, recipe)
        self.assertAlmostEqual(macro, logs['large']['head_softplus'] / 2.)
        candidate_weighted = logs['large']['head_softplus'] * 11. / 13.
        self.assertNotAlmostEqual(macro, candidate_weighted)
        matrix = [(1., 0., 0., 0., 0., 0., 2.)] * 2 + [(1., 0., 10., 0., 0., 0., 2.)] * 11
        mean, std = fit_normalizer(matrix)
        self.assertAlmostEqual(mean[2], 110. / 13.)
        self.assertNotAlmostEqual(mean[2], (0. + 10.) / 2.)
        self.assertAlmostEqual(std[2], math.sqrt(sum((r[2] - mean[2]) ** 2 for r in matrix) / 13.))

    def test_cycle_epsilon_boundary_and_held_label_guard(self):
        rows = [{'action_uid': str(c), 'family': 'fit', 'total_cycles': c} for c in (100, 101, 102)]
        recipe = build_recipe(rows, heldout_family='held-sentinel')
        self.assertEqual(recipe['K'], 10)
        self.assertEqual(recipe['families']['fit']['positive'], ('100', '101'))
        self.assertEqual(recipe['families']['fit']['negative'], ('102',))
        with self.assertRaisesRegex(ValueError, 'HEAD_HELD_LABEL_FORBIDDEN'):
            build_recipe(rows, heldout_family='fit')


if __name__ == '__main__':
    unittest.main()
