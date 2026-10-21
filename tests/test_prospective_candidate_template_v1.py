import unittest
from src.data import prospective_candidate_template_v1 as domain


class TemplateTests(unittest.TestCase):
    def test_exact_roster_no_outcome_columns(self):
        rows = domain.templates()
        self.assertEqual(len(rows), 924)
        self.assertEqual(len({r['template_uid'] for r in rows}), 924)
        for row in rows:
            self.assertEqual(set(row), {'template_uid','circuit','scheme','h_anchor','m_anchor'})
        self.assertFalse(domain.summary()['real_roster_frozen'])
        self.assertIsNone(domain.summary()['integer_action_count'])

    def test_half_up_and_positive_extremes(self):
        self.assertEqual(domain.pattern_limit('p005', 10), 1)
        self.assertEqual(domain.pattern_limit('p015', 10), 2)
        self.assertEqual(domain.pattern_limit('p100', 2**31-1), 2**31-1)
        for bad in (0, -1, True, 1.5, 2**31):
            with self.assertRaises(ValueError): domain.pattern_limit('one', bad)

    def test_integer_aliases_not_duplicate_charges(self):
        actions = domain.expand('spi', 1, {1:1})
        self.assertEqual(len(actions), 2)
        self.assertEqual(sorted(len(a['template_uids']) for a in actions), [21,441])
        order = domain.seeded_template_order('spi',20260824)
        collapsed = domain.collapse_order(order, actions)
        self.assertEqual(set(collapsed), {a['action_uid'] for a in actions})
        self.assertEqual(len(collapsed), 2)

    def test_per_h_conditional_m_endpoint_required(self):
        with self.assertRaises(ValueError): domain.expand('aes_core',20,{20:5})
        with self.assertRaises(ValueError): domain.expand('aes_core',1,{1:0})
        with self.assertRaises(ValueError): domain.expand('aes_core',1,{True:1})
        with self.assertRaises(ValueError): domain.expand('wb_dma',1,{1:1})

    def test_seeded_permutation_deterministic_and_seed_sensitive(self):
        a = domain.seeded_template_order('aes_core',20260824)
        self.assertEqual(a,domain.seeded_template_order('aes_core',20260824))
        self.assertNotEqual(a,domain.seeded_template_order('aes_core',20260825))
        self.assertEqual(len(a),len(set(a)))
        for seed in (True,-1,2**63):
            with self.assertRaises(ValueError): domain.seeded_template_order('aes_core',seed)

    def test_invalid_order_rejected_and_no_mutation(self):
        actions=domain.expand('spi',1,{1:1})
        order=domain.seeded_template_order('spi',1)
        before=repr(actions)
        for invalid in (order[:-1],order+[order[0]],['unknown']):
            with self.assertRaises(ValueError):domain.collapse_order(invalid,actions)
        self.assertEqual(repr(actions),before)


if __name__ == '__main__':
    unittest.main()
