import copy
import math
import unittest

from src.data import prospective_circuit_summary_v1 as summary


def node(sequential=False):
    return dict(node_type='standard_cell_instance', cell_type='DFF' if sequential else 'AND2',
                sequential_flag=sequential)


class CircuitSummaryTests(unittest.TestCase):
    def test_hand_calculated_chain(self):
        result = summary.summarize([node(), node(), node()], [[0, 1], [1, 2]])
        self.assertEqual(result['values'], [math.log1p(3), math.log1p(2), 0, 2 / 3, 1, 3])
        self.assertTrue(result['feature_vector_complete'])

    def test_register_cuts_feedback_and_depth_resets(self):
        result = summary.summarize([node(True), node(), node(), node(True)],
                                   [[0, 1], [1, 2], [2, 3], [3, 0]])
        self.assertEqual(result['logic_depth'], 2)
        self.assertEqual(result['sequential_cell_count'], 2)
        self.assertEqual(result['values'][2:5], [0.5, 1, 1])

    def test_combinational_cycle_stays_missing(self):
        for edges in ([[0, 1], [1, 0]], [[0, 0]]):
            result = summary.summarize([node(), node()], edges)
            self.assertIsNone(result['logic_depth'])
            self.assertIsNone(result['values'][-1])
            self.assertFalse(result['feature_vector_complete'])
            self.assertEqual(result['depth_status'], 'COMBINATIONAL_CYCLE_UNSUPPORTED')

    def test_isolated_and_sequential_only_depth(self):
        self.assertEqual(summary.summarize([node()], [])['logic_depth'], 1)
        result = summary.summarize([node(True), node(True)], [[0, 1], [1, 0]])
        self.assertEqual(result['logic_depth'], 0)
        self.assertEqual(result['values'][2], 1)

    def test_nearest_rank_p95_includes_zero_fanout_nodes(self):
        nodes = [node() for _ in range(20)]
        result = summary.summarize(nodes, [[0, i] for i in range(1, 20)])
        self.assertEqual(result['values'][4], 0)
        self.assertEqual(result['values'][3], 19 / 20)

    def test_permutations_preserve_features_and_canonical_edge_digest(self):
        nodes, edges = [node(), node(True), node()], [[1, 0], [0, 2], [2, 1]]
        first = summary.summarize(nodes, edges)
        self.assertEqual(first, summary.summarize(nodes, list(reversed(edges))))
        perm = {0: 2, 1: 0, 2: 1}
        reordered = [nodes[1], nodes[2], nodes[0]]
        remapped = [[perm[s], perm[t]] for s, t in edges]
        self.assertEqual(first['values'], summary.summarize(reordered, remapped)['values'])

    def test_duplicate_boolean_out_of_range_and_label_fields_rejected(self):
        for edges in ([[0, 1], [0, 1]], [[False, 1]], [[0, 2]]):
            with self.assertRaises(ValueError):
                summary.summarize([node(), node()], edges)
        nodes = [node()]
        nodes[0]['cycles'] = 100
        with self.assertRaisesRegex(ValueError, 'NODE_SCHEMA'):
            summary.summarize(nodes, [])
        nodes = [node()]
        nodes[0]['sequential_flag'] = 0
        with self.assertRaises(ValueError):
            summary.summarize(nodes, [])

    def test_inputs_unchanged_and_no_release_claim(self):
        nodes, edges = [node(True), node()], [[0, 1]]
        before = copy.deepcopy((nodes, edges))
        result = summary.summarize(nodes, edges)
        self.assertEqual((nodes, edges), before)
        for key in ('supplied_graph_bytes_authenticated', 'design_mode_mapping_authenticated',
                    'outcome_fields_used', 'model_inference_performed',
                    'execution_ready', 'training_release'):
            self.assertFalse(result[key])


if __name__ == '__main__':
    unittest.main()
