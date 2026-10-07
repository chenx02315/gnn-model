import tempfile
import unittest
from pathlib import Path
from scripts.audit_r4_objective_context import audit, objective_counterexample, read_pinned


class ObjectiveContextTests(unittest.TestCase):
    def test_lower_surrogate_can_miss_top10_without_any_fit(self):
        result = objective_counterexample()
        self.assertEqual(1, result['hit']['first_positive_rank'])
        self.assertEqual(11, result['miss']['first_positive_rank'])
        self.assertLess(result['miss']['pair_softplus'], result['hit']['pair_softplus'])
        self.assertEqual((1,0), (result['hit']['hit_at_10'],result['miss']['hit_at_10']))

    def test_actual_bound_evidence_and_no_cap_truncation(self):
        result = audit()
        counts = {r['family']: r['all_pairs'] for r in result['families']}
        self.assertEqual(586, counts['iscas89_s13207'])
        self.assertEqual(548, counts['iscas89_s15850'])
        self.assertTrue(all(r['all_pairs_covered'] for r in result['families']))
        self.assertFalse(result['source_checks']['real_fit_call_has_graph_arguments'])
        self.assertFalse(result['source_checks']['runtime_cost_in_objective'])
        self.assertEqual(0,result['new_training_runs'])

    def test_input_hash_and_bound_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'small.json'; path.write_bytes(b'{}')
            with self.assertRaises(ValueError): read_pinned(path,'0'*64)
            with self.assertRaises(ValueError): read_pinned(path,'0'*64,bound=1)


if __name__ == '__main__': unittest.main()
