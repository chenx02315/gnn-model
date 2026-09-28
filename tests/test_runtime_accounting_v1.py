import copy
import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPLAY = os.path.join(ROOT, "src", "replay")
if REPLAY not in sys.path:
    sys.path.insert(0, REPLAY)

from runtime_accounting_v1 import replay


METHODS = (
    "fixed_heuristic",
    "d95_safe_then_predicted_cycles",
    "d95_safe_cost_aware_topk",
)


def action(uid, circuit, family, cycles, runtime, hit):
    return {
        "role": "VALIDATION", "family": family, "circuit": circuit,
        "action_uid": uid, "action_scheme": "HF", "h_limit": "4", "m_limit": "0",
        "common_fault_count": "100", "graph_key": circuit,
        "execution_status": "SUCCESS", "is_d95_feasible": "1",
        "total_cycles": str(cycles), "policy_charged_runtime_s": str(runtime),
        "epsilon_hit": "1" if hit else "0",
    }


def rankings(rows):
    output = []
    circuits = sorted({row["circuit"] for row in rows})
    for method in METHODS:
        for circuit in circuits:
            uids = sorted(row["action_uid"] for row in rows if row["circuit"] == circuit)
            for rank, uid in enumerate(uids, 1):
                output.append({"method": method, "circuit": circuit, "rank": str(rank), "action_uid": uid})
    return output


class RuntimeAccountingV1Test(unittest.TestCase):
    def setUp(self):
        self.rows = [
            action("a1", "c1", "f1", 101, 3.0, True),
            action("a2", "c1", "f1", 100, 5.0, True),
            action("b1", "c2", "f2", 120, 2.0, False),
            action("b2", "c2", "f2", 100, 7.0, True),
        ]
        self.ranks = rankings(self.rows)

    def test_pass_charges_before_hit_and_macro_aggregates(self):
        result = replay(self.rows, self.ranks, METHODS)
        self.assertEqual("PASS_VALIDATION_REPLAY", result["status"])
        fixed = [row for row in result["per_circuit"] if row["method"] == METHODS[0]]
        self.assertEqual([1, 2], [row["hit_rank"] for row in fixed])
        self.assertEqual([3.0, 9.0], [row["cumulative_runtime_s"] for row in fixed])
        aggregate = result["aggregate_family_macro"][0]
        self.assertEqual(1.0, aggregate["family_macro_success_at_k"])
        self.assertEqual(6.0, aggregate["family_macro_cumulative_runtime_s"])

    def test_rejects_role_leakage(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["role"] = "BLIND_TEST"
        with self.assertRaisesRegex(ValueError, "VALIDATION"):
            replay(rows, self.ranks, METHODS)

    def test_rejects_inconsistent_epsilon_hit(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["epsilon_hit"] = "0"
        with self.assertRaisesRegex(ValueError, "epsilon_hit"):
            replay(rows, self.ranks, METHODS)

    def test_rejects_method_specific_action_exclusion(self):
        ranks = [row for row in self.ranks if not (row["method"] == METHODS[2] and row["action_uid"] == "a2")]
        with self.assertRaisesRegex(ValueError, "identical full action space"):
            replay(self.rows, ranks, METHODS)

    def test_rejects_noncontiguous_rank(self):
        ranks = copy.deepcopy(self.ranks)
        ranks[0]["rank"] = "9"
        with self.assertRaisesRegex(ValueError, "contiguous"):
            replay(self.rows, ranks, METHODS)

    def test_rejects_nonpositive_runtime(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["policy_charged_runtime_s"] = "0"
        with self.assertRaisesRegex(ValueError, "positive"):
            replay(rows, self.ranks, METHODS)


if __name__ == "__main__":
    unittest.main()
