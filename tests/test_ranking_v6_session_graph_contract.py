"""Repository source/contract consistency only; no real runtime rows."""
import hashlib
import json
from pathlib import Path
import unittest

from src.data import ranking_v6_session_graph as graph


class SessionGraphContractTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.contract = json.loads((self.root/'contracts/ranking_v6_session_graph_v1.json').read_text())

    def test_bounded_view_limits_match_implementation(self):
        expected = {'actions': graph.MAX_ACTIONS, 'sessions': graph.MAX_SESSIONS,
                    'edges': graph.MAX_EDGES, 'declared_source_invocations': graph.MAX_SOURCES,
                    'cumulative_input_string_chars': graph.MAX_CHARACTERS}
        for name, value in expected.items():
            self.assertEqual(self.contract['limits'][name], value)
        self.assertEqual(set(self.contract['families']), set(graph.FAMILIES.values()))
        for name, fields in (('action', graph.ACTION_FIELDS), ('session', graph.SESSION_FIELDS),
                             ('edge', graph.EDGE_FIELDS)):
            self.assertEqual(set(self.contract['view_fields'][name]), fields)
        self.assertEqual(self.contract['max_individual_string_characters'], graph.MAX_STRING)

    def test_no_candidate_quality_fields_and_session_lineage_is_explicit(self):
        forbidden = {'cycles', 'total_cycles', 'd95', 'epsilon_hit', 'outcome_rank',
                     'execution_status', 'is_d95_feasible'}
        for fields in (graph.ACTION_FIELDS, graph.SESSION_FIELDS, graph.EDGE_FIELDS):
            self.assertFalse(set(fields) & forbidden)
        self.assertTrue({'parent_attempt_id', 'session_index', 'session_count', 'order_evidence',
                         'session_lineage_sha256', 'timing_scope'} <= graph.SESSION_FIELDS)
        self.assertTrue({'stage', 'mode'} <= graph.SESSION_FIELDS)

    def test_source_inventory_is_pinned_repository_code_not_actual_evidence(self):
        inventory = json.loads((self.root/'data/manifests/ranking_v6_e33_source_audit_20261016_r1.json').read_text())
        self.assertEqual(len(inventory['source_pins']), 12)
        self.assertEqual(inventory['real_source_rows_read'], 0)
        self.assertFalse(inventory['e31_direct_adapter_implemented'])
        for pin in inventory['source_pins']:
            self.assertEqual(hashlib.sha256((self.root/pin['path']).read_bytes()).hexdigest(), pin['sha256'])

    def test_real_releases_remain_closed(self):
        for name in ('e31_direct_compatible', 'e31_records_emitted', 'fit_targets_emitted',
                     'source_authenticated', 'original_inventory_completeness_verified',
                     'invocation_semantics_verified', 'exclusive_timing_verified',
                     'real_data_access', 'real_training_release'):
            self.assertIs(self.contract[name], False)
        self.assertIs(self.contract['wall']['no_makespan_or_online_claim'], True)
        with self.assertRaisesRegex(ValueError, 'IMPLEMENTATION_OPT_IN'):
            graph.audit_graph(object(), object(), object())


if __name__ == '__main__':
    unittest.main()
