"""Fabricated materialized reference graphs; never raw files or FIT targets."""
import copy
from decimal import Decimal
import unittest
from unittest.mock import patch

from src.data import ranking_v6_session_graph as graph


def action(uid, sources):
    return dict(action_uid=uid, circuit='spi', family='iwls_spi', role='TRAIN',
                action_scheme='HF', source_candidate_uids=sources)


def session(uid, mode, wall, **changes):
    return dict(dict(attempt_id=uid, circuit='spi', family='iwls_spi', role='TRAIN',
        stage='outer_stage', mode=mode, retry_group_id='group:'+uid, retry_order='1',
        retry_order_status='KNOWN_ORDER', environment_cohort='fabricated:cohort',
        attempt_outcome_class='SUCCESS', wall_s=wall, semantics_status='CONTRACT_VERIFIED',
        semantics_contract='tessent_process_wall_seconds', elapsed_semantics='tessent_process_wall_seconds',
        elapsed_source='phase2_csv.wall_time', source_artifact_sha256='a'*64, source_log_sha256='',
        parent_attempt_id=uid, session_index='1', session_count='1', order_evidence='STRUCTURAL_SINGLETON',
        session_lineage_sha256='b'*64, timing_scope='EXCLUSIVE_PROCESS_SESSION_ELAPSED'), **changes)


def edge(owner, source, node, **changes):
    return dict(dict(action_uid=owner['action_uid'], source_candidate_uid=source,
        circuit=owner['circuit'], stage=node['stage'], mode=node['mode'],
        retry_group_id=node['retry_group_id'], retry_order=node['retry_order'],
        attempt_id=node['attempt_id'], mapping_rule='DIRECT_RESULT_BASENAME',
        action_scheme=owner['action_scheme']), **changes)


def shared_fixture(h='3', fa='2', fb='2'):
    actions = [action('action:A', ['source:A']), action('action:B', ['source:B'])]
    sessions = [session('H:shared', 'H', h), session('F:A', 'F', fa), session('F:B', 'F', fb)]
    edges = [edge(actions[0], 'source:A', sessions[0]), edge(actions[0], 'source:A', sessions[1]),
             edge(actions[1], 'source:B', sessions[0]), edge(actions[1], 'source:B', sessions[2])]
    return actions, sessions, edges


class SessionGraphTests(unittest.TestCase):
    def setUp(self):
        self.actions, self.sessions, self.edges = shared_fixture()

    def audit(self):
        return graph.audit_graph(self.actions, self.sessions, self.edges, implementation_only=True)

    def test_shared_prefix_unique_7_incidence_10_and_reviewer_15_25(self):
        result = self.audit()
        self.assertEqual(result['mapped_unique_session_elapsed_sum_s'], '7')
        self.assertEqual(result['edge_incidence_proxy_sum_s'], '10')
        self.assertEqual(result['shared_attempt_count_across_sources'], 1)
        self.assertEqual(result['shared_attempt_count_across_actions'], 1)
        self.assertEqual(len(result['session_nodes']), 3)
        self.actions, self.sessions, self.edges = shared_fixture('10', '2', '3')
        result = self.audit()
        self.assertEqual(result['mapped_unique_session_elapsed_sum_s'], '15')
        self.assertEqual(result['edge_incidence_proxy_sum_s'], '25')

    def test_repeat_source_mean_12_20_is_16_not_minimum(self):
        owner = action('action:A', ['source:A', 'source:B'])
        self.actions = [owner]
        self.sessions = [session('H', 'H', '10'), session('F:A', 'F', '2'), session('F:B', 'F', '10')]
        self.edges = [edge(owner, source, self.sessions[0]) for source in owner['source_candidate_uids']]
        self.edges += [edge(owner, 'source:A', self.sessions[1]), edge(owner, 'source:B', self.sessions[2])]
        result = self.audit()
        self.assertEqual(result['per_source_elapsed_proxy_s'], {'source:A': '12', 'source:B': '20'})
        self.assertEqual(result['per_action_arithmetic_mean_source_proxy_s'], {'action:A': '16'})
        self.assertEqual(result['multi_source_action_count'], 1)
        self.assertEqual(result['shared_attempt_count_across_actions'], 0)

    def test_independent_f_search_groups_not_renumbered_as_retries(self):
        extra = session('F:extra', 'F', '4')
        self.sessions.append(extra)
        self.edges.append(edge(self.actions[0], 'source:A', extra, mapping_rule='F_SEARCH_RUN_ID'))
        self.edges[1]['mapping_rule'] = 'F_SEARCH_RUN_ID'
        result = self.audit()
        self.assertEqual(result['multiple_groups_per_mode'], [dict(source_candidate_uid='source:A', mode='F',
                          retry_group_ids=['group:F:A', 'group:F:extra'])])
        self.assertTrue(all(node['retry_order'] == '1' for node in result['session_nodes']))

    def test_raw_group_id_is_scoped_by_circuit_not_renamed(self):
        owner = dict(action('action:C', ['source:C']), circuit='aes_core', family='iwls_aes_core')
        node = session('H:aes', 'H', '1', circuit='aes_core', family='iwls_aes_core',
                       retry_group_id=self.sessions[0]['retry_group_id'])
        self.actions.append(owner)
        self.sessions.append(node)
        self.edges.append(edge(owner, 'source:C', node))
        result = self.audit()
        self.assertEqual(result['mapped_unique_session_elapsed_sum_s'], '8')
        refs = {row['source_candidate_uid']: row for row in result['source_references']}
        self.assertEqual(refs['source:C']['observed_modes'], ['H'])
        self.assertEqual(refs['source:C']['unobserved_scheme_modes'], ['F'])
        raw_id = self.sessions[0]['retry_group_id']
        self.assertEqual(sum(row['retry_group_id'] == raw_id for row in result['session_nodes']), 2)

    def retry_fixture(self, same_parent=True):
        self.actions = [action('action:A', ['source:A'])]
        self.sessions = [session('F:1', 'F', '1', retry_group_id='original|F', retry_order='1',
                                attempt_outcome_class='FAILURE', source_log_sha256='d'*64,
                                order_evidence='EMBEDDED_SIEMENS_START_ORDER'),
                         session('F:2', 'F', '2', retry_group_id='original|F', retry_order='2',
                                source_log_sha256='d'*64,
                                order_evidence='EMBEDDED_SIEMENS_START_ORDER')]
        if same_parent:
            for i, node in enumerate(self.sessions):
                node.update(parent_attempt_id='F:2', session_index=str(i+1), session_count='2',
                            order_evidence='GNU_TIME_FOOTER_EMISSION_ORDER')
        else:
            self.sessions[1]['source_log_sha256'] = 'c'*64
        self.edges = [edge(self.actions[0], 'source:A', node) for node in self.sessions]

    def test_retry_one_based_original_ids_and_failure_all_included(self):
        self.retry_fixture()
        result = self.audit()
        self.assertEqual([n['retry_order'] for n in result['session_nodes']], ['1', '2'])
        self.assertEqual([n['retry_group_id'] for n in result['session_nodes']], ['original|F']*2)
        self.assertEqual(result['mapped_unique_session_elapsed_sum_s'], '3')
        self.assertIn('H', result['source_references'][0]['unobserved_scheme_modes'])
        self.edges.pop(0)
        with self.assertRaisesRegex(ValueError, 'PARTIAL_INVOCATION_RETRY_GROUP'):
            self.audit()

    def test_group_order_evidence_not_parent_session_count(self):
        self.retry_fixture(same_parent=False)
        self.assertEqual(len({node['source_artifact_sha256'] for node in self.sessions}), 1)
        self.assertEqual(len({node['source_log_sha256'] for node in self.sessions}), 2)
        self.assertEqual(self.audit()['mapped_unique_session_elapsed_sum_s'], '3')
        self.sessions[0]['order_evidence'] = self.sessions[1]['order_evidence'] = 'STRUCTURAL_SINGLETON'
        with self.assertRaisesRegex(ValueError, 'GROUP_ORDER_EVIDENCE'):
            self.audit()

    def test_gnu_reverse_indices_multiple_parents_and_singlefile_embedded_rejected(self):
        self.retry_fixture()
        self.sessions[0]['session_index'], self.sessions[1]['session_index'] = '2', '1'
        with self.assertRaisesRegex(ValueError, 'GNU_PARENT_SESSION_ORDER'):
            self.audit()
        self.retry_fixture(same_parent=False)
        for node in self.sessions:
            node['order_evidence'] = 'GNU_TIME_FOOTER_EMISSION_ORDER'
        with self.assertRaisesRegex(ValueError, 'GNU_PARENT_SESSION_ORDER'):
            self.audit()
        self.retry_fixture()
        for node in self.sessions:
            node['order_evidence'] = 'EMBEDDED_SIEMENS_START_ORDER'
        with self.assertRaisesRegex(ValueError, 'EMBEDDED_MULTI_FILE_REQUIRED'):
            self.audit()
        # Embedded multi-file order is supplied, not reconstructed from each
        # independent file's local session index (both legitimately equal 1).
        self.retry_fixture(same_parent=False)
        self.assertEqual(self.audit()['mapped_unique_session_elapsed_sum_s'], '3')

    def test_parent_session_count_lineage_full_indices_and_exclusive_scope(self):
        self.retry_fixture()
        for changes in (dict(session_index='1'), dict(session_count='3'),
                        dict(source_artifact_sha256='c'*64), dict(source_log_sha256='c'*64),
                        dict(session_lineage_sha256='c'*64), dict(timing_scope='INCLUSIVE_PARENT')):
            old = dict(self.sessions[1])
            self.sessions[1].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.audit()
            self.sessions[1] = old

    def test_unmapped_failure_retained_all_vs_mapped_sums(self):
        self.sessions.append(session('UNMAPPED:failure', 'F', '4', attempt_outcome_class='FAILURE'))
        result = self.audit()
        self.assertEqual(result['all_supplied_session_elapsed_sum_s'], '11')
        self.assertEqual(result['mapped_unique_session_elapsed_sum_s'], '7')
        self.assertEqual(result['edge_incidence_proxy_sum_s'], '10')
        self.assertEqual(result['unmapped_attempt_ids'], ['UNMAPPED:failure'])
        self.assertEqual(result['unmapped_counts_by_status']['FAILURE'], 1)
        self.assertEqual(result['unmapped_elapsed_by_status_s']['FAILURE'], '4')

    def test_timeouts_and_footer_elapsed_are_preserved(self):
        self.sessions[0].update(attempt_outcome_class='TIMEOUT', semantics_status='FOOTER_VERIFIED',
                                elapsed_source='gnu_time_footer', source_log_sha256='c'*64)
        result = self.audit()
        self.assertEqual(result['mapped_unique_session_elapsed_sum_s'], '7')
        self.assertEqual(next(n for n in result['session_nodes'] if n['attempt_id'] == 'H:shared')
                         ['attempt_outcome_class'], 'TIMEOUT')

    def test_all_identity_metadata_before_wall_parse(self):
        self.sessions[0]['wall_s'] = 'not_wall'
        self.sessions[-1]['role'] = 'BLIND_TEST'
        with patch.object(graph, 'Decimal', side_effect=AssertionError('DECIMAL')):
            with self.assertRaisesRegex(ValueError, 'TRAIN_FAMILY_MAPPING'):
                self.audit()

    def test_join_cohort_mapping_rule_and_unique_edges(self):
        for changes in (dict(source_candidate_uid='unknown'), dict(action_uid='action:B'),
                        dict(action_scheme='HMF'), dict(mode='M'), dict(retry_order='2'),
                        dict(retry_group_id='wrong'), dict(stage='other'),
                        dict(mapping_rule='F_SEARCH_RUN_ID')):
            old = dict(self.edges[0])
            self.edges[0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.audit()
            self.edges[0] = old
        self.edges.append(dict(self.edges[0]))
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_SOURCE_ATTEMPT'):
            self.audit()
        self.edges.pop()
        self.sessions[-1]['environment_cohort'] = 'another'
        with self.assertRaisesRegex(ValueError, 'CIRCUIT_COHORT_MIX'):
            self.audit()

    def test_cross_stage_only_explicit_and_preserves_outer_stage(self):
        for row in self.edges[:2]:
            row['stage'] = 'mapping_outer'
            row['mapping_rule'] = 'DIRECT_RESULT_BASENAME_CROSS_STAGE'
        result = self.audit()
        self.assertEqual(result['edges'][1]['stage'], 'mapping_outer')
        self.assertTrue(all(node['stage'] == 'outer_stage' for node in result['session_nodes']))
        self.assertEqual(result['source_references'][0]['invocation_stage'], 'mapping_outer')
        self.edges[1]['stage'] = 'different_mapping_outer'
        with self.assertRaisesRegex(ValueError, 'INVOCATION_STAGE_MIX'):
            self.audit()

    def test_wall_exact_strings_semantics_and_status_rejection(self):
        for value in ('-1', '', 'nan', '1e2', ' 1', '1.', '.1', '1000000001', '0.1234567890', 1., True):
            self.sessions[0]['wall_s'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.audit()
        self.sessions[0]['wall_s'] = '0'
        self.assertEqual(self.audit()['mapped_unique_session_elapsed_sum_s'], '4')
        for field, value in (('attempt_outcome_class', 'COLLECTED_SUCCESS_ONLY'),
                             ('attempt_outcome_class', 'UNKNOWN'), ('elapsed_semantics', 'cpu_seconds'),
                             ('semantics_status', 'FOOTER_VERIFIED'), ('retry_order', '01'),
                             ('retry_order', '0'), ('retry_order', '65537')):
            old = self.sessions[0][field]
            self.sessions[0][field] = value
            with self.assertRaises(ValueError):
                self.audit()
            self.sessions[0][field] = old

    def test_optin_types_schema_bounds_and_source_ownership(self):
        for optin in (False, 1, None):
            with self.assertRaises(ValueError):
                graph.audit_graph(self.actions, self.sessions, self.edges, implementation_only=optin)
        self.actions[0]['source_candidate_uids'].append('source:B')
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_SOURCE_OWNERSHIP'):
            self.audit()
        self.actions[0]['source_candidate_uids'].pop()
        for field in ('total_cycles', 'is_d95_feasible', 'execution_status'):
            self.sessions[0][field] = 'forbidden'
            with self.assertRaisesRegex(ValueError, 'EXACT_SCHEMA'):
                self.audit()
            del self.sessions[0][field]
        for limit in ('MAX_ACTIONS', 'MAX_SESSIONS', 'MAX_EDGES', 'MAX_SOURCES', 'MAX_CHARACTERS', 'MAX_STRING'):
            with patch.object(graph, limit, 1), self.assertRaises(ValueError):
                self.audit()
        with self.assertRaises(ValueError):
            graph.audit_graph(tuple(self.actions), self.sessions, self.edges, implementation_only=True)

    def test_builtin_schema_keys_reject_string_subclasses(self):
        class StringSubclass(str):
            pass
        for rows in (self.actions, self.sessions, self.edges):
            original = rows[0]
            key = next(iter(original))
            rows[0] = {StringSubclass(k) if k == key else k: value for k, value in original.items()}
            with self.assertRaisesRegex(ValueError, 'EXACT_SCHEMA'):
                self.audit()
            rows[0] = original

    def test_source_no_edge_and_zero_total_rejected(self):
        self.actions[0]['source_candidate_uids'].append('source:unmapped')
        with self.assertRaisesRegex(ValueError, 'SOURCE_WITHOUT_EDGE'):
            self.audit()
        self.actions[0]['source_candidate_uids'].pop()
        for node in self.sessions:
            node['wall_s'] = '0'
        with self.assertRaisesRegex(ValueError, 'INVOCATION_POSITIVE_TOTAL'):
            self.audit()

    def test_order_determinism_no_mutation_no_io_sampling_and_no_fit_claim(self):
        before = copy.deepcopy((self.actions, self.sessions, self.edges))
        with patch('builtins.open', side_effect=AssertionError('IO')), \
                patch('socket.socket', side_effect=AssertionError('NETWORK')), \
                patch('random.Random', side_effect=AssertionError('SAMPLING')):
            result = self.audit()
        self.assertEqual(before, (self.actions, self.sessions, self.edges))
        self.actions.reverse()
        self.sessions.reverse()
        self.edges.reverse()
        self.assertEqual(result, self.audit())
        for flag in ('E31_direct_compatible', 'fit_targets_generated', 'fit_safe_certified',
                     'real_training_release', 'real_heldout_release', 'e31_records_emitted',
                     'real_data_access', 'source_authenticity_verified', 'nonoverlap_authenticated',
                     'elapsed_meaning_authenticated', 'physical_adapter_implemented',
                     'model_implemented', 'trainer_implemented', 'online_actual_cost_claim',
                     'physical_wall_makespan_claim'):
            self.assertFalse(result[flag])
        self.assertEqual(result['decimal_precision'], 50)
        self.assertIs(type(result['edge_incidence_proxy_sum_s']), str)


if __name__ == '__main__':
    unittest.main()
