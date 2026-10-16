"""Fabricated metadata only; never opens actual pinned tables or old mapper."""
import ast
import contextlib
import copy
from decimal import Decimal
import hashlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import audit_ranking_v6_e35_mapping_metadata as mapping


def fixture():
    manifests, lineage = [], []
    for attempt, mode, seconds in (('H_SHARED','H','3'),('F_A','F','2'),('F_B','F','2'),('FAIL_EXCLUDED','F','4')):
        row = {field:'' for field in mapping.reader.MANIFEST_FIELDS}
        row.update(attempt_id=attempt,circuit='spi',family='iwls_spi',role='TRAIN',
                   mode=mode,stage='02_hf_coarse',retry_group_id='G_'+attempt,retry_order='1',
                   retry_order_status='KNOWN_ORDER',wall_s=seconds,attempt_outcome_class='SUCCESS',timeout_status='NOT_TIMEOUT')
        if attempt=='FAIL_EXCLUDED': row['attempt_outcome_class']='FAILURE'
        manifests.append(row)
        lineage.append(dict(circuit='spi',parent_attempt_id=attempt,attempt_id=attempt,retry_group_id=row['retry_group_id'],
            retry_order='1',order_evidence='STRUCTURAL_SINGLETON',session_index='1',session_count='1',
            attempt_outcome_class=row['attempt_outcome_class'],timeout_status='NOT_TIMEOUT'))
    edges = []
    for action, source, attempt in (('ACTION_A','spi:hf_coarse:file:1','H_SHARED'),
        ('ACTION_A','spi:hf_coarse:file:1','F_A'),('ACTION_B','spi:hf_coarse:file:2','H_SHARED'),
        ('ACTION_B','spi:hf_coarse:file:2','F_B')):
        node=next(row for row in manifests if row['attempt_id']==attempt)
        edges.append(dict(action_uid=action,source_candidate_uid=source,circuit='spi',stage='02_hf_coarse',
            action_scheme='HF',h_patterns='64',m_patterns='',mode=node['mode'],retry_group_id=node['retry_group_id'],
            retry_order='1',attempt_id=attempt,mapping_rule='DIRECT_RESULT_BASENAME'))
    excluded = [dict(circuit='spi',stage='02_hf_coarse',mode='F',attempt_id='FAIL_EXCLUDED',
                     exclusion_reason='NON_ELIGIBLE_SOURCE_INVOCATION')]
    return manifests,lineage,edges,excluded


class E35MappingTests(unittest.TestCase):
    def setUp(self): self.inputs=fixture()
    def audit(self): return mapping.audit(*self.inputs)

    def test_shared_prefix_three_cost_scopes_and_failed_exclusion(self):
        result=self.audit()
        self.assertEqual(result['all_supplied_unique_wall_sum_s'],'11')
        self.assertEqual(result['mapped_unique_wall_sum_s'],'7')
        self.assertEqual(result['source_edge_incidence_historical_proxy_sum_s'],'10')
        self.assertEqual(result['shared_attempt_across_actions_count'],1)
        self.assertEqual(result['attempt_partitions']['excluded_only']['declared_wall_by_outcome_s']['FAILURE'],'4')
        self.assertEqual(result['all_action_equal_source_mean_vector']['count'],2)
        self.assertNotIn('ACTION_A',json.dumps(result))

    def test_repeat_action_all_source_arithmetic_mean_not_minimum(self):
        m,l,e,x=self.inputs
        e[2]['action_uid']=e[3]['action_uid']='ACTION_A'
        m[0]['wall_s']='10'
        m[2]['wall_s']='10'
        result=self.audit()
        self.assertEqual(result['all_source_actual_edge_sum_vector']['minimum_s'],'12')
        self.assertEqual(result['all_source_actual_edge_sum_vector']['maximum_s'],'20')
        self.assertEqual(result['all_action_equal_source_mean_vector']['mean_s'],'16')
        self.assertEqual(result['action_source_repeat_count_distribution'],{'2':1})
        expected=hashlib.sha256(json.dumps([['ACTION_A','16']],ensure_ascii=False,allow_nan=False,separators=(',',':')).encode()).hexdigest()
        self.assertEqual(result['all_action_equal_source_mean_vector']['canonical_sha256'],expected)

    def test_raw_group_members_not_autoadded_across_stages_sources(self):
        m,l,e,x=self.inputs
        m[1].update(retry_group_id='RAW_GROUP',retry_order='1')
        m[2].update(retry_group_id='RAW_GROUP',retry_order='2',stage='04_integer_refine')
        l[1].update(retry_group_id='RAW_GROUP',retry_order='1')
        l[2].update(retry_group_id='RAW_GROUP',retry_order='2')
        e[1].update(retry_group_id='RAW_GROUP',retry_order='1')
        e[3].update(retry_group_id='RAW_GROUP',retry_order='2',mapping_rule='DIRECT_RESULT_BASENAME_CROSS_STAGE')
        result=self.audit()
        self.assertEqual(result['mixed_attempt_stage_group_count'],1)
        self.assertEqual(result['source_edge_incidence_historical_proxy_sum_s'],'10')
        self.assertEqual(result['mixed_stage_group_adjacency'][0]['supplied_member_count'],2)
        self.assertTrue(all(member['source_ref_count']==1 for member in result['mixed_stage_group_adjacency'][0]['members']))
        self.assertFalse(result['group_members_autoadded'])
        with patch.object(mapping,'MAX_MEMBERS',1):
            bounded=self.audit()
        self.assertTrue(bounded['status'].startswith('PARTIAL'))
        self.assertEqual(bounded['omitted_member_count'],1)
        self.assertEqual(bounded['source_edge_incidence_historical_proxy_sum_s'],'10')

    def test_full_group_reference_union_intersection_all_cases_and_empty_member(self):
        for relationship in ('two_actions','same_action_two_sources','shared_source','empty_member'):
            self.inputs=fixture()
            m,l,e,x=self.inputs
            m[1].update(retry_group_id='G_CROSS',retry_order='1')
            m[2].update(retry_group_id='G_CROSS',retry_order='2',stage='04_integer_refine')
            l[1].update(retry_group_id='G_CROSS',retry_order='1')
            l[2].update(retry_group_id='G_CROSS',retry_order='2')
            e[1].update(retry_group_id='G_CROSS',retry_order='1')
            e[3].update(retry_group_id='G_CROSS',retry_order='2',mapping_rule='DIRECT_RESULT_BASENAME_CROSS_STAGE')
            if relationship=='same_action_two_sources':
                e[2]['action_uid']=e[3]['action_uid']='ACTION_A'
            elif relationship=='shared_source':
                e[3].update(action_uid='ACTION_A',source_candidate_uid=e[1]['source_candidate_uid'])
            elif relationship=='empty_member':
                e.pop(3)
                x.append(dict(circuit='spi',stage='04_integer_refine',mode='F',attempt_id='F_B',
                              exclusion_reason='NON_TERMINAL_SEARCH_PROBE'))
            full=self.audit()['mixed_stage_group_adjacency'][0]
            expected={'two_actions':(2,0,2,0),'same_action_two_sources':(2,0,1,1),
                      'shared_source':(1,1,1,1),'empty_member':(1,0,1,0)}[relationship]
            actual=tuple(full[field] for field in ('source_union_count','source_intersection_count_all_members',
                                                   'action_union_count','action_intersection_count_all_members'))
            with self.subTest(relationship=relationship): self.assertEqual(actual,expected)
            self.assertEqual(full['mapped_member_count'],1 if relationship=='empty_member' else 2)
            self.assertEqual(full['excluded_member_count'],1 if relationship=='empty_member' else 0)
            with patch.object(mapping,'MAX_MEMBERS',1),patch.object(mapping,'MAX_REFS',0):
                limited=self.audit()['mixed_stage_group_adjacency'][0]
            for field in ('source_union_count','source_intersection_count_all_members','action_union_count',
                          'action_intersection_count_all_members','full_member_reference_canonical_sha256'):
                self.assertEqual(full[field],limited[field])

    def test_validation_filtered_before_numeric_and_blind_rejected(self):
        self.inputs[2].append({field:('s5378' if field=='circuit' else 'NOT_NUMERIC_OR_JOINED') for field in mapping.EDGE_FIELDS})
        result=self.audit()
        self.assertEqual(result['filtered_validation_edge_count'],1)
        self.inputs[2][-1]['circuit']='s9234'
        with self.assertRaisesRegex(mapping.MappingAuditError,'CIRCUIT_SCOPE'): self.audit()

    def test_duplicate_edge_unknown_attempt_and_source_two_actions_fail(self):
        for kind in ('duplicate','unknown','owner','prefix','order','extra_quality'):
            self.inputs=fixture()
            if kind=='duplicate': self.inputs[2].append(dict(self.inputs[2][0]))
            elif kind=='unknown': self.inputs[2][0]['attempt_id']='unknown'
            elif kind=='owner': self.inputs[2][1]['action_uid']='OTHER_ACTION'
            elif kind=='prefix': self.inputs[2][0]['source_candidate_uid']='s13207:hf_coarse:file:1'
            elif kind=='order': self.inputs[2][0]['retry_order']='9'
            else: self.inputs[2][0]['total_cycles']='forbidden'
            with self.subTest(kind=kind),self.assertRaises(mapping.MappingAuditError): self.audit()

    def test_both_excluded_mapped_partial_and_neither_retained(self):
        m,l,e,x=self.inputs
        x.append(dict(circuit='spi',stage='02_hf_coarse',mode='H',attempt_id='H_SHARED',exclusion_reason='OUT_OF_SCOPE_STAGE'))
        result=self.audit()
        self.assertTrue(result['status'].startswith('PARTIAL'))
        self.assertEqual(result['attempt_partitions']['both']['attempt_count'],1)
        self.assertEqual(result['all_supplied_unique_wall_sum_s'],'11')
        x.clear()
        result=self.audit()
        self.assertEqual(result['attempt_partitions']['neither']['attempt_count'],1)
        self.assertTrue(result['status'].startswith('PARTIAL'))
        self.assertFalse(result['provided_attempt_partition_complete'])

    def test_cross_stage_rule_without_difference_is_explicit_partial_issue(self):
        self.inputs[2][0]['mapping_rule']='DIRECT_RESULT_BASENAME_CROSS_STAGE'
        result=self.audit()
        self.assertEqual(result['cross_stage_rule_without_stage_difference_count'],1)
        self.assertTrue(result['status'].startswith('PARTIAL'))
        self.assertFalse(result['candidate_cost_certified'])

    def test_exact_schemas_from_source_without_importing_old_mapper(self):
        path=Path(mapping.__file__).parents[1]/'src/data/audit_runtime_action_attempt_mapping_v1.py'
        tree=ast.parse(path.read_text())
        assignments={target.id:node.value for node in tree.body if isinstance(node,ast.Assign)
                     for target in node.targets if isinstance(target,ast.Name)}
        self.assertEqual(mapping.EDGE_FIELDS,ast.literal_eval(assignments['EDGE_FIELDS']))
        self.assertEqual(mapping.EXCLUSION_FIELDS,ast.literal_eval(assignments['EXCLUSION_FIELDS']))
        ast.parse(Path(mapping.__file__).read_text(),feature_version=(3,6))
        self.assertEqual(len(mapping.LOCAL_SPECS),14)
        self.assertTrue(all(mapping.reader._SHA.match(spec['sha256']) for spec in mapping.LOCAL_SPECS))

    def test_no_io_no_mutation_vector_order_and_scope_flags(self):
        before=copy.deepcopy(self.inputs)
        with patch('builtins.open',side_effect=AssertionError('IO')),patch('os.open',side_effect=AssertionError('FD')), \
                patch('socket.socket',side_effect=AssertionError('NETWORK')):
            result=self.audit()
        self.assertEqual(before,self.inputs)
        for rows in self.inputs: rows.reverse()
        self.assertEqual(result,self.audit())
        for flag in ('raw_group_is_invocation','group_members_autoadded','groups_split','quality_based_selection',
                     'fit_targets_generated','original_logs_or_action_tables_read','source_semantics_authenticated',
                     'live_A_attestation','real_training_release','real_heldout_release'):
            self.assertFalse(result[flag])

    def test_cli_rejects_paths_before_any_source_read(self):
        with patch.object(mapping.sys,'argv',['audit','/arbitrary']), \
                patch.object(mapping.local_reader,'_stable_bytes',side_effect=AssertionError('IO')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(mapping.main(),2)
        self.assertIn('CLI_ARGUMENTS_FORBIDDEN',output.getvalue())


if __name__=='__main__': unittest.main()
