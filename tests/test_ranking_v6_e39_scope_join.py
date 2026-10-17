"""Synthetic E38-shaped responses only; never actual projections or files."""
import copy
import unittest
from unittest.mock import patch

from scripts import audit_ranking_v6_e39_scope_join as join
from scripts import project_ranking_v6_e38_roster as producer


def fixture():
    files=[dict(circuit=circuit,coverage_root=root,stage_alias=alias,path=path,sha256='a'*64,
                byte_count=256,header_sha256='b'*64,rows=[]) for circuit,root,alias,scheme,path in producer.SPECS]
    result=dict(status='PASS_SELECTED_CONFIG_METADATA_PROJECTION_ONLY',files=files,file_count=32,
        coverage_root_count=8,total_bytes=32*256,total_rows=0,
        source_identity_scope='circuit+coverage_root+stage_alias+candidate_raw',
        source_file_bytes_read_for_sha_and_structure=True,
        resource=dict(address_space_limit_bytes=1073741824,cpu_limit_s=20,workers=1))
    for flag in ('nonselected_values_decoded','nonselected_values_captured','quality_evaluated',
        'PASS_or_eligibility_filter_applied','coverage_versions_merged','pre_outcome_certified',
        'formal_builder_roots_certified','training_release','E36_inventory_emitted',
        'physical_files_written','raw_source_tables_persisted'):
        result[flag]=False
    return result


def add(projection,circuit='spi',alias='hf_coarse',candidate='1',h='064',m='0',version=None,origin='explicit_candidate'):
    file=next(item for item in projection['files'] if item['circuit']==circuit and item['stage_alias']==alias
              and (version is None or item['coverage_root'].endswith(version)))
    file['rows'].append([len(file['rows'])+2,candidate,h,m,origin])
    projection['total_rows']+=1


def edge(circuit='spi',alias='hf_coarse',candidate='1',h='64',m='16'):
    scheme='HMF' if alias.startswith('hmf') else 'HF'
    return dict(circuit=circuit,source_candidate_uid=':'.join((circuit,alias,'H64-M16-F4' if scheme=='HMF' else 'H64-F4',candidate)),
                action_uid=circuit+':'+scheme+':h'+h+(':m'+m if scheme=='HMF' else ''))


class ScopedJoinTests(unittest.TestCase):
    def setUp(self): self.projection=fixture()

    def test_exact_one_match_normalizes_controls_only_and_keeps_all_unmapped_rows(self):
        add(self.projection,h='0064',candidate='001')
        add(self.projection,candidate='2',h='128')
        result=join.summarize(self.projection,[edge(candidate='001')])
        self.assertEqual(result['status'],'PASS_PROVIDED_CONFIG_JOIN_ONLY')
        self.assertEqual(result['edge_class_counts']['ONE_SCOPED_CONFIG_MATCH'],1)
        self.assertEqual(result['provided_scoped_configuration_row_count'],2)
        self.assertEqual(result['config_equality_unmatched_scoped_row_count'],1)
        no_rewrite=join.summarize(self.projection,[edge(candidate='1')])
        self.assertEqual(no_rewrite['edge_class_counts']['UID_ABSENT'],1)
        self.assertEqual(len(result['files']),32)
        self.assertNotIn('rows',result['files'][0])

    def test_original_uid_same_configs_two_versions_is_ambiguous(self):
        for version in ('10_coverage95_v1','10_coverage95_v2_merge_reclassify'):
            add(self.projection,circuit='s35932',version=version)
        result=join.summarize(self.projection,[edge(circuit='s35932')])
        self.assertEqual(result['status'],'PARTIAL_SOURCE_SCOPE_JOIN')
        self.assertEqual(result['edge_class_counts']['MULTIPLE_SCOPED_CONFIG_MATCH'],1)
        self.assertEqual(result['unscoped_uid_collision_across_scopes_count'],1)
        self.assertEqual(result['config_equality_matched_scoped_row_count'],2)

    def test_same_uid_two_configs_exact_one_but_collision_remains_reported(self):
        add(self.projection,circuit='s38417',version='10_coverage95_v1',h='64')
        add(self.projection,circuit='s38417',version='10_coverage95_v2_merge_reclassify',h='128')
        result=join.summarize(self.projection,[edge(circuit='s38417')])
        self.assertEqual(result['status'],'PASS_PROVIDED_CONFIG_JOIN_ONLY')
        self.assertEqual(result['edge_class_counts']['ONE_SCOPED_CONFIG_MATCH'],1)
        self.assertEqual(result['unscoped_uid_collision_across_scopes_count'],1)
        self.assertEqual(result['config_equality_unmatched_scoped_row_count'],1)

    def test_absent_config_mismatch_zero_edges_and_empty_rows_explicit_partial(self):
        add(self.projection,h='128')
        mismatch=join.summarize(self.projection,[edge()])
        self.assertEqual(mismatch['edge_class_counts']['UID_PRESENT_NO_CONFIG_MATCH'],1)
        absent=join.summarize(self.projection,[edge(candidate='2')])
        self.assertEqual(absent['edge_class_counts']['UID_ABSENT'],1)
        zero=join.summarize(self.projection,[])
        self.assertEqual(zero['status'],'PARTIAL_SOURCE_SCOPE_JOIN')
        self.assertTrue(zero['no_mapping_references_supplied'])
        self.assertEqual(zero['config_equality_unmatched_scoped_row_count'],1)
        self.assertEqual(join.summarize(fixture(),[])['status'],'PARTIAL_SOURCE_SCOPE_JOIN')

    def test_duplicate_candidate_same_scoped_identity_retains_source_rows(self):
        add(self.projection)
        add(self.projection)
        result=join.summarize(self.projection,[])
        self.assertEqual(result['provided_scoped_configuration_row_count'],2)
        self.assertEqual(result['duplicate_scoped_uid_identity_count'],1)
        self.assertEqual(result['duplicate_scoped_row_excess_count'],1)
        self.assertEqual(result['config_equality_unmatched_scoped_row_count'],2)
        self.assertEqual(result['status'],'PARTIAL_SOURCE_SCOPE_JOIN')

    def test_hmf_config_match_and_candidate_origins(self):
        add(self.projection,alias='hmf_refine',h='000',m='016',origin='one_based_data_row')
        result=join.summarize(self.projection,[edge(alias='hmf_refine',h='0')])
        self.assertEqual(result['edge_class_counts']['ONE_SCOPED_CONFIG_MATCH'],1)
        self.assertEqual(result['candidate_id_origin_counts']['one_based_data_row'],1)

    def test_malformed_edges_duplicate_different_action_blind_and_extra_quality_rejected(self):
        add(self.projection)
        for value in (dict(edge(),circuit='s9234'),dict(edge(),action_uid='spi:HF:h064'),
                      dict(edge(),action_uid='spi:HMF:h64:m16'),dict(edge(),total_cycles='123'),
                      dict(edge(),source_candidate_uid='spi:hf_coarse:H64-M16-F4:1')):
            with self.subTest(value=value),self.assertRaises(join.ScopeJoinError): join.summarize(self.projection,[value])
        with self.assertRaisesRegex(join.ScopeJoinError,'DUPLICATE_SOURCE_ACTION_EDGE'):
            join.summarize(self.projection,[edge(),edge()])
        with self.assertRaisesRegex(join.ScopeJoinError,'SOURCE_MULTIPLE_ACTIONS'):
            join.summarize(self.projection,[edge(),edge(h='128')])
        with patch.object(join,'MAX_EDGES',0),self.assertRaises(join.ScopeJoinError):
            join.summarize(self.projection,[edge()])

    def test_malformed_projection_scopes_and_extra_quality_rejected(self):
        for mutation in ('blind','path','quality','ordinal','flags'):
            projected=fixture()
            add(projected)
            if mutation=='blind': projected['files'][0]['circuit']='s9234'
            elif mutation=='path': projected['files'][0]['coverage_root']+='_other'
            elif mutation=='quality': projected['total_cycles']=123
            elif mutation=='ordinal': next(item for item in projected['files'] if item['rows'])['rows'][0][0]=3
            else: projected['quality_evaluated']=True
            with self.subTest(mutation=mutation),self.assertRaises(join.ScopeJoinError): join.summarize(projected,[])

    def test_no_io_no_mutation_file_order_stability_and_false_certification_flags(self):
        add(self.projection)
        before=copy.deepcopy(self.projection)
        with patch('builtins.open',side_effect=AssertionError('CONTENT')),patch('os.open',side_effect=AssertionError('FD')), \
                patch('subprocess.Popen',side_effect=AssertionError('REMOTE')):
            result=join.summarize(self.projection,[edge()])
        self.assertEqual(before,self.projection)
        self.projection['files'].reverse()
        self.assertEqual(result,join.summarize(self.projection,[edge()]))
        for flag in ('versions_merged','rows_deduplicated','per_row_outputs_emitted','provenance_certified',
                     'pre_outcome_certified','full_history_certified','inventory_origin_authenticated',
                     'invocation_certified','training_release','costs_computed','quality_values_accessed',
                     'fit_targets_generated','physical_files_read','online_claim'):
            self.assertIs(result[flag],False)


if __name__=='__main__': unittest.main()
