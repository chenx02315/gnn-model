"""Synthetic E57 only: no committed E41/E56 result contents are opened."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import audit_ranking_v6_e57_formal_declaration_bridge as m
from scripts import audit_ranking_v6_e56_formal_config_join as config
from tests.test_ranking_v6_e56_formal_config_join import fixture as config_fixture, edge


def fixture():
    projection,bound=config_fixture()
    for item in projection['files']:
        if item['stage_alias']=='hf_refine' and item['circuit'] in ('s35932','s38417'):
            candidates=['1'] if item['circuit']=='s35932' else ['8','10','11']
            item['rows']=[[i,candidate,'0064','0','explicit_candidate'] for i,candidate in enumerate(candidates,2)]
    projection['total_rows']=sum(len(item['rows']) for item in projection['files'])
    by_path={item['path']:item for item in projection['files']}
    for row in bound['rows']:
        count=len(by_path[row['matches'][0]['path']]['rows'])
        row['formal']['row_count']=row['matches'][0]['row_count']=count
    edges=[edge(circuit=circuit,alias='hf_refine',candidate=uid.rsplit(':',1)[-1]) for uid,circuit in m.FOCUS.items()]
    e56=config.compare(projection,edges,bound)
    e56['input_audit']=dict(local_metadata_files_read=3,total_bytes=10000,
        input_sha256=['a'*64,'b'*64,'c'*64],edge_rows=dict(mixed_edge_rows=4,
            non_train_rows_byte_filtered=0,train_session_edge_rows=4,distinct_source_action_references=4),
        remote_calls=0,automatic_retries=0)
    rows=[]
    for detail in e56['changed_or_previously_ambiguous_uids']:
        for location in detail['baseline']['matching_locations']:
            version=location['coverage_root'].rsplit('/',1)[-1]
            for mode in ('H','F'):
                ordinal=len(rows)+1
                rows.append(dict(source_candidate_uid=detail['source_candidate_uid'],coverage_version=version,mode=mode,
                    declaration_missing=False,declaration_inside_expected_lexical_namespace=True,
                    result_marker_sha256=format(ordinal+100,'064x'),classification='ONE_STRICT_MATCH',
                    provided_marker_match_counts=dict(strict_namespace_stage=1,same_namespace_stage_conflict=0,
                        other_namespace=0,other_circuit_or_mode=0),
                    strict_attempt_id_sha256=[format(ordinal+200,'064x')]))
    e41=dict(status='PARTIAL_DECLARED_MARKER_JOIN_NOT_CALL_CERTIFICATION',declarations=rows,
        declaration_count=16,scoped_source_rows=8,provided_attempt_rows=6985,
        provided_path_depth_counts=dict(one_component=0,two_components=0,three_or_more_components=6985),
        strict_match_classifications=dict(ZERO_STRICT_MATCH=0,ONE_STRICT_MATCH=16,MULTIPLE_STRICT_MATCHES=0),
        total_strict_declaration_attempt_references=16,unique_strict_attempt_id_sha256_count=16,
        preserved_reference_unit='declared scoped source row plus mode; not independent physical invocation',
        diagnostic_version='E41_R2',fixed_local_input_audit=dict(file_count=3,total_bytes=10000,
            sha256=['a'*64,'b'*64,'c'*64],selected_metadata_rows=6985,
            input_bytes_decoded_as_csv_but_wall_status_not_analyzed=True,original_measurements_or_logs_opened=False,
            remote_calls=0,windows_hard_memory_cap_or_peak_claimed=False,workers=1,automatic_retries=0))
    e41.update({key:False for key in m.E41_FALSE})
    return e56,e41


class DeclarationBridgeTests(unittest.TestCase):
    def test_all16_preserved_exact_root_partition8_8_no_path_leaf(self):
        e56,e41=fixture()
        result=m.bridge(e56,e41)
        self.assertEqual(result['formal_bound_declarations'],8)
        self.assertEqual(result['other_version_declarations'],8)
        self.assertEqual(result['preserved_strict_attempt_hash_count'],16)
        self.assertEqual(len(result['declarations']),16)
        self.assertEqual([row['source_candidate_uid'] for row in result['declarations']],
                         [row['source_candidate_uid'] for row in e41['declarations']])
        self.assertNotIn('hf_measurements.tsv',json.dumps(result))
        self.assertFalse(result['other_version_attempts_discarded'])
        self.assertFalse(result['fixed_input_reader_executed'])

    def test_formal_selection_can_be_other_version_not_name_preference(self):
        e56,e41=fixture()
        # Swap which baseline root is authenticated for all four UID details and
        # their formal file summaries; no v1/v2 preference may enter the bridge.
        for detail in e56['changed_or_previously_ambiguous_uids']:
            old=detail['formal']['matching_locations'][0]
            new=next(row for row in detail['baseline']['matching_locations'] if row['coverage_root']!=old['coverage_root'])
            detail['formal']['matching_locations']=[dict(new)]
            for index,item in enumerate(e56['formal_authenticated24']['files']):
                if item['path']==old['path']:
                    e56['formal_authenticated24']['files'][index]=copy.deepcopy(
                        next(x for x in e56['baseline_all32']['files'] if x['path']==new['path']))
        result=m.bridge(e56,e41)
        self.assertTrue(all(row['coverage_version'].endswith('v2_merge_reclassify')
                            for row in result['declarations'] if row['partition']=='FORMAL_BOUND'))

    def test_duplicate_or_missing_declaration_rejected(self):
        for change in ('duplicate','missing'):
            e56,e41=fixture()
            if change=='duplicate':e41['declarations'][-1]=dict(e41['declarations'][0])
            else:e41['declarations'].pop()
            with self.assertRaises(ValueError):
                m.bridge(e56,e41)

    def test_wrong_mode_scope_candidate_spelling_or_version_rejected(self):
        for key,value in (('mode','M'),('source_candidate_uid','s35932:hf_refine:H64-F4:01'),
                          ('coverage_version','foreign_v1')):
            e56,e41=fixture()
            e41['declarations'][0][key]=value
            with self.assertRaises(ValueError):
                m.bridge(e56,e41)

    def test_root_and_sha_path_binding_errors_rejected(self):
        for key,value in (('coverage_root','/temp/jiangchuanc/foreign/root'),
                          ('source_sha256','d'*64),('path','/temp/jiangchuanc/foreign/file')):
            e56,e41=fixture()
            e56['changed_or_previously_ambiguous_uids'][0]['formal']['matching_locations'][0][key]=value
            with self.assertRaises(ValueError):
                m.bridge(e56,e41)

    def test_strict_hash_shape_duplicate_global_and_bucket_errors(self):
        for change in ('shape','duplicate_hash','extra_bucket'):
            e56,e41=fixture()
            if change=='shape':e41['declarations'][0]['strict_attempt_id_sha256']=['bad']
            elif change=='duplicate_hash':
                e41['declarations'][1]['strict_attempt_id_sha256']=list(e41['declarations'][0]['strict_attempt_id_sha256'])
            else:e41['declarations'][0]['provided_marker_match_counts']['other_namespace']=1
            with self.assertRaises(ValueError):
                m.bridge(e56,e41)

    def test_e41_totals_and_missing_strict_claim_rejected(self):
        for key,value in (('unique_strict_attempt_id_sha256_count',15),
                          ('total_strict_declaration_attempt_references',17),
                          ('declaration_count',True)):
            e56,e41=fixture()
            e41[key]=value
            with self.assertRaises(ValueError):
                m.bridge(e56,e41)
        e56,e41=fixture()
        e41['declarations'][0]['declaration_missing']=True
        with self.assertRaises(ValueError):
            m.bridge(e56,e41)

    def test_e56_no_lost_mapping_units_and_exact_four_details(self):
        e56,e41=fixture()
        e56['formal_authenticated24']['mapping_source_uid_count']+=1
        with self.assertRaises(ValueError):
            m.bridge(e56,e41)
        e56,e41=fixture()
        e56['baseline_all32']['edge_class_counts']['ONE_SCOPED_CONFIG_MATCH']+=1
        e56['baseline_all32']['edge_class_counts']['MULTIPLE_SCOPED_CONFIG_MATCH']-=1
        with self.assertRaisesRegex(ValueError,'GLOBAL_CLASS_CONSERVATION'):
            m.bridge(e56,e41)
        e56,e41=fixture()
        e56['changed_or_previously_ambiguous_uids'].pop()
        with self.assertRaises(ValueError):
            m.bridge(e56,e41)

    def test_unknown_quality_fields_or_true_quality_flags_reject(self):
        for source in ('e56','e41'):
            e56,e41=fixture()
            target=e56 if source=='e56' else e41
            target['private_quality_table']='POISON'
            with self.assertRaises(ValueError):
                m.bridge(e56,e41)
        e56,e41=fixture()
        e41['quality_evaluated']=True
        with self.assertRaises(ValueError):
            m.bridge(e56,e41)

    def test_pure_no_io_no_mutation_and_no_cost_or_training_flags(self):
        e56,e41=fixture()
        before=copy.deepcopy((e56,e41))
        with patch('builtins.open',side_effect=AssertionError('NO_IO')),patch.object(m,'stable_read',side_effect=AssertionError('NO_IO')):
            result=m.bridge(e56,e41)
        self.assertEqual((e56,e41),before)
        for key in ('costs_computed','quality_or_runtime_values_accessed','physical_call_certified',
                    'historical_pre_outcome_freeze_certified','fit_targets_generated','full_search_cost_certified','training_release'):
            self.assertIs(result[key],False)

    def test_pins_before_decode_and_duplicate_json_keys_fail(self):
        with patch.object(m,'stable_read',return_value=b'PRIVATE_NOT_JSON'):
            with self.assertRaisesRegex(ValueError,'INPUT_SHA'):
                m.read_summary_bytes('synthetic','a'*64)
        with self.assertRaisesRegex(ValueError,'DUPLICATE_JSON_KEY'):
            m.decode_summary(b'{"x":1,"x":2}')

    def test_isolated_mocked_fixed_main_no_actual_summary_reads(self):
        e56,e41=fixture()
        payload=json.dumps([e56,e41])
        path=str(Path(m.__file__).resolve())
        code=(
            "import importlib.util,json,sys\n"
            "before=list(sys.path)\n"
            "spec=importlib.util.spec_from_file_location('synthetic_e57',"+repr(path)+")\n"
            "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n"
            "assert sys.path==before and sys.flags.isolated and sys.flags.no_site\n"
            "fixture=json.loads(sys.stdin.read());calls=[]\n"
            "def pinned(path,digest):\n"
            "    index=len(calls);assert path==m.ROOT/m.PROSPECTIVE_INPUTS[index][0] and digest==m.PROSPECTIVE_INPUTS[index][1]\n"
            "    calls.append(index);return json.dumps(fixture[index]).encode('ascii')\n"
            "def forbidden(*args,**kwargs):raise AssertionError('NO_ACTUAL_READS')\n"
            "m.stable_read=forbidden;m.read_summary_bytes=pinned\n"
            "assert m.main()==0\n"
            "assert len(calls)==2 and sys.path==before\n"
        )
        with tempfile.TemporaryDirectory() as unrelated:
            result=subprocess.run([sys.executable,'-I','-S','-B','-c',code],input=payload,
                                  capture_output=True,text=True,cwd=unrelated,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stderr,'')
        output=json.loads(result.stdout)
        self.assertEqual(output['formal_bound_declarations'],8)
        self.assertEqual(output['other_version_declarations'],8)
        self.assertFalse(output['training_release'])
        self.assertTrue(output['fixed_input_reader_executed'])


if __name__=='__main__':
    unittest.main()
