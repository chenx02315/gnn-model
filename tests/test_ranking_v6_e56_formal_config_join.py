"""Synthetic E56 metadata only; never read actual E55/E38/mapping inputs."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import audit_ranking_v6_e56_formal_config_join as m


def fixture():
    files=[]
    for index,((circuit,root,alias,path),scheme) in enumerate(m.SPECS.items(),1):
        files.append(dict(circuit=circuit,coverage_root=root,stage_alias=alias,path=path,
            sha256=format(index,'064x'),byte_count=256,header_sha256='b'*64,
            rows=[[2,'001','0064','0016' if scheme=='HMF' else '0','explicit_candidate']]))
    projection=dict(status='PASS_SELECTED_CONFIG_METADATA_PROJECTION_ONLY',files=files,file_count=32,
        coverage_root_count=8,total_bytes=8192,total_rows=32,
        source_identity_scope='circuit+coverage_root+stage_alias+candidate_raw',
        source_file_bytes_read_for_sha_and_structure=True,
        resource=dict(address_space_limit_bytes=1073741824,cpu_limit_s=20,workers=1))
    projection.update({key:False for key in m.FALSE_FLAGS})
    seen=set()
    rows=[]
    for ordinal,item in enumerate(files,1):
        key=(item['circuit'],item['stage_alias'])
        if key in seen:
            continue
        seen.add(key)
        rows.append(dict(formal=dict(circuit=key[0],stage=key[1],source_sha256=item['sha256'],
            normalized_sha256='f'*64,row_count=1,source_basename='copied.tsv',
            logical_ordinal=len(rows)+1,physical_line=len(rows)+2),
            classification='ONE_ORIGINAL_SHA_MATCH',
            matches=[dict(inventory_ordinal=ordinal,coverage_root=item['coverage_root'],path=item['path'],
                          source_sha256=item['sha256'],row_count=1,basename_equal=False)]))
    bound=dict(status='PASS_ORIGINAL_SHA_COMPARISON_ONLY',training_release=False,
        normalized_sha_used_for_matching=False,formal_source_count=24,inventory_file_count=32,
        class_counts=dict(ZERO_ORIGINAL_SHA_MATCH=0,ONE_ORIGINAL_SHA_MATCH=24,MULTIPLE_IDENTICAL_BYTES_LOCATIONS=0),
        all_formal_bytes_found=True,rows=rows)
    return projection,bound


def edge(circuit='s35932',alias='hf_coarse',candidate='001',h='64',mvalue='16'):
    scheme='HMF' if alias.startswith('hmf_') else 'HF'
    return dict(circuit=circuit,
        source_candidate_uid=':'.join((circuit,alias,'H64-M16-F4' if scheme=='HMF' else 'H64-F4',candidate)),
        action_uid=circuit+':'+scheme+':h'+h+(':m'+mvalue if scheme=='HMF' else ''))


def edge_bytes(values):
    records=[]
    for value in values:
        cells=[b'']*12
        cells[0]=value['action_uid'].encode()
        cells[1]=value['source_candidate_uid'].encode()
        cells[2]=value['circuit'].encode()
        records.append(b'\t'.join(cells))
    return b'\t'.join(x.encode() for x in m.FIELDS)+b'\n'+b'\n'.join(records)+b'\n'


class FormalConfigTests(unittest.TestCase):
    def test_baseline_two_formal_one_and_all_roots_retained(self):
        projection,bound=fixture()
        result=m.compare(projection,[edge()],bound)
        self.assertEqual(result['baseline_all32']['edge_class_counts']['MULTIPLE_SCOPED_CONFIG_MATCH'],1)
        self.assertEqual(result['formal_authenticated24']['edge_class_counts']['ONE_SCOPED_CONFIG_MATCH'],1)
        self.assertEqual(len(result['baseline_all32']['files']),32)
        self.assertEqual(len(result['formal_authenticated24']['files']),24)
        self.assertEqual(result['excluded_inventory_file_count'],8)
        self.assertEqual(result['excluded_scoped_control_row_count'],8)
        detail=result['changed_or_previously_ambiguous_uids'][0]
        self.assertEqual(detail['baseline']['matching_row_count'],2)
        self.assertEqual(detail['formal']['matching_row_count'],1)
        self.assertFalse(result['historical_edges_or_costs_discarded'])

    def test_authenticated_path_not_version_name_selects_v2(self):
        projection,bound=fixture()
        entry=next(x for x in bound['rows'] if x['formal']['circuit']=='s35932' and x['formal']['stage']=='hf_coarse')
        index,item=next((i,x) for i,x in enumerate(projection['files'],1)
                       if x['circuit']=='s35932' and x['stage_alias']=='hf_coarse' and x['coverage_root'].endswith('v2_merge_reclassify'))
        entry['formal']['source_sha256']=item['sha256']
        entry['matches']=[dict(inventory_ordinal=index,coverage_root=item['coverage_root'],path=item['path'],
                              source_sha256=item['sha256'],row_count=1,basename_equal=False)]
        result=m.compare(projection,[edge()],bound)
        root=result['changed_or_previously_ambiguous_uids'][0]['formal']['matching_locations'][0]['coverage_root']
        self.assertTrue(root.endswith('v2_merge_reclassify'))

    def test_normalized_hash_never_rescues_wrong_original_hash(self):
        projection,bound=fixture()
        row=bound['rows'][0]['formal']
        row['normalized_sha256']=row['source_sha256']
        row['source_sha256']='d'*64
        with self.assertRaisesRegex(ValueError,'ORIGINAL_SHA_SCOPE_BINDING'):
            m.compare(projection,[],bound)

    def test_missing_formal_path_and_non_one_binding_fail_closed(self):
        projection,bound=fixture()
        bound['rows'][0]['matches'][0]['path']+='_missing'
        with self.assertRaises(ValueError):
            m.compare(projection,[],bound)
        projection,bound=fixture()
        bound['class_counts']['ONE_ORIGINAL_SHA_MATCH']=23
        with self.assertRaisesRegex(ValueError,'BOUND_ALL_24_ONE'):
            m.compare(projection,[],bound)

    def test_leading_zero_candidates_preserved_hm_integer_only(self):
        projection,bound=fixture()
        result=m.compare(projection,[edge(candidate='1'),edge(alias='hmf_refine')],bound)
        self.assertEqual(result['formal_authenticated24']['edge_class_counts']['UID_ABSENT'],1)
        self.assertEqual(result['formal_authenticated24']['edge_class_counts']['ONE_SCOPED_CONFIG_MATCH'],1)
        self.assertTrue(result['source_candidate_spelling_preserved'])

    def test_zero_one_multiple_classes_preserve_duplicate_control_rows(self):
        projection,bound=fixture()
        entry=next(x for x in bound['rows'] if x['formal']['circuit']=='s35932' and x['formal']['stage']=='hf_coarse')
        item=next(x for x in projection['files'] if x['path']==entry['matches'][0]['path'])
        item['rows'].append([3,'001','64','0','explicit_candidate'])
        projection['total_rows']+=1
        entry['formal']['row_count']=entry['matches'][0]['row_count']=2
        result=m.compare(projection,[edge(),edge(candidate='2'),edge(alias='hf_refine',h='128')],bound)
        classes=result['formal_authenticated24']['edge_class_counts']
        self.assertEqual(classes['MULTIPLE_SCOPED_CONFIG_MATCH'],1)
        self.assertEqual(classes['UID_ABSENT'],1)
        self.assertEqual(classes['UID_PRESENT_NO_CONFIG_MATCH'],1)
        self.assertEqual(sum(classes.values()),3)

    def test_exact_edge_triples_deduplicate_conflicting_action_rejects(self):
        projection,bound=fixture()
        result=m.compare(projection,[edge(),edge()],bound)
        self.assertEqual(result['formal_authenticated24']['mapping_source_uid_count'],1)
        with self.assertRaisesRegex(ValueError,'SOURCE_UID_ACTION_CONFLICT'):
            m.compare(projection,[edge(),edge(h='128')],bound)

    def test_edge_byte_filter_nontrain_poison_and_counts(self):
        raw=edge_bytes([edge(),edge()])
        cells=[b'PRIVATE_NONTRAIN\xff']*12
        cells[2]=b'tv80'
        raw+=b'\t'.join(cells)+b'\n'
        original=m.decode_edge
        def selected(value):
            if b'PRIVATE' in value or any(c>127 for c in value):
                raise AssertionError('NONTRAIN_DECODE')
            return original(value)
        with patch.object(m,'decode_edge',side_effect=selected):
            edges,audit=m.parse_edges(raw)
        self.assertEqual(len(edges),1)
        self.assertEqual(audit['mixed_edge_rows'],3)
        self.assertEqual(audit['non_train_rows_byte_filtered'],1)
        self.assertEqual(audit['train_session_edge_rows'],2)

    def test_unsupported_edge_schema_quotes_unknown_circuit_and_uid(self):
        raw=edge_bytes([edge()])
        for bad in (raw.replace(b'action_uid',b'quality',1),raw.replace(b'\t\t',b'\t"private"\t',1),
                    raw.replace(b'\ts35932\t',b'\tBLIND\t',1)):
            with self.assertRaises(ValueError):
                m.parse_edges(bad)
        projection,bound=fixture()
        for bad in (dict(edge(),total_cycles='123'),edge(h='064'),dict(edge(),circuit='tv80')):
            with self.assertRaises(ValueError):
                m.compare(projection,[bad],bound)

    def test_strict_projection_schema_control_row_and_flags(self):
        for mutation in ('quality','row','flag'):
            projection,bound=fixture()
            if mutation=='quality':projection['total_cycles']=123
            elif mutation=='row':projection['files'][0]['rows'][0][0]=3
            else:projection['quality_evaluated']=True
            with self.assertRaises(ValueError):
                m.compare(projection,[],bound)

    def test_bound_rowcount_contradiction_and_wrong_full_sha(self):
        projection,bound=fixture()
        bound['rows'][0]['matches'][0]['row_count']=2
        with self.assertRaisesRegex(ValueError,'BOUND_MATCH_METADATA'):
            m.compare(projection,[],bound)
        projection,bound=fixture()
        projection['files'][0]['sha256']='e'*64
        with self.assertRaisesRegex(ValueError,'ORIGINAL_SHA_SCOPE_BINDING'):
            m.compare(projection,[],bound)

    def test_pure_no_io_no_mutation_and_no_release(self):
        projection,bound=fixture()
        before=copy.deepcopy((projection,bound))
        with patch('builtins.open',side_effect=AssertionError('NO_IO')),patch.object(m,'stable_read',side_effect=AssertionError('NO_IO')):
            result=m.compare(projection,[edge()],bound)
        self.assertEqual((projection,bound),before)
        for key in ('training_release','quality_or_runtime_values_accessed','source_measurements_opened',
                    'fit_targets_generated','full_search_cost_certified','invocation_identity_certified'):
            self.assertIs(result[key],False)

    def test_input_sha_before_json_decode_and_edge_bound(self):
        with patch.object(m,'stable_read',return_value=b'PRIVATE_NOT_JSON'):
            with self.assertRaisesRegex(ValueError,'INPUT_SHA'):
                m.pinned_bytes('synthetic','a'*64,100)
        with patch.object(m,'MAX_EDGES',0):
            with self.assertRaisesRegex(ValueError,'EDGE_ROW_BOUND'):
                m.parse_edges(edge_bytes([edge()]))

    def test_isolated_synthetic_main_and_fixed_helper_without_actual_reads(self):
        projection,bound=fixture()
        payload=json.dumps({'projection':projection,'bound':bound,'edges':edge_bytes([edge()]).decode('ascii')})
        path=str(Path(m.__file__).resolve())
        code=(
            "import importlib.util,json,sys\n"
            "before=list(sys.path)\n"
            "spec=importlib.util.spec_from_file_location('synthetic_e56',"+repr(path)+")\n"
            "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n"
            "assert sys.path==before and sys.flags.isolated and sys.flags.no_site\n"
            "fixture=json.loads(sys.stdin.read())\n"
            "blobs=[json.dumps(fixture['bound']).encode('ascii'),json.dumps(fixture['projection']).encode('ascii'),fixture['edges'].encode('ascii')]\n"
            "calls=[]\n"
            "def pinned(path,digest,limit):\n"
            "    index=len(calls);assert path==m.INPUTS[index][0] and digest==m.INPUTS[index][1]\n"
            "    calls.append(index);return blobs[index]\n"
            "def forbidden(*args,**kwargs):raise AssertionError('ACTUAL_INPUT_READ')\n"
            "m.stable_read=forbidden;m.pinned_bytes=pinned\n"
            "assert m.main()==0\n"
            "assert len(calls)==3 and sys.path==before\n"
        )
        with tempfile.TemporaryDirectory() as unrelated:
            result=subprocess.run([sys.executable,'-I','-S','-B','-c',code],cwd=unrelated,
                                  capture_output=True,text=True,input=payload,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stderr,'')
        output=json.loads(result.stdout)
        self.assertEqual(output['formal_authenticated24']['edge_class_counts']['ONE_SCOPED_CONFIG_MATCH'],1)
        self.assertEqual(output['input_audit']['local_metadata_files_read'],3)
        self.assertFalse(output['training_release'])


if __name__=='__main__':
    unittest.main()
