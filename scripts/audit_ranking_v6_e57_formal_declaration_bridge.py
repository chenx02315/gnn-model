"""E57 fixed two-summary metadata namespace bridge; no physical-call claims."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

_HELPER_PATH=Path(__file__).resolve().with_name('project_ranking_v6_e54_source_binding.py')
_HELPER_SPEC=importlib.util.spec_from_file_location('_ranking_v6_e57_e54_stable',_HELPER_PATH)
if _HELPER_SPEC is None or _HELPER_SPEC.loader is None:
    raise ImportError('FIXED_STABLE_READER_UNAVAILABLE')
_HELPER_MODULE=importlib.util.module_from_spec(_HELPER_SPEC)
_HELPER_SPEC.loader.exec_module(_HELPER_MODULE)
stable_read=_HELPER_MODULE.stable_read
ROOT=Path(__file__).resolve().parents[1]

PROSPECTIVE_INPUTS = (
    ('data/manifests/ranking_v6_e56_formal_config_comparison_20261018_r1.json',
     'd4510d427790a6d2667e3e932995ebb57b11a0cbe952c257331f8beeb47c77cc'),
    ('data/manifests/ranking_v6_e41_r2_result_20261017_r1.json',
     '5a0a7cbb7c8ec087690aa551b18a5227623084e8c136f8b3e3dce73193295b99'),
)
OUTPUT_LIMIT = 65536
FOCUS = {
    's35932:hf_refine:H64-F4:1': 's35932',
    's38417:hf_refine:H64-F4:8': 's38417',
    's38417:hf_refine:H64-F4:10': 's38417',
    's38417:hf_refine:H64-F4:11': 's38417',
}
CLASSES = frozenset(('UID_ABSENT','UID_PRESENT_NO_CONFIG_MATCH','ONE_SCOPED_CONFIG_MATCH','MULTIPLE_SCOPED_CONFIG_MATCH'))
E56_FALSE = frozenset(('normalized_sha_used_for_authentication','all_control_rows_emitted',
    'coverage_versions_merged','historical_edges_or_costs_discarded','source_measurements_opened',
    'quality_or_runtime_values_accessed','invocation_identity_certified','historical_pre_outcome_freeze_certified',
    'full_search_cost_certified','fit_targets_generated','training_release'))
E56_TRUE = frozenset(('edge_triples_deduplicated','source_candidate_spelling_preserved','only_control_h_m_compared_as_integers'))
E41_FALSE = frozenset(('paths_followed_or_resolved','source_origin_assigned','quality_evaluated',
    'wall_or_status_analyzed','costs_computed','invocation_identity_certified',
    'candidate_universe_or_pre_outcome_freeze_certified','training_release'))
HEX = re.compile(r'[a-f0-9]{64}\Z')
TRAIN = frozenset(('aes_core','s13207','s15850','s35932','s38417','spi'))
STAGES = frozenset(('hf_coarse','hmf_coarse','hf_refine','hmf_refine'))


def require(ok,code):
    if not ok:
        raise ValueError('E57_'+code)


def integer(value):
    return type(value) is int and value>=0


def sha(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def metadata_root(value):
    return (type(value) is str and 0<len(value)<=512 and value.startswith('/temp/jiangchuanc/')
            and all(32<=ord(c)<127 for c in value) and '\\' not in value
            and all(x not in ('','.','..') for x in value.split('/')[1:]))


def summary(value,count):
    keys={'file_count','scoped_configuration_row_count','mapping_source_uid_count','edge_class_counts',
          'config_matched_scoped_row_count','config_unmatched_scoped_row_count','files'}
    require(type(value) is dict and set(value)==keys,'SUMMARY_SCHEMA')
    require(type(value['file_count']) is int and value['file_count']==count,'SUMMARY_FILE_COUNT')
    classes=value['edge_class_counts']
    require(type(classes) is dict and set(classes)==CLASSES and all(integer(v) for v in classes.values()),'CLASS_SCHEMA')
    require(integer(value['mapping_source_uid_count']) and sum(classes.values())==value['mapping_source_uid_count'],'SOURCE_UNIT_TOTAL')
    files=value['files']
    require(type(files) is list and len(files)==count,'SUMMARY_FILES')
    paths={}
    total=matched=unmatched=0
    for item in files:
        require(type(item) is dict and set(item)=={'circuit','stage_alias','coverage_root','path','source_sha256',
            'provided_row_count','matched_row_count','unmatched_row_count'},'FILE_SCHEMA')
        require(item['circuit'] in TRAIN and item['stage_alias'] in STAGES
                and metadata_root(item['coverage_root']) and sha(item['source_sha256']),'FILE_SCOPE')
        path=item['path']
        require(type(path) is str and path.startswith(item['coverage_root']+'/') and len(path)<=768
                and '\\' not in path and '..' not in path.split('/') and path not in paths,'FILE_PATH')
        require(all(integer(item[k]) for k in ('provided_row_count','matched_row_count','unmatched_row_count'))
                and item['matched_row_count']+item['unmatched_row_count']==item['provided_row_count'],'FILE_COUNTER')
        paths[path]=item
        total+=item['provided_row_count'];matched+=item['matched_row_count'];unmatched+=item['unmatched_row_count']
    for key,expected in (('scoped_configuration_row_count',total),('config_matched_scoped_row_count',matched),
                         ('config_unmatched_scoped_row_count',unmatched)):
        require(integer(value[key]) and value[key]==expected,'SUMMARY_COUNTER')
    return paths


def e56_bindings(value):
    keys={'status','baseline_all32','formal_authenticated24','excluded_inventory_file_count',
          'excluded_scoped_control_row_count','changed_or_previously_ambiguous_uid_count',
          'changed_or_previously_ambiguous_uids','uid_detail_limit','uid_detail_omitted_count','input_audit'} | E56_FALSE | E56_TRUE
    require(type(value) is dict and set(value)==keys,'E56_SCHEMA')
    require(value['status']=='PASS_FORMAL_FILE_CONFIG_COMPARISON_ONLY'
            and all(value[k] is False for k in E56_FALSE) and all(value[k] is True for k in E56_TRUE),'E56_FLAGS')
    baseline,formal=value['baseline_all32'],value['formal_authenticated24']
    all_files=summary(baseline,32);formal_files=summary(formal,24)
    require(baseline['mapping_source_uid_count']==formal['mapping_source_uid_count'],'SOURCE_UNITS_LOST')
    count=baseline['mapping_source_uid_count']
    require(baseline['edge_class_counts']=={'UID_ABSENT':0,'UID_PRESENT_NO_CONFIG_MATCH':0,
                'ONE_SCOPED_CONFIG_MATCH':count-4,'MULTIPLE_SCOPED_CONFIG_MATCH':4}
            and formal['edge_class_counts']=={'UID_ABSENT':0,'UID_PRESENT_NO_CONFIG_MATCH':0,
                'ONE_SCOPED_CONFIG_MATCH':count,'MULTIPLE_SCOPED_CONFIG_MATCH':0},'GLOBAL_CLASS_CONSERVATION')
    require(all(path in all_files and item==all_files[path] for path,item in formal_files.items()),'FORMAL_SUBSET')
    # Counts of matched rows differ across the two populations only by excluded files.
    require(type(value['excluded_inventory_file_count']) is int and value['excluded_inventory_file_count']==8
            and integer(value['excluded_scoped_control_row_count'])
            and value['excluded_scoped_control_row_count']==sum(item['provided_row_count'] for path,item in all_files.items() if path not in formal_files),'EXCLUDED_COUNTER')
    require(type(value['uid_detail_limit']) is int and value['uid_detail_limit']==32
            and type(value['uid_detail_omitted_count']) is int and value['uid_detail_omitted_count']==0
            and type(value['changed_or_previously_ambiguous_uid_count']) is int
            and value['changed_or_previously_ambiguous_uid_count']==4,'FOUR_DETAILS_REQUIRED')
    audit=value['input_audit']
    require(type(audit) is dict and set(audit)=={'local_metadata_files_read','total_bytes','input_sha256','edge_rows','remote_calls','automatic_retries'},'E56_AUDIT_SCHEMA')
    require(audit['local_metadata_files_read']==3 and integer(audit['total_bytes']) and audit['total_bytes']<=10485760
            and type(audit['input_sha256']) is list and len(audit['input_sha256'])==3 and all(sha(x) for x in audit['input_sha256'])
            and audit['remote_calls']==0 and audit['automatic_retries']==0,'E56_AUDIT')
    edges=audit['edge_rows']
    require(type(edges) is dict and set(edges)=={'mixed_edge_rows','non_train_rows_byte_filtered','train_session_edge_rows','distinct_source_action_references'}
            and all(integer(x) for x in edges.values()) and edges['mixed_edge_rows']<=100000
            and edges['mixed_edge_rows']==edges['non_train_rows_byte_filtered']+edges['train_session_edge_rows']
            and edges['distinct_source_action_references']==baseline['mapping_source_uid_count']
            and edges['train_session_edge_rows']>=edges['distinct_source_action_references'],'E56_EDGE_COUNTER')
    details=value['changed_or_previously_ambiguous_uids']
    require(type(details) is list and len(details)==4,'E56_DETAIL_LIST')
    bindings={}
    def locations(detail,kind,n,files,circuit):
        require(type(detail) is dict and set(detail)=={'classification','matching_row_count','matching_locations'}
                and detail['classification']==kind and type(detail['matching_row_count']) is int and detail['matching_row_count']==n,'DETAIL_CLASS')
        rows=detail['matching_locations']
        require(type(rows) is list and len(rows)==n,'DETAIL_LOCATIONS')
        roots={}
        prefix='/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/'+circuit+'/'
        for row in rows:
            require(type(row) is dict and set(row)=={'coverage_root','path','source_sha256','matching_row_count'},'LOCATION_SCHEMA')
            root=row['coverage_root'];path=row['path']
            require(metadata_root(root) and root.startswith(prefix) and len(root.split('/'))==len(prefix.split('/'))
                    and path==root+'/04_integer_refine/hf_measurements.tsv'
                    and root not in roots and path in files,'LOCATION_ROOT')
            item=files[path]
            require(item['coverage_root']==root and item['circuit']==circuit and item['stage_alias']=='hf_refine'
                    and sha(row['source_sha256']) and row['source_sha256']==item['source_sha256']
                    and type(row['matching_row_count']) is int and row['matching_row_count']==1
                    and item['matched_row_count']>=1,'LOCATION_BINDING')
            namespace=root.rsplit('/',1)[-1]
            require(namespace not in roots,'NAMESPACE_BIJECTION')
            roots[root]=dict(row)
        require(len({root.rsplit('/',1)[-1] for root in roots})==len(roots),'NAMESPACE_BIJECTION')
        return roots
    for item in details:
        require(type(item) is dict and set(item)=={'source_candidate_uid','action_uid','baseline','formal'},'DETAIL_SCHEMA')
        uid=item['source_candidate_uid']
        require(type(uid) is str and uid in FOCUS and uid not in bindings,'FOCUS_UID')
        circuit=FOCUS[uid]
        require(type(item['action_uid']) is str and re.fullmatch(re.escape(circuit)+r':HF:h(0|[1-9][0-9]{0,9})',item['action_uid']) is not None,'ACTION_UID')
        old=locations(item['baseline'],'MULTIPLE_SCOPED_CONFIG_MATCH',2,all_files,circuit)
        new=locations(item['formal'],'ONE_SCOPED_CONFIG_MATCH',1,formal_files,circuit)
        require(all(root in old and row==old[root] for root,row in new.items()),'FORMAL_DETAIL_SUBSET')
        bindings[uid]=dict(formal_root=next(iter(new)),namespace_roots={root.rsplit('/',1)[-1]:root for root in old})
    require(set(bindings)==set(FOCUS),'FOCUS_GRID')
    return bindings


def declarations(value,bindings):
    keys={'status','declarations','declaration_count','scoped_source_rows','provided_attempt_rows',
          'provided_path_depth_counts','strict_match_classifications','total_strict_declaration_attempt_references',
          'unique_strict_attempt_id_sha256_count','preserved_reference_unit','diagnostic_version','fixed_local_input_audit'} | E41_FALSE
    require(type(value) is dict and set(value)==keys,'E41_SCHEMA')
    require(value['status']=='PARTIAL_DECLARED_MARKER_JOIN_NOT_CALL_CERTIFICATION'
            and value['diagnostic_version']=='E41_R2' and all(value[k] is False for k in E41_FALSE),'E41_FLAGS')
    for key,expected in (('declaration_count',16),('scoped_source_rows',8),('provided_attempt_rows',6985),
                         ('total_strict_declaration_attempt_references',16),('unique_strict_attempt_id_sha256_count',16)):
        require(type(value[key]) is int and value[key]==expected,'E41_COUNTER')
    require(value['strict_match_classifications']=={'ZERO_STRICT_MATCH':0,'ONE_STRICT_MATCH':16,'MULTIPLE_STRICT_MATCHES':0}
            and all(type(x) is int for x in value['strict_match_classifications'].values()),'E41_CLASSES')
    require(value['preserved_reference_unit']=='declared scoped source row plus mode; not independent physical invocation','E41_REFERENCE_UNIT')
    depths=value['provided_path_depth_counts']
    require(type(depths) is dict and set(depths)=={'one_component','two_components','three_or_more_components'}
            and all(integer(x) for x in depths.values()) and sum(depths.values())==6985,'E41_DEPTH_COUNTER')
    audit=value['fixed_local_input_audit']
    require(type(audit) is dict and set(audit)=={'file_count','total_bytes','sha256','selected_metadata_rows',
        'input_bytes_decoded_as_csv_but_wall_status_not_analyzed','original_measurements_or_logs_opened',
        'remote_calls','windows_hard_memory_cap_or_peak_claimed','workers','automatic_retries'},'E41_AUDIT_SCHEMA')
    require(audit['file_count']==3 and integer(audit['total_bytes']) and audit['total_bytes']<=12582912
            and type(audit['sha256']) is list and len(audit['sha256'])==3 and all(sha(x) for x in audit['sha256'])
            and audit['selected_metadata_rows']==6985
            and audit['input_bytes_decoded_as_csv_but_wall_status_not_analyzed'] is True
            and audit['original_measurements_or_logs_opened'] is False and audit['remote_calls']==0
            and audit['windows_hard_memory_cap_or_peak_claimed'] is False
            and audit['workers']==1 and audit['automatic_retries']==0,'E41_AUDIT')
    rows=value['declarations']
    require(type(rows) is list and len(rows)==16,'DECLARATIONS_16')
    seen=set();hashes=set();output=[]
    for ordinal,row in enumerate(rows,1):
        require(type(row) is dict and set(row)=={'source_candidate_uid','coverage_version','mode',
            'declaration_missing','declaration_inside_expected_lexical_namespace','result_marker_sha256',
            'classification','provided_marker_match_counts','strict_attempt_id_sha256'},'DECLARATION_SCHEMA')
        uid=row['source_candidate_uid'];version=row['coverage_version'];mode=row['mode']
        require(type(uid) is str and uid in bindings and type(version) is str
                and version in bindings[uid]['namespace_roots'] and mode in ('H','F'),'DECLARATION_SCOPE')
        key=(uid,version,mode)
        require(key not in seen,'DUPLICATE_DECLARATION')
        seen.add(key)
        require(row['declaration_missing'] is False and row['declaration_inside_expected_lexical_namespace'] is True
                and row['classification']=='ONE_STRICT_MATCH' and sha(row['result_marker_sha256']),'STRICT_DECLARATION')
        counts=row['provided_marker_match_counts']
        require(type(counts) is dict and counts=={'strict_namespace_stage':1,'same_namespace_stage_conflict':0,
            'other_namespace':0,'other_circuit_or_mode':0} and all(type(x) is int for x in counts.values()),'STRICT_BUCKETS')
        ids=row['strict_attempt_id_sha256']
        require(type(ids) is list and len(ids)==1 and sha(ids[0]) and ids[0] not in hashes,'STRICT_HASH_UNIQUE')
        hashes.add(ids[0])
        root=bindings[uid]['namespace_roots'][version]
        output.append(dict(declaration_ordinal=ordinal,source_candidate_uid=uid,coverage_version=version,
            coverage_root=root,mode=mode,partition='FORMAL_BOUND' if root==bindings[uid]['formal_root'] else 'OTHER_VERSION',
            result_marker_sha256=row['result_marker_sha256'],strict_attempt_id_sha256=ids[0]))
    expected={(uid,version,mode) for uid,binding in bindings.items() for version in binding['namespace_roots'] for mode in ('H','F')}
    require(seen==expected and len(hashes)==16,'DECLARATION_GRID')
    return output


def bridge(e56,e41):
    bindings=e56_bindings(e56)
    rows=declarations(e41,bindings)
    formal=sum(row['partition']=='FORMAL_BOUND' for row in rows)
    require(formal==8 and len(rows)-formal==8,'PARTITION_8_8')
    result=dict(status='PASS_METADATA_NAMESPACE_BRIDGE_ONLY',declaration_count=16,
        formal_bound_declarations=8,other_version_declarations=8,preserved_strict_attempt_hash_count=16,
        declarations=rows,source_candidate_spelling_preserved=True,all_declarations_preserved=True,
        root_resolution='E41 namespace bijection to E56 baseline metadata full roots; not physical path authentication',
        other_version_attempts_discarded=False,physical_call_certified=False,costs_computed=False,
        quality_or_runtime_values_accessed=False,historical_pre_outcome_freeze_certified=False,
        full_search_cost_certified=False,fit_targets_generated=False,training_release=False,
        actual_input_hashes_verified=False,fixed_input_reader_executed=False)
    require(len(json.dumps(result,ensure_ascii=True,separators=(',',':')).encode('ascii'))+1<=OUTPUT_LIMIT,'OUTPUT_BOUND')
    return result


def main():
    try:
        require(len(sys.argv)==1,'FIXED_TWO_SUMMARIES_ONLY')
        blobs=[read_summary_bytes(ROOT/path,digest) for path,digest in PROSPECTIVE_INPUTS]
        require(sum(map(len,blobs))<=131072,'TOTAL_INPUT_BOUND')
        # Both complete byte pins pass before decoding either summary.
        e56,e41=[decode_summary(raw) for raw in blobs]
        result=bridge(e56,e41)
        result['actual_input_hashes_verified']=True
        result['fixed_input_reader_executed']=True
        result['input_audit']=dict(fixed_local_metadata_files_read=2,total_bytes=sum(map(len,blobs)),
            sha256=[digest for _,digest in PROSPECTIVE_INPUTS],remote_calls=0,automatic_retries=0)
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
        require(len(raw.encode('ascii'))+1<=OUTPUT_LIMIT,'OUTPUT_BOUND')
        print(raw)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_FORMAL_DECLARATION_BRIDGE","code":"PINNED_METADATA_REJECTED"}')
        return 2


def read_summary_bytes(path,expected):
    require(sha(expected),'INPUT_PIN')
    raw=stable_read(path,65536)
    require(hashlib.sha256(raw).hexdigest()==expected,'INPUT_SHA')
    return raw


def decode_summary(raw):
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'DUPLICATE_JSON_KEY')
            result[key]=value
        return result
    def reject(_):
        raise ValueError('NONSTANDARD_JSON_CONSTANT')
    return json.loads(raw.decode('ascii'),object_pairs_hook=unique,parse_constant=reject)


if __name__=='__main__':
    sys.exit(main())
