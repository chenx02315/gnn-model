"""E56 metadata-only formal-file config rejoin; no source/quality/runtime reads."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

_HELPER_PATH = Path(__file__).resolve().with_name('project_ranking_v6_e54_source_binding.py')
_HELPER_SPEC = importlib.util.spec_from_file_location('_ranking_v6_e56_e54_stable', _HELPER_PATH)
if _HELPER_SPEC is None or _HELPER_SPEC.loader is None:
    raise ImportError('FIXED_STABLE_READER_UNAVAILABLE')
_HELPER_MODULE = importlib.util.module_from_spec(_HELPER_SPEC)
_HELPER_SPEC.loader.exec_module(_HELPER_MODULE)
stable_read = _HELPER_MODULE.stable_read

BASE = Path(__file__).resolve().parents[2] / 'runtime_training_staging_20260928'
INPUTS = (
    (BASE/'v6_e55_original_sha_join_20261018_r2/comparison.json', '91a58264b4d339b475f0861c043ff3839eab34d72d098d893e191b78c221a225',65536),
    (BASE/'v6_e38_roster_projection_20261016_r1/stdout.log', 'a742707477aa39553fab8f3ee14c808494cccfaad3ef9a05a661a309ad8b52ed',1048576),
    (BASE/'runtime_action_attempt_mapping_v1_r5/invocation_attempt_edges_v1.tsv', 'd5b25fdd934a18a352c286f572172ad8ba79fa064cf70dbe3f68e8e44e0fdfea',10*1024*1024),
)
INPUT_LIMIT = 10*1024*1024
OUTPUT_LIMIT = 65536
MAX_EDGES = 100000
MAX_CHANGED = 32
TRAIN = frozenset(('aes_core','s13207','s15850','s35932','s38417','spi'))
FILTER_ONLY = frozenset((b's5378',b'tv80'))
STAGES = frozenset(('hf_coarse','hmf_coarse','hf_refine','hmf_refine'))
FIELDS = ('action_uid','source_candidate_uid','circuit','stage','action_scheme',
          'h_patterns','m_patterns','mode','retry_group_id','retry_order','attempt_id','mapping_rule')
CLASSES = ('UID_ABSENT','UID_PRESENT_NO_CONFIG_MATCH','ONE_SCOPED_CONFIG_MATCH','MULTIPLE_SCOPED_CONFIG_MATCH')
ROOTS = (
    ('aes_core','/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/aes_core/10_coverage95_phase4_v2'),
    ('s13207','/temp/jiangchuanc/multimode_ate_phase3_20260811_A/10_circuits/s13207/10_coverage95_v3_merge_reclassify'),
    ('s15850','/temp/jiangchuanc/multimode_ate_phase3_20260811_A/10_circuits/s15850/10_coverage95_v3_merge_reclassify'),
    ('s35932','/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s35932/10_coverage95_v1'),
    ('s35932','/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s35932/10_coverage95_v2_merge_reclassify'),
    ('s38417','/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s38417/10_coverage95_v1'),
    ('s38417','/temp/jiangchuanc/multimode_ate_phase2_20260808_A/10_circuits/s38417/10_coverage95_v2_merge_reclassify'),
    ('spi','/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/spi/10_coverage95_phase4_v2'),
)
LAYOUT = (('hf_coarse','HF','02_hf_coarse/measurements.tsv'),
          ('hmf_coarse','HMF','03_hmf_coarse/measurements.tsv'),
          ('hf_refine','HF','04_integer_refine/hf_measurements.tsv'),
          ('hmf_refine','HMF','04_integer_refine/hmf_measurements.tsv'))
SPECS = {(c,r,a,r+'/'+suffix):scheme for c,r in ROOTS for a,scheme,suffix in LAYOUT}
FALSE_FLAGS = frozenset(('nonselected_values_decoded','nonselected_values_captured','quality_evaluated',
    'PASS_or_eligibility_filter_applied','coverage_versions_merged','pre_outcome_certified',
    'formal_builder_roots_certified','training_release','E36_inventory_emitted',
    'physical_files_written','raw_source_tables_persisted'))
SOURCE_RE = re.compile(r'([^:]+):(hf_coarse|hmf_coarse|hf_refine|hmf_refine):(H64-F4|H64-M16-F4):([0-9]{1,10})\Z')
ACTION_RE = re.compile(r'([^:]+):(HF|HMF):h(0|[1-9][0-9]{0,9})(?::m(0|[1-9][0-9]{0,9}))?\Z')
DECIMAL = re.compile(r'[0-9]{1,10}\Z')
HEX = re.compile(r'[a-f0-9]{64}\Z')


def require(ok, code):
    if not ok:
        raise ValueError('E56_'+code)


def sha(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def validate_projection(value):
    top = {'status','files','file_count','coverage_root_count','total_bytes','total_rows',
           'source_identity_scope','source_file_bytes_read_for_sha_and_structure','resource'} | FALSE_FLAGS
    require(type(value) is dict and set(value)==top, 'PROJECTION_SCHEMA')
    require(value['status']=='PASS_SELECTED_CONFIG_METADATA_PROJECTION_ONLY'
            and all(value[k] is False for k in FALSE_FLAGS), 'PROJECTION_STATUS')
    require(value['source_identity_scope']=='circuit+coverage_root+stage_alias+candidate_raw'
            and value['source_file_bytes_read_for_sha_and_structure'] is True, 'PROJECTION_SCOPE')
    require(type(value['file_count']) is int and value['file_count']==32
            and type(value['coverage_root_count']) is int and value['coverage_root_count']==8, 'PROJECTION_COUNTS')
    files=value['files']
    require(type(files) is list and len(files)==32, 'FILES_32')
    seen=set()
    total_bytes=total_rows=0
    for item in files:
        require(type(item) is dict and set(item)=={'circuit','coverage_root','stage_alias','path','sha256','byte_count','header_sha256','rows'}, 'FILE_SCHEMA')
        require(all(type(item[k]) is str for k in ('circuit','coverage_root','stage_alias','path')), 'FILE_STRINGS')
        key=tuple(item[k] for k in ('circuit','coverage_root','stage_alias','path'))
        require(key in SPECS and key not in seen, 'FILE_SCOPE')
        seen.add(key)
        require(sha(item['sha256']) and sha(item['header_sha256']), 'FILE_SHA')
        require(type(item['byte_count']) is int and 0<item['byte_count']<=8*1024*1024, 'FILE_BYTES')
        require(type(item['rows']) is list and len(item['rows'])<=MAX_EDGES, 'FILE_ROWS')
        for ordinal,row in enumerate(item['rows'],2):
            require(type(row) is list and len(row)==5 and type(row[0]) is int and row[0]==ordinal, 'SOURCE_ROW')
            _,candidate,h,m,origin=row
            require(all(type(x) is str and len(x)<=32 for x in (candidate,h,m,origin))
                    and DECIMAL.fullmatch(candidate) is not None and DECIMAL.fullmatch(h) is not None, 'CONTROL_METADATA')
            require(origin in ('explicit_candidate','one_based_data_row')
                    and (origin!='one_based_data_row' or candidate==str(ordinal-1)), 'CANDIDATE_ORIGIN')
            require((DECIMAL.fullmatch(m) is not None) if SPECS[key]=='HMF'
                    else (m=='' or DECIMAL.fullmatch(m) is not None and int(m)==0), 'CONTROL_M')
        total_rows+=len(item['rows'])
        total_bytes+=item['byte_count']
    require(seen==set(SPECS) and total_rows<=MAX_EDGES and total_bytes<=40*1024*1024, 'PROJECTION_TOTAL_BOUND')
    require(type(value['total_rows']) is int and value['total_rows']==total_rows
            and type(value['total_bytes']) is int and value['total_bytes']==total_bytes, 'PROJECTION_TOTALS')
    resource=value['resource']
    require(type(resource) is dict and set(resource)=={'address_space_limit_bytes','cpu_limit_s','workers'}, 'RESOURCE_SCHEMA')
    require(all(type(resource[k]) is int for k in resource)
            and 0<resource['address_space_limit_bytes']<=1073741824
            and 0<resource['cpu_limit_s']<=20 and resource['workers']==1, 'RESOURCE_BOUND')
    return files


def authenticated_paths(bound,files):
    require(type(bound) is dict and bound.get('status')=='PASS_ORIGINAL_SHA_COMPARISON_ONLY'
            and bound.get('training_release') is False and bound.get('normalized_sha_used_for_matching') is False, 'BOUND_STATUS')
    classes=bound.get('class_counts')
    require(type(bound.get('formal_source_count')) is int and bound['formal_source_count']==24
            and type(bound.get('inventory_file_count')) is int and bound['inventory_file_count']==32
            and type(classes) is dict and all(type(value) is int for value in classes.values())
            and classes=={'ZERO_ORIGINAL_SHA_MATCH':0,'ONE_ORIGINAL_SHA_MATCH':24,'MULTIPLE_IDENTICAL_BYTES_LOCATIONS':0}
            and bound.get('all_formal_bytes_found') is True, 'BOUND_ALL_24_ONE')
    rows=bound.get('rows')
    require(type(rows) is list and len(rows)==24, 'BOUND_ROWS')
    by_path={item['path']:item for item in files}
    paths,grid=set(),set()
    for entry in rows:
        require(type(entry) is dict and set(entry)=={'formal','classification','matches'}
                and entry['classification']=='ONE_ORIGINAL_SHA_MATCH', 'BOUND_ROW_SCHEMA')
        formal=entry['formal']
        require(type(formal) is dict and set(formal)=={'circuit','stage','source_sha256','normalized_sha256','row_count','source_basename','logical_ordinal','physical_line'}, 'FORMAL_SCHEMA')
        key=(formal['circuit'],formal['stage'])
        require(formal['circuit'] in TRAIN and formal['stage'] in STAGES and key not in grid, 'FORMAL_GRID')
        grid.add(key)
        require(sha(formal['source_sha256']) and sha(formal['normalized_sha256'])
                and type(formal['row_count']) is int and formal['row_count']>=0, 'FORMAL_SHA_COUNT')
        require(type(formal['logical_ordinal']) is int and formal['logical_ordinal']>=1
                and type(formal['physical_line']) is int and formal['physical_line']==formal['logical_ordinal']+1, 'FORMAL_ORDINAL')
        require(type(formal['source_basename']) is str and 0<len(formal['source_basename'])<=128
                and '/' not in formal['source_basename'] and '\\' not in formal['source_basename'], 'FORMAL_BASENAME')
        matches=entry['matches']
        require(type(matches) is list and len(matches)==1 and type(matches[0]) is dict
                and set(matches[0])=={'inventory_ordinal','coverage_root','path','source_sha256','row_count','basename_equal'}, 'BOUND_MATCH')
        match=matches[0]
        path=match['path']
        require(type(path) is str and path in by_path and path not in paths, 'FORMAL_FILE_MISSING_OR_DUPLICATE')
        item=by_path[path]
        require((formal['circuit'],formal['stage'],formal['source_sha256'])==(item['circuit'],item['stage_alias'],item['sha256'])
                and match['source_sha256']==formal['source_sha256']
                and match['coverage_root']==item['coverage_root'], 'ORIGINAL_SHA_SCOPE_BINDING')
        require(type(match['row_count']) is int and match['row_count']==formal['row_count']==len(item['rows'])
                and type(match['inventory_ordinal']) is int and 1<=match['inventory_ordinal']<=32
                and type(match['basename_equal']) is bool, 'BOUND_MATCH_METADATA')
        paths.add(path)
    require(grid=={(c,s) for c in TRAIN for s in STAGES} and len(paths)==24, 'FORMAL_24_GRID')
    return paths


def decode_edge(value):
    return value.decode('ascii')


def parse_edges(raw):
    require(type(raw) is bytes and 0<len(raw)<=INPUT_LIMIT, 'EDGE_BYTE_BOUND')
    lines=raw.split(b'\n')
    if lines[-1]==b'':lines.pop()
    require(lines and lines[0].rstrip(b'\r')==b'\t'.join(x.encode('ascii') for x in FIELDS), 'EDGE_HEADER')
    require(len(lines)-1<=MAX_EDGES, 'EDGE_ROW_BOUND')
    train,filtered=0,0
    triples=set()
    for line in lines[1:]:
        if line.endswith(b'\r'):line=line[:-1]
        require(line and line.count(b'\t')==11 and b'"' not in line
                and not any(c<32 and c!=9 for c in line), 'UNSUPPORTED_FLAT_EDGE_ROW')
        cells=line.split(b'\t')
        require(all(len(cell)<=65536 for cell in cells), 'EDGE_FIELD_BOUND')
        circuit=cells[2]  # Exact old runner FIELDS: zero-based column 2.
        if circuit in FILTER_ONLY:
            filtered+=1
            continue
        require(circuit in {x.encode('ascii') for x in TRAIN}, 'EDGE_TRAIN_SCOPE')
        train+=1
        triples.add((decode_edge(cells[1]),decode_edge(cells[0]),decode_edge(circuit)))
    edges=[dict(source_candidate_uid=s,action_uid=a,circuit=c) for s,a,c in sorted(triples)]
    return edges,dict(mixed_edge_rows=len(lines)-1,non_train_rows_byte_filtered=filtered,
                      train_session_edge_rows=train,distinct_source_action_references=len(edges))


def owners_for(edges):
    require(type(edges) is list and len(edges)<=MAX_EDGES, 'EDGE_LIST_BOUND')
    owners={}
    for edge in edges:
        require(type(edge) is dict and set(edge)=={'source_candidate_uid','action_uid','circuit'}, 'EDGE_SCHEMA')
        require(all(type(v) is str and len(v)<=256 for v in edge.values()), 'EDGE_STRING')
        circuit=edge['circuit']
        require(circuit in TRAIN, 'EDGE_TRAIN')
        source=SOURCE_RE.fullmatch(edge['source_candidate_uid'])
        action=ACTION_RE.fullmatch(edge['action_uid'])
        require(source is not None and action is not None, 'EDGE_UID')
        alias=source.group(2)
        scheme='HMF' if alias.startswith('hmf_') else 'HF'
        require(source.group(1)==circuit==action.group(1) and action.group(2)==scheme
                and source.group(3)==('H64-M16-F4' if scheme=='HMF' else 'H64-F4')
                and ((action.group(4) is None) if scheme=='HF' else action.group(4) is not None), 'EDGE_SCOPE_SCHEME')
        uid=edge['source_candidate_uid']
        require(uid not in owners or owners[uid]==edge['action_uid'], 'SOURCE_UID_ACTION_CONFLICT')
        owners[uid]=edge['action_uid']  # Exact duplicate triples collapse as old E39 runner.
    return owners


def summarize_configs(files,owners):
    records=[]
    uid_index={}
    file_indices=[]
    for item in files:
        indices=[]
        circuit,alias=item['circuit'],item['stage_alias']
        scheme='HMF' if alias.startswith('hmf_') else 'HF'
        mode='H64-M16-F4' if scheme=='HMF' else 'H64-F4'
        for source_row,candidate,h,m,origin in item['rows']:
            uid=':'.join((circuit,alias,mode,candidate))
            action=circuit+':'+scheme+':h'+str(int(h))
            if scheme=='HMF':action+=':m'+str(int(m))
            index=len(records)
            records.append((item,source_row,uid,action))
            uid_index.setdefault(uid,[]).append(index)
            indices.append(index)
        file_indices.append(indices)
    classes={key:0 for key in CLASSES}
    details={}
    matched=set()
    for uid,action in sorted(owners.items()):
        candidates=uid_index.get(uid,[])
        matches=[i for i in candidates if records[i][3]==action]
        kind=('UID_ABSENT' if not candidates else 'UID_PRESENT_NO_CONFIG_MATCH' if not matches
              else 'ONE_SCOPED_CONFIG_MATCH' if len(matches)==1 else 'MULTIPLE_SCOPED_CONFIG_MATCH')
        classes[kind]+=1
        matched.update(matches)
        locations={}
        for i in matches:
            item=records[i][0]
            key=(item['coverage_root'],item['path'],item['sha256'])
            locations[key]=locations.get(key,0)+1
        details[uid]=dict(classification=kind,matching_row_count=len(matches),matching_locations=[
            dict(coverage_root=root,path=path,source_sha256=digest,matching_row_count=count)
            for (root,path,digest),count in sorted(locations.items())])
    summaries=[dict(circuit=item['circuit'],stage_alias=item['stage_alias'],coverage_root=item['coverage_root'],
        path=item['path'],source_sha256=item['sha256'],provided_row_count=len(indices),
        matched_row_count=sum(i in matched for i in indices),unmatched_row_count=sum(i not in matched for i in indices))
        for item,indices in zip(files,file_indices)]
    return dict(file_count=len(files),scoped_configuration_row_count=len(records),
        mapping_source_uid_count=len(owners),edge_class_counts=classes,
        config_matched_scoped_row_count=len(matched),config_unmatched_scoped_row_count=len(records)-len(matched),
        files=summaries),details


def compare(projection,edges,bound24):
    files=sorted(validate_projection(projection),key=lambda item:(item['circuit'],item['coverage_root'],item['stage_alias']))
    paths=authenticated_paths(bound24,files)
    owners=owners_for(edges)
    formal_files=[item for item in files if item['path'] in paths]
    baseline,baseline_details=summarize_configs(files,owners)
    formal,formal_details=summarize_configs(formal_files,owners)
    changed=[]
    for uid,action in sorted(owners.items()):
        old,new=baseline_details[uid],formal_details[uid]
        if old['classification']!=new['classification'] or old['classification']=='MULTIPLE_SCOPED_CONFIG_MATCH':
            changed.append(dict(source_candidate_uid=uid,action_uid=action,baseline=old,formal=new))
    excluded=[item for item in files if item['path'] not in paths]
    return dict(status='PASS_FORMAL_FILE_CONFIG_COMPARISON_ONLY',baseline_all32=baseline,formal_authenticated24=formal,
        excluded_inventory_file_count=len(excluded),excluded_scoped_control_row_count=sum(len(item['rows']) for item in excluded),
        changed_or_previously_ambiguous_uid_count=len(changed),changed_or_previously_ambiguous_uids=changed[:MAX_CHANGED],
        uid_detail_limit=MAX_CHANGED,uid_detail_omitted_count=max(0,len(changed)-MAX_CHANGED),
        edge_triples_deduplicated=True,source_candidate_spelling_preserved=True,
        only_control_h_m_compared_as_integers=True,normalized_sha_used_for_authentication=False,
        all_control_rows_emitted=False,coverage_versions_merged=False,historical_edges_or_costs_discarded=False,
        source_measurements_opened=False,quality_or_runtime_values_accessed=False,
        invocation_identity_certified=False,historical_pre_outcome_freeze_certified=False,
        full_search_cost_certified=False,fit_targets_generated=False,training_release=False)


def unique_object(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'DUPLICATE_JSON_KEY')
        result[key]=value
    return result


def pinned_bytes(path,expected,limit):
    require(sha(expected),'PIN_REQUIRED')
    raw=stable_read(path,limit)
    require(hashlib.sha256(raw).hexdigest()==expected,'INPUT_SHA')
    return raw


def decode_json(raw):
    def reject(_):
        raise ValueError('NONSTANDARD_JSON_CONSTANT')
    return json.loads(raw.decode('ascii'),object_pairs_hook=unique_object,parse_constant=reject)


def main():
    try:
        require(len(sys.argv)==1,'FIXED_THREE_INPUTS_ONLY')
        blobs=[]
        total=0
        for path,digest,limit in INPUTS:
            raw=pinned_bytes(path,digest,min(limit,INPUT_LIMIT-total))
            blobs.append(raw)
            total+=len(raw)
            require(total<=INPUT_LIMIT,'TOTAL_INPUT_BOUND')
        bound,projection=decode_json(blobs[0]),decode_json(blobs[1])
        edges,edge_audit=parse_edges(blobs[2])
        result=compare(projection,edges,bound)
        result['input_audit']=dict(local_metadata_files_read=3,total_bytes=total,
            input_sha256=[digest for _,digest,_ in INPUTS],edge_rows=edge_audit,
            remote_calls=0,automatic_retries=0)
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
        require(len(raw.encode('ascii'))+1<=OUTPUT_LIMIT,'OUTPUT_BOUND')
        print(raw)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_FORMAL_CONFIG_COMPARISON","code":"PINNED_METADATA_REJECTED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
