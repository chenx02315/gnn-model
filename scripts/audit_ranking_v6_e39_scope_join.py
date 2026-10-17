"""Pure-memory scoped config equality, not a historical invocation certificate.

Source candidate spelling (including leading zeros) is retained in original
unscoped UIDs. Only H/M CONTROL representation is canonicalized through int
for action-config comparison, matching the historical metadata mapper. Every
coverage version and logical source row remains distinct, including duplicates.
"""
import json
import re
import sys

_old_bytecode=sys.dont_write_bytecode
try:
    sys.dont_write_bytecode=True
    try:
        from scripts import run_ranking_v6_e38_readonly as transport
        from scripts import project_ranking_v6_e38_roster as _projection_definitions
    except ImportError:
        import run_ranking_v6_e38_readonly as transport
        import project_ranking_v6_e38_roster as _projection_definitions
finally:
    sys.dont_write_bytecode=_old_bytecode

MAX_EDGES=100000
MAX_STRING=256
CIRCUITS=frozenset(('aes_core','s13207','s15850','s35932','s38417','spi'))
EDGE_FIELDS=frozenset(('source_candidate_uid','action_uid','circuit'))
_SOURCE=re.compile(r'([^:]+):(hf_coarse|hmf_coarse|hf_refine|hmf_refine):(H64-F4|H64-M16-F4):([0-9]{1,10})\Z')
_ACTION=re.compile(r'([^:]+):(HF|HMF):h(0|[1-9][0-9]{0,9})(?::m(0|[1-9][0-9]{0,9}))?\Z')
CLASSES=('UID_ABSENT','UID_PRESENT_NO_CONFIG_MATCH','ONE_SCOPED_CONFIG_MATCH','MULTIPLE_SCOPED_CONFIG_MATCH')


class ScopeJoinError(ValueError):
    pass


def _require(ok,code):
    if not ok: raise ScopeJoinError('E39_'+code)


def _projection(value):
    # Producer definitions are eagerly imported above: the transport validator's
    # own import is cached before any pure-function invocation, not a data read.
    _require(type(value) is dict,'PROJECTION_DICTIONARY')
    try:
        raw=json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('ascii')
    except (TypeError,ValueError,OverflowError,RecursionError):
        raise ScopeJoinError('E39_PROJECTION_JSON')
    _require(len(raw)<=transport.LIMIT and transport.validate_response(raw),'STRICT_E38_PROJECTION_REQUIRED')
    # Operate only on validated builtin JSON values, not caller object hooks.
    return json.loads(raw.decode('ascii'))


def summarize(projection,edges):
    """Return counts only; no file reads, source selection or version collapse.

    Matched-row counts include ALL scoped rows satisfying an edge's config,
    even for an ambiguous edge. They do not allocate cost or certify a unique
    invocation. Mapping-edge source units and scoped source rows are different
    grains, separately counted. No mapping references is explicitly PARTIAL.
    """
    projected=_projection(projection)
    _require(type(edges) is list and len(edges)<=MAX_EDGES,'EXACT_EDGE_LIST_OR_BOUND')
    owners={}
    for edge in edges:
        _require(type(edge) is dict and all(type(key) is str for key in edge)
                 and set(edge)==EDGE_FIELDS,'EXACT_EDGE_METADATA_FIELDS')
        _require(all(type(value) is str and len(value)<=MAX_STRING for value in edge.values()),'EDGE_STRING_BOUND')
        circuit=edge['circuit']
        _require(circuit in CIRCUITS,'TRAIN_CIRCUIT_ONLY')
        source=_SOURCE.match(edge['source_candidate_uid'])
        action=_ACTION.match(edge['action_uid'])
        _require(source is not None and action is not None,'CANONICAL_SOURCE_ACTION_UID')
        alias=source.group(2)
        scheme='HMF' if alias.startswith('hmf_') else 'HF'
        _require(source.group(1)==circuit==action.group(1) and action.group(2)==scheme
                 and source.group(3)==('H64-M16-F4' if scheme=='HMF' else 'H64-F4')
                 and ((action.group(4) is None) if scheme=='HF' else action.group(4) is not None),
                 'SOURCE_ACTION_SCOPE_SCHEME')
        uid=edge['source_candidate_uid']
        if uid in owners:
            _require(owners[uid]==edge['action_uid'],'SOURCE_MULTIPLE_ACTIONS')
            raise ScopeJoinError('E39_DUPLICATE_SOURCE_ACTION_EDGE')
        owners[uid]=edge['action_uid']
    records=[]
    uid_index={}
    scoped_identities={}
    origins={'explicit_candidate':0,'one_based_data_row':0}
    files=sorted(projected['files'],key=lambda item:(item['circuit'],item['coverage_root'],item['stage_alias']))
    file_indices=[]
    for item in files:
        indices=[]
        circuit,root,alias=item['circuit'],item['coverage_root'],item['stage_alias']
        scheme='HMF' if alias.startswith('hmf_') else 'HF'
        mode='H64-M16-F4' if scheme=='HMF' else 'H64-F4'
        for source_row,candidate,h,m,origin in item['rows']:
            source_uid=':'.join((circuit,alias,mode,candidate))
            action_uid=circuit+':'+scheme+':h'+str(int(h))
            if scheme=='HMF': action_uid+=':m'+str(int(m))
            scoped=(circuit,root,alias,candidate)
            index=len(records)
            # source_row is retained as part of each row record; the candidate
            # identity is NOT deduplicated even if repeated in the same file.
            records.append((scoped,source_row,source_uid,action_uid))
            indices.append(index)
            uid_index.setdefault(source_uid,[]).append(index)
            scoped_identities[scoped]=scoped_identities.get(scoped,0)+1
            origins[origin]+=1
        file_indices.append(indices)
    classes={name:0 for name in CLASSES}
    matched=set()
    for uid,action in sorted(owners.items()):
        candidates=uid_index.get(uid,[])
        matches=[index for index in candidates if records[index][3]==action]
        name=('UID_ABSENT' if not candidates else 'UID_PRESENT_NO_CONFIG_MATCH' if not matches
              else 'ONE_SCOPED_CONFIG_MATCH' if len(matches)==1 else 'MULTIPLE_SCOPED_CONFIG_MATCH')
        classes[name]+=1
        matched.update(matches)
    duplicate_identities=sum(count>1 for count in scoped_identities.values())
    duplicates_extra=sum(count-1 for count in scoped_identities.values())
    across_scope_collisions=sum(len({records[index][0] for index in indices})>1 for indices in uid_index.values())
    # Only file-level aggregate metadata are returned; never rows/UIDs,
    # candidate values, action configs, quality values or cost labels.
    summaries=[dict(circuit=item['circuit'],coverage_root=item['coverage_root'],stage_alias=item['stage_alias'],
                    source_sha256=item['sha256'],provided_row_count=len(indices),
                    config_equality_matched_row_count=sum(index in matched for index in indices),
                    config_equality_unmatched_row_count=sum(index not in matched for index in indices))
               for item,indices in zip(files,file_indices)]
    partial=(not owners or duplicate_identities or classes['UID_ABSENT']
             or classes['UID_PRESENT_NO_CONFIG_MATCH'] or classes['MULTIPLE_SCOPED_CONFIG_MATCH'])
    return dict(status='PARTIAL_SOURCE_SCOPE_JOIN' if partial else 'PASS_PROVIDED_CONFIG_JOIN_ONLY',
        provided_file_count=len(files),provided_coverage_root_count=projected['coverage_root_count'],
        provided_scoped_configuration_row_count=len(records),provided_unscoped_source_uid_count=len(uid_index),
        mapping_edge_source_unit_count=len(owners),edge_class_counts=classes,
        config_equality_matched_scoped_row_count=len(matched),
        config_equality_unmatched_scoped_row_count=len(records)-len(matched),
        unscoped_uid_collision_across_scopes_count=across_scope_collisions,
        unscoped_uid_multi_record_count=sum(len(indices)>1 for indices in uid_index.values()),
        duplicate_scoped_uid_identity_count=duplicate_identities,duplicate_scoped_row_excess_count=duplicates_extra,
        candidate_id_origin_counts=origins,files=summaries,no_mapping_references_supplied=not owners,
        scoped_rows_and_mapping_source_units_are_different_grains=True,
        matched_rows_include_all_ambiguous_config_matches=True,
        source_candidate_representation_preserved=True,control_H_M_only_semantic_integer_comparison=True,
        versions_merged=False,rows_deduplicated=False,per_row_outputs_emitted=False,
        provenance_certified=False,pre_outcome_certified=False,full_history_certified=False,
        inventory_origin_authenticated=False,invocation_certified=False,training_release=False,
        costs_computed=False,quality_values_accessed=False,fit_targets_generated=False,
        physical_files_read=False,online_claim=False)
