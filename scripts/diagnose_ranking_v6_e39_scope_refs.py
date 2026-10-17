"""Pure provided-reference scope counts, never source-origin assignment.

Only the two Phase2 circuits and both E38 roots are supported. Relative log
paths are interpreted by their first component only and are never opened.
Observed reference concentration is not a historical invocation certificate.
"""
import re
import sys

_old_bytecode=sys.dont_write_bytecode
try:
    sys.dont_write_bytecode=True
    try:
        from scripts import project_ranking_v6_e38_roster as projection_definitions
    except ImportError:
        import project_ranking_v6_e38_roster as projection_definitions
finally:
    sys.dont_write_bytecode=_old_bytecode

CIRCUITS=frozenset(('s35932','s38417'))
ROOTS={circuit:frozenset(root for name,root in projection_definitions.ROOTS if name==circuit)
       for circuit in CIRCUITS}
MAX_TARGETS=16
MAX_REFS=20000
TARGET_FIELDS=frozenset(('source_candidate_uid','circuit','candidate_scope_roots'))
EDGE_FIELDS=frozenset(('source_candidate_uid','circuit','mode','attempt_id'))
ATTEMPT_FIELDS=frozenset(('circuit','mode','attempt_id','stage','source_log_path'))
_UID=re.compile(r'([^:]+):(hf_coarse|hmf_coarse|hf_refine|hmf_refine):(H64-F4|H64-M16-F4):([0-9]{1,10})\Z')


class ScopeReferenceError(ValueError):
    pass


def _require(ok,code):
    if not ok: raise ScopeReferenceError('E39_REFS_'+code)


def _shape(row,fields):
    _require(type(row) is dict and all(type(key) is str for key in row)
             and set(row)==fields,'EXACT_METADATA_FIELDS')


def _string(value,maximum=256):
    _require(type(value) is str and 1<=len(value)<=maximum
             and all(32<=ord(char)<127 for char in value),'BOUNDED_ASCII_METADATA')


def _scope(row):
    path=row['source_log_path']
    _string(path,4096)
    _require(not path.startswith('/') and '\\' not in path and ':' not in path,'RELATIVE_LOG_PATH_ONLY')
    parts=path.split('/')
    _require(all(part not in ('','.','..') for part in parts),'LOG_PATH_COMPONENT')
    # No suffix search: known Phase2 metadata is coverage-leaf relative.
    prefix=parts[0]
    matching=[root for root in ROOTS[row['circuit']] if root.rsplit('/',1)[-1]==prefix]
    _require(len(matching)<=1,'AMBIGUOUS_ROOT_LEAF')
    return matching[0] if matching else None


def diagnose(targets,edges,attempts):
    """Count exact selected refs including outside/empty; never choose a version."""
    _require(type(targets) is list and 1<=len(targets)<=MAX_TARGETS,'TARGET_LIST_BOUND')
    _require(type(edges) is list and len(edges)<=MAX_REFS
             and type(attempts) is list and len(attempts)<=MAX_REFS,'REFERENCE_LIST_BOUND')
    target_map={}
    for row in targets:
        _shape(row,TARGET_FIELDS)
        _string(row['source_candidate_uid'])
        _string(row['circuit'])
        _require(row['circuit'] in CIRCUITS,'PHASE2_TARGET_CIRCUIT')
        match=_UID.match(row['source_candidate_uid'])
        _require(match is not None and match.group(1)==row['circuit']
                 and match.group(3)==('H64-M16-F4' if match.group(2).startswith('hmf_') else 'H64-F4'),
                 'SOURCE_UID_SCOPE_SCHEME')
        roots=row['candidate_scope_roots']
        _require(type(roots) is list and len(roots)==2
                 and all(type(root) is str and len(root)<=4096 for root in roots)
                 and len(set(roots))==2 and set(roots)==ROOTS[row['circuit']],'EXACT_TWO_PHASE2_ROOTS')
        uid=row['source_candidate_uid']
        _require(uid not in target_map,'DUPLICATE_TARGET_UID')
        target_map[uid]=dict(circuit=row['circuit'],roots=sorted(roots),
                             modes=('H','M','F') if match.group(2).startswith('hmf_') else ('H','F'))
    attempt_map={}
    for row in attempts:
        _shape(row,ATTEMPT_FIELDS)
        for key in ('circuit','mode','attempt_id','stage'): _string(row[key])
        _require(row['circuit'] in CIRCUITS and row['mode'] in ('H','M','F'),'ATTEMPT_CIRCUIT_MODE')
        _require(row['attempt_id'] not in attempt_map,'DUPLICATE_ATTEMPT_ID')
        attempt_map[row['attempt_id']]=dict(circuit=row['circuit'],mode=row['mode'],scope=_scope(row))
    refs={uid:[] for uid in target_map}
    pairs=set()
    for row in edges:
        _shape(row,EDGE_FIELDS)
        for value in row.values(): _string(value)
        uid=row['source_candidate_uid']
        _require(uid in target_map and row['attempt_id'] in attempt_map,'UNKNOWN_SOURCE_OR_ATTEMPT_REFERENCE')
        target,attempt=target_map[uid],attempt_map[row['attempt_id']]
        _require(row['circuit']==target['circuit']==attempt['circuit']
                 and row['mode']==attempt['mode'] and row['mode'] in target['modes'],'REFERENCE_CIRCUIT_MODE_JOIN')
        pair=(uid,row['attempt_id'])
        _require(pair not in pairs,'DUPLICATE_SOURCE_ATTEMPT_REFERENCE')
        pairs.add(pair)
        refs[uid].append(attempt)
    summaries=[]
    for uid,target in sorted(target_map.items()):
        root_counts={root:0 for root in target['roots']}
        modes={mode:dict(candidate_scope_counts={root:0 for root in target['roots']},outside_candidate_scopes_count=0)
               for mode in ('H','M','F')}
        outside=0
        for attempt in refs[uid]:
            root=attempt['scope']
            if root not in root_counts:
                outside+=1
                modes[attempt['mode']]['outside_candidate_scopes_count']+=1
            else:
                root_counts[root]+=1
                modes[attempt['mode']]['candidate_scope_counts'][root]+=1
        occupied=sum(count>0 for count in root_counts.values())
        classification=('NO_PROVIDED_REFERENCES' if not refs[uid] else 'OUTSIDE_CANDIDATE_SCOPES' if outside
                        else 'ALL_PROVIDED_REFERENCES_ONE_SCOPE_NOT_ORIGIN_CERT' if occupied==1
                        else 'PROVIDED_MULTI_SCOPE_REFERENCES')
        summaries.append(dict(source_candidate_uid=uid,circuit=target['circuit'],candidate_scope_roots=target['roots'],
            provided_unique_session_reference_count=len(refs[uid]),candidate_scope_reference_counts=root_counts,
            outside_candidate_scopes_reference_count=outside,mode_scope_reference_counts=modes,
            reference_classification=classification,zero_or_outside_references=not refs[uid] or bool(outside),
            source_origin_assigned=False))
    return dict(status='PARTIAL_SCOPE_OWNERSHIP_NOT_CERTIFIED',target_count=len(target_map),
        provided_edge_reference_count=len(edges),provided_attempt_metadata_count=len(attempts),targets=summaries,
        source_origin_assigned=False,reference_universe_authenticated=False,provenance_authenticated=False,
        invocation_identity_certified=False,version_selected=False,majority_scope_choice_applied=False,
        source_log_paths_followed=False,physical_files_read=False,costs_computed=False,quality_accessed=False,
        training_release=False,pre_outcome_certified=False)
