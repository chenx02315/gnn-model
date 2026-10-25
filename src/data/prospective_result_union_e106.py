"""Bounded in-memory action artifact checks; no I/O, label release or launcher.

Reuses E81 text parsing and E93 mapping/class policy. Small output manifests can
be E86 output references; large MTFI bytes stay separate. Every source is supplied
by the caller, not authenticated by this function. Reported per-stage cycles are
not yet a qualified combined-pattern cycle count. No wall-time proxy is made.
"""
from . import prospective_acquisition_pilot_v1 as pilot
from . import prospective_acquisition_request_v1 as acquisition
from . import prospective_acquisition_binding_v1 as binding
from . import prospective_tessent_stage_v1 as reports
from . import prospective_fault_translation_v2 as faults

SCHEMA='prospective-result-union-e106-v1'
ARTIFACTS={'statistics','stil','driver_log','mtfi','pre_statistics'}
require=binding.require
sha=binding.sha
canonical=binding.canonical


def build_stage_reference(freeze,request,mapping_bytes,f_offset,artifacts):
    """Build an UNQUALIFIED opaque-byte reference before the next E86 slot.

    This hashes complete supplied bytes, not report validity, physical sources,
    exact E84 task admission, translation lineage, or real process completion.
    Only inspect_action performs the complete action/report/set checks below.
    """
    acquisition.validate_freeze(freeze)
    recipe=reports.compile_stage(freeze,request)
    require(type(mapping_bytes) is bytes and 0<len(mapping_bytes)<=faults.MAX_FILE,'MAPPING_BYTES_BOUND')
    require(type(f_offset) is int and -2048<=f_offset<=2048,'F_OFFSET')
    require(type(artifacts) is dict and set(artifacts)==ARTIFACTS,'ARTIFACT_KEYS')
    pins={};sizes={};total=len(mapping_bytes)
    for name,raw in artifacts.items():
        if name=='pre_statistics' and recipe['stage']=='H':
            require(raw is None,'H_NO_PRE_STATISTICS');pins[name]=None;sizes[name]=None;continue
        cap=faults.MAX_FILE if name=='mtfi' else 131072 if name=='stil' else 65536
        require(type(raw) is bytes and 0<len(raw)<=cap,'ARTIFACT_BYTES_BOUND_'+name)
        pins[name]=sha(raw);sizes[name]=len(raw);total+=len(raw)
    require(total<=faults.MAX_TOTAL,'STAGE_BYTES_BOUND')
    manifest=dict(schema=SCHEMA,qualification='UNQUALIFIED_BYTES_REFERENCE',
        freeze_sha256=freeze['freeze_sha256'],circuit=freeze['circuit'],
        run_uid=request['run_uid'],action_uid=request['action_uid'],
        task_uid=request['attempt_uid'],stage=request['stage'],
        parent_result_sha256=request['parent_result_sha256'],
        request_sha256=reports.digest(request),recipe_sha256=recipe['recipe_sha256'],
        mapping_sha256=sha(mapping_bytes),f_offset=f_offset,
        artifact_sha256=pins,artifact_bytes=sizes)
    raw=canonical(manifest)+b'\n'
    require(len(raw)<=binding.MAX_OUTPUT_BYTES,'REFERENCE_BOUND')
    return dict(output_reference_bytes=raw,output_reference_sha256=sha(raw),
                recipe=recipe,training_release=False,qualified=False)


def inspect_action(freeze,mapping_bytes,f_offset,rows):
    """Inspect exactly one complete HF/HMF caller-supplied successful chain.

Missing/failed chains are rejected, never dropped or classified infeasible;
the caller must retain their E105 lifecycle/paid-prefix rows separately.
"""
    acquisition.validate_freeze(freeze)
    require(type(mapping_bytes) is bytes and 0<len(mapping_bytes)<=faults.MAX_FILE,'MAPPING_BYTES_BOUND')
    require(type(f_offset) is int and -2048<=f_offset<=2048,'F_OFFSET')
    require(type(rows) is list and 2<=len(rows)<=3,'COMPLETE_ACTION_ROWS')
    require(all(type(row) is dict and set(row)=={'request','artifacts'} and
                type(row['request']) is dict for row in rows),'ROW_SCHEMA')
    action=rows[0]['request'].get('action_uid')
    roster={r['action_uid']:r for r in freeze['requested_roster']}
    require(type(action) is str and action in roster,'ACTION_ROSTER')
    modes=['H','F'] if roster[action]['scheme']=='HF' else ['H','M','F']
    require(len(rows)==len(modes),'COMPLETE_ACTION_ROWS')
    phase=next(p for p in pilot.build_plan()['phases'] if p['circuit']==freeze['circuit'])
    nodes=[n for n in phase['tasks'] if n['action_uid']==action and n['kind']=='TESSENT']
    require([n['stage'] for n in nodes]==modes,'PLAN_STAGE_ORDER')
    count=freeze['common_fault_count']
    require(count<=faults.MAX_COMMON,'COMMON_COUNT_BOUND')
    run_uid=rows[0]['request'].get('run_uid')
    union=set();previous=None;previous_detected=None;details=[];total_bytes=len(mapping_bytes)
    for row,node,mode in zip(rows,nodes,modes):
        request=row['request'];raws=row['artifacts']
        require(type(raws) is dict and set(raws)==ARTIFACTS,'ARTIFACT_KEYS')
        require(request.get('run_uid')==run_uid and request.get('action_uid')==action and
                request.get('attempt_uid')==node['task_uid'] and request.get('stage')==mode and
                type(request.get('stage_index')) is int and request['stage_index']==node['stage_index'] and
                request.get('control')==node['control'],'EXACT_FROZEN_TASK')
        require(request.get('parent_attempt_uid')==(None if previous is None else previous['attempt_uid']) and
                request.get('parent_result_sha256')==(None if previous is None else previous['output_reference_sha256']),
                'EXACT_PARENT_OUTPUT_REFERENCE')
        reference=build_stage_reference(freeze,request,mapping_bytes,f_offset,raws)
        recipe=reference['recipe']
        texts={}
        for name in sorted(ARTIFACTS):
            raw=raws[name]
            if name=='pre_statistics' and mode=='H':
                require(raw is None,'H_NO_PRE_STATISTICS');texts[name]=None;continue
            cap=faults.MAX_FILE if name=='mtfi' else 131072 if name=='stil' else 65536
            require(type(raw) is bytes and 0<len(raw)<=cap,'ARTIFACT_BYTES_BOUND_'+name)
            total_bytes+=len(raw)
            require(total_bytes<=faults.MAX_TOTAL,'ACTION_BYTES_BOUND')
            if name!='mtfi':
                try:texts[name]=raw.decode('utf-8')
                except UnicodeError as exc:raise ValueError('ARTIFACT_ENCODING_'+name) from exc
        parsed=reports.parse_reports(texts['statistics'],texts['stil'],texts['driver_log'],recipe,
            pre_statistics_text=texts['pre_statistics'],parent_detected_min=previous_detected)
        lookup,canonical_keys=faults.mapping_lookup(mapping_bytes,count,f_offset,mode,'H')
        observed=faults.parse_source_mtfi(raws['mtfi'],count,set(lookup))
        detected={lookup[key] for key,fault_class in observed}
        require(len(canonical_keys)==count and len(detected)==parsed['detected_common_faults'],
                'REPORT_AND_EXPLICIT_FAULT_SET_AGREEMENT')
        union.update(detected)
        previous=dict(attempt_uid=request['attempt_uid'],stage=mode,
            output_reference_sha256=reference['output_reference_sha256'],
            output_reference_bytes=reference['output_reference_bytes'],
            explicit_detected_count=len(detected),union_detected_count=len(union),
            generated_patterns=parsed['generated_patterns'],reported_stage_ate_cycles=parsed['ate_cycles'])
        details.append(previous)
        previous_detected=parsed['detected_common_faults']
    return dict(schema=SCHEMA,status='CALLER_BYTES_CHECKED_ONLY',circuit=freeze['circuit'],
        action_uid=action,run_uid=run_uid,freeze_sha256=freeze['freeze_sha256'],
        mapping_sha256=sha(mapping_bytes),common_count=count,stages=details,
        explicit_ds_di_union_count=len(union),sum_stage_detection_counts=sum(d['explicit_detected_count'] for d in details),
        meets_declared_d95_math=(100*len(union)>=95*count),
        sum_reported_stage_ate_cycles=sum(d['reported_stage_ate_cycles'] for d in details),
        combined_pattern_cycles_qualified=False,actual_atpg_wall_time_ns=None,
        complete_session_cost_qualified=False,physical_provenance_authenticated=False,
        translation_lineage_authenticated=False,process_attempt_join_authenticated=False,
        d95_verified=False,positive_training_label=None,training_release=False,
        execution_ready=False,processes_launched=0)
