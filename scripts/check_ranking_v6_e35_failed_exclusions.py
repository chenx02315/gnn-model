"""Focused failed-session exclusion facts, not eligibility or action repair.

Only the pinned local s38417 manifest and mixed exclusion metadata are read by
CLI. No original E35 audit is rerun or changed; no candidate/log/quality table
is read. Formal-stage membership is a string-enum fact, not qualification.
"""
from __future__ import print_function
from decimal import Decimal, localcontext
import json
import sys

_old_bytecode = sys.dont_write_bytecode
try:
    sys.dont_write_bytecode = True
    try:
        from scripts import audit_ranking_v6_e35_mapping_metadata as mapping
    except ImportError:
        import audit_ranking_v6_e35_mapping_metadata as mapping
finally:
    sys.dont_write_bytecode = _old_bytecode

MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_OUTPUT_BYTES = 8*1024*1024, 16*1024*1024, 64*1024
MAX_DETAILS = 64
FORMAL_STAGES = frozenset(('02_hf_coarse','03_hmf_coarse','04_integer_refine'))
LOCAL_SPECS = tuple(spec for spec in mapping.LOCAL_SPECS
                   if (spec['kind']=='manifest' and spec['circuit']=='s38417') or spec['kind']=='exclusions')


class ExclusionDiagnosticError(ValueError):
    pass


def _require(ok, code):
    if not ok:
        raise ExclusionDiagnosticError(code)


def diagnose(manifest, exclusions):
    """Exact target-attempt join; failures/timeouts retained, never reassigned."""
    _require(type(manifest) is list and type(exclusions) is list
             and len(manifest)+len(exclusions)<=mapping.MAX_ROWS,'TOTAL_ROW_CAP')
    manifests, _ = mapping._rows(manifest,mapping.reader.MANIFEST_FIELDS)
    exclusions, validation_filtered = mapping._rows(exclusions,mapping.EXCLUSION_FIELDS,mixed=True)
    _require(bool(manifests) and all(row['circuit']=='s38417' for row in manifests),'S38417_MANIFEST_ONLY')
    target, by_id = {}, {}
    for row in manifests:
        _require(row['attempt_id'] and row['attempt_id'] not in by_id,'DUPLICATE_MANIFEST_ATTEMPT')
        by_id[row['attempt_id']]=row
    other_train_filtered=0
    for row in exclusions:
        if row['circuit']!='s38417':
            other_train_filtered+=1
            continue
        _require(row['attempt_id'] not in target,'DUPLICATE_TARGET_EXCLUSION')
        target[row['attempt_id']]=row
    orphan_count=len(set(target)-set(by_id))
    unknown_classes=sum(row['attempt_outcome_class'] not in ('SUCCESS','FAILURE','TIMEOUT') for row in manifests)
    flagged=[row for row in manifests if row['attempt_outcome_class'] in ('FAILURE','TIMEOUT')]
    groups, details = {}, []
    missing=join_mismatches=unknown_reasons=0
    with localcontext() as context:
        context.prec=50
        total=Decimal(0)
        for row in sorted(flagged,key=lambda row:mapping._hash(row['attempt_id'])):
            _require(mapping.reader._WALL.match(row['wall_s']) is not None,'WALL_DECIMAL')
            elapsed=Decimal(row['wall_s'])
            _require(0<=elapsed<=Decimal('1e9'),'WALL_BOUND')
            _require(row['mode'] in ('H','M','F'),'MODE_ENUM')
            matched=target.get(row['attempt_id'])
            reason='MISSING_EXCLUSION' if matched is None else matched['exclusion_reason']
            if matched is None: missing+=1
            elif reason not in mapping._REASONS:
                reason='UNKNOWN_EXCLUSION_REASON'
                unknown_reasons+=1
            mismatch=bool(matched and (matched['stage']!=row['stage'] or matched['mode']!=row['mode']))
            join_mismatches+=mismatch
            group=groups.setdefault(reason,dict(count=0,wall=Decimal(0),failure_count=0,timeout_count=0))
            group['count']+=1
            group['wall']+=elapsed
            group['failure_count']+=row['attempt_outcome_class']=='FAILURE'
            group['timeout_count']+=row['attempt_outcome_class']=='TIMEOUT'
            total+=elapsed
            details.append(dict(attempt_id_sha256=mapping._hash(row['attempt_id']),
                retry_group_id_sha256=mapping._hash(row['retry_group_id']),
                source_log_identity_sha256=mapping._hash([row['source_log_path'],row['source_log_sha256']]),
                stage_sha256=mapping._hash(row['stage']),stage_is_formal=row['stage'] in FORMAL_STAGES,
                mode=row['mode'],declared_wall_s=str(elapsed),process_outcome_class=row['attempt_outcome_class'],
                exclusion_present=matched is not None,exclusion_reason=reason,
                exclusion_stage_mode_matches=not mismatch if matched else None))
        by_reason={reason:dict(count=group['count'],declared_wall_sum_s=str(group['wall']),
                              failure_count=group['failure_count'],timeout_count=group['timeout_count'])
                   for reason,group in sorted(groups.items())}
    omitted=max(0,len(details)-MAX_DETAILS)
    return dict(status=('PARTIAL_FAILED_EXCLUSION_DIAGNOSTIC' if missing or unknown_classes or join_mismatches
                        or unknown_reasons or orphan_count or omitted else 'PASS_FAILED_EXCLUSION_METADATA_FACTS_ONLY'),
        target_circuit='s38417',provided_manifest_count=len(manifests),failed_or_timeout_count=len(flagged),
        validation_exclusions_filtered=validation_filtered,other_train_exclusions_filtered=other_train_filtered,
        failed_timeout_declared_wall_sum_s=str(total),by_exclusion_reason=by_reason,
        missing_failed_exclusion_count=missing,unknown_process_class_count=unknown_classes,
        exclusion_stage_mode_mismatch_count=join_mismatches,unknown_exclusion_reason_count=unknown_reasons,
        orphan_target_exclusion_count=orphan_count,details=details[:MAX_DETAILS],omitted_detail_count=omitted,
        decimal_precision=50,formal_stage_is_eligibility_certificate=False,eligibility_inferred=False,
        sessions_reassigned=False,formal_action_edges_added=False,original_E35_result_changed=False,
        candidate_quality_accessed=False,source_logs_read=False,fit_targets_generated=False,
        live_A_attestation=False,snapshot_pins_only=True,real_training_release=False,remote_access=False)


def main():
    try:
        _require(len(sys.argv)==1,'CLI_ARGUMENTS_FORBIDDEN')
        limits=mapping.reader._limit_memory()
        tables,files,count={},[],0
        for spec in LOCAL_SPECS:
            raw=mapping.local_reader._stable_bytes(spec['path'],spec['sha256'],min(MAX_FILE_BYTES,MAX_TOTAL_BYTES-count))
            count+=len(raw)
            _require(count<=MAX_TOTAL_BYTES,'TOTAL_BYTE_CAP')
            if spec['kind']=='manifest':
                tables['manifest']=mapping.reader._parse(raw,'manifest','s38417',mapping.MAX_ROWS)
            else:
                tables['exclusions']=mapping._mixed_parse(raw,mapping.EXCLUSION_FIELDS)
            files.append(dict(kind=spec['kind'],sha256=spec['sha256'],bytes=len(raw)))
            del raw
        result=diagnose(tables['manifest'],tables['exclusions'])
        result.update(files=files,total_bytes=count,resource=dict(limits,**mapping.reader._usage()))
        encoded=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
        _require(len(encoded.encode('ascii'))<=MAX_OUTPUT_BYTES,'OUTPUT_BYTE_CAP')
        print(encoded)
        return 0
    except (ExclusionDiagnosticError,mapping.MappingAuditError,mapping.local_reader.DiagnosticError,mapping.reader.AuditError) as exc:
        print(json.dumps(dict(status='FAIL_CLOSED',code=str(exc)),sort_keys=True))
        return 2
    except Exception:
        print('{"code":"FAILED_EXCLUSION_DIAGNOSTIC_FAILURE","status":"FAIL_CLOSED"}')
        return 2


if __name__=='__main__': sys.exit(main())
