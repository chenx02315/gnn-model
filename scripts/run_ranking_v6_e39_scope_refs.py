"""One fixed focused local metadata read for four ambiguous Phase2 sources."""
import csv
import io
import json
import os
import sys

try:
    from scripts import diagnose_ranking_v6_e34_local_groups as stable
    from scripts import audit_ranking_v6_e39_scope_join as join
    from scripts import diagnose_ranking_v6_e39_scope_refs as diagnostic
    from scripts import run_ranking_v6_e39_local_join as previous
except ImportError:
    import diagnose_ranking_v6_e34_local_groups as stable
    import audit_ranking_v6_e39_scope_join as join
    import diagnose_ranking_v6_e39_scope_refs as diagnostic
    import run_ranking_v6_e39_local_join as previous

MANIFESTS=(
    ('s35932','af7236dc484e2a5e3a489787f98ec1ae5963ec34fe625585cd59820c48b4db36'),
    ('s38417','30aea1c23bc6751c3b17e1e2e32ae36fc3cbd7934f03df22fb78df1f7c962300'))


def main():
    try:
        if len(sys.argv)!=1:
            raise ValueError('NO_DYNAMIC_PATHS')
        total=0
        def read(path,digest):
            nonlocal total
            value=stable._stable_bytes(path,digest,20*1024*1024-total)
            total+=len(value)
            return value
        projection=json.loads(read(*previous.SPECS[0]).decode('ascii'))
        edge_raw=read(*previous.SPECS[1])
        table=csv.DictReader(io.StringIO(edge_raw.decode('utf-8')),delimiter='\t')
        if tuple(table.fieldnames or ())!=previous.FIELDS:
            raise ValueError('EDGE_SCHEMA')
        edge_rows=[]
        filtered=0
        for index,row in enumerate(table,1):
            if index>100000 or set(row)!=set(previous.FIELDS) or any(type(v) is not str or len(v)>65536 for v in row.values()):
                raise ValueError('EDGE_BOUND')
            if row['circuit'] in previous.FILTER_ONLY:
                filtered+=1
                continue
            if row['circuit'] not in previous.TRAIN:
                raise ValueError('TRAIN_SCOPE')
            edge_rows.append(row)
        triples=sorted({(r['source_candidate_uid'],r['action_uid'],r['circuit']) for r in edge_rows})
        if len(triples)!=1780:
            raise ValueError('EXPECTED_MAPPING_SOURCE_UNITS')
        refs=[dict(source_candidate_uid=s,action_uid=a,circuit=c) for s,a,c in triples]
        validated=join.summarize(projection,refs)
        if validated['edge_class_counts']!=dict(UID_ABSENT=0,UID_PRESENT_NO_CONFIG_MATCH=0,
                ONE_SCOPED_CONFIG_MATCH=1776,MULTIPLE_SCOPED_CONFIG_MATCH=4):
            raise ValueError('EXPECTED_PRIOR_DIAGNOSTIC')
        lookup={}
        for item in projection['files']:
            c,alias,root=item['circuit'],item['stage_alias'],item['coverage_root']
            scheme='HMF' if alias.startswith('hmf_') else 'HF'
            mode='H64-M16-F4' if scheme=='HMF' else 'H64-F4'
            for ordinal,candidate,h,m,origin in item['rows']:
                uid=':'.join((c,alias,mode,candidate))
                action=c+':'+scheme+':h'+str(int(h))
                if scheme=='HMF': action+=':m'+str(int(m))
                lookup.setdefault((uid,action,c),[]).append(root)
        targets=[]
        for s,a,c in triples:
            roots=lookup.get((s,a,c),[])
            if len(roots)>1:
                if c not in ('s35932','s38417') or len(roots)!=2 or len(set(roots))!=2:
                    raise ValueError('FOCUSED_SCOPE')
                targets.append(dict(source_candidate_uid=s,circuit=c,candidate_scope_roots=sorted(roots)))
        if len(targets)!=4:
            raise ValueError('FOUR_TARGETS_REQUIRED')
        target_ids={t['source_candidate_uid'] for t in targets}
        selected=[{key:row[key] for key in ('source_candidate_uid','circuit','mode','attempt_id')}
                  for row in edge_rows if row['source_candidate_uid'] in target_ids]
        attempts=[]
        for circuit,digest in MANIFESTS:
            path=os.path.join(previous.BASE,'runtime_attempt_remediation_v2_r1_remote','outputs_v2',
                              circuit+'_attempt_manifest_v2_remediated.tsv')
            raw=read(path,digest)
            reader=csv.DictReader(io.StringIO(raw.decode('utf-8')),delimiter='\t')
            if tuple(reader.fieldnames or ())!=stable.reader.MANIFEST_FIELDS:
                raise ValueError('MANIFEST_SCHEMA')
            for index,row in enumerate(reader,1):
                if (index>20000 or set(row)!=set(stable.reader.MANIFEST_FIELDS)
                        or row['circuit']!=circuit or row['role']!='TRAIN'
                        or row['family']!=stable.reader.FAMILIES[circuit]):
                    raise ValueError('MANIFEST_BOUND_OR_CIRCUIT')
                item={key:row[key] for key in ('circuit','mode','attempt_id','stage','source_log_path')}
                if any(type(value) is not str or len(value)>65536 for value in item.values()):
                    raise ValueError('SELECTED_METADATA_BOUND')
                attempts.append(item)
        result=diagnostic.diagnose(targets,selected,attempts)
        result['pure_diagnostic_function_performed_io']=result.pop('physical_files_read')
        result['local_metadata_files_read']=4
        result['fixed_local_input_audit']=dict(file_count=4,total_bytes=total,metadata_sha256=
            [digest for _,digest in previous.SPECS]+[digest for _,digest in MANIFESTS],
            target_sources=4,target_reference_edges=len(selected),selected_manifest_rows=len(attempts),
            validation_metadata_rows_filtered_before_analysis=filtered,
            source_measurements_or_logs_opened=False,status_or_wall_analyzed=False,
            remote_calls=0,windows_hard_memory_cap_or_peak_claimed=False)
        encoded=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False)
        if len(encoded.encode('ascii'))>65536:
            raise ValueError('SUMMARY_BOUND')
        print(encoded)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_SCOPE_REFERENCE_DIAGNOSTIC","code":"INPUT_OR_DIAGNOSTIC_REJECTED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
