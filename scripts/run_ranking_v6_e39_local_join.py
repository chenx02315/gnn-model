"""Fixed local metadata-only scope join; no source measurements or remote I/O."""
import csv
import io
import json
import os
import sys

try:
    from scripts import diagnose_ranking_v6_e34_local_groups as stable_reader
    from scripts import audit_ranking_v6_e39_scope_join as scope_join
except ImportError:
    import diagnose_ranking_v6_e34_local_groups as stable_reader
    import audit_ranking_v6_e39_scope_join as scope_join

BASE=os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..',
                                 'runtime_training_staging_20260928'))
SPECS=(
    (os.path.join(BASE,'v6_e38_roster_projection_20261016_r1','stdout.log'),
     'a742707477aa39553fab8f3ee14c808494cccfaad3ef9a05a661a309ad8b52ed'),
    (os.path.join(BASE,'runtime_action_attempt_mapping_v1_r5','invocation_attempt_edges_v1.tsv'),
     'd5b25fdd934a18a352c286f572172ad8ba79fa064cf70dbe3f68e8e44e0fdfea'))
FIELDS=('action_uid','source_candidate_uid','circuit','stage','action_scheme',
        'h_patterns','m_patterns','mode','retry_group_id','retry_order','attempt_id','mapping_rule')
TRAIN=frozenset(('aes_core','s13207','s15850','s35932','s38417','spi'))
FILTER_ONLY=frozenset(('s5378','tv80'))


def main():
    try:
        if len(sys.argv)!=1:
            raise ValueError('NO_ARGUMENTS')
        blobs=[]
        total=0
        for path,digest in SPECS:
            data=stable_reader._stable_bytes(path,digest,10*1024*1024-total)
            total+=len(data)
            blobs.append(data)
        if len(blobs[0])>1024*1024:
            raise ValueError('PROJECTION_BOUND')
        projection=json.loads(blobs[0].decode('ascii'))
        table=csv.DictReader(io.StringIO(blobs[1].decode('utf-8')),delimiter='\t')
        if tuple(table.fieldnames or ())!=FIELDS:
            raise ValueError('EDGE_SCHEMA')
        rows=filtered=train_edges=0
        triples=set()
        for row in table:
            rows+=1
            if rows>100000 or set(row)!=set(FIELDS) or any(type(v) is not str or len(v)>65536 for v in row.values()):
                raise ValueError('EDGE_ROW_BOUND')
            circuit=row['circuit']
            if circuit in FILTER_ONLY:
                filtered+=1
                continue
            if circuit not in TRAIN:
                raise ValueError('TRAIN_SCOPE')
            train_edges+=1
            triples.add((row['source_candidate_uid'],row['action_uid'],circuit))
        edges=[dict(source_candidate_uid=s,action_uid=a,circuit=c) for s,a,c in sorted(triples)]
        result=scope_join.summarize(projection,edges)
        result['pure_join_function_performed_io']=result.pop('physical_files_read')
        result['local_metadata_files_read']=2
        result['fixed_local_input_audit']=dict(file_count=2,total_bytes=total,
            input_sha256=[digest for _,digest in SPECS],mixed_edge_rows=rows,
            validation_metadata_rows_filtered_before_join=filtered,
            train_session_edge_rows=train_edges,distinct_source_action_references=len(edges),
            source_measurements_opened=False,remote_calls=0,
            windows_address_space_cap_or_peak_claimed=False)
        encoded=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False)
        if len(encoded.encode('ascii'))>65536:
            raise ValueError('SUMMARY_BOUND')
        print(encoded)
        return 0
    except Exception:
        print('{"status":"FAIL_CLOSED_LOCAL_SCOPE_JOIN","code":"INPUT_OR_JOIN_REJECTED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
