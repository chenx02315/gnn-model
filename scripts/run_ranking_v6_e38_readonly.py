"""Local bounded SSH transport for the fixed E38 metadata audit.

No remote task files, retries, deployment, shell-expanded data paths, or
environment-dependent Python startup. Writes only one new local receipt dir.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

SOURCE = Path(__file__).with_name('project_ranking_v6_e38_roster.py')
LIMIT = 1048576
TIMEOUT = 120
COMMAND = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'ConnectTimeout=8', 'vnc.buptic.top', '/usr/bin/python3 -I -S -B -']
CIRCUITS = {'aes_core', 's13207', 's15850', 's35932', 's38417', 'spi'}


def validate_response(raw):
    try:
        import re
        def pairs(items):
            result={}
            for key,value in items:
                if key in result: raise ValueError('DUPLICATE_JSON_KEY')
                result[key]=value
            return result
        def reject(value): raise ValueError('NONSTANDARD_JSON_CONSTANT')
        result=json.loads(bytes(raw).decode('ascii'),object_pairs_hook=pairs,parse_constant=reject)
        try:
            from scripts.project_ranking_v6_e38_roster import SPECS, MAX_ROWS
        except ImportError:
            from project_ranking_v6_e38_roster import SPECS, MAX_ROWS
        false_flags={'nonselected_values_decoded','nonselected_values_captured','quality_evaluated',
            'PASS_or_eligibility_filter_applied','coverage_versions_merged','pre_outcome_certified',
            'formal_builder_roots_certified','training_release','E36_inventory_emitted',
            'physical_files_written','raw_source_tables_persisted'}
        expected_top={'status','files','file_count','coverage_root_count','total_bytes','total_rows',
            'source_identity_scope','source_file_bytes_read_for_sha_and_structure','resource'} | false_flags
        if type(result) is not dict or set(result)!=expected_top:
            return False
        if result['status']!='PASS_SELECTED_CONFIG_METADATA_PROJECTION_ONLY' or any(result[k] is not False for k in false_flags):
            return False
        if result['source_file_bytes_read_for_sha_and_structure'] is not True:
            return False
        if result['source_identity_scope']!='circuit+coverage_root+stage_alias+candidate_raw':
            return False
        if type(result['file_count']) is not int or result['file_count']!=32 or type(result['coverage_root_count']) is not int or result['coverage_root_count']!=8:
            return False
        files=result['files']
        if type(files) is not list or len(files)!=32:
            return False
        expected={(c,r,a,p):scheme for c,r,a,scheme,p in SPECS}
        seen=set()
        total_bytes=total_rows=0
        decimal=re.compile(r'[0-9]{1,10}')
        sha=re.compile(r'[0-9a-f]{64}')
        for item in files:
            if type(item) is not dict or set(item)!={'circuit','coverage_root','stage_alias','path','sha256','byte_count','header_sha256','rows'}:
                return False
            key=tuple(item[k] for k in ('circuit','coverage_root','stage_alias','path'))
            if key not in expected or key in seen:
                return False
            seen.add(key)
            if any(type(item[k]) is not str or sha.fullmatch(item[k]) is None for k in ('sha256','header_sha256')):
                return False
            n=item['byte_count']
            if type(n) is not int or not 0<n<=8*1024*1024:
                return False
            rows=item['rows']
            if type(rows) is not list or len(rows)>MAX_ROWS:
                return False
            for index,row in enumerate(rows,2):
                if type(row) is not list or len(row)!=5 or type(row[0]) is not int or row[0]!=index:
                    return False
                _,candidate,h,m,origin=row
                if any(type(x) is not str or len(x)>32 for x in (candidate,h,m,origin)):
                    return False
                if decimal.fullmatch(candidate) is None or decimal.fullmatch(h) is None:
                    return False
                if origin not in ('explicit_candidate','one_based_data_row'):
                    return False
                if origin=='one_based_data_row' and candidate!=str(index-1):
                    return False
                if expected[key]=='HMF':
                    if decimal.fullmatch(m) is None: return False
                elif m!='' and (decimal.fullmatch(m) is None or int(m)!=0):
                    return False
            total_bytes+=n
            total_rows+=len(rows)
        if total_bytes>40*1024*1024 or total_rows>MAX_ROWS:
            return False
        if type(result['total_bytes']) is not int or result['total_bytes']!=total_bytes or type(result['total_rows']) is not int or result['total_rows']!=total_rows:
            return False
        resource=result['resource']
        return (type(resource) is dict and set(resource)=={'address_space_limit_bytes','cpu_limit_s','workers'}
            and type(resource['address_space_limit_bytes']) is int and 0<resource['address_space_limit_bytes']<=1073741824
            and type(resource['cpu_limit_s']) is int and 0<resource['cpu_limit_s']<=20
            and type(resource['workers']) is int and resource['workers']==1)
    except (ValueError,TypeError,UnicodeError,RecursionError):
        return False

def run(expected_sha, output):
    source = SOURCE.read_bytes()
    if len(source) > LIMIT or hashlib.sha256(source).hexdigest() != expected_sha:
        raise ValueError('REVIEWED_SOURCE_SHA_MISMATCH')
    output = Path(output).resolve()
    root = Path(__file__).resolve().parents[2] / 'runtime_training_staging_20260928'
    if output.parent != root or not output.name.startswith('v6_e38_roster_projection_'):
        raise ValueError('LOCAL_RECEIPT_PATH_REJECTED')
    output.mkdir(exist_ok=False)
    # The new directory reserves this execution; any failure is retained, never retried.
    (output / 'request.json').write_text(json.dumps({
        'source_sha256': expected_sha, 'command': COMMAND, 'timeout_s': TIMEOUT,
        'stdout_limit_bytes': LIMIT, 'stderr_limit_bytes': LIMIT,
        'automatic_retries': 0}, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    over = threading.Event()
    proc = subprocess.Popen(COMMAND, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    def collect(stream, name):
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            room = LIMIT - len(streams[name])
            streams[name].extend(chunk[:room])
            if len(chunk) > room:
                over.set()
                proc.kill()
                return

    readers = [threading.Thread(target=collect, args=(proc.stdout, 'stdout'), daemon=True),
               threading.Thread(target=collect, args=(proc.stderr, 'stderr'), daemon=True)]
    for reader in readers:
        reader.start()
    started = time.monotonic()
    write_failed = threading.Event()

    def send_source():
        try:
            proc.stdin.write(source)
            proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            write_failed.set()

    writer = threading.Thread(target=send_source, daemon=True)
    writer.start()
    timed_out = False
    try:
        proc.wait(timeout=max(0.01, TIMEOUT - (time.monotonic() - started)))
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait(timeout=10)
    except (BrokenPipeError, OSError):
        proc.kill()
        proc.wait(timeout=10)
    finally:
        writer.join(timeout=2)
        for reader in readers:
            reader.join(timeout=2)
    if writer.is_alive() or any(reader.is_alive() for reader in readers):
        over.set()
    for name, data in streams.items():
        (output / (name + '.log')).write_bytes(data)
    result = {'exit_code': proc.returncode, 'timeout': timed_out,
              'output_limit_exceeded': over.is_set(),
              'stdin_write_failed': write_failed.is_set(),
              'remote_termination_verified': False,
              'elapsed_local_s': round(time.monotonic() - started, 3),
              'source_sha256': expected_sha,
              'stdout_sha256': hashlib.sha256(streams['stdout']).hexdigest(),
              'stderr_sha256': hashlib.sha256(streams['stderr']).hexdigest(),
              'transport_pass': proc.returncode == 0 and not timed_out and not over.is_set()
                                and not write_failed.is_set()
                                and not streams['stderr']}
    result['audit_response_valid'] = validate_response(streams['stdout'])
    result['accepted_metadata_receipt'] = result['transport_pass'] and result['audit_response_valid']
    (output / 'transport.json').write_text(json.dumps(result, sort_keys=True, indent=2)
                                         + '\n', encoding='utf-8')
    print(json.dumps(result, sort_keys=True))
    return 0 if result['accepted_metadata_receipt'] else 2


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('expected reviewed source SHA and new local receipt directory')
    raise SystemExit(run(sys.argv[1], sys.argv[2]))
