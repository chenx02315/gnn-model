"""Local bounded SSH transport for the fixed E37 metadata audit.

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

SOURCE = Path(__file__).with_name('probe_ranking_v6_e37_source_paths.py')
LIMIT = 65536
TIMEOUT = 120
COMMAND = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'ConnectTimeout=8', 'vnc.buptic.top', '/usr/bin/python3 -I -S -B -']
CIRCUITS = {'aes_core', 's13207', 's15850', 's35932', 's38417', 'spi'}


def validate_response(raw):
    try:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError('DUPLICATE_JSON_KEY')
                result[key] = value
            return result
        def reject(value):
            raise ValueError('NONSTANDARD_JSON_CONSTANT')
        result = json.loads(bytes(raw).decode('ascii'), object_pairs_hook=pairs, parse_constant=reject)
        try:
            from scripts.probe_ranking_v6_e37_source_paths import SPECS
        except ImportError:
            from probe_ranking_v6_e37_source_paths import SPECS
        expected = set(SPECS)
        if type(result) is not dict or result.get('status') not in ('PASS_PATH_STAT_ONLY','PARTIAL_PATH_STAT_ONLY'):
            return False
        if type(result.get('files')) is not int or result['files'] != 32 or type(result.get('roots')) is not int or result['roots'] != 8:
            return False
        rows = result.get('results')
        if type(rows) is not list or len(rows) != 32:
            return False
        seen = set()
        present = 0
        statuses = {'PRESENT_ORDINARY_SIZE_BOUNDED','MISSING','DENIED','UNSAFE_ANCESTOR',
                    'NOT_REGULAR_SINGLE_LINK','SOURCE_SIZE_BOUND','OS_ERROR'}
        for row in rows:
            if type(row) is not dict or row.get('status') not in statuses:
                return False
            key = tuple(row.get(k) for k in ('circuit','coverage_root','stage_alias','path'))
            if key not in expected or key in seen:
                return False
            seen.add(key)
            good = row['status'] == 'PRESENT_ORDINARY_SIZE_BOUNDED'
            fields = {'circuit','coverage_root','stage_alias','path','status'} | ({'size_bytes'} if good else set())
            if set(row) != fields:
                return False
            if good:
                if type(row['size_bytes']) is not int or not 0 < row['size_bytes'] <= 8*1024*1024:
                    return False
                present += 1
        if type(result.get('present_ordinary_size_bounded')) is not int or result['present_ordinary_size_bounded'] != present:
            return False
        if (result['status']=='PASS_PATH_STAT_ONLY') != (present==32):
            return False
        flags = {'source_file_contents_opened','quality_values_accessed','source_rows_projected',
                 'remote_task_files_written','source_hashes_verified','formal_builder_roots_certified',
                 'complete_roster_certified','training_release'}
        if any(result.get(k) is not False for k in flags):
            return False
        if set(result) != {'status','roots','files','present_ordinary_size_bounded','results','resource'} | flags:
            return False
        resource = result['resource']
        return (type(resource) is dict and set(resource)=={'address_space_limit_bytes','cpu_limit_s','workers'}
                and type(resource['address_space_limit_bytes']) is int and 0 < resource['address_space_limit_bytes'] <= 1073741824
                and type(resource['cpu_limit_s']) is int and 0 < resource['cpu_limit_s'] <= 20
                and type(resource['workers']) is int and resource['workers']==1)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return False

def run(expected_sha, output):
    source = SOURCE.read_bytes()
    if len(source) > LIMIT or hashlib.sha256(source).hexdigest() != expected_sha:
        raise ValueError('REVIEWED_SOURCE_SHA_MISMATCH')
    output = Path(output).resolve()
    root = Path(__file__).resolve().parents[2] / 'runtime_training_staging_20260928'
    if output.parent != root or not output.name.startswith('v6_e37_source_paths_'):
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
