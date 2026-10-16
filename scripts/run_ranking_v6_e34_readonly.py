"""Local bounded SSH transport for the fixed E34 metadata audit.

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

SOURCE = Path(__file__).with_name('audit_ranking_v6_train_metadata_e34.py')
LIMIT = 65536
TIMEOUT = 120
COMMAND = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'ConnectTimeout=8', 'vnc.buptic.top', '/usr/bin/python3 -I -S -B -']
CIRCUITS = {'aes_core', 's13207', 's15850', 's35932', 's38417', 'spi'}


def validate_response(raw):
    def reject_constant(value):
        raise ValueError('NONSTANDARD_JSON_CONSTANT')

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('DUPLICATE_JSON_KEY')
            result[key] = value
        return result

    try:
        result = json.loads(bytes(raw).decode('utf-8'), object_pairs_hook=unique_pairs,
                            parse_constant=reject_constant)
        return (type(result) is dict
                and result.get('status') in ('PASS_PINNED_TRAIN_METADATA_ONLY_AUDIT',
                                            'PARTIAL_PINNED_TRAIN_METADATA_AUDIT')
                and type(result.get('file_count')) is int and result['file_count'] == 12
                and type(result.get('files')) is list and len(result['files']) == 12
                and type(result.get('circuits')) is dict and set(result['circuits']) == CIRCUITS
                and result.get('real_training_release') is False
                and result.get('candidate_quality_accessed') is False
                and type(result.get('resource')) is dict
                and result['resource'].get('address_space_limit_imposed') is True
                and type(result['resource'].get('address_space_soft_bytes')) is int
                and 0 < result['resource']['address_space_soft_bytes'] <= 1073741824)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return False


def run(expected_sha, output):
    source = SOURCE.read_bytes()
    if len(source) > LIMIT or hashlib.sha256(source).hexdigest() != expected_sha:
        raise ValueError('REVIEWED_SOURCE_SHA_MISMATCH')
    output = Path(output).resolve()
    root = Path(__file__).resolve().parents[2] / 'runtime_training_staging_20260928'
    if output.parent != root or not output.name.startswith('v6_e34_train_metadata_'):
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
