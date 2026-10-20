"""One fixed E63 read; bounded SSH transport and strict metadata response gate."""
import hashlib
import importlib.util
import re
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

SOURCE = Path(__file__).with_name('hash_ranking_v6_e63_phase4_wrapper.py')
LIMIT = 16384
TIMEOUT = 60
COMMAND = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'ConnectTimeout=8', 'vnc.buptic.top', '/usr/bin/python3 -I -S -B -']


def validate_response(raw):
    """No unknown keys, altered scope/configs, extra rows or quality fields."""
    if type(raw) not in (bytes, bytearray) or not 0 < len(raw) <= LIMIT:
        return False
    try:
        def pairs(items):
            out = {}
            for key, value in items:
                if key in out: raise ValueError('DUPLICATE_JSON_KEY')
                out[key] = value
            return out
        def reject(value): raise ValueError('NONSTANDARD_JSON_CONSTANT')
        result = json.loads(bytes(raw).decode('ascii'), object_pairs_hook=pairs, parse_constant=reject)
        spec = importlib.util.spec_from_file_location('_ranking_v6_e63_payload', SOURCE)
        if spec is None or spec.loader is None: return False
        producer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(producer)
        return producer.validate_response(result)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return False


def run(expected_sha, output):
    if type(expected_sha) is not str or re.fullmatch('[a-f0-9]{64}', expected_sha) is None:
        raise ValueError('REVIEWED_SOURCE_SHA_SHAPE')
    source = SOURCE.read_bytes()
    if len(source) > LIMIT or hashlib.sha256(source).hexdigest() != expected_sha:
        raise ValueError('REVIEWED_SOURCE_SHA_MISMATCH')
    output = Path(output).resolve()
    root = Path(__file__).resolve().parents[2] / 'runtime_training_staging_20260928'
    if output.parent != root or not output.name.startswith('v6_e63_wrapper_identity_'):
        raise ValueError('LOCAL_RECEIPT_PATH_REJECTED')
    output.mkdir(exist_ok=False)
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
            if not chunk: return
            room = LIMIT - len(streams[name])
            streams[name].extend(chunk[:room])
            if len(chunk) > room:
                over.set()
                proc.kill()
                return

    readers = [threading.Thread(target=collect, args=(proc.stdout, 'stdout'), daemon=True),
               threading.Thread(target=collect, args=(proc.stderr, 'stderr'), daemon=True)]
    for reader in readers: reader.start()
    started = time.monotonic()
    write_failed = threading.Event()

    def send_source():
        try:
            proc.stdin.write(source)
            proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError): write_failed.set()

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
        for reader in readers: reader.join(timeout=2)
    if writer.is_alive() or any(reader.is_alive() for reader in readers): over.set()
    for name, data in streams.items(): (output / (name + '.log')).write_bytes(data)
    result = {'exit_code': proc.returncode, 'timeout': timed_out,
              'output_limit_exceeded': over.is_set(), 'stdin_write_failed': write_failed.is_set(),
              'remote_termination_verified': False,
              'elapsed_local_s': round(time.monotonic() - started, 3),
              'source_sha256': expected_sha,
              'stdout_sha256': hashlib.sha256(streams['stdout']).hexdigest(),
              'stderr_sha256': hashlib.sha256(streams['stderr']).hexdigest(),
              'transport_pass': proc.returncode == 0 and not timed_out and not over.is_set()
                                and not write_failed.is_set() and not streams['stderr']}
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
