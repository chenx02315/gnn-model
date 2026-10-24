"""One approved, reviewed-source A scheduler-setup observation; no submission."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/probe_acceptance_lsf_e97.py'
TRANSPORT = ROOT / 'scripts/run_prospective_metadata_v1.py'
AUTH = ROOT / 'contracts/prospective_acceptance_authorization_e97_20261024.json'
AUTH_SHA = 'db9aa1bd63c7a3f7c9935ff4e99c2931041e59fb225b39e4338b06efd1619935'
TRANSPORT_SHA = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
PHASE = ROOT.parent / 'runtime_training_staging_20260928/v6_e97_lsf_setup_20261024_r1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def load_transport():
    if sha(TRANSPORT.read_bytes()) != TRANSPORT_SHA:
        raise ValueError('TRANSPORT_CHANGED')
    spec = importlib.util.spec_from_file_location('e97_pinned_transport', TRANSPORT)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def main():
    if len(sys.argv) != 2 or re.fullmatch('[0-9a-f]{64}', sys.argv[1]) is None:
        raise ValueError('REVIEWED_SOURCE_SHA_REQUIRED')
    source = SOURCE.read_bytes()
    if len(source) > 32768 or sha(source) != sys.argv[1]:
        raise ValueError('SOURCE_CHANGED')
    auth = AUTH.read_bytes()
    if sha(auth) != AUTH_SHA or json.loads(auth.decode('utf-8'))['user_authorization_received'] is not True:
        raise ValueError('AUTHORIZATION_CHANGED')
    helper = load_transport()
    fingerprint = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    write_new(PHASE / 'start.json', encode(dict(schema='e97-lsf-setup-start-v1',
        reader_sha256=sys.argv[1], transport_sha256=TRANSPORT_SHA,
        authorization_sha256=AUTH_SHA, host_fingerprint=fingerprint,
        sessions_max=1, automatic_retries=0, programs_launched=0,
        response_bytes_max=16384, config_body_bytes_max=262144,
        jobs_submitted=0, remote_writes=0, actual_atpg_calls=0)))
    result = helper.transport(helper.command('A'), source, 16384)
    write_new(PHASE / 'stdout.json', result['stdout'])
    write_new(PHASE / 'stderr.log', result['stderr'])
    receipt = {k: v for k, v in result.items() if k not in ('stdout', 'stderr')}
    receipt.update(stdout_bytes=len(result['stdout']), stderr_bytes=len(result['stderr']),
                   stdout_sha256=sha(result['stdout']), stderr_sha256=sha(result['stderr']))
    write_new(PHASE / 'transport.json', encode(receipt))
    if result['exit_code'] != 0 or any(result[k] for k in
            ('timeout', 'overflow', 'write_failed', 'threads_incomplete')):
        raise ValueError('OBSERVATION_FAILED_NO_RETRY')
    value = helper.decode(result['stdout'])
    if (value.get('schema') != 'acceptance_lsf_setup_e97_v1' or
            value.get('hostname') != 'bupt-vncs2' or
            value.get('execution_ready') is not False or
            value.get('jobs_submitted') != 0 or value.get('programs_launched') != 0):
        raise ValueError('HOST_OR_BOUNDARY')
    print(json.dumps(dict(status=value.get('status'), jobs_submitted=0,
                          actual_atpg_calls=0, training_runs=0)))


if __name__ == '__main__':
    main()
