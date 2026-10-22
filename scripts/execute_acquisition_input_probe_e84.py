"""One fresh E84 input observation; old E70 execution quota is not reused.

Reuse only the reviewed host-key check and bounded SSH transport functions.
No E70 run(), phase journal, old approval receipt or file-read budget is invoked.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/probe_acquisition_inputs_e84.py'
TRANSPORT = ROOT / 'scripts/run_prospective_metadata_v1.py'
PHASE = ROOT.parent / 'runtime_training_staging_20260928/v6_e84_input_observation_20261023_r1'
TRANSPORT_SHA = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def main():
    if len(sys.argv) != 2 or re.fullmatch('[0-9a-f]{64}', sys.argv[1]) is None:
        raise ValueError('ONE_REVIEWED_READER_SHA_REQUIRED')
    raw = SOURCE.read_bytes()
    transport_raw = TRANSPORT.read_bytes()
    if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != sys.argv[1]:
        raise ValueError('REVIEWED_READER_CHANGED')
    if hashlib.sha256(transport_raw).hexdigest() != TRANSPORT_SHA:
        raise ValueError('TRANSPORT_SOURCE_CHANGED')
    spec = importlib.util.spec_from_file_location('e84_reused_transport', TRANSPORT)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    fingerprint = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    write_new(PHASE / 'start.json', encode(dict(
        schema='e84-input-observation-start-v1',
        basis='Current user instruction to start the preceding acquisition preparation plan',
        scope='Fresh E84 read-only input observation, not reuse of E70 quota',
        reader_sha256=sys.argv[1], transport_sha256=TRANSPORT_SHA,
        ssh_endpoint='vnc.buptic.top', expected_hostname='bupt-vncs2',
        host_fingerprint=fingerprint, sessions_max=1, fixed_paths=20,
        directories_enumerated_max=0, file_bytes_max=8388608,
        total_bytes_max=33554432, response_bytes_max=32768,
        helper_address_space_bytes=268435456, helper_cpu_seconds=15,
        local_ssh_timeout_seconds=60, automatic_retries=0,
        execution_ready=False, training_release=False)))
    result = helper.transport(helper.command('A'), raw, 32768)
    write_new(PHASE / 'stdout.json', result['stdout'])
    write_new(PHASE / 'stderr.log', result['stderr'])
    metadata = {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
    metadata.update(stdout_sha256=hashlib.sha256(result['stdout']).hexdigest(),
                    stderr_sha256=hashlib.sha256(result['stderr']).hexdigest(),
                    stdout_bytes=len(result['stdout']), stderr_bytes=len(result['stderr']))
    write_new(PHASE / 'transport.json', encode(metadata))
    if result['exit_code'] != 0 or any(result[key] for key in (
            'timeout', 'overflow', 'write_failed', 'threads_incomplete')):
        raise ValueError('OBSERVATION_TRANSPORT_FAILED_NO_RETRY')
    observation = json.loads(result['stdout'].decode('ascii'))
    if observation.get('hostname') != 'bupt-vncs2' or observation.get('schema') != 'e84-input-observation-v1':
        raise ValueError('OBSERVATION_IDENTITY_OR_SCHEMA')
    complete = observation['stat_path_count'] == 20
    print(json.dumps(dict(status=('READ_ONLY_INPUT_OBSERVATION_COMPLETE' if complete
                                 else 'READ_ONLY_INPUT_OBSERVATION_PARTIAL'),
        path_count=observation['stat_path_count'], bytes_read=observation['bytes_read'],
        actual_atpg_calls=0, training_runs=0, execution_ready=False)))


if __name__ == '__main__':
    main()
