"""One bounded E85 follow-up observation of actual input/environment identity."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/probe_acquisition_tree_inputs_e85.py'
TRANSPORT = ROOT / 'scripts/run_prospective_metadata_v1.py'
TRANSPORT_SHA = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
PHASE = ROOT.parent / 'runtime_training_staging_20260928/v6_e85_tree_inputs_20261023_r1'


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def main():
    if len(sys.argv) != 2 or re.fullmatch('[a-f0-9]{64}', sys.argv[1]) is None:
        raise ValueError('ONE_REVIEWED_READER_SHA_REQUIRED')
    source = SOURCE.read_bytes()
    if len(source) > 32768 or hashlib.sha256(source).hexdigest() != sys.argv[1]:
        raise ValueError('READER_CHANGED')
    if hashlib.sha256(TRANSPORT.read_bytes()).hexdigest() != TRANSPORT_SHA:
        raise ValueError('TRANSPORT_CHANGED')
    spec = importlib.util.spec_from_file_location('e85_bounded_transport', TRANSPORT)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    fingerprint = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    write_new(PHASE / 'start.json', encode(dict(
        schema='e85-tree-input-start-v1',
        basis='Continue current user-approved acquisition preparation plan with bounded read-only input checks',
        reader_sha256=sys.argv[1], transport_sha256=TRANSPORT_SHA,
        endpoint='vnc.buptic.top', expected_hostname='bupt-vncs2',
        host_fingerprint=fingerprint, sessions_max=1, automatic_retries=0,
        library_symlink_hops_max=4, tsdb_roots=6, tree_depth_max=8,
        global_tree_directories_max=128, global_tree_entries_max=1024,
        input_file_bytes_max=67108864, input_body_bytes_max=134217728,
        path_components_max=32, path_component_characters_max=512,
        fixed_system_reads=['/proc/meminfo', '/proc/self/cgroup'],
        system_read_bytes_max_each=4096, response_bytes_max=65536,
        helper_address_space_bytes=268435456, helper_cpu_seconds=20,
        ssh_timeout_seconds=60, executable_launches=0,
        remote_writes=0, actual_atpg_calls=0, training_runs=0)))
    result = helper.transport(helper.command('A'), source, 65536)
    write_new(PHASE / 'stdout.json', result['stdout'])
    write_new(PHASE / 'stderr.log', result['stderr'])
    record = {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
    record.update(stdout_bytes=len(result['stdout']), stderr_bytes=len(result['stderr']),
                  stdout_sha256=hashlib.sha256(result['stdout']).hexdigest(),
                  stderr_sha256=hashlib.sha256(result['stderr']).hexdigest())
    write_new(PHASE / 'transport.json', encode(record))
    if result['exit_code'] != 0 or any(result[key] for key in (
            'timeout', 'overflow', 'write_failed', 'threads_incomplete')):
        raise ValueError('OBSERVATION_FAILED_NO_AUTOMATIC_RETRY')
    value = json.loads(result['stdout'].decode('ascii'))
    if value.get('schema') != 'e85-acquisition-tree-input-probe-v1':
        raise ValueError('OBSERVATION_SCHEMA')
    if value.get('hostname') != 'bupt-vncs2':
        raise ValueError('OBSERVATION_HOST')
    print(json.dumps(dict(status=value['status'],
        body_bytes_hashed=value.get('body_bytes_hashed'),
        actual_atpg_calls=0, training_runs=0, execution_ready=False)))


if __name__ == '__main__':
    main()
