"""One versioned read-only A capability observation, not Tessent execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/probe_tessent_resource_capability_e94.py'
TRANSPORT = ROOT / 'scripts/run_prospective_metadata_v1.py'
TRANSPORT_SHA = 'e0b1e62352781f96dc7d0e5a2a1a27e7f278b63c8aaaa07dbd946c1795c0f434'
PHASE = ROOT.parent / 'runtime_training_staging_20260928/v6_e94_resource_capability_20261023_r1'
CAP = 16384
ROOTS = {'/sys/fs/cgroup', '/sys/fs/cgroup/memory', '/sys/fs/cgroup/freezer',
         '/sys/fs/cgroup/pids'}


def exact(value, keys, reason):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError(reason)


def digest_valid(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def capability_fields(value):
    if type(value['uid']) is not int or not 0 <= value['uid'] <= 2**32 - 1:
        raise ValueError('UID')
    rows = value['memberships']
    if type(rows) is not list or not 0 < len(rows) <= 64:
        raise ValueError('MEMBERSHIP_COUNT')
    seen = set()
    for row in rows:
        exact(row, ('hierarchy', 'controllers', 'relative_path_sha256',
                    'at_hierarchy_root'), 'MEMBERSHIP_KEYS')
        number = row['hierarchy']; names = row['controllers']
        if (type(number) is not int or not 0 <= number <= 2**31 - 1 or
                number in seen or type(names) is not list or len(names) > 64 or
                any(type(x) is not str or re.fullmatch(r'[A-Za-z0-9_=.-]{1,64}', x)
                    is None for x in names) or len(set(names)) != len(names) or
                not digest_valid(row['relative_path_sha256']) or
                type(row['at_hierarchy_root']) is not bool):
            raise ValueError('MEMBERSHIP_FIELDS')
        seen.add(number)
    rows = value['mounts']
    if type(rows) is not list or len(rows) > 64:
        raise ValueError('MOUNT_COUNT')
    controllers = {'memory', 'freezer', 'pids', 'cpu', 'cpuacct', 'cpuset',
                   'devices', 'blkio'}
    for row in rows:
        exact(row, ('version', 'conventional_mount', 'mount_path_sha256',
                    'mount_read_only', 'controllers'), 'MOUNT_KEYS')
        names = row['controllers']; point = row['conventional_mount']
        if (type(row['version']) is not int or row['version'] not in (1, 2) or
                not (point is None or type(point) is str and point in ROOTS) or
                not digest_valid(row['mount_path_sha256']) or
                type(row['mount_read_only']) is not bool or type(names) is not list or
                any(type(x) is not str or x not in controllers for x in names) or
                len(set(names)) != len(names)):
            raise ValueError('MOUNT_FIELDS')
    enabled = value['controller_enabled']
    exact(enabled, ('memory', 'freezer', 'pids'), 'CONTROLLER_KEYS')
    if any(x is not None and type(x) is not bool for x in enabled.values()):
        raise ValueError('CONTROLLER_FIELDS')
    rows = value['root_metadata']
    if type(rows) is not list or len(rows) != 4:
        raise ValueError('ROOT_COUNT')
    seen = set()
    for row in rows:
        exact(row, ('path', 'exists', 'is_directory_not_symlink',
                    'write_access_hint', 'owner_uid', 'mode'), 'ROOT_KEYS')
        point = row['path']
        if type(point) is not str or point not in ROOTS or point in seen:
            raise ValueError('ROOT_SET')
        seen.add(point)
        if any(type(row[k]) is not bool for k in
               ('exists', 'is_directory_not_symlink', 'write_access_hint')):
            raise ValueError('ROOT_BOOLEAN')
        if row['exists']:
            if (type(row['owner_uid']) is not int or
                    not 0 <= row['owner_uid'] <= 2**32 - 1 or
                    type(row['mode']) is not int or not 0 <= row['mode'] <= 4095):
                raise ValueError('ROOT_STAT')
        elif (row['owner_uid'] is not None or row['mode'] is not None or
              row['is_directory_not_symlink'] or row['write_access_hint']):
            raise ValueError('ABSENT_ROOT')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def validate(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError('DUPLICATE_JSON_KEY')
            result[k] = v
        return result
    value = json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE')))
    exact(value, ('schema', 'status', 'hostname', 'uid', 'files_read',
        'body_bytes', 'input_metadata', 'memberships', 'mounts',
        'controller_enabled', 'root_metadata', 'helper_address_space_bytes',
        'helper_cpu_seconds', 'guard_installed', 'limit_write_tested',
        'group_kill_tested', 'actual_atpg_memory_limit_bytes',
        'actual_atpg_timeout_s', 'directory_scans', 'external_programs_launched',
        'remote_writes', 'actual_atpg_calls', 'training_runs', 'execution_ready',
        'training_release'), 'EXACT_OBSERVATION_KEYS')
    if (type(value) is not dict or
            value.get('schema') != 'e94-tessent-resource-capability-v1' or
            value.get('status') != 'OBSERVED_CAPABILITY_HINTS_NOT_RESOURCE_ADMISSION' or
            value.get('hostname') != 'bupt-vncs2' or value.get('files_read') != 4 or
            type(value.get('body_bytes')) is not int or
            not 0 < value['body_bytes'] <= 524288):
        raise ValueError('OBSERVATION_SCHEMA_OR_BOUND')
    for name in ('guard_installed', 'limit_write_tested', 'group_kill_tested',
                 'execution_ready', 'training_release'):
        if value.get(name) is not False:
            raise ValueError('UNSUPPORTED_RELEASE_CLAIM')
    for name in ('directory_scans', 'external_programs_launched', 'remote_writes',
                 'actual_atpg_calls', 'training_runs'):
        if type(value.get(name)) is not int or value[name] != 0:
            raise ValueError('FORBIDDEN_MUTATION')
    if (value.get('actual_atpg_memory_limit_bytes') is not None or
            value.get('actual_atpg_timeout_s') is not None or
            value.get('helper_address_space_bytes') != 134217728 or
            value.get('helper_cpu_seconds') != 5):
        raise ValueError('RESOURCE_ROLE')
    rows = value.get('input_metadata')
    paths = {'/proc/self/cgroup', '/proc/self/mountinfo', '/proc/cgroups', '/proc/self/limits'}
    if (type(rows) is not list or len(rows) != 4 or
            {x.get('path') for x in rows if type(x) is dict} != paths):
        raise ValueError('FIXED_PROC_SCOPE')
    for row in rows:
        if (set(row) != {'path', 'bytes', 'sha256'} or
                type(row['bytes']) is not int or not 0 < row['bytes'] <= 131072 or
                not digest_valid(row['sha256'])):
            raise ValueError('FILE_METADATA')
    if sum(x['bytes'] for x in rows) != value['body_bytes']:
        raise ValueError('BODY_ACCOUNTING')
    if len(raw) > CAP:
        raise ValueError('RESPONSE_BOUND')
    capability_fields(value)
    return value


def main():
    if len(sys.argv) != 2 or re.fullmatch('[0-9a-f]{64}', sys.argv[1]) is None:
        raise ValueError('REVIEWED_READER_SHA_REQUIRED')
    source = SOURCE.read_bytes()
    if len(source) > 32768 or sha(source) != sys.argv[1]:
        raise ValueError('READER_CHANGED')
    if sha(TRANSPORT.read_bytes()) != TRANSPORT_SHA:
        raise ValueError('TRANSPORT_CHANGED')
    spec = importlib.util.spec_from_file_location('e94_pinned_transport', TRANSPORT)
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    fingerprint = helper.verify_cached_host('A')
    PHASE.mkdir(exist_ok=False)
    write_new(PHASE / 'start.json', encode({
        'schema': 'e94-capability-start-v1', 'reader_sha256': sys.argv[1],
        'transport_sha256': TRANSPORT_SHA, 'host_fingerprint': fingerprint,
        'sessions_max': 1, 'automatic_retries': 0,
        'fixed_proc_files': 4, 'fixed_root_metadata_paths': 4,
        'per_file_bytes_max': 131072, 'total_bytes_max': 524288,
        'response_bytes_max': CAP, 'helper_address_space_bytes': 134217728,
        'helper_cpu_seconds': 5, 'transport_seconds': 60,
        'remote_writes': 0, 'external_programs_launched': 0,
        'actual_atpg_calls': 0, 'training_runs': 0,
        'role': 'PARTIAL_CAPABILITY_HINTS_NOT_GUARD_INSTALLATION_OR_TESSENT_ADMISSION'}))
    result = helper.transport(helper.command('A'), source, CAP)
    write_new(PHASE / 'stdout.json', result['stdout'])
    write_new(PHASE / 'stderr.log', result['stderr'])
    receipt = {k: v for k, v in result.items() if k not in ('stdout', 'stderr')}
    receipt.update(stdout_bytes=len(result['stdout']), stderr_bytes=len(result['stderr']),
        stdout_sha256=sha(result['stdout']), stderr_sha256=sha(result['stderr']))
    write_new(PHASE / 'transport.json', encode(receipt))
    if (result['exit_code'] != 0 or result['stderr'] or any(result[k] for k in
            ('timeout', 'overflow', 'write_failed', 'threads_incomplete'))):
        raise ValueError('OBSERVATION_FAILED_NO_AUTOMATIC_RETRY')
    value = validate(result['stdout'])
    print(json.dumps({'status': value['status'], 'execution_ready': False,
                      'training_release': False}, sort_keys=True))


if __name__ == '__main__':
    main()
