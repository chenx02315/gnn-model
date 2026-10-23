"""Bounded read-only real-input translation compatibility computation.

The controller appends one reviewed configuration and the exact reviewed core
source to this file.  This helper reads ten fixed files and computes four
in-memory candidates.  It never writes, scans directories, or launches tools.
"""
from __future__ import print_function

import hashlib
import json
import os
import re
import socket
import stat
import sys
import types

HOST = 'bupt-vncs2'
ROOT = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits'
CIRCUITS = ('aes_core', 'spi')
TARGETS = ('M', 'F')
MAX_FILE = 8 * 1024 * 1024
MAX_BODY = 32 * 1024 * 1024
MAX_OUTPUT = 16 * 1024
MAX_PAYLOAD = 65536
MAX_ADDRESS_SPACE = 256 * 1024 * 1024
MAX_CPU_SECONDS = 20
CHUNK = 65536
SHA_RE = re.compile(r'[0-9a-f]{64}\Z')
CORE_SHA256 = '2488abc20cf6e55aabb5d80317615645ed9bbaf80eb97d75f05920befd8b1961'


class ProbeError(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise ProbeError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def common_root(circuit):
    require(circuit in CIRCUITS, 'CIRCUIT_SCOPE')
    return (ROOT + '/' + circuit + '/03_fault_universe/common_' + circuit +
            '_m16_phase4_v2')


def source_mtfi_path(circuit):
    require(circuit in CIRCUITS, 'CIRCUIT_SCOPE')
    return (ROOT + '/' + circuit + '/04_single_mode/H_' + circuit +
            '_H_full_phase4_v2/faults.mtfi')


def file_paths(circuit):
    base = common_root(circuit)
    return {'manifest': base + '/manifest.json',
            'mapping': base + '/canonical_fault_mapping.tsv',
            'M_basic': base + '/M_common_initial_faults.basic',
            'F_basic': base + '/F_common_initial_faults.basic',
            'source_mtfi': source_mtfi_path(circuit)}


def allowed_paths():
    return {path for circuit in CIRCUITS
            for path in file_paths(circuit).values()}


def identity(info):
    core = (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns)
    return core + (info.st_ctime_ns,) if os.name == 'posix' else core


def require_capability():
    require(sys.platform.startswith('linux') and hasattr(os, 'O_NOFOLLOW') and
            hasattr(os, 'O_DIRECTORY') and os.open in os.supports_dir_fd and
            os.stat in os.supports_dir_fd and
            os.stat in os.supports_follow_symlinks, 'ANCHORED_IO_UNAVAILABLE')


class Budget(object):
    def __init__(self):
        self.body_bytes = 0
        self.files_read = 0


def read_file(path, budget):
    """Read one fixed regular single-link file through held directory FDs."""
    require(type(path) is str and path in allowed_paths(), 'EXACT_FILE_SCOPE')
    require_capability()
    require(path.startswith('/') and '\x00' not in path and len(path) <= 2048 and
            not any(part in ('', '.', '..') for part in path.split('/')[1:]),
            'FIXED_ABSOLUTE_PATH')
    parts = path.split('/')[1:]
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open('/', directory_flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=parent)
            os.close(parent)
            parent = child
        name = parts[-1]
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1,
                'NOT_SINGLE_LINK_REGULAR')
        require(0 < named.st_size <= MAX_FILE and
                budget.body_bytes + named.st_size <= MAX_BODY,
                'BODY_BYTE_BOUND')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                     getattr(os, 'O_NONBLOCK', 0), dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(identity(named) == identity(before), 'FILE_CHANGED_BEFORE_READ')
            left = before.st_size
            blocks = []
            hasher = hashlib.sha256()
            while left:
                block = os.read(fd, min(CHUNK, left))
                require(bool(block), 'SHORT_FILE_READ')
                blocks.append(block)
                hasher.update(block)
                budget.body_bytes += len(block)
                left -= len(block)
            after = os.fstat(fd)
            last = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(identity(before) == identity(after) == identity(last),
                    'FILE_CHANGED_DURING_READ')
            budget.files_read += 1
            return b''.join(blocks), {'sha256': hasher.hexdigest(),
                                      'bytes': before.st_size}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'DUPLICATE_JSON_KEY')
        value[key] = item
    return value


def parse_manifest(raw, circuit, pins):
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               ProbeError('NONFINITE_JSON')))
    except (UnicodeError, ValueError) as exc:
        raise ProbeError('MANIFEST_FORMAT') from exc
    require(type(value) is dict and
            value.get('schema') == 'multimode_common_fault_universe_v1' and
            value.get('fault_model') == 'stuck-at', 'MANIFEST_SCHEMA_MODEL')
    count = value.get('common_fault_count')
    offset = value.get('f_flat_instance_offset')
    require(type(count) is int and not isinstance(count, bool) and
            count == pins['common_count'] and 1 <= count <= 100000,
            'MANIFEST_COMMON_COUNT')
    require(type(offset) is int and not isinstance(offset, bool) and
            -2048 <= offset <= 2048, 'MANIFEST_F_OFFSET')
    mapping = value.get('mapping')
    require(type(mapping) is dict and
            mapping.get('path') == 'canonical_fault_mapping.tsv' and
            mapping.get('sha256') == pins['mapping'] and
            mapping.get('row_count_excluding_header') == count,
            'MANIFEST_MAPPING_BINDING')
    files = value.get('files')
    require(type(files) is dict, 'MANIFEST_FILES')
    for mode in TARGETS:
        item = files.get(mode)
        require(type(item) is dict and
                item.get('path') == mode + '_common_initial_faults.basic' and
                item.get('sha256') == pins[mode + '_basic'] and
                item.get('fault_count') == count,
                'MANIFEST_' + mode + '_BINDING')
    return count, offset


def validate_config(config):
    require(type(config) is dict and set(config) == {
        'schema', 'core_sha256', 'observations', 'circuits'}, 'CONFIG_SCHEMA')
    require(config['schema'] == 'e93-translation-input-binding-v1' and
            config['core_sha256'] == CORE_SHA256, 'CONFIG_CORE')
    require(type(config['observations']) is dict and
            set(config['observations']) == {'e88', 'e90'} and
            all(type(pin) is str and SHA_RE.fullmatch(pin) is not None
                for pin in config['observations'].values()), 'OBSERVATION_PINS')
    require(type(config['circuits']) is dict and
            set(config['circuits']) == set(CIRCUITS), 'CONFIG_CIRCUITS')
    required = {'common_count', 'manifest', 'mapping', 'M_basic', 'F_basic',
                'source_mtfi'}
    for circuit in CIRCUITS:
        pins = config['circuits'][circuit]
        require(type(pins) is dict and set(pins) == required and
                type(pins['common_count']) is int and
                not isinstance(pins['common_count'], bool) and
                all(type(pins[name]) is str and
                    SHA_RE.fullmatch(pins[name]) is not None
                    for name in required - {'common_count'}), 'CONFIG_INPUT_PINS')


def load_core(core_source):
    require(type(core_source) is bytes and 0 < len(core_source) <= 32768 and
            sha(core_source) == CORE_SHA256, 'CORE_SOURCE_PIN')
    module = types.ModuleType('_e93_reviewed_translation_core')
    code = compile(core_source.decode('utf-8'),
                   '<reviewed-prospective-fault-translation-v2>', 'exec')
    exec(code, module.__dict__)
    require(callable(getattr(module, 'translate', None)), 'CORE_API')
    return module


def enforce_limits():
    import resource
    for kind, ceiling in ((resource.RLIMIT_AS, MAX_ADDRESS_SPACE),
                          (resource.RLIMIT_CPU, MAX_CPU_SECONDS)):
        soft, hard = resource.getrlimit(kind)
        chosen = ceiling if soft == resource.RLIM_INFINITY else min(soft, ceiling)
        if hard != resource.RLIM_INFINITY:
            chosen = min(chosen, hard)
        resource.setrlimit(kind, (chosen, hard))


def collect(config, core_source):
    require(socket.gethostname() == HOST and sys.platform.startswith('linux'),
            'HOST_OR_PLATFORM_BEFORE_READS')
    enforce_limits()
    validate_config(config)
    core = load_core(core_source)
    budget = Budget()
    results = []
    input_files = []
    for circuit in CIRCUITS:
        pins = config['circuits'][circuit]
        raw = {}
        meta = {}
        for name, path in file_paths(circuit).items():
            raw[name], meta[name] = read_file(path, budget)
            require(meta[name]['sha256'] == pins[name],
                    'INPUT_SHA_MISMATCH_' + circuit + '_' + name)
            input_files.append({'circuit': circuit, 'role': name,
                                'sha256': meta[name]['sha256'],
                                'bytes': meta[name]['bytes']})
        count, offset = parse_manifest(raw['manifest'], circuit, pins)
        for target in TARGETS:
            expected = {'mapping': pins['mapping'],
                        'source_mtfi': pins['source_mtfi'],
                        'target_basic': pins[target + '_basic']}
            candidate = core.translate(raw['mapping'], raw['source_mtfi'],
                raw[target + '_basic'], 'H', target, count, offset, expected)
            results.append(dict(
                circuit=circuit, transition='H_TO_' + target,
                status='PASS_COMPUTED_COMPATIBILITY_ONLY',
                output_mtfi_sha256=candidate['output_mtfi_sha256'],
                manifest_sha256=candidate['manifest_sha256'],
                byte_counts={'mapping': meta['mapping']['bytes'],
                             'source_mtfi': meta['source_mtfi']['bytes'],
                             'target_basic': meta[target + '_basic']['bytes'],
                             'output_mtfi': len(candidate['output_mtfi_bytes']),
                             'manifest': len(candidate['manifest_bytes'])},
                input_sha256=expected))
    require(budget.files_read == 10 and len(results) == 4,
            'FIXED_READ_OR_RESULT_COUNT')
    return dict(schema='e93-real-input-translation-compatibility-v1',
                validation_role=('READ_ONLY_COMPUTED_COMPATIBILITY_NOT_TESSENT_'
                                 'ACCEPTANCE_ATPG_OR_PILOT_COST'),
                observation_sha256=config['observations'],
                files_read=budget.files_read, body_bytes=budget.body_bytes,
                input_files=input_files, results=results,
                actual_atpg_calls=0, training_runs=0, remote_writes=0,
                programs_launched=0, execution_ready=False,
                training_release=False)


def main(config, core_source):
    result = collect(config, core_source)
    encoded = canonical(result)
    require(len(encoded) + 1 <= MAX_OUTPUT, 'RESPONSE_BYTE_BOUND')
    sys.stdout.write(encoded.decode('ascii') + '\n')
    return 0

