"""Bounded A-side read-only common-fault semantics probe; Python 3.6.8.

Exactly ten fixed common-input files and one fixed launcher are read. No
directory scan, executable invocation, result file, graph, or TSDB access.
"""
from __future__ import print_function

import csv
import hashlib
import io
import json
import os
import re
import socket
import stat
import sys

HOST = 'bupt-vncs2'
ROOT = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A'
LAUNCHER = '/cad/mentor/tessent2021_2/bin/tessent'
LAUNCHER_SHA256 = 'd92e81eaacf0727fd18d4cafa67d7c9a066069c6d8f7fc05caaf1252c3e44905'
EXPECTED = {'aes_core': 71216, 'spi': 10418}
MODES = ('H', 'M', 'F')
NAMES = ('manifest.json', 'canonical_fault_mapping.tsv') + tuple(
    mode + '_common_initial_faults.basic' for mode in MODES)
MAX_FILE = 8 * 1024 * 1024
MAX_BODY = 32 * 1024 * 1024
CHUNK = 65536
MAX_OUTPUT = 32768
MAX_ADDRESS_SPACE = 256 * 1024 * 1024
MAX_CPU_SECONDS = 20
MAX_PATH = 1024
BASIC_RE = re.compile(r'^\s*([01])\s+(\S+)\s+(.+?)\s*$')
FLAT_INSTANCE_RE = re.compile(r'(?<=/)U(\d+)(?=/)')
SHA_RE = re.compile(r'[0-9a-f]{64}\Z')
MAPPING_COLUMNS = {'stuck_value', 'canonical_core_path'} | {
    mode + '_native_path' for mode in MODES}


class ProbeError(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise ProbeError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    core = (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns)
    return core + (info.st_ctime_ns,) if os.name == 'posix' else core


def root_for(circuit):
    require(circuit in EXPECTED, 'CIRCUIT_SCOPE')
    return (ROOT + '/10_circuits/' + circuit + '/03_fault_universe/common_' +
            circuit + '_m16_phase4_v2')


def allowed_paths():
    return {LAUNCHER} | {root_for(circuit) + '/' + name
                         for circuit in EXPECTED for name in NAMES}


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
    """Open all ancestors under held dir FDs; no path-based body open."""
    require(type(path) is str and path in allowed_paths(), 'FIXED_FILE_SCOPE')
    require_capability()
    require(type(path) is str and path.startswith('/') and '\x00' not in path and
            len(path) <= 2048 and not any(p in ('', '.', '..') for p in path.split('/')[1:]),
            'FIXED_ABSOLUTE_PATH')
    pieces = path.split('/')[1:]
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open('/', directory_flags)
    try:
        for piece in pieces[:-1]:
            child = os.open(piece, directory_flags, dir_fd=parent)
            os.close(parent)
            parent = child
        name = pieces[-1]
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
            remaining = before.st_size
            parts = []
            hasher = hashlib.sha256()
            while remaining:
                block = os.read(fd, min(CHUNK, remaining))
                require(bool(block), 'SHORT_FILE_READ')
                parts.append(block)
                hasher.update(block)
                budget.body_bytes += len(block)
                remaining -= len(block)
            after = os.fstat(fd)
            last_named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(identity(before) == identity(after) == identity(last_named),
                    'FILE_CHANGED_DURING_READ')
            budget.files_read += 1
            return b''.join(parts), {'sha256': hasher.hexdigest(), 'bytes': before.st_size}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def parse_manifest(raw, expected):
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_object_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               ProbeError('NONFINITE_JSON')))
    except (UnicodeError, ValueError) as exc:
        raise ProbeError('MANIFEST_FORMAT') from exc
    require(type(value) is dict and
            value.get('schema') == 'multimode_common_fault_universe_v1' and
            value.get('fault_model') == 'stuck-at', 'MANIFEST_SCHEMA_MODEL')
    offset = value.get('f_flat_instance_offset')
    require(type(offset) is int and -2048 <= offset <= 2048,
            'MANIFEST_F_OFFSET')
    require(type(value.get('common_fault_count')) is int and
            value['common_fault_count'] == expected, 'MANIFEST_COMMON_COUNT')
    mapping = value.get('mapping')
    require(type(mapping) is dict and
            mapping.get('path') == 'canonical_fault_mapping.tsv' and
            type(mapping.get('sha256')) is str and
            SHA_RE.fullmatch(mapping['sha256']) is not None and
            type(mapping.get('row_count_excluding_header')) is int and
            mapping['row_count_excluding_header'] == expected,
            'MANIFEST_MAPPING_BINDING')
    files = value.get('files')
    require(type(files) is dict and all(type(files.get(mode)) is dict and
            type(files[mode].get('fault_count')) is int and
            files[mode]['fault_count'] == expected and
            files[mode].get('path') == mode + '_common_initial_faults.basic' and
            type(files[mode].get('sha256')) is str and
            SHA_RE.fullmatch(files[mode]['sha256']) is not None
            for mode in MODES),
            'MANIFEST_MODE_COUNTS')
    return {'count': expected, 'offset': offset,
            'mapping_sha256': mapping['sha256'],
            'mode_sha256': {mode: files[mode]['sha256'] for mode in MODES}}


def _path(value, code):
    require(type(value) is str and 0 < len(value) <= MAX_PATH and
            value == value.strip() and not any(ch in value for ch in '\x00\r\n\t"'),
            code)
    return value


def shift_f(location, offset):
    return FLAT_INSTANCE_RE.sub(
        lambda match: 'U' + str(int(match.group(1)) + offset), location)


def parse_mapping(raw, expected, offset):
    try:
        stream = io.StringIO(raw.decode('utf-8'), newline='')
        reader = csv.DictReader(stream, delimiter='\t', strict=True)
        header = reader.fieldnames
        require(header is not None and len(MAPPING_COLUMNS) <= len(header) <= 16 and
                len(set(header)) == len(header) and
                MAPPING_COLUMNS.issubset(set(header)) and
                all(type(name) is str and 0 < len(name) <= 128 and
                    name == name.strip() and not any(ch in name for ch in '\x00\r\n\t')
                    for name in header), 'MAPPING_HEADER')
        canonical_keys = set()
        modes = {mode: set() for mode in MODES}
        count = 0
        for row in reader:
            count += 1
            require(count <= expected and None not in row and
                    all(type(row.get(key)) is str for key in header),
                    'MAPPING_ROW')
            stuck = row['stuck_value']
            require(stuck in ('0', '1'), 'MAPPING_STUCK')
            core_path = _path(row['canonical_core_path'], 'MAPPING_CORE_PATH')
            core = (stuck, core_path)
            require(core not in canonical_keys, 'MAPPING_DUPLICATE_CANONICAL')
            canonical_keys.add(core)
            for mode in MODES:
                key = (stuck, _path(row[mode + '_native_path'],
                                    'MAPPING_NATIVE_PATH'))
                if mode in ('H', 'M'):
                    require(key[1] == core_path,
                            'MAPPING_' + mode + '_CANONICAL')
                else:
                    require(shift_f(key[1], offset) == core_path,
                            'MAPPING_F_OFFSET_CANONICAL')
                require(key not in modes[mode], 'MAPPING_DUPLICATE_NATIVE')
                modes[mode].add(key)
        require(count == expected, 'MAPPING_COUNT')
        return modes
    except (UnicodeError, csv.Error) as exc:
        raise ProbeError('MAPPING_FORMAT') from exc


def parse_basic(raw, mode, expected):
    require(mode in MODES, 'BASIC_MODE')
    try:
        text = raw.decode('utf-8')
    except UnicodeError as exc:
        raise ProbeError('BASIC_FORMAT') from exc
    keys = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        match = BASIC_RE.match(line)
        require(match is not None, 'BASIC_LINE')
        stuck, fault_class, location = match.groups()
        _path(fault_class, 'BASIC_CLASS')
        location = location.strip()
        if location.startswith('"') or location.endswith('"'):
            require(len(location) >= 2 and location.startswith('"') and
                    location.endswith('"'), 'BASIC_QUOTE')
            location = location[1:-1]
        key = (stuck, _path(location, 'BASIC_PATH'))
        require(key not in keys, 'BASIC_DUPLICATE')
        keys.add(key)
        require(len(keys) <= expected, 'BASIC_COUNT')
    require(len(keys) == expected, 'BASIC_COUNT')
    return keys


def collect():
    result = dict(schema='e88-acquisition-semantics-probe-v1',
                  hostname=socket.gethostname(), status='PARTIAL',
                  python_version=list(sys.version_info[:3]),
                  roots=[], launcher={'sha256': None, 'pin_match': False},
                  body_bytes=0, files_read=0, file_scope=11,
                  directory_entries_enumerated=0, external_programs_launched=0,
                  remote_writes=0, actual_atpg_calls=0, training_runs=0,
                  fault_mapping_semantics_verified=False,
                  mapping_namespace_and_set_consistency_verified=False,
                  executable_version_verified=False, execution_ready=False,
                  training_release=False)
    if result['hostname'] != HOST or not sys.platform.startswith('linux'):
        result['reason'] = 'HOST_OR_PLATFORM_BEFORE_SOURCE_READ'
        return result
    try:
        enforce_limits()
    except (ImportError, OSError, ValueError) as exc:
        result['reason'] = 'SELF_LIMITS_BEFORE_SOURCE_READ_' + exc.__class__.__name__
        return result
    budget = Budget()
    try:
        raw, meta = read_file(LAUNCHER, budget)
        result['launcher'] = dict(sha256=meta['sha256'], bytes=meta['bytes'],
                                  pin_match=meta['sha256'] == LAUNCHER_SHA256)
        require(result['launcher']['pin_match'], 'LAUNCHER_PIN_MISMATCH')
        del raw
        for circuit in ('aes_core', 'spi'):
            root = root_for(circuit)
            item = dict(circuit=circuit, expected_common_count=EXPECTED[circuit],
                        files={}, mode_set_equal={})
            result['roots'].append(item)
            raw, meta = read_file(root + '/manifest.json', budget)
            item['files']['manifest.json'] = meta
            manifest = parse_manifest(raw, EXPECTED[circuit])
            del raw
            raw, meta = read_file(root + '/canonical_fault_mapping.tsv', budget)
            item['files']['canonical_fault_mapping.tsv'] = meta
            require(meta['sha256'] == manifest['mapping_sha256'],
                    'MANIFEST_MAPPING_SHA')
            mode_sets = parse_mapping(raw, manifest['count'], manifest['offset'])
            del raw
            for mode in MODES:
                name = mode + '_common_initial_faults.basic'
                raw, meta = read_file(root + '/' + name, budget)
                item['files'][name] = meta
                require(meta['sha256'] == manifest['mode_sha256'][mode],
                        'MANIFEST_' + mode + '_SHA')
                observed = parse_basic(raw, mode, manifest['count'])
                del raw
                require(observed == mode_sets.pop(mode), 'MODE_SET_MISMATCH_' + mode)
                item['mode_set_equal'][mode] = True
                del observed
            item['status'] = 'COMMON_INPUT_SETS_EQUAL'
        result['status'] = 'PASS_BOUNDED_NAMESPACE_SETS_AND_LAUNCHER_BODY_ONLY'
        result['mapping_namespace_and_set_consistency_verified'] = True
    except (OSError, ProbeError, MemoryError) as exc:
        result['reason'] = (str(exc)[:96] if isinstance(exc, ProbeError) else
                            exc.__class__.__name__)
    result['body_bytes'] = budget.body_bytes
    result['files_read'] = budget.files_read
    return result


def enforce_limits():
    import resource
    for kind, ceiling in ((resource.RLIMIT_AS, MAX_ADDRESS_SPACE),
                          (resource.RLIMIT_CPU, MAX_CPU_SECONDS)):
        soft, hard = resource.getrlimit(kind)
        chosen = ceiling if soft == resource.RLIM_INFINITY else min(soft, ceiling)
        if hard != resource.RLIM_INFINITY:
            chosen = min(chosen, hard)
        resource.setrlimit(kind, (chosen, hard))


def main():
    result = collect()
    raw = canonical(result)
    if len(raw) + 1 > MAX_OUTPUT:
        raw = canonical(dict(schema='e88-acquisition-semantics-probe-v1',
                             status='PARTIAL_OUTPUT_BOUND', execution_ready=False,
                             training_release=False, actual_atpg_calls=0))
    sys.stdout.write(raw.decode('ascii') + '\n')


if __name__ == '__main__':
    main()
