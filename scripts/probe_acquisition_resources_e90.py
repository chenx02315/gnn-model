"""Read six fixed TRAIN files; export grammar/RSS metadata, never labels.

Historical RSS observations are not limits or reservations. No program launch,
remote write, directory scan, fault row or candidate metric is exported.
"""
import hashlib
import json
import os
import re
import socket
import stat
import sys

HOST = 'bupt-vncs2'
ROOT = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits'
COUNTS = {'aes_core': 71216, 'spi': 10418}
MAX_FILE = 8 * 1024 * 1024
MAX_BODY = 32 * 1024 * 1024
MAX_OUTPUT = 16384
FAULT = re.compile(r'^\s*([01])\s*,\s*([^,]+?)\s*,\s*"([^"\r\n]+)";\s*$')
COMPACT_RSS = re.compile(r'(?<![0-9])([0-9]{1,15})maxresident(?=\s|$)')
VERBOSE_RSS = re.compile(r'^\s*Maximum resident set size \(kbytes\):\s*([0-9]{1,15})\s*$', re.M)
E89_HEADER = ('FaultInformation {\n version : 1;\n FaultType (Stuck) {\n'
              '  FaultList {\n   FaultCollapsing : FALSE;\n'
              '   Format : Identifier, Class, Location;\n   Instance ("") {\n').encode('ascii')
E89_FOOTER = b'   }\n  }\n }\n}\n'


class ProbeError(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise ProbeError(reason)


def specs():
    result = []
    for circuit in ('aes_core', 'spi'):
        base = ROOT + '/' + circuit
        result.append((circuit, 'MTFI_H', base +
            '/04_single_mode/H_' + circuit + '_H_full_phase4_v2/faults.mtfi'))
        for mode in ('H', 'F'):
            result.append((circuit, 'RESOURCE_' + mode, base + '/logs/' +
                mode + '_' + circuit + '_' + mode + '_full_phase4_v2.driver.log'))
    return result


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, budget):
    require(path in {item[2] for item in specs()}, 'EXACT_FILE_SCOPE')
    require(sys.platform.startswith('linux') and hasattr(os, 'O_NOFOLLOW') and
            hasattr(os, 'O_DIRECTORY') and os.open in os.supports_dir_fd and
            os.stat in os.supports_dir_fd and os.stat in os.supports_follow_symlinks,
            'ANCHORED_IO_UNAVAILABLE')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open('/', flags)
    try:
        parts = path.split('/')[1:]
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        first = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and
                0 < first.st_size <= MAX_FILE and
                budget[0] + first.st_size <= MAX_BODY, 'REGULAR_OR_BYTE_BOUND')
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        try:
            require(identity(os.fstat(fd)) == identity(first), 'FILE_CHANGED')
            chunks = []
            left = first.st_size
            while left:
                block = os.read(fd, min(left, 65536))
                require(bool(block), 'SHORT_READ')
                chunks.append(block)
                budget[0] += len(block)
                left -= len(block)
            require(identity(os.fstat(fd)) == identity(first) ==
                    identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)),
                    'FILE_CHANGED')
            return b''.join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def mtfi_projection(raw, expected):
    text = raw.decode('utf-8', errors='strict')
    rows = 0
    bad_fault_lines = 0
    class_spellings = set()
    envelope = []
    for line in text.splitlines():
        match = FAULT.fullmatch(line)
        if match:
            rows += 1
            label = match.group(2).strip()
            require(len(label) <= 32 and re.fullmatch(r'[A-Z][A-Za-z0-9_.:]*', label),
                    'UNSUPPORTED_CLASS_SPELLING')
            class_spellings.add(label)
            require(len(class_spellings) <= 32, 'CLASS_DIALECT_BOUND')
            continue
        stripped = line.strip()
        if re.match(r'^[01]\s*,', stripped):
            bad_fault_lines += 1
        if stripped and not stripped.startswith('//'):
            envelope.append(re.sub(r'\s+', '', stripped))
    joined = ''.join(envelope)
    canonical = ('FaultInformation{version:1;FaultType(Stuck){FaultList{'
                 'FaultCollapsing:FALSE;Format:Identifier,Class,Location;Instance(""){}}}}')
    return dict(fault_rows=rows, expected_rows=expected,
                fault_row_count_matches=rows == expected,
                malformed_fault_line_count=bad_fault_lines,
                standard_envelope_matches=joined == canonical,
                exact_e89_envelope_matches=raw.startswith(E89_HEADER) and raw.endswith(E89_FOOTER),
                e89_line_endings_compatible=b'\r' not in raw and b'\x00' not in raw and raw.endswith(b'\n'),
                provisional_e89_classes_compatible=all(label in
                    ('DS','DI','FU','PT','UU','TI','AU','UC','UO') or
                    re.fullmatch(r'DI_[1-9][0-9]?', label) is not None
                    for label in class_spellings),
                nonfault_syntax_sha256=hashlib.sha256(joined.encode('utf-8')).hexdigest(),
                class_dialect_spellings=sorted(class_spellings),
                source_native_key_identity_verified=False,
                quality_or_detection_counts_exported=False)


def resource_projection(raw):
    # Only footer metadata; no ATPG statistics, cycles or elapsed-time labels.
    footer = raw[-16384:].decode('utf-8', errors='replace')
    compact = COMPACT_RSS.findall(footer)
    verbose = VERBOSE_RSS.findall(footer)
    require(len(compact) <= 8 and len(verbose) <= 8, 'AMBIGUOUS_RSS_BOUND')
    return dict(compact_maxresident_values=compact,
                compact_units_verified=False,
                explicit_kbytes_values=verbose,
                record_is_unique=len(compact) + len(verbose) == 1,
                actual_atpg_limit_bytes=None, resource_reservation_verified=False,
                historical_observation_not_enforcement=True)


def enforce_limits():
    import resource
    for kind, ceiling in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 20)):
        soft, hard = resource.getrlimit(kind)
        chosen = ceiling if soft == resource.RLIM_INFINITY else min(soft, ceiling)
        if hard != resource.RLIM_INFINITY:
            chosen = min(chosen, hard)
        resource.setrlimit(kind, (chosen, hard))


def collect():
    result = dict(schema='e90-resource-dialect-observation-v1',
                  hostname=socket.gethostname(), python_version=list(sys.version_info[:3]),
                  status='PARTIAL', files=[], body_bytes=0, actual_atpg_calls=0,
                  programs_launched=0, remote_writes=0, training_runs=0,
                  execution_ready=False, training_release=False,
                  actual_atpg_memory_limit_bytes=None, actual_atpg_timeout_s=None)
    if result['hostname'] != HOST or not sys.platform.startswith('linux'):
        result['reason'] = 'HOST_OR_PLATFORM_BEFORE_READS'
        return result
    try:
        enforce_limits()
    except (ImportError, OSError, ValueError):
        result['reason'] = 'SELF_LIMITS_BEFORE_READS'
        return result
    budget = [0]
    for circuit, role, path in specs():
        item = dict(circuit=circuit, role=role, status='PARTIAL')
        result['files'].append(item)
        try:
            raw = read_file(path, budget)
            item.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                        metadata=(mtfi_projection(raw, COUNTS[circuit])
                                  if role == 'MTFI_H' else resource_projection(raw)),
                        status='BOUNDED_METADATA_OBSERVED')
        except (OSError, ProbeError, UnicodeError, MemoryError) as exc:
            item['reason'] = str(exc) if isinstance(exc, ProbeError) else type(exc).__name__
            break
    result['body_bytes'] = budget[0]
    if len(result['files']) == 6 and all(row['status'] == 'BOUNDED_METADATA_OBSERVED'
                                        for row in result['files']):
        result['status'] = 'PASS_BOUNDED_METADATA_NOT_RESOURCE_ADMISSION'
    return result


if __name__ == '__main__':
    result = collect()
    raw = json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    if len(raw) + 1 > MAX_OUTPUT:
        raw = b'{"schema":"e90-resource-dialect-observation-v1","status":"PARTIAL_OUTPUT_BOUND","execution_ready":false}'
    sys.stdout.write(raw.decode('ascii') + '\n')
