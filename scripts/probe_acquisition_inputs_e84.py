"""One bounded read-only A-side input metadata observation, Python 3.6+.

Stat exact source-known paths; hash only the fixed small ordinary input files.
No directory enumeration, result/log parsing, executable launch or remote write.
TSDB contents and executable version remain unverified by this observation.
"""
import hashlib
import json
import os
import socket
import stat
import sys


ROOT = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A'
LIBRARY = '/home/jiangchuanc/Desktop/multimode_ate_20260725_A_staging/00_inputs_readonly/scc28nhk_hsc31_lvt_scan.tcelllib'
FILE_CAP = 8 * 1024 * 1024
TOTAL_CAP = 32 * 1024 * 1024
OUTPUT_CAP = 32768


def specs():
    values = [(ROOT + '/00_framework/translate_fault_state_v1.py', 'TRANSLATOR')]
    values.append((LIBRARY, 'CELL_LIBRARY'))
    for circuit in ('aes_core', 'spi'):
        base = ROOT + '/10_circuits/' + circuit
        values.append((base + '/01_config/config.env', 'CONFIG'))
        faults = base + '/03_fault_universe/common_' + circuit + '_m16_phase4_v2'
        for name in ('manifest.json', 'canonical_fault_mapping.tsv',
                     'H_common_initial_faults.basic', 'M_common_initial_faults.basic',
                     'F_common_initial_faults.basic'):
            values.append((faults + '/' + name, 'COMMON_INPUT'))
        for mode in ('H', 'M', 'F'):
            values.append((base + '/99_tmp/' + mode + '_mapped_tsdb', 'TSDB_DIRECTORY'))
    return values


def observe():
    rows = []
    total = 0
    for path, role in specs():
        row = dict(path=path, role=role, sha256=None, bytes_read=0)
        rows.append(row)
        try:
            before = os.lstat(path)
            row.update(size=before.st_size, mode=stat.S_IFMT(before.st_mode),
                       device=before.st_dev, inode=before.st_ino,
                       mtime_ns=before.st_mtime_ns)
            if role == 'TSDB_DIRECTORY':
                row['status'] = 'DIRECTORY_METADATA_ONLY' if stat.S_ISDIR(before.st_mode) else 'NOT_DIRECTORY'
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                row['status'] = 'NOT_SINGLE_LINK_REGULAR_FILE'
                continue
            if before.st_size > FILE_CAP or total + before.st_size > TOTAL_CAP:
                row['status'] = 'BODY_HASH_CAP_SKIPPED'
                continue
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            fd = os.open(path, flags)
            try:
                opened = os.fstat(fd)
                identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink,
                                      s.st_size, s.st_mtime_ns)
                if identity(opened) != identity(before):
                    raise ValueError('INPUT_CHANGED')
                hasher = hashlib.sha256()
                consumed = 0
                while consumed < before.st_size:
                    allowance = min(65536, before.st_size - consumed, TOTAL_CAP - total)
                    if allowance <= 0:
                        raise ValueError('READ_CAP_OR_INPUT_CHANGED')
                    block = os.read(fd, allowance)
                    if not block:
                        break
                    consumed += len(block)
                    total += len(block)
                    row['bytes_read'] = consumed
                    if consumed > before.st_size or total > TOTAL_CAP:
                        raise ValueError('READ_CAP_OR_INPUT_CHANGED')
                    hasher.update(block)
                if consumed != before.st_size or identity(os.fstat(fd)) != identity(before) or identity(os.lstat(path)) != identity(before):
                    raise ValueError('INPUT_CHANGED')
                row.update(status='CURRENT_RAW_BYTES_HASHED_NO_CONTENT_EXPORTED',
                           sha256=hasher.hexdigest())
            finally:
                os.close(fd)
        except OSError as error:
            row.update(status='OS_ERROR', errno=error.errno)
        except ValueError as error:
            row.update(status=str(error), sha256=None)
            break
    return dict(schema='e84-input-observation-v1', hostname=socket.gethostname(),
        python_version=list(sys.version_info[:3]), paths=rows,
        stat_path_count=len(rows), bytes_read=total,
        tessent_path_from_current_PATH=None,
        executable_path_discovery_performed=False,
        executable_version_verified=False, executable_body_hashed=False,
        tsdb_contents_authenticated=False, fault_mapping_semantics_verified=False,
        graph_authenticated=False, actual_atpg_memory_limit_bytes=None,
        actual_atpg_timeout_s=None, remote_writes=0, directory_entries_enumerated=0,
        external_programs_launched_by_probe=0, training_runs=0, actual_atpg_calls=0,
        execution_ready=False, training_release=False)


def main():
    if sys.platform != 'linux':
        raise ValueError('LINUX_ONLY')
    if socket.gethostname() != 'bupt-vncs2':
        raise ValueError('EXPECTED_A_HOSTNAME')
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
    result = observe()
    raw = (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    if len(raw) > OUTPUT_CAP:
        raise ValueError('OUTPUT_CAP')
    sys.stdout.buffer.write(raw)


if __name__ == '__main__':
    main()
