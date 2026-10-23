"""Read-only cgroup v1/v2 capability metadata, never a guard installation.

Only fixed proc files and conventional cgroup mount metadata are inspected.
No process is launched, cgroup created, environment exported, or limit changed.
"""
import hashlib
import json
import os
import re
import socket
import stat
import sys

PROC_FILES = ('/proc/self/cgroup', '/proc/self/mountinfo', '/proc/cgroups',
              '/proc/self/limits')
ROOTS = ('/sys/fs/cgroup', '/sys/fs/cgroup/memory', '/sys/fs/cgroup/freezer',
         '/sys/fs/cgroup/pids')
MAX_FILE = 131072
MAX_TOTAL = 524288
MAX_OUTPUT = 16384


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def parse_memberships(raw):
    text = raw.decode('ascii')
    rows = []
    for line in text.splitlines():
        fields = line.split(':', 2)
        require(len(fields) == 3 and fields[0].isdigit(), 'CGROUP_RECORD')
        controllers = fields[1].split(',') if fields[1] else []
        require(all(re.fullmatch(r'[A-Za-z0-9_=.-]{1,64}', x)
                    for x in controllers), 'CONTROLLER_TOKEN')
        path = fields[2]
        require(path.startswith('/') and len(path) <= 2048 and
                not any(x in ('.', '..') for x in path.split('/')) and
                not any(ord(c) < 32 or ord(c) == 127 for c in path),
                'CGROUP_PATH')
        rows.append({'hierarchy': int(fields[0]), 'controllers': controllers,
                     'relative_path_sha256': hashlib.sha256(
                         path.encode('ascii')).hexdigest(),
                     'at_hierarchy_root': path == '/'})
    require(0 < len(rows) <= 64 and
            len({x['hierarchy'] for x in rows}) == len(rows), 'CGROUP_COUNT')
    return rows


def parse_mounts(raw):
    rows = []
    lines = raw.decode('ascii').splitlines()
    require(len(lines) <= 2048, 'MOUNT_COUNT')
    for line in lines:
        require(len(line) <= 8192, 'MOUNT_LINE')
        parts = line.split(' - ')
        require(len(parts) == 2, 'MOUNT_FORMAT')
        left = parts[0].split(); right = parts[1].split()
        require(len(left) >= 6 and len(right) >= 3, 'MOUNT_FIELDS')
        if right[0] not in ('cgroup', 'cgroup2'):
            continue
        # Never decode mount escaping or derive a filesystem read from it.
        point = left[4]
        require(len(point) <= 2048, 'MOUNT_PATH_BOUND')
        rows.append({'version': 2 if right[0] == 'cgroup2' else 1,
                     'conventional_mount': point if point in ROOTS else None,
                     'mount_path_sha256': hashlib.sha256(
                         point.encode('ascii')).hexdigest(),
                     'mount_read_only': 'ro' in left[5].split(','),
                     'controllers': sorted(set(right[2].split(',')) &
                         {'memory', 'freezer', 'pids', 'cpu', 'cpuacct',
                          'cpuset', 'devices', 'blkio'})})
    require(len(rows) <= 64, 'CGROUP_MOUNT_COUNT')
    return rows


def parse_controller_support(raw):
    rows = {}
    for line in raw.decode('ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split()
        require(len(fields) == 4 and fields[1].isdigit() and
                fields[2].isdigit() and fields[3] in ('0', '1'),
                'CONTROLLER_RECORD')
        require(re.fullmatch(r'[a-z_]{1,64}', fields[0]) is not None and
                fields[0] not in rows, 'CONTROLLER_NAME')
        rows[fields[0]] = fields[3] == '1'
    require(len(rows) <= 64, 'CONTROLLER_COUNT')
    return {name: rows.get(name) for name in ('memory', 'freezer', 'pids')}


def read_proc(path, budget):
    require(path in PROC_FILES, 'FIXED_PROC_SCOPE')
    # /proc/self is a kernel link by design; final file must not be a symlink.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), 'PROC_REGULAR')
        chunks = []; size = 0
        while True:
            block = os.read(fd, min(4096, MAX_FILE + 1 - size))
            if not block:
                break
            size += len(block); budget[0] += len(block)
            require(size <= MAX_FILE and budget[0] <= MAX_TOTAL, 'READ_BOUND')
            chunks.append(block)
        return b''.join(chunks)
    finally:
        os.close(fd)


def root_metadata(path):
    require(path in ROOTS, 'FIXED_ROOT_SCOPE')
    try:
        info = os.lstat(path)
        return {'path': path, 'exists': True,
                'is_directory_not_symlink': stat.S_ISDIR(info.st_mode),
                'write_access_hint': bool(os.access(path, os.W_OK)),
                'owner_uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode)}
    except FileNotFoundError:
        return {'path': path, 'exists': False,
                'is_directory_not_symlink': False, 'write_access_hint': False,
                'owner_uid': None, 'mode': None}


def collect():
    require(sys.platform.startswith('linux') and socket.gethostname() ==
            'bupt-vncs2', 'LINUX_HOST_REQUIRED')
    import resource
    for kind, cap in ((resource.RLIMIT_AS, 134217728), (resource.RLIMIT_CPU, 5)):
        soft, hard = resource.getrlimit(kind)
        chosen = cap if soft == resource.RLIM_INFINITY else min(cap, soft)
        if hard != resource.RLIM_INFINITY:
            chosen = min(chosen, hard)
        resource.setrlimit(kind, (chosen, hard))
    budget = [0]; raws = {}
    for path in PROC_FILES:
        raws[path] = read_proc(path, budget)
    memberships = parse_memberships(raws[PROC_FILES[0]])
    mounts = parse_mounts(raws[PROC_FILES[1]])
    # Limits body and controller file body are hashed, not exported.
    return {'schema': 'e94-tessent-resource-capability-v1',
            'status': 'OBSERVED_CAPABILITY_HINTS_NOT_RESOURCE_ADMISSION',
            'hostname': socket.gethostname(), 'uid': os.getuid(),
            'files_read': len(raws), 'body_bytes': budget[0],
            'input_metadata': [{'path': p, 'bytes': len(raws[p]),
                'sha256': hashlib.sha256(raws[p]).hexdigest()} for p in PROC_FILES],
            'memberships': memberships, 'mounts': mounts,
            'controller_enabled': parse_controller_support(raws[PROC_FILES[2]]),
            'root_metadata': [root_metadata(p) for p in ROOTS],
            'helper_address_space_bytes': 134217728, 'helper_cpu_seconds': 5,
            'guard_installed': False, 'limit_write_tested': False,
            'group_kill_tested': False, 'actual_atpg_memory_limit_bytes': None,
            'actual_atpg_timeout_s': None, 'directory_scans': 0,
            'external_programs_launched': 0, 'remote_writes': 0,
            'actual_atpg_calls': 0, 'training_runs': 0,
            'execution_ready': False, 'training_release': False}


def main():
    value = collect()
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                     allow_nan=False).encode('ascii') + b'\n'
    require(len(raw) <= MAX_OUTPUT, 'OUTPUT_BOUND')
    sys.stdout.write(raw.decode('ascii'))


if __name__ == '__main__':
    main()
