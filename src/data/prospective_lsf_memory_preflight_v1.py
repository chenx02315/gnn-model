"""Read-only LSF memory-cgroup-v1 preflight; never a Tessent runner.

The accepted path dialect is deliberately limited to the IBM-documented
parallel-job component ``job.<jobid>.<job_res_pid>.<time_stamp>``.  It is a
future A-side acceptance dialect, not a claim about every LSF installation.
"""
import hashlib
import errno
import json
import os
import re
import socket
import stat

SCHEMA = 'prospective-lsf-memory-preflight-v1'
MOUNT = '/sys/fs/cgroup/memory'
MAX_FIXED = 64 * 1024
MAX_SUFFIX = 4 * 1024
MAX_CGROUP_TOTAL = 64 * 1024
MAX_COMPONENTS = 32
MAX_INTEGER = 2**63 - 1
# Linux cgroup-v1 commonly exposes a page-aligned LONG_MAX sentinel as
# "unlimited".  It is numeric text but is not a finite hard cap.
CGROUP_V1_UNLIMITED_MIN = 0x7ffffffffffff000
COMPONENT = re.compile(r'[A-Za-z0-9_.-]{1,255}\Z')
BOOT_ID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
LIMIT_FILES = ('memory.limit_in_bytes', 'memory.memsw.limit_in_bytes',
               'memory.use_hierarchy')
JOB_CONTROL_FILES = LIMIT_FILES + ('cgroup.procs', 'tasks')


class PreflightError(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise PreflightError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _identity(info):
    core = (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns)
    return core + (info.st_ctime_ns,) if os.name == 'posix' else core


def _capability():
    require(hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY') and
            os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd and
            os.stat in os.supports_follow_symlinks and
            os.access in os.supports_dir_fd and
            os.access in os.supports_effective_ids and
            os.access in os.supports_follow_symlinks and hasattr(os, 'getxattr'),
            'ANCHORED_IO_UNAVAILABLE')


def _read_fd(fd, cap, budget=None):
    parts = []
    total = 0
    while True:
        remaining = cap - total
        if budget is not None:
            remaining = min(remaining, MAX_CGROUP_TOTAL - budget[0])
        require(remaining > 0, 'READ_BYTE_BOUND')
        requested = min(4096, remaining)
        block = os.read(fd, requested)
        if not block:
            break
        require(len(block) <= requested, 'READ_CONTRACT')
        parts.append(block)
        total += len(block)
        require(total <= cap, 'READ_BYTE_BOUND')
        if budget is not None:
            budget[0] += len(block)
            require(budget[0] <= MAX_CGROUP_TOTAL, 'CGROUP_TOTAL_BYTE_BOUND')
    return b''.join(parts)


def _read_fixed(path, cap=MAX_FIXED):
    """Read one fixed proc/kernel file without following a final symlink."""
    require(type(path) is str and path in {
        '/proc/self/cgroup', '/proc/self/mountinfo', '/proc/self/stat',
        '/proc/sys/kernel/random/boot_id'}, 'FIXED_READ_SCOPE')
    require(type(cap) is int and 1 <= cap <= MAX_FIXED, 'FIXED_READ_CAP')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                 getattr(os, 'O_NONBLOCK', 0))
    try:
        before = os.fstat(fd)
        require((stat.S_ISREG(before.st_mode) or path.startswith('/proc/')) and
                before.st_nlink == 1, 'FIXED_NOT_SINGLE_REGULAR')
        raw = _read_fd(fd, cap)
        after = os.fstat(fd)
        require(_identity(before) == _identity(after), 'FIXED_CHANGED_DURING_READ')
        return raw
    finally:
        os.close(fd)


def _mountinfo(raw):
    try:
        text = raw.decode('ascii')
    except UnicodeError as exc:
        raise PreflightError('MOUNTINFO_ENCODING') from exc
    matches = []
    for line in text.splitlines():
        left, separator, right = line.partition(' - ')
        if not separator:
            continue
        before = left.split()
        after = right.split()
        require(len(before) >= 6 and len(after) >= 3, 'MOUNTINFO_LINE')
        require(not before[4].startswith(MOUNT + '/'), 'NESTED_MEMORY_MOUNT')
        if before[4] == MOUNT:
            require(after[0] == 'cgroup' and before[3] == '/' and
                    'memory' in after[2].split(','), 'MEMORY_MOUNT_CONFLICT')
        if (after[0] == 'cgroup' and before[3] == '/' and before[4] == MOUNT and
                'memory' in after[2].split(',')):
            require(re.fullmatch(r'[0-9]+:[0-9]+', before[2]) is not None,
                    'MOUNT_DEVICE')
            matches.append(tuple(int(x) for x in before[2].split(':')))
    require(len(matches) == 1, 'UNIQUE_MEMORY_V1_MOUNT')
    return matches[0]


def _membership(raw, expected_job_id):
    try:
        text = raw.decode('ascii')
    except UnicodeError as exc:
        raise PreflightError('CGROUP_ENCODING') from exc
    paths = []
    for line in text.splitlines():
        fields = line.split(':')
        require(len(fields) == 3, 'CGROUP_LINE')
        if 'memory' in fields[1].split(','):
            paths.append(fields[2])
    require(len(paths) == 1, 'UNIQUE_MEMORY_MEMBERSHIP')
    path = paths[0]
    require(path.startswith('/') and '\x00' not in path and '\\' not in path,
            'MEMBERSHIP_ABSOLUTE')
    components = path.split('/')[1:]
    require(1 <= len(components) <= MAX_COMPONENTS and
            all(item not in ('', '.', '..') and COMPONENT.fullmatch(item)
                for item in components), 'MEMBERSHIP_COMPONENTS')
    job_re = re.compile(r'job\.%d\.[0-9]+\.[0-9]+\Z' % expected_job_id)
    matches = [index for index, item in enumerate(components)
               if job_re.fullmatch(item)]
    require(len(matches) == 1, 'EXACT_JOB_COMPONENT')
    job_index = matches[0]
    descendant = components[job_index + 1:]
    require(bool(descendant), 'WORKER_MUST_BE_JOB_DESCENDANT')
    for item in descendant:
        if item.startswith('tsk.'):
            match = re.fullmatch(r'tsk\.([0-9]+)\.[0-9]+', item)
            require(match is not None and int(match.group(1)) == expected_job_id,
                    'TASK_COMPONENT_JOB_MISMATCH')
    return dict(path=path, components=components, job_index=job_index,
                job_component=components[job_index], descendant=descendant,
                job_path='/' + '/'.join(components[:job_index + 1]))


def _process_identity(stat_raw, boot_raw, expected_pid):
    try:
        text = stat_raw.decode('ascii').strip()
        boot = boot_raw.decode('ascii').strip()
    except UnicodeError as exc:
        raise PreflightError('IDENTITY_ENCODING') from exc
    close = text.rfind(') ')
    require(close > 1 and text[:text.find(' ')].isdigit(), 'PROC_STAT_FORMAT')
    pid = int(text[:text.find(' ')])
    tail = text[close + 2:].split()
    require(pid == expected_pid and len(tail) >= 20 and tail[19].isdigit(),
            'PROC_STAT_IDENTITY')
    start_ticks = int(tail[19])
    require(1 <= start_ticks <= MAX_INTEGER and BOOT_ID.fullmatch(boot) is not None,
            'PROCESS_IDENTITY_BOUND')
    return dict(pid=pid, start_ticks=start_ticks, boot_id=boot,
                hostname=socket.gethostname())


def _open_mount(expected_device):
    _capability()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open('/', flags)
    try:
        for component in MOUNT.split('/')[1:]:
            child = os.open(component, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        info = os.fstat(parent)
        require(stat.S_ISDIR(info.st_mode), 'MEMORY_MOUNT_NOT_DIRECTORY')
        require((os.major(info.st_dev), os.minor(info.st_dev)) == expected_device,
                'OPENED_MEMORY_MOUNT_DEVICE')
        return parent
    except BaseException:
        os.close(parent)
        raise


def _read_at(directory_fd, name, cap, budget):
    require(name in set(LIMIT_FILES) | {'cgroup.procs'}, 'CGROUP_SUFFIX_SCOPE')
    require(type(cap) is int and 1 <= cap <= MAX_FIXED, 'CGROUP_SUFFIX_CAP')
    named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1,
            'CGROUP_SUFFIX_NOT_SINGLE_REGULAR')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                 getattr(os, 'O_NONBLOCK', 0), dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        require(_identity(named) == _identity(before), 'CGROUP_SUFFIX_CHANGED')
        raw = _read_fd(fd, cap, budget)
        after = os.fstat(fd)
        last = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        require(_identity(before) == _identity(after) == _identity(last),
                'CGROUP_SUFFIX_CHANGED')
        return raw
    finally:
        os.close(fd)


def _directory_meta(info):
    return dict(dev=info.st_dev, ino=info.st_ino, uid=info.st_uid,
                gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))


def _reject_access_acl(fd):
    # Reject ACL-bearing controls rather than trusting older faccessat
    # emulation, which may evaluate only mode bits for effective-ID checks.
    try:
        raw = os.getxattr(fd, 'system.posix_acl_access')
    except OSError as exc:
        require(exc.errno in (errno.ENODATA, errno.ENOTSUP), 'ACL_QUERY_FAILED')
        return
    require(not raw, 'ACCESS_ACL_UNSUPPORTED')


def _write_access(directory_fd, name):
    require(name == '.' or name in JOB_CONTROL_FILES, 'ACCESS_CHECK_SCOPE')
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0)
    if name == '.':
        flags |= os.O_DIRECTORY
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        _reject_access_acl(fd)
        return os.access(name, os.W_OK, dir_fd=directory_fd, effective_ids=True,
                         follow_symlinks=False)
    finally:
        os.close(fd)


def _stat_at(directory_fd, name):
    require(name in set(JOB_CONTROL_FILES), 'CGROUP_CONTROL_SCOPE')
    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            'CGROUP_CONTROL_NOT_SINGLE_REGULAR')
    return info


def _cgroup_reads(membership, expected_pid, expected_device):
    """Read each layer from exact job ancestor through the current worker."""
    root_fd = _open_mount(expected_device)
    current = os.dup(root_fd)
    chain = []
    budget = [0]
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        root_before = os.fstat(root_fd)
        for index, component in enumerate(membership['components']):
            child = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = child
            if index >= membership['job_index']:
                chain.append((component, os.dup(current)))
        require(chain and current != root_fd, 'JOB_ANCESTOR_FD')
        directory_before = [os.fstat(fd) for _, fd in chain]
        first_chain = [{name: _read_at(fd, name, MAX_SUFFIX, budget)
                        for name in LIMIT_FILES} for _, fd in chain]
        procs_first = _read_at(current, 'cgroup.procs', MAX_FIXED, budget)
        second_chain = [{name: _read_at(fd, name, MAX_SUFFIX, budget)
                         for name in LIMIT_FILES} for _, fd in chain]
        procs_second = _read_at(current, 'cgroup.procs', MAX_FIXED, budget)
        root_after = os.fstat(root_fd)
        directory_after = [os.fstat(fd) for _, fd in chain]
        require(first_chain == second_chain and procs_first == procs_second and
                _identity(root_before) == _identity(root_after) and
                [_identity(item) for item in directory_before] ==
                [_identity(item) for item in directory_after],
                'CGROUP_REREAD_CHANGED')
        _parse_procs(procs_first, expected_pid)
        job_fd = chain[0][1]
        controls = [(fd, name, _stat_at(fd, name))
                    for fd in (root_fd, job_fd) for name in JOB_CONTROL_FILES]
        require(not _write_access(root_fd, '.') and
                not _write_access(job_fd, '.') and
                not any(_write_access(fd, name) for fd, name, _ in controls),
                'ROOT_OR_JOB_WRITE_ACCESS')
        require(all(_identity(info) == _identity(_stat_at(fd, name))
                    for fd, name, info in controls), 'CONTROL_ACCESS_CHANGED')
        return dict(job_limits=first_chain[0], chain_limits=first_chain,
            chain_components=[name for name, _ in chain],
            procs=procs_first, cgroup_bytes=budget[0],
            root_directory=_directory_meta(root_after),
            job_directory=_directory_meta(directory_after[0]),
            current_directory=_directory_meta(directory_after[-1]),
            root_and_job_write_access_checks_clear=True)
    finally:
        for _, fd in chain:
            os.close(fd)
        os.close(current)
        os.close(root_fd)


def _limit(raw, reason):
    try:
        text = raw.decode('ascii').strip()
    except UnicodeError as exc:
        raise PreflightError(reason) from exc
    require(re.fullmatch(r'[0-9]{1,20}', text) is not None, reason)
    value = int(text)
    require(0 <= value <= MAX_INTEGER, reason)
    return None if value >= CGROUP_V1_UNLIMITED_MIN else value


def _decimal(raw, reason):
    value = _limit(raw, reason)
    require(value is not None, reason + '_NOT_FINITE')
    return value


def _parse_procs(raw, expected_pid):
    try:
        lines = raw.decode('ascii').splitlines()
        require(bool(lines) and all(re.fullmatch(r'[1-9][0-9]{0,9}', line)
                                    for line in lines), 'CGROUP_PROCS_FORMAT')
        pids = [int(line) for line in lines]
    except (UnicodeError, ValueError) as exc:
        raise PreflightError('CGROUP_PROCS_FORMAT') from exc
    require(expected_pid in pids and len(pids) == len(set(pids)),
            'CURRENT_PID_NOT_IN_WORKER_CGROUP')
    return pids


def _evaluate_values(membership, limits, expected_job_id, approved_cap,
                     chain_limits=None):
    require(membership['job_component'].startswith('job.%d.' % expected_job_id),
            'JOB_BINDING')
    memory = _decimal(limits['memory.limit_in_bytes'], 'MEMORY_LIMIT')
    memsw = _decimal(limits['memory.memsw.limit_in_bytes'], 'MEMSW_LIMIT')
    hierarchy = _decimal(limits['memory.use_hierarchy'], 'USE_HIERARCHY')
    require(0 < memory <= memsw <= approved_cap, 'APPROVED_HARD_CAP')
    require(hierarchy == 1, 'HIERARCHY_REQUIRED')
    if chain_limits is not None:
        require(type(chain_limits) is list and bool(chain_limits) and
                chain_limits[0] == limits, 'CHAIN_JOB_LIMIT_BINDING')
        for row in chain_limits:
            exact = set(row) == set(LIMIT_FILES)
            require(exact and _decimal(row['memory.use_hierarchy'],
                    'CHAIN_USE_HIERARCHY') == 1, 'CHAIN_HIERARCHY_REQUIRED')
            child_memory = _limit(row['memory.limit_in_bytes'],
                                  'CHAIN_MEMORY_LIMIT')
            child_memsw = _limit(row['memory.memsw.limit_in_bytes'],
                                 'CHAIN_MEMSW_LIMIT')
            require(not (child_memory is None and child_memsw is not None) and
                    (child_memory is None or child_memsw is None or
                     child_memory <= child_memsw), 'CHAIN_LIMIT_ORDER')
    return memory, memsw, hierarchy


def evaluate_snapshot(snapshot, expected_job_id, approved_memory_cap_bytes):
    """Validate caller data only; it can never authenticate OS state."""
    _arguments(expected_job_id, approved_memory_cap_bytes)
    require(type(snapshot) is dict and set(snapshot) ==
            {'membership', 'limits'}, 'SNAPSHOT_SCHEMA')
    membership = _membership(snapshot['membership'], expected_job_id)
    memory, memsw, hierarchy = _evaluate_values(
        membership, snapshot['limits'], expected_job_id,
        approved_memory_cap_bytes)
    return dict(schema=SCHEMA, snapshot_consistent=True,
                os_authenticated=False, memory_preflight_passed=False,
                job_id=expected_job_id,
                actual_hard_caps=dict(memory_limit_bytes=memory,
                    memory_memsw_limit_bytes=memsw, use_hierarchy=hierarchy))


def _arguments(expected_job_id, approved_memory_cap_bytes):
    require(type(expected_job_id) is int and
            1 <= expected_job_id <= MAX_INTEGER, 'EXPECTED_JOB_ID')
    require(type(approved_memory_cap_bytes) is int and
            1 <= approved_memory_cap_bytes <= MAX_INTEGER,
            'APPROVED_MEMORY_CAP_REQUIRED')


def _evidence(raw, reads=2):
    return dict(sha256=sha(raw), bytes=len(raw), reads=reads,
                total_bytes=len(raw) * reads)


def _evidence_pair(first, second):
    return dict(before_sha256=sha(first), before_bytes=len(first),
                after_sha256=sha(second), after_bytes=len(second), reads=2,
                total_bytes=len(first) + len(second))


def collect_preflight(expected_job_id, approved_memory_cap_bytes):
    """Collect one real read-only preflight; never changes or creates a cgroup."""
    _arguments(expected_job_id, approved_memory_cap_bytes)
    require(os.environ.get('LSB_JOBID') == str(expected_job_id),
            'LSB_JOBID_MISMATCH')
    job_index = os.environ.get('LSB_JOBINDEX')
    require(job_index is None or job_index == '0', 'LSB_JOB_ARRAY_UNSUPPORTED')
    require(sys_platform_linux(), 'LINUX_REQUIRED')
    pid = os.getpid()
    first = {path: _read_fixed(path) for path in (
        '/proc/self/cgroup', '/proc/self/mountinfo', '/proc/self/stat',
        '/proc/sys/kernel/random/boot_id')}
    device = _mountinfo(first['/proc/self/mountinfo'])
    membership = _membership(first['/proc/self/cgroup'], expected_job_id)
    identity = _process_identity(first['/proc/self/stat'],
                                 first['/proc/sys/kernel/random/boot_id'], pid)
    cgroup = _cgroup_reads(membership, pid, device)
    second = {path: _read_fixed(path) for path in first}
    require(first['/proc/self/cgroup'] == second['/proc/self/cgroup'] and
            first['/proc/self/mountinfo'] == second['/proc/self/mountinfo'] and
            first['/proc/sys/kernel/random/boot_id'] ==
            second['/proc/sys/kernel/random/boot_id'], 'PROC_REREAD_CHANGED')
    identity_after = _process_identity(second['/proc/self/stat'],
        second['/proc/sys/kernel/random/boot_id'], pid)
    require(identity == identity_after, 'PROCESS_IDENTITY_CHANGED')
    memory, memsw, hierarchy = _evaluate_values(
        membership, cgroup['job_limits'], expected_job_id,
        approved_memory_cap_bytes, cgroup['chain_limits'])
    reads = {path: _evidence_pair(raw, second[path])
             for path, raw in first.items()}
    chain_prefix = membership['components'][:membership['job_index']]
    for component, row in zip(cgroup['chain_components'],
                              cgroup['chain_limits']):
        chain_prefix = chain_prefix + [component]
        directory = MOUNT + '/' + '/'.join(chain_prefix)
        for name, raw in row.items():
            reads[directory + '/' + name] = _evidence(raw)
    reads[MOUNT + membership['path'] + '/cgroup.procs'] = _evidence(cgroup['procs'])
    result = dict(schema=SCHEMA, memory_preflight_passed=True,
        job_id=expected_job_id, approved_memory_cap_bytes=approved_memory_cap_bytes,
        process_identity=identity, job_component=membership['job_component'],
        guard_scope='EXACT_JOB_ANCESTOR_NOT_PARENT_ROOT',
        job_ancestor_depth=membership['job_index'] + 1,
        worker_descendant_depth=len(membership['descendant']),
        actual_hard_caps=dict(memory_limit_bytes=memory,
            memory_memsw_limit_bytes=memsw, use_hierarchy=hierarchy),
        job_directory_identity=cgroup['job_directory'],
        current_directory_identity=cgroup['current_directory'],
        root_and_job_write_access_checks_clear=cgroup['root_and_job_write_access_checks_clear'],
        global_migration_or_limit_immutability_verified=False,
        descendant_hierarchy_verified=True,
        read_evidence=reads, cgroup_bytes_read=cgroup['cgroup_bytes'],
        physical_io='READ_ONLY_NO_SCAN_NO_WRITE_NO_PROCESS')
    require(len(json.dumps(result, sort_keys=True, allow_nan=False).encode('ascii'))
            <= 65536, 'EVIDENCE_OUTPUT_BOUND')
    return result


def sys_platform_linux():
    import sys
    return sys.platform.startswith('linux')
