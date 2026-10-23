"""E85 bounded A-side read-only metadata probe; Python 3.6, no subprocess.

Only six E84 TSDB directory anchors, its one library link, exact PATH/tessent
candidates, and fixed small host-resource metadata are in scope. No output is
an ATPG memory/time guard, reservation, input-semantics proof, or run permit.
"""
from __future__ import print_function

import hashlib
import json
import os
import posixpath
import socket
import stat
import sys

EXPECTED_HOST = 'bupt-vncs2'
PHASE = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A'
LIBRARY = ('/home/jiangchuanc/Desktop/multimode_ate_20260725_A_staging/'
           '00_inputs_readonly/scc28nhk_hsc31_lvt_scan.tcelllib')
ROOTS = tuple(PHASE + '/10_circuits/' + circuit + '/99_tmp/' + mode + '_mapped_tsdb'
              for circuit in ('aes_core', 'spi') for mode in ('H', 'M', 'F'))
MAX_LINKS = 4
MAX_NAME = 1024
MAX_DEPTH = 8
MAX_DIRS = 128
MAX_ENTRIES = 1024
MAX_ANOMALIES = 16
MAX_FILE = 64 * 1024 * 1024
MAX_BODY = 128 * 1024 * 1024
CHUNK = 65536
MAX_OUTPUT = 65536
MAX_ADDRESS_SPACE = 256 * 1024 * 1024
MAX_CPU_SECONDS = 20
MAX_PATH_PARTS = 32
MAX_PATH_COMPONENT = 512
SYSTEM_READ = 4096
FORBIDDEN_ROOTS = ('/proc', '/sys', '/dev', '/etc', '/root', '/ssd')
FORBIDDEN_NAMES = ('.ssh', 'ssh', 'secrets', 'secret', 'credential',
                   'credentials', 'token', 'tokens', 'private_key', 'id_rsa')
BLOCKED_TREE_SUFFIXES = ('.log', '.ckpt', '.pt', '.pth')


class ProbeError(Exception):
    pass


def require(value, reason):
    if not value:
        raise ProbeError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def identity(info):
    core = (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns)
    return core + (info.st_ctime_ns,) if os.name == 'posix' else core


def safe_path(path):
    require(isinstance(path, str) and path.startswith('/') and '\x00' not in path,
            'UNSAFE_ABSOLUTE_PATH')
    normalized = posixpath.normpath(path)
    pieces = normalized.split('/')[1:]
    require(all(piece and len(piece) <= MAX_NAME for piece in pieces), 'PATH_NAME_BOUND')
    lower = [piece.lower() for piece in pieces]
    require(not any(normalized == root or normalized.startswith(root + '/')
                    for root in FORBIDDEN_ROOTS) and
            not any(piece in FORBIDDEN_NAMES or 'secret' in piece or
                    'credential' in piece or
                    any(term in piece for term in ('blind', 'checkpoint', 'outcome', 'graph')) or
                    piece in ('log', 'logs') or piece.startswith('logs_') or
                    piece.endswith(BLOCKED_TREE_SUFFIXES)
                    for piece in lower), 'PROTECTED_PATH')
    return normalized


def sensitive_tree_name(name):
    lower = name.lower()
    return (lower in FORBIDDEN_NAMES or
            any(term in lower for term in ('secret', 'credential', 'checkpoint',
                                            'outcome', 'blind')) or
            lower in ('log', 'logs') or lower.startswith('logs_') or
            lower.endswith(BLOCKED_TREE_SUFFIXES))


def resolve_links(path):
    """Resolve every component with lstat/readlink, at most four links total."""
    pending = safe_path(path).split('/')[1:]
    current = '/'
    links = 0
    while pending:
        piece = pending.pop(0)
        candidate = safe_path(posixpath.join(current, piece))
        info = os.lstat(candidate)
        if stat.S_ISLNK(info.st_mode):
            links += 1
            require(links <= MAX_LINKS, 'SYMLINK_HOP_BOUND')
            target = os.readlink(candidate)
            require(isinstance(target, str) and 0 < len(target) <= MAX_NAME,
                    'LINK_TARGET_BOUND')
            target = (target if target.startswith('/') else
                      posixpath.join(posixpath.dirname(candidate), target))
            target = safe_path(target)
            pending = target.split('/')[1:] + pending
            current = '/'
        else:
            current = candidate
    return current, info, links


def require_anchored_io():
    """Never fall back to pathname body reads on unsupported platforms."""
    require(sys.platform.startswith('linux') and hasattr(os, 'O_NOFOLLOW') and
            hasattr(os, 'O_DIRECTORY') and os.open in os.supports_dir_fd and
            os.stat in os.supports_dir_fd and os.stat in os.supports_follow_symlinks and
            os.path.isdir('/proc/self/fd'), 'ANCHORED_IO_UNAVAILABLE')


def open_directory(path):
    """Return (held directory, held parent, final name, initial stat). Caller closes both."""
    require_anchored_io()
    pieces = safe_path(path).split('/')[1:]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open('/', flags)
    try:
        if not pieces:
            fd = os.dup(parent)
            try:
                return fd, parent, '.', os.fstat(fd)
            except BaseException:
                os.close(fd)
                raise
        for piece in pieces[:-1]:
            child = os.open(piece, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        name = pieces[-1]
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(named.st_mode),
                'TREE_ROOT_OR_ANCESTOR_NOT_DIRECT_DIRECTORY')
        fd = os.open(name, flags, dir_fd=parent)
        try:
            first = os.fstat(fd)
            require(identity(named) == identity(first), 'TREE_DIRECTORY_CHANGED')
            return fd, parent, name, first
        except BaseException:
            os.close(fd)
            raise
    except BaseException:
        os.close(parent)
        raise


def direct_directory(path):
    """Metadata-only direct-directory check; close both held descriptors."""
    fd, parent, name, info = open_directory(path)
    try:
        return safe_path(path), info
    finally:
        os.close(fd)
        os.close(parent)


class ReadBudget(object):
    def __init__(self):
        self.body_bytes = 0
        self.tree_directories = 0
        self.tree_entries = 0
        self.tree_exhausted = False

    def hash_regular_at(self, parent, name, per_file=MAX_FILE):
        require(name not in ('', '.', '..') and '/' not in name and '\x00' not in name and
                len(name) <= MAX_NAME and not sensitive_tree_name(name),
                'PROTECTED_TREE_ENTRY_NOT_READ')
        first = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(first.st_mode) and first.st_nlink == 1,
                'NOT_SINGLE_LINK_REGULAR')
        require(0 <= first.st_size <= per_file and
                self.body_bytes + first.st_size <= MAX_BODY, 'BODY_BYTE_BOUND')
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(name, flags, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(identity(before) == identity(first), 'FILE_CHANGED_BEFORE_READ')
            left = before.st_size
            hasher = hashlib.sha256()
            while left:
                block = os.read(fd, min(CHUNK, left))
                require(bool(block), 'SHORT_FILE_READ')
                hasher.update(block)
                self.body_bytes += len(block)
                left -= len(block)
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(identity(before) == identity(after) == identity(named),
                    'FILE_CHANGED_DURING_READ')
            return {'sha256': hasher.hexdigest(), 'bytes': before.st_size,
                    'mode': stat.S_IMODE(before.st_mode)}
        finally:
            os.close(fd)

    def hash_regular(self, path, per_file=MAX_FILE):
        path = safe_path(path)
        parent, grandparent, name, _ = open_directory(posixpath.dirname(path))
        try:
            return self.hash_regular_at(parent, posixpath.basename(path), per_file)
        finally:
            os.close(parent)
            os.close(grandparent)


def inspect_link_file(path, budget, require_executable=False):
    result = {'path': path, 'status': 'PARTIAL', 'resolved_path': None,
              'symlink_hops': None, 'body_sha256': None, 'bytes': None}
    try:
        resolved, info, hops = resolve_links(path)
        result['resolved_path'] = resolved
        result['symlink_hops'] = hops
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                'NOT_SINGLE_LINK_REGULAR')
        if require_executable:
            require(os.access(resolved, os.X_OK), 'NOT_EXECUTABLE')
        hashed = budget.hash_regular(resolved)
        result.update(status='CURRENT_BODY_HASHED', body_sha256=hashed['sha256'],
                      bytes=hashed['bytes'], mode=hashed['mode'])
    except (OSError, ProbeError) as exc:
        result['reason'] = (exc.__class__.__name__ if isinstance(exc, OSError)
                            else str(exc)[:160])
    return result


def inspect_tree(root, budget):
    """Digest sorted relative membership (name/type/size/hash), not file data."""
    result = {'root': root, 'status': 'PARTIAL', 'tree_complete': False,
              'tree_sha256': None, 'directories': 0, 'entries': 0,
              'regular_files_hashed': 0, 'body_bytes': 0, 'anomaly_count': 0,
              'anomalies': []}
    records = []
    initial_bytes = budget.body_bytes

    if (budget.tree_exhausted or budget.tree_directories >= MAX_DIRS or
            budget.tree_entries >= MAX_ENTRIES):
        result['anomaly_count'] = 1
        result['anomalies'] = [{'relative_path': '', 'code': 'TREE_GLOBAL_BOUND'}]
        return result

    def anomaly(rel, code):
        result['anomaly_count'] += 1
        if len(result['anomalies']) < MAX_ANOMALIES:
            result['anomalies'].append({'relative_path': rel[:MAX_NAME], 'code': code})

    def visit(fd, parent, name, rel, depth):
        require(not budget.tree_exhausted, 'TREE_GLOBAL_BOUND')
        require(depth <= MAX_DEPTH, 'TREE_DEPTH_BOUND')
        budget.tree_directories += 1
        result['directories'] += 1
        if budget.tree_directories >= MAX_DIRS:
            budget.tree_exhausted = True
            raise ProbeError('TREE_GLOBAL_DIRECTORY_BOUND')
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode) and before.st_nlink >= 1,
                'TREE_DIRECTORY_CHANGED')
        records.append([rel, 'directory', 0, None])
        children = []
        # Python 3.6 cannot scandir(fd). This fixed procfs alias names the held fd,
        # not a mutable path in the inspected tree.
        with os.scandir('/proc/self/fd/%d' % fd) as stream:
            for entry in stream:
                budget.tree_entries += 1
                result['entries'] += 1
                if budget.tree_entries >= MAX_ENTRIES:
                    budget.tree_exhausted = True
                    raise ProbeError('TREE_GLOBAL_ENTRY_BOUND')
                require(entry.name not in ('.', '..') and '/' not in entry.name and
                        '\x00' not in entry.name and len(entry.name) <= MAX_NAME,
                        'TREE_NAME_BOUND')
                children.append(entry.name)
        for child_name in sorted(children):
            child_rel = rel + '/' + child_name if rel else child_name
            if sensitive_tree_name(child_name):
                records.append([child_rel, 'blocked', 0, None])
                anomaly(child_rel, 'PROTECTED_TREE_ENTRY_NOT_READ')
                continue
            try:
                info = os.stat(child_name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child_fd = os.open(child_name, os.O_RDONLY | os.O_DIRECTORY |
                                       os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        require(identity(info) == identity(os.fstat(child_fd)),
                                'TREE_DIRECTORY_CHANGED')
                        visit(child_fd, fd, child_name, child_rel, depth + 1)
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(info.st_mode):
                    value = budget.hash_regular_at(fd, child_name)
                    records.append([child_rel, 'file', value['bytes'], value['sha256']])
                    result['regular_files_hashed'] += 1
                else:
                    records.append([child_rel, 'other', info.st_size, None])
                    anomaly(child_rel, 'SYMLINK_OR_SPECIAL_NOT_FOLLOWED')
            except (OSError, ProbeError) as exc:
                anomaly(child_rel, str(exc)[:80])
                if budget.tree_exhausted:
                    raise
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(identity(before) == identity(after) == identity(named),
                'TREE_DIRECTORY_CHANGED')

    try:
        fd, parent, name, info = open_directory(root)
        try:
            require(stat.S_ISDIR(info.st_mode), 'TREE_ROOT_NOT_DIRECT_DIRECTORY')
            visit(fd, parent, name, '', 0)
        finally:
            os.close(fd)
            os.close(parent)
        result['tree_sha256'] = digest(records)
        result['body_bytes'] = budget.body_bytes - initial_bytes
        result['tree_complete'] = result['anomaly_count'] == 0
        result['status'] = ('CURRENT_TREE_HASHED' if result['tree_complete']
                            else 'PARTIAL')
    except (OSError, ProbeError) as exc:
        anomaly('', str(exc)[:80])
        result['body_bytes'] = budget.body_bytes - initial_bytes
    return result


def probe_path_binary(budget, path_value=None):
    if path_value is None:
        path_value = os.environ.get('PATH', '')
    result = {'status': 'PARTIAL', 'components_inspected': 0,
              'invalid_components': 0, 'candidates_tested': 0,
              'resolved_binary': None, 'body_sha256': None,
              'version_verified': False, 'program_launched': False}
    components = path_value.split(':', MAX_PATH_PARTS)[:MAX_PATH_PARTS]
    for component in components:
        result['components_inspected'] += 1
        if not component or not component.startswith('/') or len(component) > MAX_PATH_COMPONENT:
            result['invalid_components'] += 1
            continue
        try:
            candidate = safe_path(posixpath.join(component, 'tessent'))
        except ProbeError:
            continue
        result['candidates_tested'] += 1
        item = inspect_link_file(candidate, budget, require_executable=True)
        if item['status'] == 'CURRENT_BODY_HASHED':
            result.update(status='CURRENT_BINARY_BODY_HASHED_NO_VERSION',
                          resolved_binary=item['resolved_path'],
                          body_sha256=item['body_sha256'], bytes=item['bytes'],
                          symlink_hops=item['symlink_hops'])
            break
        result['last_candidate_reason'] = item.get('reason', 'PARTIAL')
    return result


def _small_system_read(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                 getattr(os, 'O_NONBLOCK', 0))
    try:
        raw = os.read(fd, SYSTEM_READ)
        require(len(raw) < SYSTEM_READ, 'SYSTEM_READ_BOUND_OR_TRUNCATED')
        return raw.decode('ascii', 'strict')
    finally:
        os.close(fd)


def host_resource_metadata():
    value = {'status': 'PARTIAL_INFORMATIONAL_ONLY',
             'actual_atpg_memory_limit_bytes': None,
             'actual_atpg_timeout_s': None, 'reservation_verified': False}
    try:
        memory = _small_system_read('/proc/meminfo')
        selected = {}
        for line in memory.splitlines():
            parts = line.split()
            if (len(parts) == 3 and parts[0] in ('MemTotal:', 'MemAvailable:') and
                    parts[1].isdigit() and parts[2] == 'kB'):
                selected[parts[0][:-1]] = int(parts[1])
        require(set(selected) == {'MemTotal', 'MemAvailable'}, 'MEMINFO_FIELDS')
        value['memory_kb'] = selected
        raw = _small_system_read('/proc/self/cgroup')
        lines = raw.splitlines()
        require(0 < len(lines) <= 64, 'CGROUP_LINES_BOUND')
        unified = [line[3:] for line in lines if line.startswith('0::')]
        require(len(unified) <= 1 and all(len(x) <= MAX_NAME for x in unified),
                'CGROUP_PATH_BOUND')
        value['cgroup_version_hint'] = 2 if unified else 1
        value['self_cgroup_path'] = unified[0] if unified else None
        controllers = os.lstat('/sys/fs/cgroup/cgroup.controllers')
        value['controllers_path_is_regular'] = stat.S_ISREG(controllers.st_mode)
        value['cgroup_root_write_access_hint'] = os.access('/sys/fs/cgroup', os.W_OK)
        value['status'] = 'CURRENT_HOST_METADATA_NOT_ATPG_GUARD'
    except (OSError, UnicodeError, ProbeError) as exc:
        value['reason'] = str(exc)[:160]
    return value


def enforce_self_limits():
    import resource  # Linux-only; imported only after the host/platform guard.
    for kind, ceiling in ((resource.RLIMIT_AS, MAX_ADDRESS_SPACE),
                          (resource.RLIMIT_CPU, MAX_CPU_SECONDS)):
        soft, hard = resource.getrlimit(kind)
        chosen = ceiling if soft == resource.RLIM_INFINITY else min(soft, ceiling)
        if hard != resource.RLIM_INFINITY:
            chosen = min(chosen, hard)
        resource.setrlimit(kind, (chosen, hard))


def collect():
    output = {'schema': 'e85-acquisition-tree-input-probe-v1',
              'status': 'PARTIAL', 'hostname': socket.gethostname(),
              'platform': sys.platform, 'python_version': list(sys.version_info[:3]),
              'execution_ready': False, 'training_release': False,
              'actual_atpg_calls': 0, 'external_programs_launched': 0,
              'remote_writes': 0, 'actual_atpg_memory_limit_bytes': None,
              'actual_atpg_timeout_s': None, 'executable_version_verified': False,
              'fault_mapping_semantics_verified': False,
              'graph_authenticated': False}
    if output['hostname'] != EXPECTED_HOST or not sys.platform.startswith('linux'):
        output['status'] = 'BLOCKED_HOST_OR_PLATFORM_BEFORE_SOURCE_CHECKS'
        return output
    try:
        enforce_self_limits()
        output['helper_self_limits_applied'] = True
    except (ImportError, OSError, ValueError) as exc:
        output['status'] = 'BLOCKED_HELPER_RESOURCE_LIMIT_BEFORE_SOURCE_CHECKS'
        output['helper_self_limits_applied'] = False
        output['limit_error_type'] = exc.__class__.__name__
        return output
    budget = ReadBudget()
    output['library'] = inspect_link_file(LIBRARY, budget)
    output['tsdb_trees'] = [inspect_tree(root, budget) for root in ROOTS]
    output['binary'] = probe_path_binary(budget)
    output['host_resource_metadata'] = host_resource_metadata()
    try:
        fs = os.statvfs(PHASE)
        output['filesystem_available'] = {
            'bytes': fs.f_bavail * fs.f_frsize, 'inodes': fs.f_favail,
            'reservation_verified': False}
    except OSError as exc:
        output['filesystem_available'] = {'status': 'PARTIAL', 'reason': str(exc)[:160],
                                          'reservation_verified': False}
    output['body_bytes_hashed'] = budget.body_bytes
    output['tree_directories_observed'] = budget.tree_directories
    output['tree_entries_observed'] = budget.tree_entries
    output['tree_global_bound_reached'] = budget.tree_exhausted
    output['status'] = ('PASS_BOUNDED_INPUT_HASHES_ONLY_NOT_EXECUTION_READY'
                        if output['library']['status'] == 'CURRENT_BODY_HASHED' and
                        all(tree['tree_complete'] for tree in output['tsdb_trees']) and
                        output['binary']['status'] == 'CURRENT_BINARY_BODY_HASHED_NO_VERSION'
                        else 'PARTIAL')
    return output


def main():
    result = collect()
    raw = canonical(result)
    if len(raw) + 1 > MAX_OUTPUT:
        for tree in result.get('tsdb_trees', []):
            tree['anomalies'] = []
            tree['tree_complete'] = False
            tree['status'] = 'PARTIAL_OUTPUT_BOUND'
        result['status'] = 'PARTIAL_OUTPUT_BOUND'
        result['output_anomalies_elided'] = True
        raw = canonical(result)
    if len(raw) + 1 > MAX_OUTPUT:
        raw = canonical({'schema': 'e85-acquisition-tree-input-probe-v1',
                         'status': 'PARTIAL_OUTPUT_BOUND', 'execution_ready': False,
                         'training_release': False, 'actual_atpg_calls': 0})
    sys.stdout.write(raw.decode('ascii') + '\n')


if __name__ == '__main__':
    main()
