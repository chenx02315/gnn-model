"""E97 read-only LSF setup metadata; never executes scheduler programs.

Setup evidence is not proof of an actual job's memory units or enforcement.
Python 3.6 compatible; stdout is bounded JSON and errors are fixed codes.
"""
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys

EXECUTABLES = ('bsub', 'bjobs', 'bresume', 'blaunch', 'lsid', 'bqueues')
DIRECTORIES = ('LSF_ENVDIR', 'LSF_BINDIR', 'LSF_SERVERDIR')
PARAMETERS = ('LSF_UNIT_FOR_LIMITS', 'LSB_JOB_MEMLIMIT',
              'LSB_MEMLIMIT_ENFORCE', 'LSF_PROCESS_TRACKING',
              'LSF_LINUX_CGROUP_ACCT')
CONFIG_CAP = 256 * 1024
OUTPUT_CAP = 16 * 1024


class ProbeError(Exception):
    pass


def apply_caps():
    try:
        import resource
        for kind, requested in ((resource.RLIMIT_AS, 256 * 1024 * 1024),
                                (resource.RLIMIT_CPU, 20)):
            soft, hard = resource.getrlimit(kind)
            limit = requested if hard == resource.RLIM_INFINITY else min(hard, requested)
            if soft != resource.RLIM_INFINITY:
                limit = min(limit, soft)
            resource.setrlimit(kind, (limit, limit))
    except Exception:
        raise ProbeError('E97_CAPS_FAILED')


def canonical_path(value):
    # Explicit ASCII and control checks also work on Python 3.6.
    if (not isinstance(value, str) or not value or len(value) > 2048 or
            any(ord(c) < 32 or ord(c) > 126 for c in value) or
            not os.path.isabs(value)):
        raise ProbeError('E97_PATH_INVALID')
    resolved = os.path.realpath(value)
    if resolved != value:
        raise ProbeError('E97_PATH_NOT_CANONICAL')
    return resolved


def metadata(info):
    return {'dev': info.st_dev, 'ino': info.st_ino, 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
            'size': info.st_size, 'mtime_ns': info.st_mtime_ns}


def parse_selected(raw):
    found = dict((name, []) for name in PARAMETERS)
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(b'#'):
            continue
        for name in PARAMETERS:
            key = name.encode('ascii')
            if re.match(re.escape(key) + rb'(?:\s|=|$)', line):
                match = re.match(re.escape(key) + rb'\s*=\s*([^\s#]+)\s*(?:#.*)?$', line)
                token = match.group(1) if match else b''
                valid = (0 < len(token) <= 64 and
                         all(33 <= c <= 126 for c in token) and
                         not any(c in token for c in (b'"', b"'", b'`', b'$', b';', b'\\')))
                found[name].append(token.decode('ascii') if valid else None)
    result = {}
    for name, values in found.items():
        if not values:
            result[name] = {'status': 'absent', 'count': 0}
        elif len(values) == 1 and values[0] is not None:
            result[name] = {'status': 'present', 'count': 1, 'raw_token': values[0]}
        else:
            result[name] = {'status': 'ambiguous', 'count': len(values)}
    return result


def read_config(envdir):
    # Anchor the canonical directory, reject a final lsf.conf symlink, and
    # verify the opened object before reading any bytes. Root ownership is OK.
    directory_fd = os.open(envdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open('lsf.conf', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ProbeError('E97_CONFIG_NOT_REGULAR')
            if before.st_size > CONFIG_CAP:
                raise ProbeError('E97_CONFIG_TOO_LARGE')
            chunks = []
            total = 0
            while total < before.st_size:
                chunk = os.read(fd, min(8192, before.st_size - total))
                if not chunk:
                    raise ProbeError('E97_CONFIG_SHORT_READ')
                total += len(chunk)
                chunks.append(chunk)
            after = os.fstat(fd)
            named = os.stat('lsf.conf', dir_fd=directory_fd, follow_symlinks=False)
            if (metadata(before) != metadata(after) or
                    not stat.S_ISREG(named.st_mode) or
                    metadata(after) != metadata(named)):
                raise ProbeError('E97_CONFIG_CHANGED')
            raw = b''.join(chunks)
            return {'status': 'read', 'sha256': hashlib.sha256(raw).hexdigest(),
                    'byte_count': len(raw), 'metadata': metadata(before),
                    'selected_parameters': parse_selected(raw)}
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def collect():
    host = platform.node()
    if platform.system() != 'Linux' or host != 'bupt-vncs2':
        raise ProbeError('E97_HOST_INVALID')
    result = {'schema': 'acceptance_lsf_setup_e97_v1', 'hostname': host,
              'python': {'version': list(sys.version_info[:3]),
                         'implementation': platform.python_implementation()},
              'actual_job_memory_proof': False, 'directories': {},
              'executables': {}, 'errors': []}
    for name in DIRECTORIES:
        value = os.environ.get(name)
        if value is None:
            result['directories'][name] = {'status': 'absent'}
            continue
        try:
            path = canonical_path(value)
            result['directories'][name] = {'status': 'present', 'path': path}
        except ProbeError:
            result['directories'][name] = {'status': 'invalid'}
            result['errors'].append('E97_DIRECTORY_INVALID_' + name)
    for name in EXECUTABLES:
        try:
            path = shutil.which(name)
            if path is None:
                result['executables'][name] = {'status': 'absent'}
                continue
            path = canonical_path(os.path.realpath(path))
            info = os.stat(path)
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise ProbeError('E97_EXECUTABLE_TYPE')
            result['executables'][name] = {'status': 'present', 'path': path,
                                           'metadata': metadata(info)}
        except Exception:
            result['executables'][name] = {'status': 'invalid'}
            result['errors'].append('E97_EXECUTABLE_INVALID_' + name)
    envdir = result['directories']['LSF_ENVDIR']
    result['config'] = {'status': 'not_read'}
    if envdir['status'] == 'present':
        try:
            result['config'] = read_config(envdir['path'])
        except ProbeError as exc:
            result['errors'].append(str(exc))
        except OSError as exc:
            import errno
            code = ('E97_CONFIG_SYMLINK' if exc.errno == errno.ELOOP
                    else 'E97_CONFIG_IO_FAILED')
            result['errors'].append(code)
    result.update(boundaries())
    result['status'] = ('PARTIAL' if result['errors'] else
                        'PASS_BOUNDED_SETUP_METADATA_ONLY')
    return result


def boundaries():
    return {'execution_ready': False, 'training_release': False,
            'actual_job_memory_proof': False, 'actual_atpg_calls': 0,
            'jobs_submitted': 0, 'programs_launched': 0, 'remote_writes': 0}


def error_envelope(code):
    result = boundaries()
    result.update({'schema': 'acceptance_lsf_setup_e97_v1',
                   'status': 'PARTIAL', 'errors': [code]})
    return result


def main():
    code = 0
    try:
        apply_caps()
        result = collect()
        code = int(bool(result['errors']))
        payload = json.dumps(result, sort_keys=True, ensure_ascii=True)
        if len(payload.encode('ascii')) + 1 > OUTPUT_CAP:
            raise ProbeError('E97_OUTPUT_TOO_LARGE')
    except ProbeError as exc:
        payload = json.dumps(error_envelope(str(exc)))
        code = 1
    except Exception:
        payload = json.dumps(error_envelope('E97_INTERNAL_FAILED'))
        code = 1
    sys.stdout.write(payload + '\n')
    return code


if __name__ == '__main__':
    sys.exit(main())
