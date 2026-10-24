"""Reviewed literal-config deployment helper. No main, jobs, or automatic calls."""
import base64
import binascii
import hashlib
import io
import json
import os
import platform
import re
import stat
import sys
import tarfile
import zlib

ROOT = '/temp/jiangchuanc/gnn_model_acceptance_e97_20261024_r1_bundle'
AUTH = 'contracts/prospective_acceptance_authorization_e97_20261024.json'
AUTH_SHA256 = 'db9aa1bd63c7a3f7c9935ff4e99c2931041e59fb225b39e4338b06efd1619935'
MANIFEST = 'e97_code_manifest.json'
SOURCE_CAP = 1048576
MANIFEST_CAP = 65536
ARCHIVE_CAP = 524288
TAR_CAP = 2097152
DATA_MODULES = ('prospective_acceptance_materializer_v1', 'prospective_acceptance_process_v1',
    'prospective_acceptance_coordinator_v1', 'prospective_acceptance_scratch_v1',
    'prospective_lsf_memory_preflight_v1', 'prospective_fault_translation_v2',
    'prospective_tessent_acceptance_v1')
TEST_MODULES = ('prospective_acceptance_materializer_v1', 'prospective_acceptance_process_v1',
    'prospective_acceptance_coordinator_v1', 'prospective_acceptance_scratch_v1',
    'prospective_lsf_memory_preflight_v1', 'prospective_acceptance_linux_e97')
FILES = frozenset(tuple('src/data/' + n + '.py' for n in DATA_MODULES) +
    tuple('tests/test_' + n + '.py' for n in TEST_MODULES) + (
    'src/__init__.py', 'src/data/__init__.py', 'tests/__init__.py', 'scripts/__init__.py',
    'tests/test_prospective_acquisition_tree_inputs_e85.py',
    'scripts/probe_acquisition_tree_inputs_e85.py', 'scripts/run_acceptance_job_e97.py', AUTH,
    'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json',
    'data/manifests/ranking_v6_e93_input_observation_20261023_r1.json'))


class DeployError(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise DeployError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _strict_headers(raw):
    """Reject hidden extension records and concatenated/trailing tar payloads."""
    require(len(raw) % 512 == 0, 'TAR_BLOCK_BOUND')
    offset = 0
    while offset < len(raw):
        header = raw[offset:offset + 512]
        if header == b'\0' * 512:
            require(len(raw) - offset >= 1024 and not any(raw[offset:]), 'TAR_TRAILING_DATA')
            return
        require(header[156:157] in (b'0', b'\0'), 'TAR_NONREGULAR_HEADER')
        size_token = header[124:136].strip(b'\0 ')
        require(bool(size_token) and all(48 <= c <= 55 for c in size_token), 'TAR_SIZE_ENCODING')
        size = int(size_token, 8)
        require(size <= SOURCE_CAP, 'TAR_HEADER_SIZE')
        offset += 512 + ((size + 511) // 512) * 512
        require(offset <= len(raw), 'TAR_TRUNCATED')
    raise DeployError('TAR_END_REQUIRED')


def _unpack(config):
    require(type(config) is dict and set(config) == {'archive_b64', 'archive_sha256',
        'manifest_sha256', 'manifest_files', 'tar_bytes'}, 'CONFIG_KEYS')
    require(_digest(config['archive_sha256']) and _digest(config['manifest_sha256']), 'CONFIG_DIGEST')
    require(type(config['tar_bytes']) is int and 0 < config['tar_bytes'] <= TAR_CAP, 'TAR_BOUND')
    expected = config['manifest_files']
    require(type(expected) is dict and set(expected) == FILES and
            all(_digest(v) for v in expected.values()) and expected[AUTH] == AUTH_SHA256,
            'EXPECTED_MEMBER_MAP')
    encoded = config['archive_b64']
    require(type(encoded) is str and len(encoded) <= 4 * ((ARCHIVE_CAP + 2) // 3), 'BASE64_BOUND')
    try:
        archive = base64.b64decode(encoded.encode('ascii'), validate=True)
    except (ValueError, UnicodeError, binascii.Error):
        raise DeployError('BASE64_INVALID')
    require(len(archive) <= ARCHIVE_CAP and sha(archive) == config['archive_sha256'], 'ARCHIVE_PIN')
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    pieces = []
    total = 0
    pending = archive
    try:
        while pending:
            require(total < config['tar_bytes'], 'DECOMPRESSED_BOUND')
            chunk = inflater.decompress(pending, min(65536, config['tar_bytes'] - total))
            pieces.append(chunk)
            total += len(chunk)
            pending = inflater.unconsumed_tail
            if inflater.eof:
                require(not inflater.unused_data and not pending, 'GZIP_TRAILING_DATA')
                break
            require(bool(chunk) or bool(pending), 'GZIP_TRUNCATED')
    except zlib.error:
        raise DeployError('GZIP_INVALID')
    require(inflater.eof and not inflater.unused_data and total == config['tar_bytes'], 'GZIP_SIZE_OR_EOF')
    raw_tar = b''.join(pieces)
    _strict_headers(raw_tar)
    contents = {}
    source_bytes = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_tar), mode='r:') as bundle:
            for member in bundle:
                name = member.name
                require(name in FILES or name == MANIFEST, 'TAR_MEMBER_NAME')
                require(name not in contents and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                        and not member.pax_headers,
                        'TAR_TYPE_OR_DUPLICATE')
                cap = MANIFEST_CAP if name == MANIFEST else SOURCE_CAP
                require(type(member.size) is int and 0 <= member.size <= cap, 'TAR_MEMBER_BOUND')
                if name != MANIFEST:
                    source_bytes += member.size
                    require(source_bytes <= SOURCE_CAP, 'SOURCE_TOTAL_BOUND')
                stream = bundle.extractfile(member)
                require(stream is not None, 'TAR_MEMBER_STREAM')
                value = stream.read(member.size)
                require(len(value) == member.size, 'TAR_SHORT_MEMBER')
                contents[name] = value
                require(len(contents) <= len(FILES) + 1, 'TAR_MEMBER_COUNT')
    except (tarfile.TarError, EOFError):
        raise DeployError('TAR_INVALID')
    require(set(contents) == FILES | {MANIFEST}, 'TAR_MEMBER_SET')
    require(sha(contents[MANIFEST]) == config['manifest_sha256'], 'MANIFEST_PIN')
    try:
        manifest = json.loads(contents[MANIFEST].decode('utf-8'), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError):
        raise DeployError('MANIFEST_JSON')
    require(type(manifest) is dict and set(manifest) == {'schema', 'files'} and
            manifest['schema'] == 'e97-code-manifest-v1' and manifest['files'] == expected,
            'MANIFEST_CONTENT')
    require(all(sha(contents[name]) == expected[name] for name in FILES), 'MEMBER_PIN')
    require(sha(contents[AUTH]) == AUTH_SHA256, 'AUTHORIZATION_PIN')
    for name in ('src/__init__.py', 'src/data/__init__.py', 'tests/__init__.py', 'scripts/__init__.py'):
        require(contents[name] == b'', 'NONEMPTY_INIT')
    return contents


def _check_directory(fd):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o700, 'DIRECTORY_OWNER_MODE')


def _open_parent():
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in ROOT.rsplit('/', 1)[0].split('/')[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_file(root_fd, name, raw):
    parent = os.dup(root_fd)
    fd = None
    try:
        _check_directory(parent)
        parts = name.split('/')
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            _check_directory(child)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600,
                'FILE_OWNER_MODE')
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:offset + 65536])
            require(type(count) is int and 0 < count <= min(65536, len(raw) - offset), 'SHORT_WRITE')
            offset += count
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        left = len(raw)
        while left:
            chunk = os.read(fd, min(65536, left))
            require(bool(chunk) and len(chunk) <= left, 'READBACK_BOUND')
            digest.update(chunk)
            left -= len(chunk)
        after = os.fstat(fd)
        named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        require(after.st_size == len(raw) and after.st_nlink == 1 and
                (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) ==
                (named.st_dev, named.st_ino) and digest.hexdigest() == sha(raw), 'READBACK_IDENTITY')
        os.fsync(parent)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def deploy(config):
    require(sys.platform.startswith('linux') and platform.node() == 'bupt-vncs2', 'LINUX_HOST_REQUIRED')
    contents = _unpack(config)  # All source and archive validation precedes writes.
    parent = _open_parent()
    root = None
    try:
        os.mkdir(ROOT.rsplit('/', 1)[1], 0o700, dir_fd=parent)  # Collision is fatal; never resume.
        os.fsync(parent)
        root = os.open(ROOT.rsplit('/', 1)[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                       dir_fd=parent)
        _check_directory(root)
        for name in sorted(contents):
            _write_file(root, name, contents[name])
        os.fsync(root)
        return dict(schema='e97-bundle-deployment-v1', status='DEPLOYED_ONLY', root=ROOT,
            manifest_sha256=config['manifest_sha256'], files=len(contents),
            bytes=sum(len(value) for value in contents.values()), jobs_submitted=0)
    finally:
        if root is not None:
            os.close(root)
        os.close(parent)
