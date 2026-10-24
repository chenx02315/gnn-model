"""Offline E97 exact-allowset bundle builder. No deployment or execution.

Main creates only a new fixed local stage, exclusively; never overwrites it.
"""
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT.parent / 'runtime_training_staging_20260928' / 'v6_e97_execution_bundle_20261024_r1'
SOURCE_CAP = 1048576
TAR_CAP = 2097152
GZIP_CAP = 524288


class BundleError(Exception):
    pass


def require(ok, code):
    if not ok:
        raise BundleError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True) + '\n').encode('ascii')


def safe_name(name):
    require(type(name) is str and len(name) <= 240 and
            re.fullmatch(r'[A-Za-z0-9_./-]+', name) is not None and
            not name.startswith('/') and
            all(p not in ('', '.', '..') for p in name.split('/')),
            'E97_UNSAFE_MEMBER')


def read_source(name, cap):
    safe_name(name)
    path = ROOT
    require(not path.is_symlink() and path.is_dir(), 'E97_ROOT_TYPE')
    parts = name.split('/')
    for index, component in enumerate(parts):
        path = path / component
        row = path.lstat()
        require(not stat.S_ISLNK(row.st_mode), 'E97_SOURCE_SYMLINK')
        if index < len(parts) - 1:
            require(stat.S_ISDIR(row.st_mode), 'E97_SOURCE_PARENT')
    require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and
            0 <= row.st_size <= cap, 'E97_SOURCE_TYPE_OR_CAP')
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno())
        require((row.st_dev, row.st_ino) == (opened.st_dev, opened.st_ino),
                'E97_SOURCE_REPLACED')
        raw = handle.read(row.st_size)
        after = os.fstat(handle.fileno())
    named = path.lstat()
    require(len(raw) == row.st_size and stable_source(row, opened, after, named),
            'E97_SOURCE_CHANGED')
    return raw


def stable_source(named_before, fd_before, fd_after, named_after):
    identity = lambda r: (r.st_dev, r.st_ino, r.st_mode, r.st_nlink,
                          r.st_size, r.st_mtime_ns)
    rows = (named_before, fd_before, fd_after, named_after)
    if not all(identity(row) == identity(named_before) for row in rows):
        return False
    if os.name == 'nt':
        # Windows may expose creation time via lstat but modified time via
        # fstat. Each view must remain stable; do not compare unlike views.
        return (named_before.st_ctime_ns == named_after.st_ctime_ns and
                fd_before.st_ctime_ns == fd_after.st_ctime_ns)
    return all(row.st_ctime_ns == named_before.st_ctime_ns for row in rows)


def load_module(name, member):
    # Fixed repository-only imports; module main guards are not executed.
    spec = importlib.util.spec_from_file_location(name, str(ROOT / member))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assemble(snapshot, entry, compiler):
    require(type(snapshot) is dict and set(snapshot) == set(entry.FILES),
            'E97_EXACT_ALLOWSET')
    require('e97_code_manifest.json' not in snapshot, 'E97_MANIFEST_COLLISION')
    for name, raw in snapshot.items():
        safe_name(name)
        require(type(raw) is bytes, 'E97_SOURCE_BYTES')
    require(all(snapshot[name] == b'' for name in entry.EMPTY), 'E97_EMPTY_INITS')
    for name, pin in ((entry.AUTH, entry.AUTH_SHA256),
                      (entry.E85, compiler.E85_SHA256),
                      (entry.E93, compiler.E93_SHA256)):
        require(sha(snapshot[name]) == pin, 'E97_IDENTITY_PIN')
    manifest = canonical_json({'schema': 'e97-code-manifest-v1',
                              'files': dict((n, sha(snapshot[n])) for n in sorted(snapshot))})
    require(sum(len(v) for v in snapshot.values()) + len(manifest) <= SOURCE_CAP,
            'E97_SOURCE_CAP')
    members = dict(snapshot)
    members['e97_code_manifest.json'] = manifest
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(members):
            item = tarfile.TarInfo(name)
            item.size = len(members[name])
            item.mode = 0o600
            item.uid = item.gid = item.mtime = 0
            item.uname = item.gname = ''
            archive.addfile(item, io.BytesIO(members[name]))
    tar = stream.getvalue()
    require(len(tar) <= TAR_CAP, 'E97_TAR_CAP')
    compressed = io.BytesIO()
    with gzip.GzipFile(filename='', fileobj=compressed, mode='wb', mtime=0,
                       compresslevel=9) as zipped:
        zipped.write(tar)
    bundle = compressed.getvalue()
    require(len(bundle) <= GZIP_CAP, 'E97_GZIP_CAP')
    receipt = {'schema': 'e97-local-bundle-receipt-v1',
               'manifest_sha256': sha(manifest), 'archive_sha256': sha(bundle),
               'manifest_bytes': len(manifest), 'archive_bytes': len(bundle),
               'tar_bytes': len(tar), 'member_count': len(members),
               'remote_writes': 0, 'jobs_submitted': 0, 'programs_launched': 0,
               'execution_ready': False, 'training_release': False}
    return {'manifest_bytes': manifest, 'archive_bytes': bundle, 'receipt': receipt}


def build():
    entry = load_module('e97_bundle_entry', 'scripts/run_acceptance_job_e97.py')
    compiler = load_module('e97_bundle_compiler', 'src/data/prospective_tessent_acceptance_v1.py')
    snapshot = {}
    total = 0
    for name in sorted(entry.FILES):
        safe_name(name)
        raw = b'' if name in entry.EMPTY else read_source(name, SOURCE_CAP - total)
        snapshot[name] = raw
        total += len(raw)
        require(total <= SOURCE_CAP, 'E97_SOURCE_CAP')
    return assemble(snapshot, entry, compiler)


def main():
    result = build()
    require(STAGE.parent.is_dir() and not STAGE.parent.is_symlink(), 'E97_STAGE_PARENT')
    STAGE.mkdir()  # Exclusive: an existing stage always fails, including symlinks.
    for name, raw in (('e97_execution_bundle.tar.gz', result['archive_bytes']),
                      ('e97_code_manifest.json', result['manifest_bytes']),
                      ('e97_local_bundle_receipt.json', canonical_json(result['receipt']))):
        with (STAGE / name).open('xb') as handle:
            handle.write(raw)
    print(json.dumps(result['receipt'], sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
