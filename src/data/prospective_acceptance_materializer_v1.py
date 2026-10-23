"""Physical, exclusive E94 publication. No process launch or approval inference.

Authorization is a caller assertion, not proof of user approval. Linux anchored
IO is mandatory; failed partial bundles are retained and cannot be retried.
"""
import hashlib
import json
import os
import stat
import sys

from . import prospective_tessent_acceptance_v1 as compiler
from . import prospective_fault_translation_v2 as translation
from .prospective_lsf_memory_preflight_v1 import collect_preflight

RECIPE_SHA256 = '67c927c315354adf9ad09466fa679e46c3417d64065d0cb44819af8a3e65271e'
CHUNK = 65536
MAX_FILE = 128 * 1024 * 1024
MAX_TREE = 128 * 1024 * 1024
MAX_VERIFY_TREE_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_DEPTH = 24
require = compiler.require
sha = compiler.sha
canonical = compiler.canonical


def _identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size,
            s.st_mtime_ns, s.st_ctime_ns)


def _directory(path):
    require(sys.platform.startswith('linux') and hasattr(os, 'O_NOFOLLOW'),
            'ANCHORED_LINUX_REQUIRED')
    require(type(path) is str and path.startswith('/') and '\x00' not in path
            and all(p not in ('', '.', '..') for p in path.split('/')[1:]),
            'ABSOLUTE_CANONICAL_PATH_REQUIRED')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.split('/')[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_at(parent, name, budget, sink=None, expected_bytes=None, max_bytes=MAX_TREE):
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1,
            'SINGLE_LINK_REGULAR_REQUIRED')
    require(expected_bytes is None or named.st_size == expected_bytes,
            'PINNED_SIZE_MISMATCH')
    require(named.st_size <= MAX_FILE and budget[0] + named.st_size <= max_bytes,
            'BYTE_BOUND')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    blocks = []
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        require(_identity(named) == _identity(before), 'SOURCE_CHANGED')
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(CHUNK, remaining))
            require(bool(block), 'SHORT_READ')
            remaining -= len(block)
            budget[0] += len(block)
            digest.update(block)
            if sink is None:
                blocks.append(block)
            else:
                _write_all(sink, block)
        require(_identity(before) == _identity(os.fstat(fd)) ==
                _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                'SOURCE_CHANGED')
        return b''.join(blocks), before.st_size, digest.hexdigest()
    finally:
        os.close(fd)


def _read(path, expected_bytes=None):
    parent, name = path.rsplit('/', 1)
    fd = _directory(parent)
    try:
        return _read_at(fd, name, [0], expected_bytes=expected_bytes)[0]
    finally:
        os.close(fd)


def _write_all(fd, raw):
    while raw:
        n = os.write(fd, raw)
        require(n > 0, 'SHORT_WRITE')
        raw = raw[n:]


def _publish(fd, name, raw):
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                  0o600, dir_fd=fd)
    try:
        _write_all(out, raw)
        os.fsync(out)
    finally:
        os.close(out)
    os.fsync(fd)
    require(_read_at(fd, name, [0])[2] == sha(raw), 'PUBLICATION_REREAD_SHA')


def _mkdir(fd, name):
    os.mkdir(name, 0o700, dir_fd=fd)
    os.fsync(fd)
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)


def _tree_digest(rows):
    # E85 commits sorted-child depth-first visitation, NOT global path sorting.
    return sha(canonical(rows))


def _tree(source, destination=None, expected_bytes=MAX_TREE,
          expected_files=MAX_ENTRIES, expected_directories=MAX_ENTRIES):
    """Hash and optionally copy an anchored tree; all bodies are chunk bounded."""
    rows, budget, entries, counts = [], [0], [0], [0, 0]

    def visit(fd, dest, relative, depth):
        require(depth <= MAX_DEPTH, 'TREE_DEPTH_BOUND')
        counts[1] += 1
        require(counts[1] <= expected_directories, 'TREE_PINNED_DIRECTORY_BOUND')
        before = os.fstat(fd)
        rows.append([relative, 'directory', 0, None])
        names = []
        with os.scandir('/proc/self/fd/%d' % fd) as stream:
            for entry in stream:
                entries[0] += 1
                require(entries[0] <= MAX_ENTRIES, 'TREE_ENTRY_BOUND')
                require(entries[0] < expected_files + expected_directories,
                        'TREE_PINNED_ENTRY_BOUND')
                names.append(entry.name)
        for name in sorted(names):
            require(name not in ('.', '..') and '/' not in name and
                    '\x00' not in name and len(name) <= 255 and
                    name.lower() not in ('.ssh', 'ssh', 'token', 'tokens', 'private_key', 'id_rsa', 'log', 'logs') and
                    not name.lower().startswith('logs_') and
                    not name.lower().endswith(('.log', '.ckpt', '.pt', '.pth')) and
                    not any(t in name.lower() for t in
                            ('blind', 'checkpoint', 'secret', 'credential', 'outcome')),
                    'PROTECTED_OR_INVALID_TREE_NAME')
            rel = relative + '/' + name if relative else name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                require(counts[1] < expected_directories, 'TREE_PINNED_DIRECTORY_BOUND')
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                target = None
                try:
                    require(_identity(info) == _identity(os.fstat(child)), 'SOURCE_CHANGED')
                    if dest is not None:
                        target = _mkdir(dest, name)
                    visit(child, target, rel, depth + 1)
                    require(_identity(info) == _identity(os.stat(name, dir_fd=fd, follow_symlinks=False)), 'SOURCE_CHANGED')
                finally:
                    os.close(child)
                    if target is not None:
                        os.close(target)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'TREE_SPECIAL_OR_HARDLINK')
                counts[0] += 1
                require(counts[0] <= expected_files, 'TREE_PINNED_FILE_BOUND')
                require(budget[0] + info.st_size <= expected_bytes, 'TREE_PINNED_BYTE_BOUND')
                out = None
                try:
                    if dest is not None:
                        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dest)
                    _, size, digest = _read_at(fd, name, budget, out, max_bytes=expected_bytes)
                    if out is not None:
                        os.fsync(out)
                    rows.append([rel, 'file', size, digest])
                finally:
                    if out is not None:
                        os.close(out)
        require(_identity(before) == _identity(os.fstat(fd)), 'SOURCE_DIRECTORY_CHANGED')
        if dest is not None:
            os.fsync(dest)
    source_fd = _directory(source)
    try:
        visit(source_fd, destination, '', 0)
        named_fd = _directory(source)
        try:
            require(_identity(os.fstat(source_fd)) == _identity(os.fstat(named_fd)), 'SOURCE_ROOT_REPLACED')
        finally:
            os.close(named_fd)
    finally:
        os.close(source_fd)
    return _tree_digest(rows)


def verify_materialized_item(item):
    for path, pin in ((compiler.LAUNCHER, item['launcher_sha256']),
                      (compiler.LIBRARY, item['library_sha256']),
                      (item['common_basic_path'], item['common_basic_sha256']),
                      (item['tcl_path'], item['tcl_sha256']),
                      (item['translated_status_path'], item['translated_status_sha256']),
                      (item['translation_manifest_path'], item['translation_manifest_sha256'])):
        require(sha(_read(path)) == pin, 'PHYSICAL_PIN_MISMATCH')
    require(_tree(item['isolated_tsdb_copy'], expected_bytes=MAX_VERIFY_TREE_BYTES,
                  expected_files=item['tsdb_source_regular_files'],
                  expected_directories=item['tsdb_source_directories']) == item['tsdb_source_tree_sha256'], 'COPY_TREE_SHA')
    return dict(verified=True, execution_ready=False)


class Materializer(object):
    def __init__(self, raw_e85, raw_e93, authorization):
        self.recipe = compiler.compile_acceptance(raw_e85, raw_e93,
            compiler.E85_SHA256, compiler.E93_SHA256)
        require(self.recipe['recipe_sha256'] == RECIPE_SHA256, 'RECIPE_PIN')
        require(type(authorization) is dict, 'EXPLICIT_AUTHORIZATION_REQUIRED')
        expected = dict(schema='e96-acceptance-authorization-v1', approved=True,
            job_id=authorization.get('job_id'), memory_cap_bytes=authorization.get('memory_cap_bytes'),
            recipe_sha256=RECIPE_SHA256, scope='E94_FOUR_NO_PATTERN_ACCEPTANCE_ONLY')
        require(authorization == expected and authorization.get('approved') is True and
                type(expected['job_id']) is int and expected['job_id'] > 0 and
                type(expected['memory_cap_bytes']) is int and expected['memory_cap_bytes'] > 0,
                'AUTHORIZATION_SCOPE')
        self.authorization = dict(authorization)
        self.e85 = json.loads(raw_e85.decode('ascii'))
        self.e93 = json.loads(raw_e93.decode('ascii'))
        self.root_fd = self.scratch_fd = None
        self.failed = False

    def _preflight(self):
        result = collect_preflight(self.authorization['job_id'], self.authorization['memory_cap_bytes'])
        require(result.get('memory_preflight_passed') is True and
                result.get('job_id') == self.authorization['job_id'] and
                result.get('approved_memory_cap_bytes') == self.authorization['memory_cap_bytes'], 'FRESH_PREFLIGHT_REQUIRED')
        return result

    def _owned_bundle(self):
        require(self.root_fd is not None and self.scratch_fd is not None, 'BUNDLE_NOT_ACTIVE')
        for path, held in ((compiler.ROOT, self.root_fd), (compiler.ROOT + '/scratch', self.scratch_fd)):
            fd = _directory(path)
            try:
                require(os.fstat(fd).st_ino == os.fstat(held).st_ino and
                        os.fstat(fd).st_dev == os.fstat(held).st_dev, 'BUNDLE_REPLACED')
            finally:
                os.close(fd)

    def initialize_bundle(self):
        require(self.root_fd is None and not self.failed, 'BUNDLE_ALREADY_INITIALIZED')
        preflight = self._preflight()
        parent, name = compiler.ROOT.rsplit('/', 1)
        fd = _directory(parent)
        try:
            self.root_fd = _mkdir(fd, name)
            _publish(self.root_fd, 'materialization_header.json', canonical(dict(
                authorization=self.authorization, preflight=preflight, recipe_sha256=RECIPE_SHA256)) + b'\n')
            self.scratch_fd = _mkdir(self.root_fd, 'scratch')
        except BaseException:
            self.failed = True
            raise
        finally:
            os.close(fd)
        return self.recipe

    def materialize_item(self, circuit, transition):
        require(self.root_fd is not None and self.scratch_fd is not None and not self.failed, 'BUNDLE_NOT_ACTIVE')
        selected = [x for x in self.recipe['items'] if x['circuit'] == circuit and x['transition'] == transition]
        require(len(selected) == 1, 'EXACT_SELECTOR_REQUIRED')
        item = selected[0]
        preflight = self._preflight()
        self._owned_bundle()
        item_fd = inputs_fd = tree_fd = None
        try:
            # All source bytes and computed translation are checked before writes.
            for path, pin, size in ((compiler.LAUNCHER, compiler.LAUNCHER_SHA256, self.e85['binary']['bytes']),
                                    (compiler.LIBRARY, compiler.LIBRARY_SHA256, self.e85['library']['bytes'])):
                require(sha(_read(path, expected_bytes=size)) == pin, 'SOURCE_PIN')
            base = compiler.PHASE4 + '/' + circuit
            common = base + '/03_fault_universe/common_' + circuit + '_m16_phase4_v2'
            paths = dict(manifest=common + '/manifest.json', mapping=common + '/canonical_fault_mapping.tsv',
                source_mtfi=base + '/04_single_mode/H_' + circuit + '_H_full_phase4_v2/faults.mtfi',
                target_basic=item['common_basic_path'])
            pins = {r['role']: r for r in self.e93['input_files'] if r['circuit'] == circuit}
            raw = {k: _read(p, expected_bytes=pins[item['target_mode'] + '_basic' if k == 'target_basic' else k]['bytes'])
                   for k, p in paths.items()}
            for role, body in raw.items():
                pin = pins[item['target_mode'] + '_basic' if role == 'target_basic' else role]
                require(len(body) == pin['bytes'] and sha(body) == pin['sha256'], 'INPUT_PIN')
            manifest = json.loads(raw['manifest'].decode('utf-8'))
            candidate = translation.translate(raw['mapping'], raw['source_mtfi'], raw['target_basic'],
                'H', item['target_mode'], item['expected_common_count'], manifest['f_flat_instance_offset'],
                {k: sha(raw[k]) for k in ('mapping', 'source_mtfi', 'target_basic')})
            require(candidate['output_mtfi_sha256'] == item['translated_status_sha256'] and
                    candidate['manifest_sha256'] == item['translation_manifest_sha256'], 'TRANSLATION_OUTPUT_PIN')
            tree_pin = [r for r in self.e85['tsdb_trees'] if r['root'] == item['tsdb_source_root']][0]
            tree_bounds = dict(expected_bytes=tree_pin['body_bytes'],
                expected_files=item['tsdb_source_regular_files'],
                expected_directories=item['tsdb_source_directories'])
            item_fd = _mkdir(self.scratch_fd, circuit + '_' + item['target_mode'])
            inputs_fd = _mkdir(item_fd, 'inputs')
            tree_fd = _mkdir(item_fd, 'isolated_tsdb')
            require(_tree(item['tsdb_source_root'], tree_fd, **tree_bounds) == item['tsdb_source_tree_sha256'], 'SOURCE_TREE_SHA')
            require(_tree(item['isolated_tsdb_copy'], **tree_bounds) == item['tsdb_source_tree_sha256'], 'COPY_TREE_SHA')
            require(_tree(item['tsdb_source_root'], **tree_bounds) == item['tsdb_source_tree_sha256'], 'SOURCE_REREAD_TREE_SHA')
            _publish(inputs_fd, 'translated_status.mtfi', candidate['output_mtfi_bytes'])
            _publish(inputs_fd, 'translation_manifest.json', candidate['manifest_bytes'])
            _publish(item_fd, 'accept_translated_status.tcl', item['tcl_bytes'])
            verify_materialized_item(item)
            _publish(item_fd, 'materialization_receipt.json', canonical(dict(status='PUBLISHED_NOT_EXECUTED',
                recipe_sha256=RECIPE_SHA256, circuit=circuit, transition=transition, preflight=preflight)) + b'\n')
            return dict(item)
        except BaseException as exc:
            self.failed = True
            if item_fd is not None:
                try:
                    _publish(item_fd, 'materialization_failed.json', canonical(dict(status='FAILED_NO_RETRY', error_type=type(exc).__name__)) + b'\n')
                except (OSError, ValueError):
                    pass
            raise
        finally:
            for fd in (tree_fd, inputs_fd, item_fd):
                if fd is not None:
                    os.close(fd)

    def close(self):
        for name in ('scratch_fd', 'root_fd'):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def journal_directory_fd(self):
        require(self.root_fd is not None and not self.failed, 'BUNDLE_NOT_ACTIVE')
        self._owned_bundle()
        return os.dup(self.root_fd)
