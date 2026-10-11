"""TRAIN-task-scoped pinned Torch JIT admission v2, isolated process only.

The caller authenticates this helper, the old context/helpers and source snapshot.
This is not a sandbox, dependency seal, TRAIN authorization or Linux resource proof.
No general temporary-directory import path is admitted.
"""
from contextlib import contextmanager
import hashlib
import importlib.machinery as machinery
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
from types import FunctionType, ModuleType, SimpleNamespace


GENERATED_NAME = '_remote_module_non_scriptable'
GENERATED_SHA256 = '8205b16956fb264841ecd8644784a0d157f87df79b17c16825dc1163433ce5d8'
GENERATED_BYTES = 2355
SOURCE_PINS = {
    'torch.distributed.nn.jit.instantiator': (5459, '440a619c764e4133564d7956ba060a7223e94664854b94a4a2074d095756db7e'),
    'torch.distributed.nn.jit.templates.remote_module_template': (3463, '0ff1856bbd031b5298d46c06c0502abc20bd804f42c1949ed4127e8c773660cc'),
}
MAX_SOURCE_BYTES = 8192
_ACTIVE = False
_VERIFY = None
SOURCE_ROOT = '/ssd/cjc/gnn_model_ranking_v5_train_20261011_r1'
FAMILIES = ('iwls_aes_core', 'iscas89_s13207', 'iscas89_s15850', 'iscas89_s35932',
            'iscas89_s38417', 'iwls_spi')
SEEDS = (20260824, 20260825, 20260826)
TASK_ROOTS = frozenset(SOURCE_ROOT + '/jit_tmp/' + family + '_' + str(seed)
                       for family in FAMILIES for seed in SEEDS)


def _require(condition, token):
    if not condition:
        raise ValueError('V5_JIT_' + token)


def _root(value):
    _require(type(value) is str and len(value) <= 2048 and value in TASK_ROOTS,
             'ROOT')
    return value


def _ordinary(value, directory=False):
    path = Path(value)
    for item in (path, *path.parents):
        _require(not item.is_symlink(), 'SYMLINK')
    info = path.lstat()
    _require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'ORDINARY')
    _require(path.resolve(strict=True).as_posix() == value, 'REALPATH')
    if not directory:
        _require(info.st_nlink == 1, 'HARDLINK')
    return info


def _read(value, expected_size, expected_sha):
    """Bounded regular-file read; no generated source loader filesystem reread."""
    before = _ordinary(value)
    _require(before.st_size == expected_size and 0 < expected_size <= MAX_SOURCE_BYTES, 'SOURCE_SIZE')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(value, flags)
    try:
        opened = os.fstat(fd)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        _require(identity(before) == identity(opened) and stat.S_ISREG(opened.st_mode)
                 and opened.st_nlink == 1, 'SOURCE_IDENTITY')
        parts, total = [], 0
        while total <= expected_size:
            part = os.read(fd, expected_size + 1 - total)
            if not part:
                break
            parts.append(part)
            total += len(part)
        raw = b''.join(parts)
        _require(identity(opened) == identity(os.fstat(fd)), 'SOURCE_IDENTITY')
    finally:
        os.close(fd)
    _require(identity(before) == identity(_ordinary(value)), 'SOURCE_IDENTITY')
    _require(len(raw) == expected_size and hashlib.sha256(raw).hexdigest() == expected_sha, 'SOURCE_HASH')
    return raw


def _private(value):
    info = _ordinary(value, directory=True)
    _require(sys.platform == 'linux' and info.st_uid == os.getuid()
             and info.st_mode & 0o077 == 0, 'PRIVATE_DIRECTORY')


def _pinned_modules(base):
    instantiator = None
    template = None
    for name, (size, digest) in SOURCE_PINS.items():
        module = sys.modules.get(name)
        origin = base.SITE_ROOT + '/' + name.replace('.', '/') + '.py'
        _require(type(module) is ModuleType, 'PINNED_MODULE')
        spec = module.__dict__.get('__spec__')
        _require(spec is not None and spec.name == name and spec.origin == origin
                 and type(spec.loader) is machinery.SourceFileLoader
                 and spec.loader.name == name and spec.loader.path == origin
                 and spec.submodule_search_locations is None
                 and module.__dict__.get('__file__') == origin
                 and module.__dict__.get('__loader__') is spec.loader, 'PINNED_ORIGIN')
        _read(origin, size, digest)
        if name.endswith('.instantiator'):
            instantiator = module
        else:
            template = module
    function = template.__dict__.get('get_remote_module_template')
    _require(instantiator.__dict__.get('_FILE_PREFIX') == '_remote_module_'
             and type(function) is FunctionType
             and function.__name__ == 'get_remote_module_template'
             and function.__module__ == template.__name__
             and function.__code__.co_filename == base.SITE_ROOT + '/' + template.__name__.replace('.', '/') + '.py'
             and function.__globals__ is template.__dict__
             and instantiator.__dict__.get('get_remote_module_template') is function, 'TEMPLATE_BINDING')
    return instantiator


def verify_generated_template(receipt):
    """Revalidate cache/source identity inside the active context, before save."""
    _require(_ACTIVE and _VERIFY is not None, 'VERIFY_CONTEXT')
    _VERIFY(receipt)


validate_current = verify_generated_template


class _SnapshotLoader(machinery.SourceFileLoader):
    def __init__(self, origin, raw):
        super().__init__(GENERATED_NAME, origin)
        self._raw = raw
        self._code = compile(raw, origin, 'exec')
        self._executed_module = None

    def get_code(self, fullname):
        _require(fullname == GENERATED_NAME, 'LOADER_NAME')
        return self._code

    def get_data(self, path):
        _require(path == self.path, 'LOADER_PATH')
        return self._raw

    def exec_module(self, module):
        _require(module.__name__ == GENERATED_NAME, 'LOADER_NAME')
        exec(self._code, module.__dict__)
        self._executed_module = module


@contextmanager
def controlled_imports(source_bytes, pins, *, frozen_helper, observation_helper,
                       lock_raw, base_context, jit_root, generated_raw):
    """Preserve old fixed metadata gate, adding only the exact pinned JIT module.

    The mutable receipt is completed after successful generated execution and
    exit validation. Paths and the old finder class are restored on every exit.
    """
    global _ACTIVE, _VERIFY
    _root(jit_root)  # Refuse denied roots before any filesystem operation.
    _require(not _ACTIVE and type(base_context) is ModuleType
             and type(observation_helper) is ModuleType, 'CONTEXT')
    _require(type(generated_raw) is bytes and len(generated_raw) == GENERATED_BYTES
             and hashlib.sha256(generated_raw).hexdigest() == GENERATED_SHA256, 'SNAPSHOT')
    fixed = observation_helper.SEARCH_PATHS
    observation_helper._search_paths(sys.path)
    _require(type(fixed) is tuple and len(fixed) == 5, 'BASE_PATHS')
    _require(GENERATED_NAME not in sys.modules, 'PRELOADED_GENERATED')
    _require(os.environ.get('TMPDIR') == jit_root
             and all(os.environ.get(name) in (None, jit_root) for name in ('TMP', 'TEMP'))
             and tempfile.tempdir in (None, jit_root), 'TEMP_ENVIRONMENT')
    _private(jit_root)
    _require(tempfile.gettempdir() == jit_root, 'TEMP_DEFAULT')
    facade = ModuleType(observation_helper.__name__)
    facade.__dict__.update(observation_helper.__dict__)
    receipt = dict(jit_template_proven=False, generated_source_sha256=GENERATED_SHA256,
                   generated_source_bytes=GENERATED_BYTES, jit_root=jit_root,
                   jit_temp_dir=None, installed_source_pins={name: digest for name, (_, digest) in SOURCE_PINS.items()},
                   formal_training_release=False, actual_linux_resource_proof=False)
    origin_used = [None]
    loader_used = [None]

    def search_paths(paths):
        _require(type(paths) is list and len(paths) in (5, 6)
                 and all(type(item) is str for item in paths) and tuple(paths[:5]) == fixed, 'SEARCH_PATHS')
        if len(paths) == 5:
            _require(receipt['jit_temp_dir'] is None, 'TEMP_REMOVED')
            return
        extra = paths[5]
        _require(len(extra) <= 2048 and re.fullmatch(re.escape(jit_root) + r'/tmp[a-z0-9_]{8}', extra) is not None
                 and PurePosixPath(extra).as_posix() == extra, 'TEMP_PATH')
        instantiator = _pinned_modules(base_context)
        temp = instantiator.__dict__.get('_TEMP_DIR')
        _require(type(temp) is tempfile.TemporaryDirectory
                 and type(getattr(temp, 'name', None)) is str and temp.name == extra
                 and instantiator.__dict__.get('INSTANTIATED_TEMPLATE_DIR_PATH') == extra, 'TEMP_OWNER')
        _private(jit_root)
        _private(extra)
        if receipt['jit_temp_dir'] is not None:
            _require(receipt['jit_temp_dir'] == extra, 'TEMP_CHANGED')
        receipt['jit_temp_dir'] = extra

    facade._search_paths = search_paths
    old_finder = base_context._RuntimeFinder
    # Rebind only this inherited method's machinery reference. Never patch global
    # PathFinder, stdlib imports, sys.path during delegated lookup, or Torch.
    class FixedPathFinder:
        @staticmethod
        def find_spec(name, path=None, target=None):
            return machinery.PathFinder.find_spec(name, list(fixed) if path is None else path, target)
    machine_facade = SimpleNamespace(**vars(machinery))
    machine_facade.PathFinder = FixedPathFinder
    inherited_globals = dict(old_finder.find_spec.__globals__)
    inherited_globals['machinery'] = machine_facade
    inherited = FunctionType(old_finder.find_spec.__code__, inherited_globals,
                             old_finder.find_spec.__name__, old_finder.find_spec.__defaults__)

    class Finder(old_finder):
        def find_spec(self, fullname, path=None, target=None):
            search_paths(sys.path)
            _require(type(fullname) is str, 'MODULE_NAME')
            if fullname != GENERATED_NAME:
                return inherited(self, fullname, path, target)
            _require(path is None and target is None and len(sys.path) == 6, 'GENERATED_IMPORT')
            origin = sys.path[5] + '/' + GENERATED_NAME + '.py'
            raw = _read(origin, GENERATED_BYTES, GENERATED_SHA256)
            _require(raw == generated_raw, 'GENERATED_BYTES')
            loader = _SnapshotLoader(origin, raw)
            _require(loader_used[0] is None, 'GENERATED_RELOAD')
            loader_used[0] = loader
            origin_used[0] = origin
            spec = machinery.ModuleSpec(fullname, loader, origin=origin)
            spec.has_location = True
            return spec

    def proof(candidate):
        _require(candidate is receipt, 'VERIFY_RECEIPT')
        receipt['jit_template_proven'] = False
        search_paths(sys.path)
        _require(len(sys.path) == 6 and origin_used[0] == sys.path[5] + '/' + GENERATED_NAME + '.py',
                 'GENERATED_PATH_PROOF')
        module = sys.modules.get(GENERATED_NAME)
        _require(type(module) is ModuleType and origin_used[0] is not None, 'GENERATED_MISSING')
        spec = module.__dict__.get('__spec__')
        _require(spec is not None and spec.name == GENERATED_NAME and spec.origin == origin_used[0]
                 and spec.loader is loader_used[0] and type(spec.loader) is _SnapshotLoader
                 and spec.loader.path == origin_used[0]
                 and spec.loader._raw == generated_raw and spec.submodule_search_locations is None
                 and spec.loader._executed_module is module
                 and module.__dict__.get('__file__') == origin_used[0]
                 and module.__dict__.get('__loader__') is spec.loader, 'GENERATED_PROOF')
        _read(origin_used[0], GENERATED_BYTES, GENERATED_SHA256)
        receipt['jit_template_proven'] = True

    completed = False
    try:
        _ACTIVE = True
        _VERIFY = proof
        base_context._RuntimeFinder = Finder
        with base_context.controlled_imports(source_bytes, pins, frozen_helper=frozen_helper,
                observation_helper=facade, lock_raw=lock_raw) as old_receipt:
            receipt.update(dict(old_receipt))
            yield receipt
            proof(receipt)
        completed = True
    finally:
        if not completed:
            receipt['jit_template_proven'] = False
        own_tail = receipt['jit_temp_dir']
        if (own_tail is not None and type(sys.path) is list and len(sys.path) == 6
                and tuple(sys.path[:5]) == fixed and sys.path[5] == own_tail):
            sys.path.pop()
        own_loader = loader_used[0]
        if (own_loader is not None and own_loader._executed_module is not None
                and sys.modules.get(GENERATED_NAME) is own_loader._executed_module):
            del sys.modules[GENERATED_NAME]
        base_context._RuntimeFinder = old_finder
        _VERIFY = None
        _ACTIVE = False
