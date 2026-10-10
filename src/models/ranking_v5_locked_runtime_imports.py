"""Controlled import protocol for frozen sources and a fixed dependency root.

Externally authenticate this module, both helper modules, and lock bytes before
calling. Dedicated isolated process only; no concurrent imports or mutation of
import machinery. This is not a hostile-code sandbox, dependency-content seal,
native-library audit, resource proof, consent, or a formal training release.
The synthetic import fence is neither entered nor modified here.
"""
from contextlib import contextmanager
import importlib.abc
import importlib.machinery as machinery
import importlib.util
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from types import MappingProxyType, ModuleType


SITE_ROOT = '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages'
STDLIB_ROOT = '/usr/lib/python3.11'
MAX_CACHED_MODULES = 2048
ROOT_DISTRIBUTIONS = MappingProxyType({
    'jinja2': ('jinja2',), 'markupsafe': ('markupsafe',),
    'cloudpickle': ('cloudpickle',), 'filelock': ('filelock',),
    'fsspec': ('fsspec',), 'joblib': ('joblib',), 'mpmath': ('mpmath',),
    'networkx': ('networkx',), 'numpy': ('numpy',), 'pip': ('pip',),
    'sklearn': ('scikit-learn',), 'scipy': ('scipy',),
    'setuptools': ('setuptools',), '_distutils_hack': ('setuptools',),
    'pkg_resources': ('setuptools',), 'sympy': ('sympy',),
    'threadpoolctl': ('threadpoolctl',), 'torch': ('torch',),
    'torchgen': ('torch',),  # Installed by the same pinned Torch distribution.
    'triton': ('triton',), 'typing_extensions': ('typing-extensions',),
    'xgboost': ('xgboost',),
    'nvidia': ('nvidia-cublas-cu12', 'nvidia-cuda-cupti-cu12', 'nvidia-cuda-nvrtc-cu12',
               'nvidia-cuda-runtime-cu12', 'nvidia-cudnn-cu12', 'nvidia-cufft-cu12',
               'nvidia-curand-cu12', 'nvidia-cusolver-cu12', 'nvidia-cusparse-cu12',
               'nvidia-nccl-cu12', 'nvidia-nvjitlink-cu12', 'nvidia-nvtx-cu12'),
})
NVIDIA_PACKAGES = frozenset(('cublas', 'cuda_cupti', 'cuda_nvrtc', 'cuda_runtime',
                            'cudnn', 'cufft', 'curand', 'cusolver', 'cusparse',
                            'nccl', 'nvjitlink', 'nvtx'))
_MODULE_NAME = re.compile(r'[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*\Z')
_FILE_LOADERS = (machinery.SourceFileLoader, machinery.SourcelessFileLoader,
                 machinery.ExtensionFileLoader)


def _normal(value):
    return (type(value) is str and 0 < len(value) <= 2048 and '\\' not in value
            and not any(ord(char) < 32 for char in value) and value == value.strip()
            and PurePosixPath(value).is_absolute() and PurePosixPath(value).as_posix() == value
            and '..' not in PurePosixPath(value).parts)


def _below(value, root):
    return _normal(value) and (value == root or value.startswith(root + '/'))


def _ordinary(value, *, directory=False):
    # Call only after lexical containment validation; never inspect denied paths.
    path = Path(value)
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError('V5_CONTROLLED_IMPORT_SYMLINK')
    mode = path.lstat().st_mode
    if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        raise ValueError('V5_CONTROLLED_IMPORT_NOT_ORDINARY')
    if path.resolve(strict=True).as_posix() != value:
        raise ValueError('V5_CONTROLLED_IMPORT_REALPATH')


def _owned(name):
    return name in ('src', 'scripts') or name.startswith(('src.', 'scripts.'))


class _RuntimeFinder(importlib.abc.MetaPathFinder):
    def __init__(self, compiled, frozen_helper, observation_helper, external_names):
        self._compiled = compiled
        self._frozen = frozen_helper
        self._observation = observation_helper
        self._externals = external_names
        self._stdlib = frozenset(sys.stdlib_module_names) | frozenset(sys.builtin_module_names)

    def _runtime_spec(self, fullname, spec, *, freeze_paths=True):
        if spec is None or spec.name != fullname:
            raise ModuleNotFoundError('V5_CONTROLLED_IMPORT_MISSING:' + fullname, name=fullname)
        root = fullname.partition('.')[0]
        if root in self._stdlib:
            if spec.origin == 'built-in' and spec.loader is machinery.BuiltinImporter:
                return spec
            if spec.origin == 'frozen' and spec.loader is machinery.FrozenImporter:
                return spec
            if not _below(spec.origin, STDLIB_ROOT):
                raise ValueError('V5_CONTROLLED_IMPORT_STDLIB_ORIGIN:' + fullname)
            base = STDLIB_ROOT
        elif root in ROOT_DISTRIBUTIONS:
            if root == 'nvidia' and '.' in fullname and fullname.split('.')[1] not in NVIDIA_PACKAGES:
                raise ModuleNotFoundError('V5_CONTROLLED_IMPORT_NVIDIA_PACKAGE:' + fullname, name=fullname)
            base = SITE_ROOT
            stem = SITE_ROOT + '/' + fullname.replace('.', '/')
            origin = spec.origin
            if origin is not None:
                allowed = {stem + '.py', stem + '.pyc', stem + '/__init__.py', stem + '/__init__.pyc'}
                extension = (type(origin) is str and origin.startswith(stem + '.')
                             and '/' not in origin[len(stem):] and origin.endswith('.so'))
                if not _below(origin, SITE_ROOT) or (origin not in allowed and not extension):
                    raise ValueError('V5_CONTROLLED_IMPORT_DEPENDENCY_ORIGIN:' + fullname)
        else:
            raise ModuleNotFoundError('V5_CONTROLLED_IMPORT_UNKNOWN_ROOT:' + fullname, name=fullname)
        locations = spec.submodule_search_locations
        if spec.origin is None:
            if spec.loader is not None or locations is None:
                raise ValueError('V5_CONTROLLED_IMPORT_NAMESPACE:' + fullname)
        else:
            if type(spec.loader) not in _FILE_LOADERS or spec.loader.path != spec.origin:
                raise ValueError('V5_CONTROLLED_IMPORT_LOADER:' + fullname)
            _ordinary(spec.origin)
        if locations is not None:
            paths = list(locations)
            if not 1 <= len(paths) <= 8 or len(set(paths)) != len(paths):
                raise ValueError('V5_CONTROLLED_IMPORT_PACKAGE_PATH:' + fullname)
            for path in paths:
                if not _below(path, base):
                    raise ValueError('V5_CONTROLLED_IMPORT_PACKAGE_PATH:' + fullname)
                if root not in self._stdlib and path != SITE_ROOT + '/' + fullname.replace('.', '/'):
                    raise ValueError('V5_CONTROLLED_IMPORT_PACKAGE_PATH:' + fullname)
                _ordinary(path, directory=True)
            if freeze_paths:
                spec.submodule_search_locations = paths
        elif spec.origin is None:
            raise ValueError('V5_CONTROLLED_IMPORT_NAMESPACE:' + fullname)
        return spec

    def find_spec(self, fullname, path=None, target=None):
        self._observation._search_paths(sys.path)
        if type(fullname) is not str or _MODULE_NAME.fullmatch(fullname) is None:
            raise ModuleNotFoundError('V5_CONTROLLED_IMPORT_NAME', name=fullname)
        if fullname in self._frozen.NAMESPACES:
            spec = importlib.util.spec_from_loader(fullname, self._frozen._NamespaceLoader(), is_package=True)
            spec.origin = 'sealed://namespace/' + fullname
            spec.submodule_search_locations = []
            return spec
        if _owned(fullname):
            item = self._compiled.get(fullname)
            if item is None:
                raise ModuleNotFoundError('V5_CONTROLLED_IMPORT_UNKNOWN_LOCAL:' + fullname, name=fullname)
            code, origin = item
            return importlib.util.spec_from_loader(fullname, self._frozen._FrozenLoader(code, origin), origin=origin)
        root = fullname.partition('.')[0]
        if root not in self._stdlib and root not in ROOT_DISTRIBUTIONS:
            raise ModuleNotFoundError('V5_CONTROLLED_IMPORT_UNKNOWN_ROOT:' + fullname, name=fullname)
        if root == 'nvidia' and '.' in fullname and fullname.split('.')[1] not in NVIDIA_PACKAGES:
            raise ModuleNotFoundError('V5_CONTROLLED_IMPORT_NVIDIA_PACKAGE:' + fullname, name=fullname)
        parent = fullname.rpartition('.')[0]
        if parent:
            base = STDLIB_ROOT if root in self._stdlib else SITE_ROOT
            expected_path = base + '/' + parent.replace('.', '/')
            # Never let a finder inspect a supplied package path before admission.
            # Namespace specs created here have already frozen their path to a list.
            if (type(path) not in (list, tuple) or len(path) != 1
                    or type(path[0]) is not str or not _normal(path[0])
                    or path[0] != expected_path):
                raise ValueError('V5_CONTROLLED_IMPORT_INPUT_PACKAGE_PATH:' + fullname)
        elif path is not None:
            raise ValueError('V5_CONTROLLED_IMPORT_INPUT_PACKAGE_PATH:' + fullname)
        spec = machinery.BuiltinImporter.find_spec(fullname)
        if spec is None:
            spec = machinery.FrozenImporter.find_spec(fullname)
        if spec is None:
            spec = machinery.PathFinder.find_spec(fullname, path)
        return self._runtime_spec(fullname, spec)


def _validate_typing_namespace(fullname, namespace, finder):
    """Only Python 3.11.2's two cached deprecated class namespaces.

    Validate the ordinary typing parent first. No arbitrary spec-less object,
    generic typing subtree, cache removal, or new filesystem root is admitted.
    Like the rest of this protocol, this is not a hostile same-user sandbox.
    """
    parent = sys.modules.get('typing')
    if tuple(sys.version_info[:3]) != (3, 11, 2) or type(parent) is not ModuleType:
        raise ValueError('V5_CONTROLLED_IMPORT_TYPING_PARENT:' + fullname)
    spec = getattr(parent, '__spec__', None)
    if (spec is None or spec.name != 'typing' or spec.origin != STDLIB_ROOT + '/typing.py'
            or type(spec.loader) is not machinery.SourceFileLoader
            or spec.submodule_search_locations is not None):
        raise ValueError('V5_CONTROLLED_IMPORT_TYPING_PARENT:' + fullname)
    _validate_existing_module('typing', parent, finder)
    suffix = fullname.split('.')[1]
    meta = parent.__dict__.get('_DeprecatedType')
    exports = ('IO', 'TextIO', 'BinaryIO') if suffix == 'io' else ('Pattern', 'Match')
    declared = namespace.__dict__.get('__all__') if type(namespace) is meta else None
    if (type(meta) is not type or meta.__module__ != 'typing' or meta.__name__ != '_DeprecatedType'
            or namespace is not parent.__dict__.get(suffix) or type(namespace) is not meta
            or namespace.__module__ != 'typing' or namespace.__name__ != fullname
            or getattr(namespace, '__spec__', None) is not None
            or getattr(namespace, '__file__', None) is not None
            or getattr(namespace, '__loader__', None) is not None
            or getattr(namespace, '__path__', None) is not None
            or type(declared) is not list or any(type(name) is not str for name in declared)
            or declared != list(exports)
            or any(name not in parent.__dict__ or namespace.__dict__.get(name) is not parent.__dict__[name]
                   for name in exports)):
        raise ValueError('V5_CONTROLLED_IMPORT_TYPING_NAMESPACE:' + fullname)


def _validate_existing_module(fullname, module, finder):
    if fullname in ('typing.io', 'typing.re'):
        _validate_typing_namespace(fullname, module, finder)
        return
    root = fullname.partition('.')[0]
    if root not in finder._stdlib and root not in ROOT_DISTRIBUTIONS:
        raise ValueError('V5_CONTROLLED_IMPORT_PRELOADED_UNKNOWN:' + fullname)
    spec = getattr(module, '__spec__', None)
    if spec is None:
        raise ValueError('V5_CONTROLLED_IMPORT_PRELOADED_SPEC:' + fullname)
    aliases = {('os.path', 'posixpath'), ('importlib._bootstrap', '_frozen_importlib'),
               ('importlib._bootstrap_external', '_frozen_importlib_external')}
    if spec.name != fullname and (fullname, spec.name) not in aliases:
        raise ValueError('V5_CONTROLLED_IMPORT_PRELOADED_ALIAS:' + fullname)
    if getattr(module, '__loader__', None) is not spec.loader:
        raise ValueError('V5_CONTROLLED_IMPORT_PRELOADED_LOADER:' + fullname)
    module_file = getattr(module, '__file__', None)
    if spec.origin == 'built-in':
        if module_file is not None:
            raise ValueError('V5_CONTROLLED_IMPORT_PRELOADED_FILE:' + fullname)
    elif spec.origin == 'frozen':
        frozen_files = {'_frozen_importlib': 'importlib/_bootstrap.py',
                        '_frozen_importlib_external': 'importlib/_bootstrap_external.py'}
        expected = STDLIB_ROOT + '/' + frozen_files.get(spec.name, spec.name.replace('.', '/') + '.py')
        if module_file is not None and module_file != expected:
            raise ValueError('V5_CONTROLLED_IMPORT_PRELOADED_FILE:' + fullname)
    elif module_file != spec.origin:
        raise ValueError('V5_CONTROLLED_IMPORT_PRELOADED_FILE:' + fullname)
    # Only Python's fixed bootstrap/os aliases may use a different spec name.
    finder._runtime_spec(spec.name, spec, freeze_paths=False)
    locations = getattr(module, '__path__', None)
    if spec.submodule_search_locations is not None:
        if locations is None or list(locations) != list(spec.submodule_search_locations):
            raise ValueError('V5_CONTROLLED_IMPORT_PRELOADED_PATH:' + fullname)


def _check_cached_modules(finder):
    cached = tuple(sys.modules.items())
    if len(cached) > MAX_CACHED_MODULES:
        raise ValueError('V5_CONTROLLED_IMPORT_CACHE_BOUND')
    for name, module in cached:
        if type(name) is not str:
            raise ValueError('V5_CONTROLLED_IMPORT_CACHE_NAME')
        if _owned(name):
            raise ValueError('V5_CONTROLLED_IMPORT_PRELOADED_LOCAL')
        if name.partition('.')[0] in finder._frozen.HEAVY_ROOTS:
            raise ValueError('V5_CONTROLLED_IMPORT_PRELOADED_HEAVY')
        if name == '__main__' or name in finder._externals:
            continue
        _validate_existing_module(name, module, finder)


@contextmanager
def controlled_imports(source_bytes, pins, *, frozen_helper, observation_helper, lock_raw):
    """Keep the controlled finder active through imports and the guarded callback.

    Helpers must be independently authenticated, externally loaded ModuleTypes.
    Source/pin dictionaries contain the exact 25 frozen Python entries; lock_raw
    is the independently authenticated 26th core artifact. Every source hash and
    compilation precedes registry/finder writes. A fresh fixed-cwd runtime query
    is mandatory; no previously saved metadata receipt enables ML imports.
    Cached heavy/local modules are refused; other cached origins are validated.
    __main__ and the three trusted external bootstrap modules are exempt from
    cached-origin validation, never src/scripts. No formal-fit permission is
    created here. Exit preserves unrelated/runtime imports and removes owned
    local modules plus this finder. Reentry after ML import requires a new process.
    """
    externals = set()
    for helper in (frozen_helper, observation_helper):
        if (type(helper) is not ModuleType or type(helper.__name__) is not str
                or re.fullmatch('[A-Za-z_][A-Za-z_0-9]*', helper.__name__) is None
                or _owned(helper.__name__)):
            raise ValueError('V5_CONTROLLED_IMPORT_EXTERNAL_HELPER')
        externals.add(helper.__name__)
    externals.add(__name__)
    sources, trusted_pins, total = frozen_helper._snapshot(source_bytes, pins)
    compiled = {name[:-3].replace('/', '.'): (compile(raw, 'sealed://' + name, 'exec'), 'sealed://' + name)
                for name, raw in sorted(sources.items())}
    finder = _RuntimeFinder(MappingProxyType(compiled), frozen_helper, observation_helper, frozenset(externals))
    observation_helper._runtime(sys.platform, sys.executable, tuple(sys.version_info[:3]),
                                observation_helper.os.getcwd())
    observation_helper._search_paths(sys.path)
    _check_cached_modules(finder)
    observed = observation_helper.observe_runtime(lock_raw)
    requested = observation_helper.parse_lock_bytes(lock_raw)
    if (type(observed) is not dict or observed.get('status') != 'PASS_FIXED_RUNTIME_METADATA_ONLY'
            or observed.get('versions') != requested or observed.get('distribution_count') != 31
            or {name for values in ROOT_DISTRIBUTIONS.values() for name in values} != set(requested)
            or observation_helper.SITE_ROOT != SITE_ROOT
            or observed.get('sys_path') != list(observation_helper.SEARCH_PATHS)
            or observed.get('actual_ml_permitted') is not False
            or observed.get('formal_training_release') is not False):
        raise ValueError('V5_CONTROLLED_IMPORT_FRESH_METADATA')
    # Recheck caches/search paths after the read-only query, before installation.
    observation_helper._search_paths(sys.path)
    _check_cached_modules(finder)
    receipt = MappingProxyType(dict(status='CONTROLLED_SOURCE_RUNTIME_IMPORT_CONTEXT_ONLY',
        source_count=len(sources), total_source_bytes=total, sources=trusted_pins,
        dependency_lock_sha256=observed['dependency_lock_sha256'],
        runtime_metadata_status=observed['status'], runtime_imports_enabled=True,
        dependency_contents_sealed=False, native_libraries_verified=False,
        actual_training_proven=False, actual_linux_resource_proof=False,
        formal_training_release=False, authentic_user_consent_proven=False))
    sys.meta_path.insert(0, finder)
    try:
        yield receipt
    finally:
        sys.meta_path[:] = [item for item in sys.meta_path if item is not finder]
        for name in tuple(sys.modules):
            if type(name) is str and _owned(name):
                del sys.modules[name]
