"""Bounded supplied-byte imports for a SYNTHETIC_GATE, not a sandbox.

Load this helper under an external name before entering the fence. Independent
SHA pins must come from the caller's trust anchor, not from these source bytes.
No paths are read here. This is not consent, environment preflight, provenance,
hostile-code isolation, or permission to run actual ML/training. The ordinary
Python import protocol is assumed; code may not mutate import machinery.
The stdlib-name whitelist governs cache misses, not origin verification or
already cached unrelated modules. Those modules are deliberately left alone.
"""
from contextlib import contextmanager
import hashlib
import importlib.abc
import importlib.util
import re
import sys
from types import MappingProxyType


# Deliberately duplicated: importing the binder first would defeat the fence.
FILES = frozenset((
    'src/models/runtime_ranking_v3.py', 'src/models/runtime_training_v2.py',
    'src/models/neural_ranking_v3.py', 'src/models/run_runtime_ranking_v3.py',
    'src/models/ranking_v3_freeze_io.py', 'src/data/ranking_v3_real_fold_package.py',
    'scripts/ranking_v4_near_optimal_pairs.py', 'src/models/ranking_v4_training_worker.py',
    'src/models/ranking_v4_memory_guard.py', 'src/models/preflight_runtime_v2.py',
    'src/models/ranking_v5_execution_boundary.py', 'src/models/ranking_v5_head_objective.py',
    'src/models/ranking_v5_training_kernel.py', 'src/models/ranking_v5_physical_worker.py',
    'src/models/ranking_v5_approval_binding.py', 'src/models/ranking_v5_bound_input_reader.py',
    'src/models/ranking_v5_package_binding.py', 'src/models/ranking_v5_real_request_loader.py',
    'src/models/ranking_v5_v3_fold_adapter.py', 'src/models/ranking_v5_held_replay_reader.py',
    'src/models/ranking_v5_real_artifact_store.py', 'src/models/ranking_v5_single_fit_worker.py',
    'src/models/ranking_v5_worker_resource_context.py',
    'src/models/ranking_v5_parent_guard_receipt.py',
    'src/models/ranking_v5_caller_source_binding.py',
))
MAX_FILES = 27
MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 1024 * 1024
NAMESPACES = frozenset(('src', 'src.models', 'src.data', 'scripts'))
HEAVY_ROOTS = frozenset(('torch', 'numpy', 'scipy', 'sklearn', 'xgboost'))
_PY_NAME = re.compile(r'(?:src/(?:models|data)|scripts)/[A-Za-z_][A-Za-z_0-9]*\.py\Z')
_SHA = re.compile(r'[0-9a-f]{64}\Z')


def _owned(name):
    return (type(name) is str and
            (name in ('src', 'scripts') or name.startswith(('src.', 'scripts.'))))


def _snapshot(source_bytes, expected_sha256):
    if type(source_bytes) is not dict or type(expected_sha256) is not dict:
        raise ValueError('V5_FENCE_DICTIONARY_REQUIRED')
    if len(source_bytes) > MAX_FILES or len(expected_sha256) > MAX_FILES:
        raise ValueError('V5_FENCE_FILE_COUNT_BOUND')
    sources, pins = dict(source_bytes), dict(expected_sha256)
    if any(type(name) is not str or _PY_NAME.fullmatch(name) is None
           for name in sources):
        raise ValueError('V5_FENCE_SOURCE_NAME')
    if set(sources) != FILES or set(pins) != FILES:
        raise ValueError('V5_FENCE_SOURCE_SET')
    total = 0
    for name in sorted(FILES):
        raw, pin = sources[name], pins[name]
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES:
            raise ValueError('V5_FENCE_SOURCE_BOUND:' + name)
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('V5_FENCE_TOTAL_BOUND')
        if (type(pin) is not str or _SHA.fullmatch(pin) is None or
                hashlib.sha256(raw).hexdigest() != pin):
            raise ValueError('V5_FENCE_SOURCE_DRIFT:' + name)
    # All SHA checks precede any compilation. bytes/str values are immutable.
    return MappingProxyType(sources), MappingProxyType(pins), total


class _FrozenLoader(importlib.abc.Loader):
    def __init__(self, code, origin):
        self._code, self._origin = code, origin

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__file__ = self._origin
        exec(self._code, module.__dict__)


class _NamespaceLoader(importlib.abc.Loader):
    def create_module(self, spec):
        return None

    def exec_module(self, module):
        # A literal empty path cannot dynamically rediscover disk namespaces.
        module.__path__ = []


class _FenceFinder(importlib.abc.MetaPathFinder):
    def __init__(self, compiled):
        self._compiled = compiled
        self._stdlib = frozenset(sys.stdlib_module_names) | {'builtins'}

    def find_spec(self, fullname, path=None, target=None):
        root = fullname.partition('.')[0]
        if root in HEAVY_ROOTS:
            raise ModuleNotFoundError('V5_FENCE_HEAVY_IMPORT:' + fullname, name=fullname)
        if fullname in NAMESPACES:
            spec = importlib.util.spec_from_loader(fullname, _NamespaceLoader(), is_package=True)
            spec.origin = 'sealed://namespace/' + fullname
            spec.submodule_search_locations = []
            return spec
        if _owned(fullname):
            item = self._compiled.get(fullname)
            if item is None:
                raise ModuleNotFoundError('V5_FENCE_UNKNOWN_LOCAL:' + fullname, name=fullname)
            code, origin = item
            return importlib.util.spec_from_loader(fullname, _FrozenLoader(code, origin),
                                                  origin=origin)
        if root not in self._stdlib:
            raise ModuleNotFoundError('V5_FENCE_NON_STDLIB_IMPORT:' + fullname, name=fullname)
        return None


@contextmanager
def sealed_imports(source_bytes, expected_sha256):
    """Temporarily own src/scripts using exactly 25 pinned Python sources.

    Both inputs must be exact dictionaries with matching FILES keys and immutable
    bytes/lowercase SHA-256 values. Entry verifies every hash and compiles every
    source before altering import state. No previously loaded src/scripts or
    heavy-ML module is accepted, including this helper under an owned name.
    On exit only this finder and all newly owned src/scripts modules are removed;
    unrelated imports and import-system changes are preserved. Not thread-safe:
    use a dedicated isolated process with no concurrent imports.
    """
    sources, pins, total = _snapshot(source_bytes, expected_sha256)
    if any(_owned(name) for name in tuple(sys.modules)):
        raise ValueError('V5_FENCE_PRELOADED_LOCAL')
    if any(type(name) is str and name.partition('.')[0] in HEAVY_ROOTS
           for name in tuple(sys.modules)):
        raise ValueError('V5_FENCE_PRELOADED_HEAVY')
    compiled = {}
    for name in sorted(sources):
        origin = 'sealed://' + name
        compiled[name[:-3].replace('/', '.')] = (compile(sources[name], origin, 'exec'), origin)
    finder = _FenceFinder(MappingProxyType(compiled))
    receipt = MappingProxyType(dict(status='SYNTHETIC_GATE_ONLY', source_count=len(sources),
                                   total_source_bytes=total, sources=pins,
                                   actual_ml_permitted=False, formal_training_release=False))
    sys.meta_path.insert(0, finder)
    try:
        yield receipt
    finally:
        # Preserve unrelated modules/finders, even when the body raises.
        sys.meta_path[:] = [entry for entry in sys.meta_path if entry is not finder]
        for name in tuple(sys.modules):
            if _owned(name):
                del sys.modules[name]
