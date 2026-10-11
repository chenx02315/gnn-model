"""Pinned trace_rules fixed skip-list absence; isolated process, never TRAIN release.

Authenticate this supplemental helper and every delegated helper externally.
No machinery, dependency policy, numerical code or old source is modified.
"""
from contextlib import contextmanager
import hashlib
import importlib.machinery as machinery
import os
from pathlib import Path
import stat
import sys
from types import FunctionType, ModuleType

NAME = 'fx2trt_oss'
NEGATIVE_NAMES = ('fx2trt_oss', 'hypothesis', 'omegaconf', 'onnx', 'onnxruntime',
                  'onnx_tf', 'pandas', 'tabulate', 'tensorflow', 'tensorrt',
                  'torch2trt', 'tqdm', 'tree', 'tvm', 'xarray')
TRACE = 'torch._dynamo.trace_rules'
TRACE_BYTES = 140951
TRACE_SHA256 = 'ba438afd2b574d5d733532e7995ed04c29306f32b75df87657978288375bced5'
ADD_LINE = 3353
CALL_LINE = 3359
PROOF_FIELDS = {'probe_verified', 'probe_name', 'probe_invocations', 'trace_source_bytes',
                'trace_source_sha256', 'trace_origin', 'search_paths',
                'negative_probe_names', 'probe_counts',
                'formal_training_release', 'actual_linux_resource_proof'}
_ACTIVE = False
_JIT = None
_RECEIPT = None


def _require(ok, token):
    if not ok:
        raise ValueError('V5_FX2TRT_' + token)


def _read(origin):
    path = Path(origin)
    _require(not any(p.is_symlink() for p in (path, *path.parents)), 'SOURCE_SYMLINK')
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size == TRACE_BYTES
             and path.resolve(strict=True).as_posix() == origin, 'SOURCE_FILE')
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    fd = os.open(origin, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        opened = os.fstat(fd)
        _require(identity(before) == identity(opened) and stat.S_ISREG(opened.st_mode)
                 and opened.st_nlink == 1, 'SOURCE_IDENTITY')
        parts, total = [], 0
        while total <= TRACE_BYTES:
            part = os.read(fd, TRACE_BYTES + 1 - total)
            if not part:
                break
            parts.append(part)
            total += len(part)
        raw = b''.join(parts)
        _require(identity(opened) == identity(os.fstat(fd)), 'SOURCE_IDENTITY')
    finally:
        os.close(fd)
    _require(identity(before) == identity(path.lstat()), 'SOURCE_IDENTITY')
    _require(len(raw) == TRACE_BYTES and hashlib.sha256(raw).hexdigest() == TRACE_SHA256,
             'SOURCE_HASH')
    return raw


def _caller(base, frame):
    origin = base.SITE_ROOT + '/torch/_dynamo/trace_rules.py'
    module = sys.modules.get(TRACE)
    _require(type(module) is ModuleType, 'TRACE_MODULE')
    spec = module.__dict__.get('__spec__')
    _require(spec is not None and spec.name == TRACE and spec.origin == origin
             and type(spec.loader) is machinery.SourceFileLoader
             and spec.loader.name == TRACE and spec.loader.path == origin
             and spec.submodule_search_locations is None
             and module.__dict__.get('__file__') == origin
             and module.__dict__.get('__loader__') is spec.loader, 'TRACE_ORIGIN')
    raw = _read(origin)
    function = module.__dict__.get('add')
    _require(type(function) is FunctionType and function.__name__ == 'add'
             and function.__module__ == TRACE and function.__globals__ is module.__dict__
             and function.__code__.co_filename == origin
             and function.__code__.co_firstlineno == ADD_LINE
             and frame.f_code is function.__code__ and frame.f_globals is module.__dict__
             and frame.f_lineno == CALL_LINE, 'CALLER')
    # Match the in-memory function to a fresh compilation of authenticated bytes,
    # not merely a function with a forged name/file/line number.
    code = compile(raw, origin, 'exec', dont_inherit=True, optimize=sys.flags.optimize)
    candidates = [c for c in code.co_consts if type(c) is type(code)
                  and c.co_name == 'add' and c.co_firstlineno == ADD_LINE]
    _require(len(candidates) == 1 and function.__code__ == candidates[0], 'CALLER_CODE')
    return origin


def verify_generated_template(receipt):
    """Delegate with the original JIT receipt object, never copy its identity."""
    _require(_ACTIVE and _JIT is not None and receipt is _RECEIPT, 'VERIFY_CONTEXT')
    _JIT.verify_generated_template(receipt)


validate_current = verify_generated_template


@contextmanager
def controlled_imports(source_bytes, pins, *, frozen_helper, observation_helper,
                       lock_raw, base_context, jit_root, generated_raw, jit_admission):
    global _ACTIVE, _JIT, _RECEIPT
    _require(not _ACTIVE and type(base_context) is ModuleType
             and type(observation_helper) is ModuleType and type(jit_admission) is ModuleType,
             'CONTEXT')
    fixed = observation_helper.SEARCH_PATHS
    _require(type(fixed) is tuple and len(fixed) == 5
             and all(type(p) is str for p in fixed), 'BASE_PATHS')
    old = base_context._optional_probe
    _require(type(old) is FunctionType, 'BASE_PROBE')
    counts = {name: 0 for name in NEGATIVE_NAMES}
    proof = dict(probe_verified=False, probe_name=NAME, probe_invocations=0,
                 negative_probe_names=list(NEGATIVE_NAMES),
                 probe_counts={name: 0 for name in NEGATIVE_NAMES},
                 trace_source_bytes=TRACE_BYTES, trace_source_sha256=TRACE_SHA256,
                 trace_origin=base_context.SITE_ROOT+'/torch/_dynamo/trace_rules.py',
                 search_paths=list(fixed), formal_training_release=False,
                 actual_linux_resource_proof=False)

    def probe(fullname, package=None, *, observation_helper):
        if type(fullname) is not str or fullname not in NEGATIVE_NAMES or package is not None:
            return old(fullname, package, observation_helper=observation_helper)
        _require(observation_helper.SEARCH_PATHS == fixed, 'BASE_PATHS')
        observation_helper._search_paths(sys.path)  # JIT facade validates its owned tail.
        bridge = sys._getframe(1)
        bridges = [c for c in base_context.controlled_imports.__wrapped__.__code__.co_consts
                   if type(c) is type(bridge.f_code) and c.co_name == 'optional_probe']
        _require(len(bridges) == 1 and bridge.f_code is bridges[0]
                 and bridge.f_globals is base_context.__dict__, 'PROBE_BRIDGE')
        _caller(base_context, bridge.f_back)
        _require(not any(type(n) is str and (n == fullname or n.startswith(fullname+'.'))
                         for n in sys.modules), 'OPTIONAL_CACHE')
        _require(machinery.PathFinder.find_spec(fullname, list(fixed)) is None, 'OPTIONAL_PRESENT')
        counts[fullname] += 1
        proof['probe_invocations'] = sum(counts.values())
        proof['probe_counts'] = dict(counts)
        return None

    completed = False
    receipt = None
    try:
        _ACTIVE = True
        _JIT = jit_admission
        base_context._optional_probe = probe
        with jit_admission.controlled_imports(source_bytes, pins, frozen_helper=frozen_helper,
                observation_helper=observation_helper, lock_raw=lock_raw, base_context=base_context,
                jit_root=jit_root, generated_raw=generated_raw) as receipt:
            _RECEIPT = receipt
            receipt['fx2trt_probe'] = proof
            yield receipt
            _require(base_context._optional_probe is probe
                     and receipt.get('fx2trt_probe') is proof
                     and all(counts[n] >= 1 for n in NEGATIVE_NAMES),
                     'PROBE_NOT_OBSERVED')
            # Rebuild evidence from private observations, not caller-writable counts.
            proof.clear()
            proof.update(probe_verified=False, probe_name=NAME, probe_invocations=sum(counts.values()),
                negative_probe_names=list(NEGATIVE_NAMES), probe_counts=dict(counts),
                trace_source_bytes=TRACE_BYTES, trace_source_sha256=TRACE_SHA256,
                trace_origin=base_context.SITE_ROOT+'/torch/_dynamo/trace_rules.py',
                search_paths=list(fixed), formal_training_release=False, actual_linux_resource_proof=False)
        proof['probe_verified'] = True
        completed = True
    finally:
        if not completed:
            proof['probe_verified'] = False
        base_context._optional_probe = old
        _RECEIPT = None
        _JIT = None
        _ACTIVE = False
