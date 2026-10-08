"""One physical TRAIN child entry; externally guarded, never self-authorizing.

The parent MUST launch this once via the existing sampled-RSS resource guard,
with fixed Linux interpreter/cwd/search paths. Its independently authenticated
prelaunch envelope and completed review are mandatory. This CLI grants no new
release or genuine consent, performs no retry/scheduling, and proves neither
parent enforcement nor a formal 18-fit result. No hostile same-user guarantee.
All bootstrap imports are stdlib; local code is executed only from pinned bytes.
"""
import argparse
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from types import ModuleType

INTERPRETER = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'
CWD = '/ssd/cjc'
PACKAGE_ROOT = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds'
ROOT_PATTERN = r'/ssd/cjc/gnn_model_ranking_v5_train_[0-9]{8}_r[1-9][0-9]*'
PROTECTED_ROOT = '/ssd/cjc/multimode_ate_gnn_v1'
CORE_MANIFEST_SHA256 = '5394779faac5c77800a0a9d8ed52bf9f24ba2dd701f499a49754e51e7ddceae7'
AUTHORIZATION_SHA256 = 'fc79123d92d80bbb0044e6568a9a72b9c7e0b2242534949a2f4592e5977ac1b1'
AUTHORIZATION_ID = 'USER_ASYNC_V5_18_TRAIN_20261008'
SYNTHETIC_LINUX_GATE_SHA256 = 'ac347199478f244b8577b4e011f6dbfabca0db73e9da8b3113b11a96fd486790'
LOCK_SHA256 = 'a9427b7cbf01048a317009dcf0f625ace51cc739b4e7e2e626a17166ed14c96f'
FAMILIES = frozenset(('iwls_aes_core', 'iscas89_s13207', 'iscas89_s15850',
                      'iscas89_s35932', 'iscas89_s38417', 'iwls_spi'))
SEEDS = (20260824, 20260825, 20260826)
CORE_FILES = frozenset((
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
    'src/models/ranking_v5_worker_resource_context.py', 'src/models/ranking_v5_parent_guard_receipt.py',
    'src/models/ranking_v5_caller_source_binding.py', 'requirements/runtime_v2.lock.txt'))
RELEASE_SOURCE_FILES = frozenset((
    'src/models/runtime_ranking_v3.py', 'src/models/runtime_training_v2.py',
    'src/models/neural_ranking_v3.py', 'src/models/run_runtime_ranking_v3.py',
    'src/models/ranking_v3_freeze_io.py', 'src/data/ranking_v3_real_fold_package.py',
    'scripts/ranking_v4_near_optimal_pairs.py', 'src/models/ranking_v4_training_worker.py',
    'src/models/ranking_v5_head_objective.py', 'src/models/ranking_v5_training_kernel.py',
    'requirements/runtime_v2.lock.txt', 'src/models/ranking_v5_execution_boundary.py'))
HELPERS = ('src/models/ranking_v5_frozen_import_fence.py',
           'src/models/ranking_v5_locked_runtime_observations.py',
           'src/models/ranking_v5_locked_runtime_imports.py')
MANIFEST_NAME = 'data/manifests/ranking_v5_caller_source_bytes_20261008.json'
EVIDENCE = {'authorization.json': 'authorization_sha256',
            'release.json': 'release_file_sha256', 'review.json': 'review_sha256',
            'physical_gate.json': 'physical_gate_sha256',
            'synthetic_linux_gate.json': 'synthetic_linux_gate_sha256'}
ENVELOPE_FIELDS = frozenset(('schema', 'source_root', 'output', 'package_root', 'family', 'seed',
    'roles', 'parent_resource_guard_required', 'core_manifest_sha256', 'helper_sha256',
    'authorization_sha256', 'authorization_id', 'release_file_sha256', 'review_sha256',
    'physical_gate_sha256', 'synthetic_linux_gate_sha256'))
JSON_CAP = 20*1024
SOURCE_CAP = 64*1024
TOTAL_SOURCE_CAP = 1024*1024


def _require(ok, code):
    if not ok:
        raise ValueError('V5_TRAIN_CLI_' + code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _runtime():
    _require(sys.platform == 'linux', 'PLATFORM')
    _require(sys.executable == INTERPRETER, 'INTERPRETER')
    _require(tuple(sys.version_info[:3]) == (3, 11, 2), 'PYTHON')
    _require(os.getcwd() == CWD, 'CWD')


def _lexical(source_root, output, package_root, family, seed):
    _require(type(family) is str and family in FAMILIES, 'FAMILY')
    _require(type(seed) is int and seed in SEEDS, 'SEED')
    for value in (source_root, output, package_root):
        _require(type(value) is str and len(value) <= 2048, 'PATH')
        text = value.replace('\\', '/').casefold()
        _require(not (text == PROTECTED_ROOT.casefold() or text.startswith(PROTECTED_ROOT.casefold()+'/')), 'PROTECTED_ROOT')
        _require(value == value.strip() and '\\' not in value and '//' not in value
                 and not any(p in ('', '.', '..') for p in value.split('/')[1:]), 'PATH')
    _require(re.fullmatch(ROOT_PATTERN, source_root) is not None, 'SOURCE_ROOT')
    _require(output == source_root + '_' + family + '_' + str(seed), 'OUTPUT_ROOT')
    _require(package_root == PACKAGE_ROOT, 'PACKAGE_ROOT')


def _json(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= JSON_CAP, 'JSON_BOUND')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, 'JSON_DUPLICATE')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('V5_TRAIN_CLI_JSON_NONFINITE')
    def integer(text):
        _require(len(text) <= 309, 'JSON_INTEGER')
        value = int(text)
        _require(value.bit_length() <= 1024, 'JSON_INTEGER')
        return value
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                           parse_constant=constant, parse_int=integer)
        nodes = 0
        def visit(item, depth):
            nonlocal nodes
            nodes += 1
            _require(depth <= 64 and nodes <= 4096, 'JSON_GRAPH')
            kind = type(item)
            if kind is float: _require(math.isfinite(item), 'JSON_NONFINITE')
            elif kind is str: _require(len(item) <= 2048, 'JSON_STRING')
            elif kind in (list, dict):
                _require(len(item) <= 1024, 'JSON_CONTAINER')
                if kind is dict:
                    for key, child in item.items(): visit(key, depth+1); visit(child, depth+1)
                else:
                    for child in item: visit(child, depth+1)
        visit(value, 0)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError('V5_TRAIN_CLI_JSON_INVALID') from error
    _require(type(value) is dict, 'JSON_OBJECT')
    return value


def _ordinary(info, directory=False):
    _require(not stat.S_ISLNK(info.st_mode)
             and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'SYMLINK')
    _require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'ORDINARY_FILE')


def _read(root, relative, cap):
    """Only internal fixed relative names are accepted, never envelope paths."""
    envelopes = {f'prelaunch_{family}_{seed}.json' for family in FAMILIES for seed in SEEDS}
    allowed = CORE_FILES | set(HELPERS) | set(EVIDENCE) | {MANIFEST_NAME} | envelopes
    _require(relative in allowed, 'UNKNOWN_FILE')
    try:
        path = Path(root) / relative
        for ancestor in path.parents:
            _ordinary(ancestor.lstat(), directory=True)
        before = path.lstat(); _ordinary(before)
        _require(0 < before.st_size <= cap, 'FILE_BOUND')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno()); _ordinary(info)
            _require((info.st_dev, info.st_ino, info.st_size) ==
                     (before.st_dev, before.st_ino, before.st_size), 'FILE_CHANGED')
            raw = stream.read(cap+1)
            after = os.fstat(stream.fileno())
        final = path.lstat(); _ordinary(final)
        _require(0 < len(raw) == before.st_size <= cap
                 and (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) ==
                     (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                 and (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns), 'FILE_CHANGED')
        return raw
    except OSError as error:
        raise ValueError('V5_TRAIN_CLI_FILE_IO') from error


def _envelope(raw, trusted_sha256, source_root, output, package_root, family, seed):
    _require(_pin(trusted_sha256) and type(raw) is bytes and 0 < len(raw) <= JSON_CAP
             and _sha(raw) == trusted_sha256, 'ENVELOPE_SHA')
    value = _json(raw)
    _require(set(value) == ENVELOPE_FIELDS and value['schema'] == 'v5-train-prelaunch-envelope-v1', 'ENVELOPE_SCHEMA')
    _require(value['source_root'] == source_root and value['output'] == output
             and value['package_root'] == package_root and value['family'] == family
             and type(value['seed']) is int and value['seed'] == seed
             and value['roles'] == ['TRAIN'] and value['parent_resource_guard_required'] is True, 'ENVELOPE_BINDING')
    _require(value['core_manifest_sha256'] == CORE_MANIFEST_SHA256
             and value['authorization_sha256'] == AUTHORIZATION_SHA256
             and value['authorization_id'] == AUTHORIZATION_ID
             and value['synthetic_linux_gate_sha256'] == SYNTHETIC_LINUX_GATE_SHA256, 'FIXED_SEALS')
    _require(type(value['helper_sha256']) is dict and set(value['helper_sha256']) == set(HELPERS)
             and all(_pin(pin) for pin in value['helper_sha256'].values())
             and all(_pin(value[key]) for key in EVIDENCE.values()), 'ENVELOPE_PINS')
    return value


def _helper(raw, name):
    """Externally named ModuleType, never a disk import of src/scripts."""
    module = ModuleType(name)
    module.__file__ = 'sealed-bootstrap://' + name
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def _import(name):
    return importlib.import_module(name)


def execute_prelaunch(envelope_raw, *, trusted_envelope_sha256, source_root,
                      output, package_root, family, seed):
    """Execute one guarded child callback. Trusted envelope is not consent proof."""
    _runtime()
    _lexical(source_root, output, package_root, family, seed)
    envelope = _envelope(envelope_raw, trusted_envelope_sha256, source_root, output, package_root, family, seed)
    manifest_raw = _read(source_root, MANIFEST_NAME, min(JSON_CAP, 20000))
    _require(_sha(manifest_raw) == CORE_MANIFEST_SHA256, 'CORE_MANIFEST_SHA')
    manifest = _json(manifest_raw)
    _require(set(manifest) == {'schema', 'formal_training_release', 'sources'}
             and manifest['schema'] == 'v5-caller-source-bytes-v1'
             and manifest['formal_training_release'] is False
             and type(manifest['sources']) is dict and set(manifest['sources']) == CORE_FILES
             and all(_pin(pin) for pin in manifest['sources'].values()), 'CORE_MANIFEST_SCHEMA')
    sources, helper_raw, total = {}, {}, 0
    for name in sorted(CORE_FILES | set(HELPERS)):
        raw = _read(source_root, name, SOURCE_CAP)
        total += len(raw)
        _require(total <= TOTAL_SOURCE_CAP, 'SOURCE_TOTAL_BOUND')
        pin = manifest['sources'][name] if name in CORE_FILES else envelope['helper_sha256'][name]
        _require(_sha(raw) == pin, 'SOURCE_SHA:' + name)
        (sources if name in CORE_FILES else helper_raw)[name] = raw
    lock_raw = sources['requirements/runtime_v2.lock.txt']
    _require(_sha(lock_raw) == LOCK_SHA256, 'LOCK_SHA')
    evidence = {}
    for name, field in EVIDENCE.items():
        raw = _read(source_root, name, JSON_CAP)
        _require(_sha(raw) == envelope[field], 'EVIDENCE_SHA:' + name)
        evidence[name] = raw
        _json(raw)
    auth = _json(evidence['authorization.json'])
    _require(auth.get('authorization_id') == AUTHORIZATION_ID, 'AUTHORIZATION_ID')
    release = _json(evidence['release.json'])
    _require(release.get('user_authorization_id') == AUTHORIZATION_ID, 'RELEASE_AUTHORIZATION_ID')
    frozen = _helper(helper_raw[HELPERS[0]], '_v5_train_frozen_helper')
    observation = _helper(helper_raw[HELPERS[1]], '_v5_train_observation_helper')
    runtime = _helper(helper_raw[HELPERS[2]], '_v5_train_runtime_helper')
    py_sources = {k: v for k, v in sources.items() if k.endswith('.py')}
    py_pins = {k: manifest['sources'][k] for k in py_sources}
    expected_sources = {k: manifest['sources'][k] for k in RELEASE_SOURCE_FILES}
    with runtime.controlled_imports(py_sources, py_pins, frozen_helper=frozen,
                                    observation_helper=observation, lock_raw=lock_raw):
        # The context performs fresh fixed metadata observations before imports.
        binder = _import('src.models.ranking_v5_caller_source_binding')
        binder.validate_source_bytes(manifest_raw, sources, trusted_manifest_sha256=CORE_MANIFEST_SHA256)
        approval = _import('src.models.ranking_v5_approval_binding')
        approval.validate_approval_integrity(release, expected_sources, evidence['authorization.json'],
            evidence['review.json'], trusted_authorization_sha256=AUTHORIZATION_SHA256,
            trusted_review_sha256=envelope['review_sha256'],
            trusted_physical_gate_sha256=envelope['physical_gate_sha256'])
        resource = _import('src.models.ranking_v5_worker_resource_context')
        resource.check_current_process()
        worker = _import('src.models.ranking_v5_single_fit_worker')
        # Only after integrity, approval, metadata and child resource checks.
        torch, np = _import('torch'), _import('numpy')
        _require(torch.cuda.is_available() is False, 'CUDA_VISIBLE')
        result = worker.execute_single_fit(package_root, family, seed, release, expected_sources,
            evidence['authorization.json'], evidence['review.json'], output=output, torch=torch, np=np,
            trusted_authorization_sha256=AUTHORIZATION_SHA256,
            trusted_review_sha256=envelope['review_sha256'],
            trusted_physical_gate_sha256=envelope['physical_gate_sha256'])
    _require(type(result) is dict and result.get('status') == 'PASS_SINGLE_FIT_CALLBACK_ADAPTER_ONLY'
             and result.get('formal_training_authorized_by_this_function') is False
             and result.get('new_formal_18_fit_release') is False, 'WORKER_RECEIPT')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--package-root', required=True)
    parser.add_argument('--envelope-sha256', required=True)
    parser.add_argument('--family', required=True)
    parser.add_argument('--seed', required=True, type=int)
    args = parser.parse_args(argv)
    _runtime()
    _lexical(args.source_root, args.output, args.package_root, args.family, args.seed)
    _require(_pin(args.envelope_sha256), 'ENVELOPE_SHA')
    # One shared fresh source root can hold all 18 independently pinned,
    # create-once per-fit envelopes. Never accept an arbitrary envelope path.
    name = f'prelaunch_{args.family}_{args.seed}.json'
    raw = _read(args.source_root, name, JSON_CAP)
    result = execute_prelaunch(raw, trusted_envelope_sha256=args.envelope_sha256,
        source_root=args.source_root, output=args.output, package_root=args.package_root,
        family=args.family, seed=args.seed)
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
