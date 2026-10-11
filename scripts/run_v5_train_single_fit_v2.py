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
SOURCE_ROOT = '/ssd/cjc/gnn_model_ranking_v5_train_20261011_r1'
ROOT_PATTERN = re.escape(SOURCE_ROOT)
PROTECTED_ROOT = '/ssd/cjc/multimode_ate_gnn_v1'
CORE_MANIFEST_SHA256 = '5394779faac5c77800a0a9d8ed52bf9f24ba2dd701f499a49754e51e7ddceae7'
AUTHORIZATION_SHA256 = '0235f1f342521b569f16a4a329580177aa0b65628dd64890edc64a8197d98c92'
AUTHORIZATION_ID = 'USER_V5_OPTIMIZER_GATE_THEN_18_TRAIN_20261010'
SCOPE_AUTHORIZATION_SHA256 = 'eeb15f2c564c34fa46f99389fba4a092d306fcd1b6db782886ee902ad3ff14a0'
OPTIMIZER_PROGRAM = 'scripts/run_v5_fx2trt_optimizer_gate.py'
CPU_PROGRAM = 'scripts/run_v5_controlled_runtime_gate.py'
OPTIMIZER_SOURCE_SHA256 = 'bd3139f857f150452727779238058fc28731a76a449a2c197f0185de5aabb681'
JIT = 'src/models/ranking_v5_jit_template_admission.py'
TRAIN_JIT = 'src/models/ranking_v5_train_jit_admission_v2.py'
PROBE = 'src/models/ranking_v5_fx2trt_probe_admission.py'
SNAPSHOT = 'data/fixtures/ranking_v5_remote_module_non_scriptable_20261010.txt'
SMOKE_ROOT = '/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261011_r1'
AUDIT = 'actual_optimizer_audit.json'
GATE_SOURCES = (OPTIMIZER_PROGRAM, CPU_PROGRAM, JIT, PROBE, SNAPSHOT)
OPTIMIZER_EVIDENCE_PINS = {
    'controlled_optimizer.child.json': '103fda7cb49ddef4d8d0e531bb3e057f51f9411704417b8df32fa943aad2e00b',
    'controlled_optimizer.log.memory.json': '788c4b43fd9d60a154bfe37bb49c9013343f9c0cdfe199c0531149ebea5c2b03',
    'controlled_optimizer.launch.json': '47abb3722d7070caa7e2fa4d2dbf3afba2ddb8c46c3f207f93b3860e48ac1560',
    AUDIT: 'a30a1bf8f0f07d6892be0359a3bece886341078a13e462b461d3933762bb9df0',
}
FIXED_HELPER_PINS = {
    'src/models/ranking_v5_frozen_import_fence.py': 'c8ba5ae9bc8f900a620b7eaf03e37e11f303d9fc8b08ccbc8c423682b0afafed',
    'src/models/ranking_v5_locked_runtime_observations.py': '0524a7b8cce7d017c3fe9fe38dcc86b29a440ed7b373c1c2361ebbb7738459c8',
    'src/models/ranking_v5_locked_runtime_imports.py': 'b1bddbda1ef6ea2323a1b3face282fbb21cd1a01db64d68dff8deaa28308b1da',
}
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
           'src/models/ranking_v5_locked_runtime_imports.py', TRAIN_JIT)
MANIFEST_NAME = 'data/manifests/ranking_v5_caller_source_bytes_20261008.json'
EVIDENCE = {'authorization.json': 'authorization_sha256',
            'release.json': 'release_file_sha256', 'review.json': 'review_sha256',
            'physical_gate.json': 'physical_gate_sha256',
            'synthetic_linux_gate.json': 'synthetic_linux_gate_sha256',
            'scope_authorization.json': 'scope_authorization_sha256',
            'controlled_optimizer.child.json': 'optimizer_child_sha256',
            'controlled_optimizer.log.memory.json': 'optimizer_memory_sha256',
            'controlled_optimizer.launch.json': 'optimizer_launch_sha256',
            AUDIT: 'optimizer_audit_sha256'}
ENVELOPE_FIELDS = frozenset(('schema', 'source_root', 'output', 'package_root', 'family', 'seed',
    'roles', 'parent_resource_guard_required', 'core_manifest_sha256', 'helper_sha256',
    'authorization_sha256', 'authorization_id', 'release_file_sha256', 'review_sha256',
    'physical_gate_sha256', 'synthetic_linux_gate_sha256', 'gate_source_sha256',
    'scope_authorization_sha256', 'optimizer_child_sha256', 'optimizer_memory_sha256',
    'optimizer_launch_sha256', 'optimizer_audit_sha256', 'jit_root'))
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
    sidecars = {f'jit_admission_{family}_{seed}.json' for family in FAMILIES for seed in SEEDS}
    allowed = CORE_FILES | set(HELPERS) | set(GATE_SOURCES) | set(EVIDENCE) | {MANIFEST_NAME} | envelopes | sidecars
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


def jit_root_for(source_root, family, seed):
    _require(type(family) is str and family in FAMILIES and type(seed) is int and seed in SEEDS, 'TASK')
    _lexical(source_root, source_root+'_'+family+'_'+str(seed), PACKAGE_ROOT, family, seed)
    return source_root+'/jit_tmp/'+family+'_'+str(seed)


def validate_external_trust(trusted_supplement_sha256, trusted_evidence_sha256):
    """Trust maps come from the reviewed launch, never from its envelope."""
    _require(type(trusted_supplement_sha256) is dict
             and set(trusted_supplement_sha256) == set(HELPERS)
             and all(_pin(v) for v in trusted_supplement_sha256.values())
             and all(trusted_supplement_sha256[p] == v for p, v in FIXED_HELPER_PINS.items()), 'SUPPLEMENT_TRUST')
    _require(type(trusted_evidence_sha256) is dict and set(trusted_evidence_sha256) == set(EVIDENCE)
             and all(_pin(v) for v in trusted_evidence_sha256.values())
             and trusted_evidence_sha256['authorization.json'] == AUTHORIZATION_SHA256
             and trusted_evidence_sha256['scope_authorization.json'] == SCOPE_AUTHORIZATION_SHA256
             and trusted_evidence_sha256['synthetic_linux_gate.json'] == SYNTHETIC_LINUX_GATE_SHA256
             and all(trusted_evidence_sha256[p] == v for p, v in OPTIMIZER_EVIDENCE_PINS.items()), 'EVIDENCE_TRUST')


def _envelope(raw, trusted_sha256, source_root, output, package_root, family, seed, *,
              trusted_supplement_sha256, trusted_evidence_sha256):
    validate_external_trust(trusted_supplement_sha256, trusted_evidence_sha256)
    _require(_pin(trusted_sha256) and type(raw) is bytes and 0 < len(raw) <= JSON_CAP
             and _sha(raw) == trusted_sha256, 'ENVELOPE_SHA')
    value = _json(raw)
    _require(set(value) == ENVELOPE_FIELDS and value['schema'] == 'v5-train-prelaunch-envelope-v2', 'ENVELOPE_SCHEMA')
    _require(value['source_root'] == source_root and value['output'] == output
             and value['package_root'] == package_root and value['family'] == family
             and type(value['seed']) is int and value['seed'] == seed
             and value['roles'] == ['TRAIN'] and value['parent_resource_guard_required'] is True
             and value['jit_root'] == jit_root_for(source_root, family, seed), 'ENVELOPE_BINDING')
    _require(value['core_manifest_sha256'] == CORE_MANIFEST_SHA256
             and value['authorization_sha256'] == AUTHORIZATION_SHA256
             and value['authorization_id'] == AUTHORIZATION_ID
             and value['scope_authorization_sha256'] == SCOPE_AUTHORIZATION_SHA256
             and value['synthetic_linux_gate_sha256'] == SYNTHETIC_LINUX_GATE_SHA256, 'FIXED_SEALS')
    _require(value['helper_sha256'] == trusted_supplement_sha256
             and all(value[field] == trusted_evidence_sha256[name] for name, field in EVIDENCE.items()), 'ENVELOPE_PINS')
    _require(type(value['gate_source_sha256']) is dict
             and value['gate_source_sha256'] == optimizer_source_pins(), 'OPTIMIZER_SOURCE_PINS')
    return value


def optimizer_source_pins():
    return {OPTIMIZER_PROGRAM: OPTIMIZER_SOURCE_SHA256,
            CPU_PROGRAM: '0a4bb0389cce25c2ac50f3adcc721ac2b2545acbf2d15df3c41d5ac8bca5c462',
            JIT: 'd961ccd389c43ef2ae887e2072142259aa1b1e139133433a15863c9c157d3396',
            PROBE: 'def81c6af0454909685957edf6e3aa7c2c48b66fb09b5ad31de20def70d54f6e',
            SNAPSHOT: '8205b16956fb264841ecd8644784a0d157f87df79b17c16825dc1163433ce5d8'}


def _typed_equal(a, b):
    if type(a) is not type(b):
        return False
    if type(b) is dict:
        return a.keys() == b.keys() and all(_typed_equal(a[k], b[k]) for k in b)
    if type(b) is list:
        return len(a) == len(b) and all(_typed_equal(x, y) for x, y in zip(a, b))
    return a == b


def validate_actual_audit(audit, child, memory, final):
    fixed = dict(schema='v5-fixed-probe-actual-synthetic-evidence-v1',
        status='PASS_ACTUAL_SYNTHETIC_EVIDENCE_ONLY', root=SMOKE_ROOT,
        authorization_sha256=SCOPE_AUTHORIZATION_SHA256, exit_code=0,
        optimizer_invocations=1, optimizer_steps=120, fitting_log_records=122,
        negative_probe_count=15, all_fixed_probe_counts_equal_one=True,
        probe_verified=True, jit_template_proven=True, address_space_cap_bytes=8*1024**3,
        sampled_combined_rss_cap_bytes=1024**3, workers=1, threads=1,
        automatic_retries=0, formal_fits=0, formal_package_reads=0, held_label_reads=0,
        formal_training_release=False, model_quality_or_generalization_claim=False,
        checkpoint_remains_on_B=True)
    _require(type(audit) is dict and all(k in audit and _typed_equal(audit[k], v) for k, v in fixed.items()), 'ACTUAL_AUDIT')
    for key, path in (('child_raw_sha256', 'controlled_optimizer.child.json'),
                      ('memory_raw_sha256', 'controlled_optimizer.log.memory.json'),
                      ('final_raw_sha256', 'controlled_optimizer.launch.json')):
        _require(audit.get(key) == OPTIMIZER_EVIDENCE_PINS[path], 'AUDIT_RAW_BINDING')
    for key in ('model_sha256', 'model_bytes', 'fitting_log_sha256', 'fitting_log_bytes'):
        _require(key in audit and _typed_equal(audit[key], child[key]), 'AUDIT_ARTIFACT_BINDING')
    for audit_key, memory_key in (('sampled_combined_rss_peak_bytes', 'peak_combined_rss_bytes'),
                                  ('group_rss_peak_bytes', 'peak_group_rss_bytes'),
                                  ('sample_count', 'sample_count'), ('elapsed_seconds', 'elapsed_seconds')):
        _require(audit_key in audit and _typed_equal(audit[audit_key], memory[memory_key]), 'AUDIT_RESOURCE_BINDING')
    _require(final['actual_linux_resource_proof'] is True, 'AUDIT_RESOURCE_PROOF')


def validate_optimizer_evidence(source, evidence, receipt):
    """Pure authenticated prerequisite; never opens a formal package."""
    _require(type(source) is dict and type(evidence) is dict
             and all(p in source and type(source[p]) is bytes for p in set(GATE_SOURCES) | set(FIXED_HELPER_PINS))
             and all(p in evidence and type(evidence[p]) is bytes for p in
                     ('authorization.json', 'scope_authorization.json'))
             and all(p in evidence and type(evidence[p]) is bytes and _sha(evidence[p]) == v
                     for p, v in OPTIMIZER_EVIDENCE_PINS.items()), 'ACTUAL_EVIDENCE_BYTES')
    _require(_sha(evidence['authorization.json']) == AUTHORIZATION_SHA256
             and _json(evidence['authorization.json']).get('authorization_id') == AUTHORIZATION_ID
             and _sha(evidence['scope_authorization.json']) == SCOPE_AUTHORIZATION_SHA256,
             'OPTIMIZER_AUTHORIZATION')
    pins = optimizer_source_pins()
    _require(all(name in source and _sha(source[name]) == value
                 for name, value in pins.items()), 'OPTIMIZER_SOURCE_BYTES')
    _require(_sha(source[HELPERS[1]]) == '0524a7b8cce7d017c3fe9fe38dcc86b29a440ed7b373c1c2361ebbb7738459c8'
             and _sha(source[HELPERS[2]]) == 'b1bddbda1ef6ea2323a1b3face282fbb21cd1a01db64d68dff8deaa28308b1da',
             'OPTIMIZER_RUNTIME_BINDING')
    optimizer = _helper(source[OPTIMIZER_PROGRAM], '_v5_optimizer_prerequisite')
    transport = _helper(source[CPU_PROGRAM], '_v5_optimizer_transport')
    child = _json(evidence['controlled_optimizer.child.json'])
    memory = _json(evidence['controlled_optimizer.log.memory.json'])
    final = _json(evidence['controlled_optimizer.launch.json'])
    gate_pins = {**pins,
        HELPERS[1]: _sha(source[HELPERS[1]]), HELPERS[2]: _sha(source[HELPERS[2]]),
        'auth/user_authorization.raw.txt': SCOPE_AUTHORIZATION_SHA256}
    optimizer.validate_final(final, gate_pins, transport, receipt)
    _require(final['root'] == SMOKE_ROOT, 'ACTUAL_SMOKE_ROOT')
    _require(type(memory.get('peak_group_rss_bytes')) is int
             and memory['peak_group_rss_bytes'] > 0, 'OPTIMIZER_ZERO_CHILD_RSS')
    _require(final['child_receipt_sha256'] == _sha(evidence['controlled_optimizer.child.json'])
             and transport.typed_equal(final['child_receipt'], child)
             and transport.typed_equal(final['parent_guard_receipt'], memory), 'OPTIMIZER_RECEIPT_BINDING')
    validate_actual_audit(_json(evidence[AUDIT]), child, memory, final)


def _helper(raw, name):
    """Externally named ModuleType, never a disk import of src/scripts."""
    module = ModuleType(name)
    module.__file__ = 'sealed-bootstrap://' + name
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def _import(name):
    return importlib.import_module(name)


def execute_prelaunch(envelope_raw, *, trusted_envelope_sha256, source_root,
                      output, package_root, family, seed,
                      trusted_supplement_sha256, trusted_evidence_sha256):
    """Execute one guarded child callback. Trusted envelope is not consent proof."""
    _runtime()
    _lexical(source_root, output, package_root, family, seed)
    envelope = _envelope(envelope_raw, trusted_envelope_sha256, source_root, output, package_root, family, seed,
        trusted_supplement_sha256=trusted_supplement_sha256, trusted_evidence_sha256=trusted_evidence_sha256)
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
    gate_source = {**helper_raw}
    for name, value in optimizer_source_pins().items():
        raw = _read(source_root, name, SOURCE_CAP)
        total += len(raw)
        _require(total <= TOTAL_SOURCE_CAP and _sha(raw) == value, 'OPTIMIZER_SOURCE_BYTES')
        gate_source[name] = raw
    auth = _json(evidence['authorization.json'])
    _require(auth.get('authorization_id') == AUTHORIZATION_ID, 'AUTHORIZATION_ID')
    release = _json(evidence['release.json'])
    _require(release.get('user_authorization_id') == AUTHORIZATION_ID, 'RELEASE_AUTHORIZATION_ID')
    frozen = _helper(helper_raw[HELPERS[0]], '_v5_train_frozen_helper')
    observation = _helper(helper_raw[HELPERS[1]], '_v5_train_observation_helper')
    runtime = _helper(helper_raw[HELPERS[2]], '_v5_train_runtime_helper')
    train_jit = _helper(helper_raw[TRAIN_JIT], '_v5_train_jit_helper')
    admission = _helper(gate_source[PROBE], '_v5_train_negative_helper')
    py_sources = {k: v for k, v in sources.items() if k.endswith('.py')}
    py_pins = {k: manifest['sources'][k] for k in py_sources}
    expected_sources = {k: manifest['sources'][k] for k in RELEASE_SOURCE_FILES}
    with admission.controlled_imports(py_sources, py_pins, frozen_helper=frozen,
            observation_helper=observation, lock_raw=lock_raw, base_context=runtime,
            jit_root=envelope['jit_root'], generated_raw=gate_source[SNAPSHOT],
            jit_admission=train_jit) as admission_receipt:
        # The context performs fresh fixed metadata observations before imports.
        binder = _import('src.models.ranking_v5_caller_source_binding')
        binder.validate_source_bytes(manifest_raw, sources, trusted_manifest_sha256=CORE_MANIFEST_SHA256)
        approval = _import('src.models.ranking_v5_approval_binding')
        approval.validate_approval_integrity(release, expected_sources, evidence['authorization.json'],
            evidence['review.json'], trusted_authorization_sha256=AUTHORIZATION_SHA256,
            trusted_review_sha256=envelope['review_sha256'],
            trusted_physical_gate_sha256=envelope['physical_gate_sha256'])
        validate_optimizer_evidence(gate_source, evidence,
            _import('src.models.ranking_v5_parent_guard_receipt'))
        resource = _import('src.models.ranking_v5_worker_resource_context')
        resource.check_current_process()
        worker = _import('src.models.ranking_v5_single_fit_worker')
        # Only after integrity, approval, metadata and child resource checks.
        torch, np = _import('torch'), _import('numpy')
        _require(torch.cuda.is_available() is False, 'CUDA_VISIBLE')
        # Real lazy-import chain, no fake Torch and no new optimizer fit. This
        # proof is at fit boundaries, not a hook inside immutable worker save.
        _import('torch._dynamo')
        admission.validate_current(admission_receipt)
        result = worker.execute_single_fit(package_root, family, seed, release, expected_sources,
            evidence['authorization.json'], evidence['review.json'], output=output, torch=torch, np=np,
            trusted_authorization_sha256=AUTHORIZATION_SHA256,
            trusted_review_sha256=envelope['review_sha256'],
            trusted_physical_gate_sha256=envelope['physical_gate_sha256'])
        admission.validate_current(admission_receipt)
    _require(type(result) is dict and result.get('status') == 'PASS_SINGLE_FIT_CALLBACK_ADAPTER_ONLY'
             and result.get('formal_training_authorized_by_this_function') is False
             and result.get('new_formal_18_fit_release') is False, 'WORKER_RECEIPT')
    sidecar = dict(schema='v5-train-fit-boundary-admission-v2',
        status='PASS_TRAIN_FIT_BOUNDARY_ADMISSION_ONLY', source_root=source_root, output=output,
        family=family, seed=seed, helper_sha256=dict(trusted_supplement_sha256),
        jit_admission={k: admission_receipt[k] for k in JIT_PROOF_FIELDS},
        fx2trt_probe=admission_receipt['fx2trt_probe'], admission_at_fit_boundaries_only=True,
        inside_save_hook_verified=False, formal_training_authorized_by_this_function=False)
    sidecar_raw = json.dumps(sidecar, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    validate_fit_admission_receipt(sidecar_raw, source_root=source_root, output=output,
        family=family, seed=seed, trusted_supplement_sha256=trusted_supplement_sha256)
    persist_admission_sidecar(sidecar_raw, source_root, family, seed)
    return result


JIT_PROOF_FIELDS = frozenset(('jit_template_proven', 'generated_source_sha256',
    'generated_source_bytes', 'jit_root', 'jit_temp_dir', 'installed_source_pins',
    'formal_training_release', 'actual_linux_resource_proof'))


def admission_sidecar_path(source_root, family, seed):
    jit_root_for(source_root, family, seed)
    return source_root+'/jit_admission_'+family+'_'+str(seed)+'.json'


def validate_fit_admission_receipt(raw, *, source_root, output, family, seed,
                                   trusted_supplement_sha256):
    _lexical(source_root, output, PACKAGE_ROOT, family, seed)
    _require(type(trusted_supplement_sha256) is dict
             and set(trusted_supplement_sha256) == set(HELPERS)
             and all(_pin(v) for v in trusted_supplement_sha256.values())
             and all(trusted_supplement_sha256[p] == v for p, v in FIXED_HELPER_PINS.items()), 'SIDECAR_TRUST')
    value = _json(raw)
    fixed = dict(schema='v5-train-fit-boundary-admission-v2',
        status='PASS_TRAIN_FIT_BOUNDARY_ADMISSION_ONLY', source_root=source_root, output=output,
        family=family, seed=seed, helper_sha256=trusted_supplement_sha256,
        admission_at_fit_boundaries_only=True, inside_save_hook_verified=False,
        formal_training_authorized_by_this_function=False)
    _require(set(value) == set(fixed) | {'jit_admission', 'fx2trt_probe'}
             and all(_typed_equal(value[k], v) for k, v in fixed.items()), 'SIDECAR_BINDING')
    jit_proof = value['jit_admission']
    expected_jit = dict(jit_template_proven=True, generated_source_sha256=optimizer_source_pins()[SNAPSHOT],
        generated_source_bytes=2355, jit_root=jit_root_for(source_root, family, seed),
        installed_source_pins={
            'torch.distributed.nn.jit.instantiator': '440a619c764e4133564d7956ba060a7223e94664854b94a4a2074d095756db7e',
            'torch.distributed.nn.jit.templates.remote_module_template': '0ff1856bbd031b5298d46c06c0502abc20bd804f42c1949ed4127e8c773660cc'},
        formal_training_release=False, actual_linux_resource_proof=False)
    _require(type(jit_proof) is dict and set(jit_proof) == JIT_PROOF_FIELDS
             and all(_typed_equal(jit_proof[k], v) for k, v in expected_jit.items())
             and type(jit_proof['jit_temp_dir']) is str
             and re.fullmatch(re.escape(expected_jit['jit_root'])+r'/tmp[a-z0-9_]{8}', jit_proof['jit_temp_dir']) is not None,
             'SIDECAR_JIT')
    probe = value['fx2trt_probe']
    names = ('fx2trt_oss', 'hypothesis', 'omegaconf', 'onnx', 'onnxruntime', 'onnx_tf', 'pandas',
             'tabulate', 'tensorflow', 'tensorrt', 'torch2trt', 'tqdm', 'tree', 'tvm', 'xarray')
    expected_probe = dict(probe_verified=True, probe_name='fx2trt_oss', probe_invocations=15,
        negative_probe_names=list(names), probe_counts={name: 1 for name in names},
        trace_source_bytes=140951, trace_source_sha256='ba438afd2b574d5d733532e7995ed04c29306f32b75df87657978288375bced5',
        trace_origin='/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages/torch/_dynamo/trace_rules.py',
        search_paths=['/usr/lib/python311.zip', '/usr/lib/python3.11', '/usr/lib/python3.11/lib-dynload',
            '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/lib/python3.11/site-packages',
            '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages'],
        formal_training_release=False, actual_linux_resource_proof=False)
    _require(_typed_equal(probe, expected_probe), 'SIDECAR_PROBE')
    return value


def persist_admission_sidecar(raw, source_root, family, seed):
    path = Path(admission_sidecar_path(source_root, family, seed))
    _require(type(raw) is bytes and 0 < len(raw) <= JSON_CAP, 'SIDECAR_BOUND')
    for ancestor in path.parents:
        _ordinary(ancestor.lstat(), directory=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
                 | getattr(os, 'O_BINARY', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        _ordinary(os.fstat(stream.fileno()))
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    _require(_read(source_root, path.name, JSON_CAP) == raw, 'SIDECAR_READBACK')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--package-root', required=True)
    parser.add_argument('--envelope-sha256', required=True)
    parser.add_argument('--family', required=True)
    parser.add_argument('--seed', required=True, type=int)
    parser.add_argument('--trusted-supplement-sha256-json', required=True)
    parser.add_argument('--trusted-evidence-sha256-json', required=True)
    args = parser.parse_args(argv)
    _runtime()
    _lexical(args.source_root, args.output, args.package_root, args.family, args.seed)
    _require(_pin(args.envelope_sha256), 'ENVELOPE_SHA')
    supplement_pins = _json(args.trusted_supplement_sha256_json.encode())
    evidence_pins = _json(args.trusted_evidence_sha256_json.encode())
    validate_external_trust(supplement_pins, evidence_pins)
    # One shared fresh source root can hold all 18 independently pinned,
    # create-once per-fit envelopes. Never accept an arbitrary envelope path.
    name = f'prelaunch_{args.family}_{args.seed}.json'
    raw = _read(args.source_root, name, JSON_CAP)
    result = execute_prelaunch(raw, trusted_envelope_sha256=args.envelope_sha256,
        source_root=args.source_root, output=args.output, package_root=args.package_root,
        family=args.family, seed=args.seed, trusted_supplement_sha256=supplement_pins,
        trusted_evidence_sha256=evidence_pins)
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
