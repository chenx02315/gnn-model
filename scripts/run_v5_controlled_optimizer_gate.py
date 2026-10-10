"""One-use CPU synthetic optimizer smoke, never a formal TRAIN release.

No ML imports at module startup. Externally trusted pins authenticate the old
transport before reuse; its immutable core/source/lock checks remain unchanged.
Authorization authenticity is an external review obligation, not a self-claim.
"""
import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from types import ModuleType

INTERPRETER = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'
CORE_SHA = '5394779faac5c77800a0a9d8ed52bf9f24ba2dd701f499a49754e51e7ddceae7'
PROGRAM = 'scripts/run_v5_controlled_optimizer_gate.py'
TRANSPORT = 'scripts/run_v5_controlled_runtime_gate.py'
OBS = 'src/models/ranking_v5_locked_runtime_observations.py'
CONTEXT = 'src/models/ranking_v5_locked_runtime_imports.py'
AUTH = 'auth/user_authorization.raw.txt'
SEARCH_PATHS = ('/usr/lib/python311.zip', '/usr/lib/python3.11', '/usr/lib/python3.11/lib-dynload',
    '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/lib/python3.11/site-packages',
    '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages')
GLOBAL_LOCK = '/ssd/cjc/gnn_model_ranking_v5_serial_parent.lock'
ONCE_PREFIX = '/ssd/cjc/gnn_model_ranking_v5_optimizer_gate.authorization_'
STARTED = 'optimizer.started.json'
CHILD_STARTED = 'optimizer.child.started.json'
LOG = 'controlled_optimizer.log'
CHILD = 'controlled_optimizer.child.json'
FINAL = 'controlled_optimizer.launch.json'
MODEL = 'synthetic_model.pt'
FITTING = 'synthetic_fitting.jsonl'
CAP = 65536
JSON_CAP = 20000
MODEL_CAP = 1024 * 1024
LOG_CAP = 3 * 1024 * 1024
CHILD_STATUS = 'PASS_CONTROLLED_CPU_SYNTHETIC_OPTIMIZER_ONLY'
FINAL_STATUS = 'PASS_BOUNDED_CONTROLLED_CPU_SYNTHETIC_OPTIMIZER_ONLY'
SYNTHETIC_REQUEST_SHA = 'db1fde590c5fea061b5cbf3a551dbe2e045eae63cdfc3317df93f1321ddb4814'
SYNTHETIC_RECIPE_SHA = '9a038927a01a88b77472a7878df0af93b0997e2fedb6703f3ba6cef6c6b79dd2'


def require(ok, code):
    if not ok:
        raise ValueError('V5_OPTIMIZER_GATE_' + code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def root_valid(root):
    return type(root) is str and re.fullmatch(
        '/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_[0-9]{8}_r[1-9][0-9]*', root) is not None


def read(path, cap=CAP):
    path = Path(path)
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'SYMLINK')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= cap, 'FILE')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns), 'IDENTITY')
        raw = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) == before.st_size and (after.st_size, after.st_mtime_ns) ==
            (before.st_size, before.st_mtime_ns), 'CHANGED')
    return raw


def external(name, raw):
    module = ModuleType(name)
    module.__file__ = 'sealed://' + name
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def preconditions(root, pins):
    require(sys.platform == 'linux' and sys.executable == INTERPRETER
            and tuple(sys.version_info[:3]) == (3, 11, 2), 'RUNTIME')
    require(os.getcwd() == '/ssd/cjc' and sys.flags.no_site == 1 and sys.flags.isolated == 1
            and sys.path == list(SEARCH_PATHS) and 'sitecustomize' not in sys.modules
            and 'usercustomize' not in sys.modules, 'SITE_BOOTSTRAP')
    require(root_valid(root), 'ROOT')
    require(type(pins) is dict and set(pins) == {PROGRAM, TRANSPORT, OBS, CONTEXT, AUTH}
            and all(pin(value) for value in pins.values()), 'PINS')
    require(os.environ.get('SETUPTOOLS_USE_DISTUTILS') == 'stdlib', 'DISTUTILS_ENV')


def load(root, pins):
    preconditions(root, pins)  # before any source/auth/core I/O
    raw = read(Path(root) / TRANSPORT)
    require(sha(raw) == pins[TRANSPORT], 'TRANSPORT_SHA')
    transport = external('optimizer_authenticated_runtime_transport', raw)
    transport.preconditions = preconditions
    loaded = transport.load(root, pins)
    return transport, loaded


def bootstrap(root, program_sha):
    require(root_valid(root) and pin(program_sha), 'BOOTSTRAP')
    return ('import sys;assert sys.flags.no_site==1 and sys.flags.isolated==1;'
        + 'sys.path[:]=' + repr(list(SEARCH_PATHS)) + ';'
        + 'import os,hashlib;from pathlib import Path;'
        + 'p=Path(' + repr(root + '/' + PROGRAM) + ');'
        + 'assert not any(q.is_symlink() for q in (p,*p.parents));'
        + 'f=p.open("rb");raw=f.read(65537);f.close();'
        + 'assert 0<len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==' + repr(program_sha) + ';'
        + 'os.chdir("/ssd/cjc");exec(compile(raw,str(p),"exec"))')


def request_for(runtime, kernel):
    rows, cycles = [], {}
    held = sorted(runtime.FAMILIES.values())[0]
    for circuit, family in runtime.FAMILIES.items():
        for index in range(12):
            uid = '%s:synthetic:%02d' % (circuit, index)
            rows.append(dict(action_uid=uid, circuit=circuit, family=family, role='TRAIN',
                **{name: float(index + column + 1) for column, name in enumerate(runtime.FEATURES)}))
            if family != held:
                cycles[uid] = 100 if index == 0 else 200 + index
    return dict(scope=kernel.SCOPE, source_sha256='0'*64, family=held,
                seed=20260824, model='candidate_mlp', rows=rows, fit_cycles=cycles)


def expected_bindings(runtime, kernel):
    """Rebuild the exact fixture and recipe from authenticated core, no ML/I/O."""
    request = request_for(runtime, kernel)
    _, recipe = kernel.prepare(request)
    request_sha, recipe_sha = runtime.digest(request), runtime.digest(recipe)
    require(request_sha == SYNTHETIC_REQUEST_SHA and recipe_sha == SYNTHETIC_RECIPE_SHA,
            'FIXTURE_BINDING')
    return request_sha, recipe_sha


class BoundedBuffer(io.BytesIO):
    def write(self, raw):
        require(self.tell() + len(raw) <= MODEL_CAP, 'MODEL_BOUND')
        return super().write(raw)


def finite_tree(value):
    if type(value) in (int, float):
        require(math.isfinite(value), 'NONFINITE')
    elif type(value) is dict:
        require(all(type(k) is str for k in value), 'LOG_KEYS')
        for item in value.values():
            finite_tree(item)
    elif type(value) is list:
        for item in value:
            finite_tree(item)
    else:
        require(type(value) in (str, bool, type(None)), 'LOG_TYPE')


def log_bytes(records, request_sha, recipe_sha):
    require(request_sha == SYNTHETIC_REQUEST_SHA and recipe_sha == SYNTHETIC_RECIPE_SHA,
            'LOG_EXPECTED_BINDING')
    require(type(records) is list and len(records) == 122, 'LOG_COUNT')
    lines = []
    for i, row in enumerate(records):
        phase, epoch = ('INITIAL', 0) if i == 0 else ('FINAL', 120) if i == 121 else ('EPOCH', i)
        require(type(row) is dict and row.get('phase') == phase and type(row.get('epoch')) is int
                and row['epoch'] == epoch and row.get('canonical_request_sha256') == request_sha,
                'LOG_SEQUENCE')
        require(set(row) == {'scope', 'epoch', 'phase', 'K', 'epsilon', 'recipe_sha256', 'families',
            'macro_head_loss', 'objective_signal_families', 'macro_family_count',
            'macro_pair_softplus_reference', 'canonical_request_sha256'}
            and row['scope'] == 'FITTING_ONLY_DIAGNOSTIC_NOT_RELEASE' and row['epsilon'] == '101/100'
            and type(row['K']) is int and row['K'] == 10 and row['recipe_sha256'] == recipe_sha
            and type(row['objective_signal_families']) is int and row['objective_signal_families'] == 5
            and type(row['macro_family_count']) is int and row['macro_family_count'] == 5
            and type(row['families']) is list and len(row['families']) == 5, 'LOG_SCHEMA')
        require([f.get('family') for f in row['families'] if type(f) is dict] ==
            ['iscas89_s15850', 'iscas89_s35932', 'iscas89_s38417', 'iwls_aes_core', 'iwls_spi'], 'LOG_FAMILIES')
        for family in row['families']:
            require(set(family) == {'family', 'actions', 'positive_count', 'negative_count',
                'first_positive_rank', 'hit_at_10', 'negatives_before_first_positive',
                'top10_cycle_regret', 'head_gap', 'head_softplus', 'guaranteed_hit_by_size',
                'strict_score_hit_certificate', 'tie_at_boundary', 'pair_softplus_reference'}, 'LOG_FAMILY_FIELDS')
            for key, expected in (('actions', 12), ('positive_count', 1), ('negative_count', 11)):
                require(type(family.get(key)) is int and family[key] == expected, 'LOG_FAMILY_COUNTS')
            rank, hit = family['first_positive_rank'], family['hit_at_10']
            require(type(rank) is int and 1 <= rank <= 12 and type(hit) is int
                    and hit == int(rank <= 10)
                    and type(family['negatives_before_first_positive']) is int
                    and family['negatives_before_first_positive'] == rank - 1, 'LOG_FAMILY_RANK')
            require(all(type(family[k]) is float and math.isfinite(family[k]) for k in
                    ('top10_cycle_regret', 'head_gap', 'head_softplus', 'pair_softplus_reference'))
                    and all(family[k] >= 0 for k in ('top10_cycle_regret', 'head_softplus', 'pair_softplus_reference')),
                    'LOG_FAMILY_FINITE')
            gap = family['head_gap']
            require(family['guaranteed_hit_by_size'] is False
                    and type(family['strict_score_hit_certificate']) is bool
                    and family['strict_score_hit_certificate'] == (gap > 0)
                    and type(family['tie_at_boundary']) is bool and family['tie_at_boundary'] == (gap == 0),
                    'LOG_FAMILY_CERTIFICATE')
            expected_loss = max(-gap, 0.) + math.log1p(math.exp(-abs(gap)))
            require(math.isclose(family['head_softplus'], expected_loss, rel_tol=1e-12, abs_tol=1e-12)
                    and (gap == 0 or hit == int(gap > 0))
                    and (family['top10_cycle_regret'] == 0 if hit else family['top10_cycle_regret'] > 0),
                    'LOG_FAMILY_DERIVED')
        finite_tree(row)
        require(type(row.get('macro_head_loss')) is float and type(row.get('macro_pair_softplus_reference')) is float,
                'LOG_METRICS')
        require(row['macro_head_loss'] >= 0 and row['macro_pair_softplus_reference'] >= 0
                and math.isclose(row['macro_head_loss'], sum(f['head_softplus'] for f in row['families']) / 5,
                    rel_tol=1e-12, abs_tol=1e-12)
                and math.isclose(row['macro_pair_softplus_reference'],
                    math.fsum(f['pair_softplus_reference'] for f in row['families']) / 5,
                    rel_tol=1e-12, abs_tol=1e-12), 'LOG_MACRO_CONSISTENCY')
        raw = (json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        require(len(raw) <= JSON_CAP, 'LOG_RECORD_BOUND')
        lines.append(raw)
    result = b''.join(lines)
    require(len(result) <= LOG_CAP, 'LOG_BOUND')
    return result


def persist(path, raw, cap):
    require(type(raw) is bytes and 0 < len(raw) <= cap, 'ARTIFACT_BOUND')
    path = Path(path)
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'SYMLINK')
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    reread = read(path, cap)
    require(reread == raw, 'ARTIFACT_READBACK')
    return sha(reread)


def started_payload(root, pins):
    return dict(status='STARTED_ONE_USE_NO_RETRY', root=root, supplemental_sha256=pins,
                authorization_raw_sha256=pins[AUTH], core_manifest_sha256=CORE_SHA,
                automatic_retries=0, formal_training_release=False)


def claim_once(root, pins, transport):
    payload = started_payload(root, pins)
    # Authorization-specific O_EXCL marker is never removed, even on failure.
    transport.write(ONCE_PREFIX + pins[AUTH] + '.once.json', payload)
    transport.write(Path(root) / STARTED, payload)


def verify_started(root, pins, transport):
    expected = started_payload(root, pins)
    for path in (ONCE_PREFIX + pins[AUTH] + '.once.json', Path(root) / STARTED):
        require(transport.typed_equal(transport.decode(read(path, JSON_CAP)), expected), 'STARTED_BINDING')


@contextmanager
def global_worker_lock():
    """Same advisory lock as TRAIN serial parent, held through receipt readback."""
    import fcntl
    path = Path(GLOBAL_LOCK)
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'LOCK_SYMLINK')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size == 0, 'LOCK_CONTENT')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = path.lstat()
        require(stat.S_ISREG(current.st_mode) and (info.st_dev, info.st_ino) ==
                (current.st_dev, current.st_ino), 'LOCK_CHANGED')
        yield
    finally:
        os.close(fd)


def child(root, pins):
    transport, (fence, supplemental, sources, python, python_pins) = load(root, pins)
    verify_started(root, pins, transport)
    # Refuse direct child replay before any ML import/optimizer work as well.
    transport.write(Path(root) / CHILD_STARTED, started_payload(root, pins))
    observation = external('optimizer_observation', supplemental[OBS])
    context = external('optimizer_context', supplemental[CONTEXT])
    with context.controlled_imports(python, python_pins, frozen_helper=fence,
            observation_helper=observation, lock_raw=sources['requirements/runtime_v2.lock.txt']):
        from src.models import ranking_v5_worker_resource_context as resources
        prerequisites = resources.check_current_process()  # must precede ML
        import torch
        import numpy
        torch.set_num_threads(1)
        torch.set_num_interop_threads(1)
        require(torch.get_num_threads() == 1 and torch.get_num_interop_threads() == 1
                and torch.cuda.is_available() is False, 'CPU_THREADS')
        from src.models import ranking_v5_training_kernel as kernel
        from src.models import runtime_ranking_v3 as runtime
        request = request_for(runtime, kernel)
        request_sha, recipe_sha = expected_bindings(runtime, kernel)
        records, total = [], 0
        def emit(row):
            nonlocal total
            finite_tree(row)
            raw = json.dumps(row, allow_nan=False).encode()
            require(len(records) < 122 and len(raw) <= JSON_CAP and total + len(raw) <= LOG_CAP, 'LOG_SINK_BOUND')
            total += len(raw)
            records.append(row)
        model = kernel.fit_synthetic(torch, numpy, request, emit)
        fitting_raw = log_bytes(records, request_sha, recipe_sha)
        buffer = BoundedBuffer()
        torch.save(model.state_dict(), buffer)
        model_raw = buffer.getvalue()
        model_sha = persist(Path(root) / MODEL, model_raw, MODEL_CAP)
        fitting_sha = persist(Path(root) / FITTING, fitting_raw, LOG_CAP)
        payload = dict(status=CHILD_STATUS, supplemental_sha256=pins, core_manifest_sha256=CORE_SHA,
            authorization_raw_sha256=pins[AUTH], authentic_user_consent_proven=False,
            torch_version=str(torch.__version__), numpy_version=str(numpy.__version__),
            torch_origin=torch.__file__, numpy_origin=numpy.__file__, threads=1, interop_threads=1,
            cuda_available=False, child_prerequisites=prerequisites, synthetic_optimizer_fits=1,
            optimizer_steps=120, fitting_log_records=122, actual_formal_fits=0,
            production_package_reads=0, held_label_reads=0, formal_training_release=False,
            automatic_retries=0, request_sha256=request_sha, model_sha256=model_sha,
            model_bytes=len(model_raw), fitting_log_sha256=fitting_sha, fitting_log_bytes=len(fitting_raw),
            initial_head_loss=records[0]['macro_head_loss'], final_head_loss=records[-1]['macro_head_loss'],
            initial_pair_reference=records[0]['macro_pair_softplus_reference'],
            final_pair_reference=records[-1]['macro_pair_softplus_reference'])
    validate_child(payload, pins)
    transport.write(Path(root) / CHILD, payload)
    return payload


def validate_child(payload, pins):
    fixed = dict(status=CHILD_STATUS, supplemental_sha256=pins, core_manifest_sha256=CORE_SHA,
        authorization_raw_sha256=pins[AUTH], authentic_user_consent_proven=False,
        torch_version='2.5.1+cu124', numpy_version='2.1.3',
        threads=1, interop_threads=1, cuda_available=False, synthetic_optimizer_fits=1,
        optimizer_steps=120, fitting_log_records=122, actual_formal_fits=0,
        production_package_reads=0, held_label_reads=0, formal_training_release=False, automatic_retries=0)
    site = SEARCH_PATHS[-1] + '/'
    fixed.update(torch_origin=site+'torch/__init__.py', numpy_origin=site+'numpy/__init__.py',
        child_prerequisites=dict(status='PASS_CHILD_PREREQUISITES_ONLY', address_space_limits=[8*1024**3]*2,
            core_limits=[0, 0], threads=1, parent_sampled_rss_enforcement_proven=False, authentic_user_consent_proven=False))
    variable = {'request_sha256', 'model_sha256', 'fitting_log_sha256', 'model_bytes', 'fitting_log_bytes',
                'initial_head_loss', 'final_head_loss', 'initial_pair_reference', 'final_pair_reference'}
    require(type(payload) is dict and set(payload) == set(fixed) | variable, 'CHILD_FIELDS')
    def equal(a, b):
        return type(a) is type(b) and (a.keys() == b.keys() and all(equal(a[k], b[k]) for k in b)
            if type(b) is dict else len(a) == len(b) and all(equal(x, y) for x, y in zip(a, b))
            if type(b) is list else a == b)
    require(all(equal(payload[k], v) for k, v in fixed.items()), 'CHILD_BINDING')
    require(all(pin(payload[k]) for k in ('request_sha256', 'model_sha256', 'fitting_log_sha256')), 'CHILD_SHA')
    require(payload['request_sha256'] == SYNTHETIC_REQUEST_SHA, 'CHILD_REQUEST_BINDING')
    require(type(payload['model_bytes']) is int and 0 < payload['model_bytes'] <= MODEL_CAP
            and type(payload['fitting_log_bytes']) is int and 0 < payload['fitting_log_bytes'] <= LOG_CAP, 'CHILD_SIZE')
    require(all(type(payload[k]) is float and math.isfinite(payload[k]) and payload[k] >= 0
                for k in ('initial_head_loss', 'final_head_loss', 'initial_pair_reference', 'final_pair_reference')), 'CHILD_FINITE')


def validate_final(payload, pins, transport, receipt):
    require(type(payload) is dict and set(payload) == {'status', 'root', 'supplemental_sha256',
        'core_manifest_sha256', 'child_receipt_sha256', 'child_receipt', 'parent_guard_receipt',
        'actual_linux_resource_proof', 'formal_training_release', 'automatic_retries', 'worker_count'}, 'FINAL_FIELDS')
    require(payload['status'] == FINAL_STATUS and root_valid(payload['root'])
            and transport.typed_equal(payload['supplemental_sha256'], pins)
            and payload['core_manifest_sha256'] == CORE_SHA and pin(payload['child_receipt_sha256'])
            and payload['actual_linux_resource_proof'] is True and payload['formal_training_release'] is False
            and type(payload['automatic_retries']) is int and payload['automatic_retries'] == 0
            and type(payload['worker_count']) is int and payload['worker_count'] == 1, 'FINAL_BINDING')
    validate_child(payload['child_receipt'], pins)
    require(sha(json.dumps(payload['child_receipt'], sort_keys=True, allow_nan=False).encode())
            == payload['child_receipt_sha256'], 'FINAL_CHILD_SHA')
    receipt.validate_parent_guard_receipt(payload['parent_guard_receipt'], payload['parent_guard_receipt'])


def parent(root, pins):
    preconditions(root, pins)  # reject invalid runtime/root before lock I/O
    with global_worker_lock():
        return parent_locked(root, pins)


def parent_locked(root, pins):
    transport, (fence, supplemental, sources, python, python_pins) = load(root, pins)
    for name in (STARTED, CHILD_STARTED, LOG, LOG+'.memory.json', CHILD, FINAL, MODEL, FITTING):
        path = Path(root) / name
        require(not any(p.is_symlink() for p in (path, *path.parents)) and not path.exists(), 'ARTIFACT_EXISTS')
    claim_once(root, pins, transport)
    env = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
        OMP_NUM_THREADS='1', MKL_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', NUMEXPR_NUM_THREADS='1',
        CUDA_VISIBLE_DEVICES='', PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1', SETUPTOOLS_USE_DISTUTILS='stdlib')
    with fence.sealed_imports(python, python_pins):
        from src.models import ranking_v4_memory_guard as guard
        from src.models import ranking_v5_parent_guard_receipt as receipt
        from src.models import ranking_v5_training_kernel as kernel
        from src.models import runtime_ranking_v3 as runtime
        expected_request_sha, expected_recipe_sha = expected_bindings(runtime, kernel)
        args = [INTERPRETER, '-I', '-S', '-B', '-c', bootstrap(root, pins[PROGRAM]), '--root', root, '--child']
        for name, flag in ((OBS, 'observation'), (CONTEXT, 'context'), (PROGRAM, 'program'),
                           (TRANSPORT, 'transport'), (AUTH, 'authorization')):
            args.extend(['--'+flag+'-sha256', pins[name]])
        returned = guard.run_bounded(args, Path(root) / LOG, env)
        memory = transport.decode(read(Path(root) / (LOG+'.memory.json'), JSON_CAP))
        receipt.validate_parent_guard_receipt(returned, memory)
        require(memory['peak_group_rss_bytes'] > 0, 'ZERO_CHILD_RSS')
        worker_raw = read(Path(root) / CHILD, JSON_CAP)
        worker = transport.decode(worker_raw)
        validate_child(worker, pins)
        model_raw = read(Path(root) / MODEL, MODEL_CAP)
        require(sha(model_raw) == worker['model_sha256'] and len(model_raw) == worker['model_bytes'], 'MODEL_READBACK')
        fitting = read(Path(root) / FITTING, LOG_CAP)
        require(sha(fitting) == worker['fitting_log_sha256'] and len(fitting) == worker['fitting_log_bytes'], 'FITTING_READBACK')
        rows = [transport.decode(line) for line in fitting.splitlines()]
        require(log_bytes(rows, expected_request_sha, expected_recipe_sha) == fitting, 'FITTING_SEQUENCE')
        for receipt_key, index, log_key in (('initial_head_loss', 0, 'macro_head_loss'),
                ('final_head_loss', -1, 'macro_head_loss'),
                ('initial_pair_reference', 0, 'macro_pair_softplus_reference'),
                ('final_pair_reference', -1, 'macro_pair_softplus_reference')):
            require(worker[receipt_key] == rows[index][log_key], 'FITTING_SUMMARY')
        payload = dict(status=FINAL_STATUS, root=root, supplemental_sha256=pins, core_manifest_sha256=CORE_SHA,
            child_receipt_sha256=sha(worker_raw), child_receipt=worker, parent_guard_receipt=memory,
            actual_linux_resource_proof=True, formal_training_release=False, automatic_retries=0, worker_count=1)
        validate_final(payload, pins, transport, receipt)
    transport.write(Path(root) / FINAL, payload)
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--child', action='store_true')
    for flag in ('observation', 'context', 'program', 'transport', 'authorization'):
        parser.add_argument('--'+flag+'-sha256', required=True)
    args = parser.parse_args()
    pins = {OBS: args.observation_sha256, CONTEXT: args.context_sha256, PROGRAM: args.program_sha256,
            TRANSPORT: args.transport_sha256, AUTH: args.authorization_sha256}
    print(json.dumps((child if args.child else parent)(args.root, pins), sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
