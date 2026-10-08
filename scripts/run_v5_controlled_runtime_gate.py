"""One CPU import/tensor gate, no production data, model, fit or release.

Parent uses the previously sealed core and existing process-group RSS guard.
All supplemental bytes are authenticated again in the isolated child. No retry.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import ModuleType

INTERPRETER = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'
CORE_ROOT = '/ssd/cjc/gnn_model_ranking_v5_import_gate_20261008_r1'
CORE_MANIFEST = 'data/manifests/ranking_v5_caller_source_bytes_20261008.json'
CORE_SHA = '5394779faac5c77800a0a9d8ed52bf9f24ba2dd701f499a49754e51e7ddceae7'
FENCE = 'src/models/ranking_v5_frozen_import_fence.py'
FENCE_SHA = 'c8ba5ae9bc8f900a620b7eaf03e37e11f303d9fc8b08ccbc8c423682b0afafed'
OBS = 'src/models/ranking_v5_locked_runtime_observations.py'
CONTEXT = 'src/models/ranking_v5_locked_runtime_imports.py'
PROGRAM = 'scripts/run_v5_controlled_runtime_gate.py'
LOG = 'controlled_runtime.log'
CHILD = 'controlled_runtime.child.json'
FINAL = 'controlled_runtime.launch.json'
CAP = 64 * 1024
JSON_CAP = 20000
SEARCH_PATHS = ('/usr/lib/python311.zip', '/usr/lib/python3.11', '/usr/lib/python3.11/lib-dynload',
    '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/lib/python3.11/site-packages',
    '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages')


def require(ok, code):
    if not ok:
        raise ValueError('V5_RUNTIME_GATE_' + code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def typed_equal(left, right):
    if type(left) is not type(right):
        return False
    if type(right) is dict:
        return left.keys() == right.keys() and all(typed_equal(left[key], value) for key, value in right.items())
    if type(right) is list:
        return len(left) == len(right) and all(typed_equal(a, b) for a, b in zip(left, right))
    return left == right


def bootstrap(root, program_sha):
    """For fixed interpreter -I -S -B ONLY: no site startup hook or pth runs.

    Explicitly reinstate the already reviewed five runtime search paths, never
    cwd/repository/extra paths. This is not a native-library or hostile sandbox.
    The parent transport and guarded child use the same authenticated program.
    """
    require(type(root) is str and re.fullmatch(
        '/ssd/cjc/gnn_model_ranking_v5_runtime_gate_[0-9]{8}_r[1-9][0-9]*', root) is not None, 'ROOT')
    require(pin(program_sha), 'PROGRAM_PIN')
    return ('import sys;assert sys.flags.no_site==1 and sys.flags.isolated==1;'
        + 'sys.path[:]=' + repr(list(SEARCH_PATHS)) + ';'
        + 'import os,hashlib;from pathlib import Path;'
        + 'p=Path(' + repr(root + '/' + PROGRAM) + ');'
        + 'assert not any(q.is_symlink() for q in (p,*p.parents));'
        + 'f=p.open("rb");raw=f.read(65537);f.close();'
        + 'assert 0<len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==' + repr(program_sha) + ';'
        + 'os.chdir("/ssd/cjc");exec(compile(raw,str(p),"exec"))')


def preconditions(root, pins):
    require(sys.platform == 'linux' and sys.executable == INTERPRETER
            and tuple(sys.version_info[:3]) == (3, 11, 2), 'RUNTIME')
    require(os.getcwd() == '/ssd/cjc', 'CWD')
    require(sys.flags.no_site == 1 and sys.flags.isolated == 1
            and sys.path == list(SEARCH_PATHS) and 'sitecustomize' not in sys.modules
            and 'usercustomize' not in sys.modules, 'SITE_BOOTSTRAP')
    require(type(root) is str and re.fullmatch(
        '/ssd/cjc/gnn_model_ranking_v5_runtime_gate_[0-9]{8}_r[1-9][0-9]*', root) is not None, 'ROOT')
    require(type(pins) is dict and set(pins) == {OBS, CONTEXT, PROGRAM}
            and all(pin(value) for value in pins.values()), 'PINS')


def read(path, cap=CAP):
    path = Path(path)
    require(not any(item.is_symlink() for item in (path, *path.parents)), 'SYMLINK')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= cap, 'FILE')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns), 'IDENTITY')
        raw = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) == before.st_size and (after.st_size, after.st_mtime_ns)
            == (before.st_size, before.st_mtime_ns), 'CHANGED')
    return raw


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= JSON_CAP, 'JSON_BOUND')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'DUPLICATE')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False, 'NONFINITE'))


def external(name, raw):
    module = ModuleType(name)
    module.__file__ = 'sealed://' + name
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def load(root, pins):
    preconditions(root, pins)
    supplemental = {name: read(Path(root) / name) for name in sorted(pins)}
    require(all(sha(supplemental[name]) == pins[name] for name in pins), 'SUPPLEMENT_SHA')
    fence_raw = read(Path(CORE_ROOT) / FENCE)
    require(sha(fence_raw) == FENCE_SHA, 'FENCE_SHA')
    manifest_raw = read(Path(CORE_ROOT) / CORE_MANIFEST, JSON_CAP)
    require(sha(manifest_raw) == CORE_SHA, 'CORE_SHA')
    fence = external('v5_runtime_gate_fence', fence_raw)
    manifest = decode(manifest_raw)
    require(type(manifest) is dict and set(manifest) == {'schema', 'sources', 'formal_training_release'}
            and manifest['schema'] == 'v5-caller-source-bytes-v1'
            and manifest['formal_training_release'] is False
            and type(manifest['sources']) is dict
            and set(manifest['sources']) == fence.FILES | {'requirements/runtime_v2.lock.txt'}
            and all(pin(value) for value in manifest['sources'].values()), 'CORE_SCHEMA')
    sources = {name: read(Path(CORE_ROOT) / name) for name in sorted(manifest['sources'])}
    require(sum(map(len, sources.values())) <= 1024 * 1024, 'SOURCE_BOUND')
    require(all(sha(sources[name]) == manifest['sources'][name] for name in sources), 'SOURCE_SHA')
    python = {name: raw for name, raw in sources.items() if name.endswith('.py')}
    python_pins = {name: manifest['sources'][name] for name in python}
    return fence, supplemental, sources, python, python_pins


def write(path, payload):
    raw = json.dumps(payload, sort_keys=True, allow_nan=False).encode()
    require(0 < len(raw) <= JSON_CAP, 'RECEIPT_BOUND')
    path = Path(path)
    require(not any(item.is_symlink() for item in (path, *path.parents)), 'SYMLINK')
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(read(path, JSON_CAP) == raw, 'READBACK')


def child(root, pins):
    fence, supplemental, sources, python, python_pins = load(root, pins)
    observation = external('v5_runtime_gate_observation', supplemental[OBS])
    context = external('v5_runtime_gate_context', supplemental[CONTEXT])
    with context.controlled_imports(python, python_pins, frozen_helper=fence,
                                   observation_helper=observation,
                                   lock_raw=sources['requirements/runtime_v2.lock.txt']):
        from src.models import ranking_v5_worker_resource_context as resource_context
        prerequisites = resource_context.check_current_process()  # before ML
        import torch
        import numpy
        torch.set_num_threads(1)
        torch.set_num_interop_threads(1)
        require(torch.get_num_threads() == 1 and torch.get_num_interop_threads() == 1, 'THREADS')
        require(torch.cuda.is_available() is False, 'CUDA')
        require(torch.tensor([1., 2.], device='cpu').sum().item() == 3., 'TORCH_VALUE')
        require(numpy.array([1., 2.]).sum().item() == 3., 'NUMPY_VALUE')
        payload = dict(status='PASS_CONTROLLED_CPU_IMPORT_TENSOR_ONLY',
            supplemental_sha256=pins, core_manifest_sha256=CORE_SHA,
            torch_version=torch.__version__, numpy_version=numpy.__version__,
            torch_origin=torch.__file__, numpy_origin=numpy.__file__,
            threads=1, interop_threads=1, cuda_available=False,
            child_prerequisites=prerequisites, actual_torch_fits=0,
            production_package_reads=0, formal_training_release=False, automatic_retries=0)
    write(Path(root) / CHILD, payload)
    return payload


def validate_child(payload, pins):
    fields = {'status', 'supplemental_sha256', 'core_manifest_sha256', 'torch_version',
              'numpy_version', 'torch_origin', 'numpy_origin', 'threads', 'interop_threads',
              'cuda_available', 'child_prerequisites', 'actual_torch_fits',
              'production_package_reads', 'formal_training_release', 'automatic_retries'}
    require(type(payload) is dict and set(payload) == fields, 'CHILD_FIELDS')
    require(payload['status'] == 'PASS_CONTROLLED_CPU_IMPORT_TENSOR_ONLY'
            and payload['supplemental_sha256'] == pins
            and payload['core_manifest_sha256'] == CORE_SHA, 'CHILD_BINDING')
    site = '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages/'
    require(payload['torch_version'] == '2.5.1+cu124' and payload['numpy_version'] == '2.1.3'
            and payload['torch_origin'] == site + 'torch/__init__.py'
            and payload['numpy_origin'] == site + 'numpy/__init__.py', 'CHILD_RUNTIME')
    require(all(type(payload[key]) is int and payload[key] == 1 for key in ('threads', 'interop_threads'))
            and all(type(payload[key]) is int and payload[key] == 0 for key in (
                'actual_torch_fits', 'production_package_reads', 'automatic_retries'))
            and payload['cuda_available'] is False and payload['formal_training_release'] is False, 'CHILD_BOUNDARY')
    expected = dict(status='PASS_CHILD_PREREQUISITES_ONLY', address_space_limits=[8*1024**3]*2,
        core_limits=[0, 0], threads=1, parent_sampled_rss_enforcement_proven=False,
        authentic_user_consent_proven=False)
    require(typed_equal(payload['child_prerequisites'], expected), 'CHILD_PREREQUISITES')


def parent(root, pins):
    fence, supplemental, sources, python, python_pins = load(root, pins)
    for name in (LOG, LOG + '.memory.json', CHILD, FINAL):
        path = Path(root) / name
        require(not any(item.is_symlink() for item in (path, *path.parents)), 'SYMLINK')
        require(not path.exists(), 'ARTIFACT_EXISTS')
    env = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
        OMP_NUM_THREADS='1', MKL_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1',
        NUMEXPR_NUM_THREADS='1', CUDA_VISIBLE_DEVICES='', PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
    with fence.sealed_imports(python, python_pins):
        from src.models import ranking_v4_memory_guard as guard
        from src.models import ranking_v5_parent_guard_receipt as receipt
        args = [INTERPRETER, '-I', '-S', '-B', '-c', bootstrap(root, pins[PROGRAM]), '--root', root, '--child']
        for name, flag in ((OBS, 'observation'), (CONTEXT, 'context'), (PROGRAM, 'program')):
            args.extend(['--' + flag + '-sha256', pins[name]])
        returned = guard.run_bounded(args, Path(root) / LOG, env)
        memory = decode(read(Path(root) / (LOG + '.memory.json'), JSON_CAP))
        receipt.validate_parent_guard_receipt(returned, memory)
        require(memory['peak_group_rss_bytes'] > 0, 'ZERO_CHILD_RSS')
        worker_raw = read(Path(root) / CHILD, JSON_CAP)
        worker = decode(worker_raw)
        validate_child(worker, pins)
    payload = dict(status='PASS_BOUNDED_CONTROLLED_CPU_IMPORT_ONLY', root=root,
        supplemental_sha256=pins, core_manifest_sha256=CORE_SHA,
        child_receipt_sha256=sha(worker_raw), child_receipt=worker,
        parent_guard_receipt=memory, actual_linux_resource_proof=True,
        actual_torch_fits=0, production_package_reads=0, formal_training_release=False,
        automatic_retries=0, worker_count=1,
        claim_boundary='Actual CPU import and tiny tensor only; not fit, dependency content seal, native audit or TRAIN release')
    write(Path(root) / FINAL, payload)
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--child', action='store_true')
    for name in ('observation', 'context', 'program'):
        parser.add_argument('--' + name + '-sha256', required=True)
    args = parser.parse_args()
    pins = {OBS: args.observation_sha256, CONTEXT: args.context_sha256, PROGRAM: args.program_sha256}
    result = (child if args.child else parent)(args.root, pins)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
