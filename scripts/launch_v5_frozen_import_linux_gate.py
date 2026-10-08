"""One fresh Linux bounded SOURCE-IMPORT gate; never ML or training consent."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types


INTERPRETER = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'
MANIFEST = 'data/manifests/ranking_v5_caller_source_bytes_20261008.json'
HELPER = 'src/models/ranking_v5_frozen_import_fence.py'
VERIFIER = 'scripts/verify_v5_frozen_import_gate.py'
MAX_SOURCE = 64 * 1024
MAX_TOTAL = 1024 * 1024
MAX_JSON = 20000
MAX_LOG = 40000
LOG = 'frozen_import_gate.log'
RECEIPT = 'frozen_import_gate.launch.json'


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _preconditions(root):
    # Pure lexical/runtime checks before stat/open/resolve or any source I/O.
    if sys.platform != 'linux':
        raise RuntimeError('LINUX_IMPORT_GATE_PLATFORM')
    if sys.executable != INTERPRETER:
        raise RuntimeError('LINUX_IMPORT_GATE_INTERPRETER')
    value = os.fspath(root)
    if type(value) is not str or re.fullmatch(
            r'/ssd/cjc/gnn_model_ranking_v5_import_gate_[0-9]{8}_r[1-9][0-9]*', value) is None:
        raise ValueError('LINUX_IMPORT_GATE_ROOT')
    if os.getcwd() != value:
        raise ValueError('LINUX_IMPORT_GATE_CWD')
    return Path(value)


def _ordinary_read(path, cap):
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError('LINUX_IMPORT_GATE_SYMLINK')
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('LINUX_IMPORT_GATE_NOT_REGULAR')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    if not 0 < len(raw) <= cap:
        raise ValueError('LINUX_IMPORT_GATE_BYTE_BOUND')
    return raw


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('LINUX_IMPORT_GATE_DUPLICATE_JSON')
        result[key] = value
    return result


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              ValueError('LINUX_IMPORT_GATE_NONFINITE')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('LINUX_IMPORT_GATE_JSON') from error


def _environment():
    return dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
                OMP_NUM_THREADS='1', MKL_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1',
                NUMEXPR_NUM_THREADS='1', CUDA_VISIBLE_DEVICES='',
                PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')


def _fresh_artifacts(root):
    for name in (LOG, LOG + '.memory.json', RECEIPT):
        path = root / name
        if any(item.is_symlink() for item in (path, *path.parents)):
            raise ValueError('LINUX_IMPORT_GATE_SYMLINK')
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise ValueError('LINUX_IMPORT_GATE_ARTIFACT_EXISTS:' + name)


def _worker_receipt(payload, sources, manifest_sha256, helper_sha256):
    fields = {'status', 'loaded_python_modules', 'origins', 'namespaces_empty',
              'heavy_ml_imports_blocked', 'actual_torch_fits', 'production_package_reads',
              'actual_linux_resource_proof', 'formal_training_release', 'manifest_sha256',
              'helper_sha256', 'child_exit_code', 'automatic_retries', 'isolated_python_child',
              'worker_count', 'claim_boundary'}
    if type(payload) is not dict or set(payload) != fields:
        raise ValueError('LINUX_IMPORT_GATE_WORKER_FIELDS')
    allowed = {'sealed://' + name for name in sources if name.endswith('.py')}
    origins = payload['origins']
    if (payload['status'] != 'PASS_FROZEN_SOURCE_IMPORT_GATE_ONLY'
            or payload['manifest_sha256'] != manifest_sha256
            or payload['helper_sha256'] != helper_sha256
            or type(payload['loaded_python_modules']) is not int
            or not 1 <= payload['loaded_python_modules'] <= 25
            or type(origins) is not list or any(type(name) is not str or name not in allowed for name in origins)
            or len(origins) != payload['loaded_python_modules'] or len(set(origins)) != len(origins)
            or 'sealed://src/models/ranking_v5_single_fit_worker.py' not in origins
            or any(payload[key] is not True for key in ('namespaces_empty', 'heavy_ml_imports_blocked', 'isolated_python_child'))
            or any(payload[key] is not False for key in ('actual_linux_resource_proof', 'formal_training_release'))
            or any(type(payload[key]) is not int or payload[key] != 0
                   for key in ('actual_torch_fits', 'production_package_reads', 'child_exit_code', 'automatic_retries'))
            or type(payload['worker_count']) is not int or payload['worker_count'] != 1
            or payload['claim_boundary'] != 'Actual local source-import experiment only; not Linux RSS, installed ML runtime, consent or training'):
        raise ValueError('LINUX_IMPORT_GATE_WORKER_RECEIPT')


def execute(root, manifest_sha256, helper_sha256, verifier_sha256):
    """Execute exactly once, preserve failed artifacts, no retries/public bypass.

    The deployed launcher's own SHA is checked separately by the deployment
    caller. All three supplied pins are independent trust anchors. RLIMIT_AS
    applies to descendants; combined parent/process-group RSS is sampled by
    the existing guard, not a hard RSS limit or provenance/consent guarantee.
    """
    root = _preconditions(root)
    if not all(_sha(pin) for pin in (manifest_sha256, helper_sha256, verifier_sha256)):
        raise ValueError('LINUX_IMPORT_GATE_SHA_ARGUMENT')
    _fresh_artifacts(root)
    total = 0

    def read(name, cap):
        nonlocal total
        raw = _ordinary_read(root / name, cap)
        total += len(raw)
        if total > MAX_TOTAL:
            raise ValueError('LINUX_IMPORT_GATE_TOTAL_BOUND')
        return raw

    helper_raw = read(HELPER, MAX_SOURCE)
    if hashlib.sha256(helper_raw).hexdigest() != helper_sha256:
        raise ValueError('LINUX_IMPORT_GATE_HELPER_SHA')
    verifier_raw = read(VERIFIER, MAX_SOURCE)
    if hashlib.sha256(verifier_raw).hexdigest() != verifier_sha256:
        raise ValueError('LINUX_IMPORT_GATE_VERIFIER_SHA')
    manifest_raw = read(MANIFEST, MAX_JSON)
    if hashlib.sha256(manifest_raw).hexdigest() != manifest_sha256:
        raise ValueError('LINUX_IMPORT_GATE_MANIFEST_SHA')
    helper = types.ModuleType('v5_linux_gate_external_fence')
    helper.__file__ = 'sealed://external-fence'
    exec(compile(helper_raw, helper.__file__, 'exec'), helper.__dict__)
    manifest = _json(manifest_raw)
    names = helper.FILES | {'requirements/runtime_v2.lock.txt'}
    if (type(manifest) is not dict or set(manifest) != {'schema', 'formal_training_release', 'sources'}
            or manifest['schema'] != 'v5-caller-source-bytes-v1'
            or manifest['formal_training_release'] is not False
            or type(manifest['sources']) is not dict or set(manifest['sources']) != names
            or any(not _sha(pin) for pin in manifest['sources'].values())):
        raise ValueError('LINUX_IMPORT_GATE_MANIFEST_SCHEMA')
    sources = {}
    for name in sorted(names):
        raw = read(name, MAX_SOURCE)
        if hashlib.sha256(raw).hexdigest() != manifest['sources'][name]:
            raise ValueError('LINUX_IMPORT_GATE_SOURCE_SHA:' + name)
        sources[name] = raw
    python_sources = {name: raw for name, raw in sources.items() if name.endswith('.py')}
    pins = {name: manifest['sources'][name] for name in python_sources}
    with helper.sealed_imports(python_sources, pins):
        from src.models import ranking_v5_caller_source_binding as binder
        from src.models import ranking_v4_memory_guard as guard
        from src.models import ranking_v5_parent_guard_receipt as parent_receipt
        binder.validate_source_bytes(manifest_raw, sources,
                                     trusted_manifest_sha256=manifest_sha256)
        argv = [INTERPRETER, '-I', '-B', str(root / VERIFIER),
                '--manifest-sha256', manifest_sha256, '--helper-sha256', helper_sha256]
        returned = guard.run_bounded(argv, root / LOG, _environment())
        reread = _json(_ordinary_read(root / (LOG + '.memory.json'), MAX_JSON))
        parent_receipt.validate_parent_guard_receipt(returned, reread)
        if reread['peak_group_rss_bytes'] <= 0:
            raise ValueError('LINUX_IMPORT_GATE_ZERO_CHILD_RSS')
        worker = _json(_ordinary_read(root / LOG, MAX_LOG))
        _worker_receipt(worker, sources, manifest_sha256, helper_sha256)
    receipt = dict(status='PASS_LINUX_BOUNDED_FROZEN_SOURCE_IMPORT_GATE_ONLY',
                   manifest_sha256=manifest_sha256, helper_sha256=helper_sha256,
                   verifier_sha256=verifier_sha256, sources=dict(manifest['sources']),
                   parent_guard_receipt=reread, source_import_receipt=worker,
                   actual_linux_resource_proof=True, actual_ml_permitted=False,
                   actual_torch_fits=0, production_package_reads=0,
                   formal_training_release=False, authentic_user_consent_proven=False,
                   automatic_retries=0, worker_count=1,
                   claim_boundary='One bounded synthetic source-import process group only; no ML, training, consent or 18-fit release')
    encoded = json.dumps(receipt, sort_keys=True, allow_nan=False).encode()
    if len(encoded) > MAX_JSON:
        raise ValueError('LINUX_IMPORT_GATE_RECEIPT_BOUND')
    with (root / RECEIPT).open('xb') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    if _ordinary_read(root / RECEIPT, MAX_JSON) != encoded:
        raise ValueError('LINUX_IMPORT_GATE_RECEIPT_READBACK')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'helper', 'verifier'):
        parser.add_argument('--' + name + '-sha256', required=True)
    args = parser.parse_args()
    root = Path(__file__).parents[1]
    print(json.dumps(execute(root, args.manifest_sha256, args.helper_sha256,
                             args.verifier_sha256), sort_keys=True))


if __name__ == '__main__':
    main()
