"""Local isolated source-import experiment; never a training launcher.

Load verified in-memory code snapshots with ML imports blocked. No production
package, remote host, physical Linux limit, or authentic approval is observed.
The new fence helper pin is external to the existing 26-item source seal.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

MAX_SOURCE = 64 * 1024
MAX_PACKET = 1024 * 1024
HELPER = 'src/models/ranking_v5_frozen_import_fence.py'
MANIFEST = 'data/manifests/ranking_v5_caller_source_bytes_20261008.json'
CHILD = r'''
import base64, hashlib, json, sys, types
raw = sys.stdin.buffer.read(1024*1024+1)
if len(raw) > 1024*1024: raise ValueError('IMPORT_GATE_PACKET_BOUND')
packet = json.loads(raw)
helper = base64.b64decode(packet['helper'], validate=True)
if hashlib.sha256(helper).hexdigest() != packet['helper_sha256']:
    raise ValueError('IMPORT_GATE_HELPER_SHA')
module = types.ModuleType('v5_verified_external_fence')
module.__file__ = 'sealed://external-fence'
sys.modules[module.__name__] = module
exec(compile(helper, module.__file__, 'exec'), module.__dict__)
sources = {p:base64.b64decode(value,validate=True) for p,value in packet['sources'].items()}
with module.sealed_imports(sources, packet['pins']):
    import src.models.ranking_v5_single_fit_worker as worker
    if not callable(worker.execute_single_fit): raise ValueError('IMPORT_GATE_ENTRYPOINT')
    owned = {name:value for name,value in sys.modules.items()
             if name == 'src' or name.startswith('src.') or name == 'scripts' or name.startswith('scripts.')}
    paths = []
    for name, value in owned.items():
        if name in ('src','src.models','src.data','scripts'):
            if list(value.__path__) != []: raise ValueError('IMPORT_GATE_NAMESPACE')
        else:
            origin = 'sealed://' + name.replace('.','/') + '.py'
            if value.__file__ != origin or value.__spec__.origin != origin:
                raise ValueError('IMPORT_GATE_ORIGIN')
            paths.append(origin)
    for name in ('torch','numpy','scipy','sklearn','xgboost'):
        try:
            __import__(name)
        except ModuleNotFoundError as error:
            if error.name != name or 'V5_FENCE_HEAVY_IMPORT:' + name not in str(error):
                raise ValueError('IMPORT_GATE_HEAVY_WRONG_REFUSAL') from error
        else:
            raise ValueError('IMPORT_GATE_HEAVY_NOT_BLOCKED')
    result = dict(status='PASS_FROZEN_SOURCE_IMPORT_GATE_ONLY',
                  loaded_python_modules=len(paths), origins=sorted(paths),
                  namespaces_empty=True, heavy_ml_imports_blocked=True,
                  actual_torch_fits=0, production_package_reads=0,
                  actual_linux_resource_proof=False, formal_training_release=False)
if any(n=='src' or n.startswith('src.') or n=='scripts' or n.startswith('scripts.') for n in sys.modules):
    raise ValueError('IMPORT_GATE_CLEANUP')
print(json.dumps(result,sort_keys=True))
'''


def bounded_read(path, cap):
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError('IMPORT_GATE_SYMLINK')
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('IMPORT_GATE_NOT_REGULAR')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    if not 0 < len(raw) <= cap:
        raise ValueError('IMPORT_GATE_BYTE_BOUND')
    return raw


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('IMPORT_GATE_DUPLICATE')
        result[key] = value
    return result


def run(*, manifest_sha256, helper_sha256):
    """Execute exactly one isolated local Python child, no automatic retry."""
    if not _sha(manifest_sha256) or not _sha(helper_sha256):
        raise ValueError('IMPORT_GATE_TRUSTED_SHA')
    root = Path(__file__).resolve().parents[1]
    manifest_raw = bounded_read(root / MANIFEST, 20000)
    if hashlib.sha256(manifest_raw).hexdigest() != manifest_sha256:
        raise ValueError('IMPORT_GATE_MANIFEST_SHA')
    manifest = json.loads(manifest_raw, object_pairs_hook=_unique)
    if (type(manifest) is not dict or set(manifest) != {'schema','formal_training_release','sources'}
            or manifest['schema'] != 'v5-caller-source-bytes-v1'
            or manifest['formal_training_release'] is not False
            or type(manifest['sources']) is not dict or len(manifest['sources']) != 26):
        raise ValueError('IMPORT_GATE_MANIFEST_SCHEMA')
    sources = {}
    for path, pin in manifest['sources'].items():
        if (type(path) is not str or not _sha(pin)
                or not re.fullmatch(r'(src/models|src/data|scripts)/[a-z0-9_]+\.py|requirements/runtime_v2\.lock\.txt', path)):
            raise ValueError('IMPORT_GATE_SOURCE_PATH')
        raw = bounded_read(root / path, MAX_SOURCE)
        if hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError('IMPORT_GATE_SOURCE_SHA')
        if path.endswith('.py'): sources[path] = raw
    helper = bounded_read(root / HELPER, MAX_SOURCE)
    if hashlib.sha256(helper).hexdigest() != helper_sha256:
        raise ValueError('IMPORT_GATE_HELPER_SHA')
    packet = dict(helper=base64.b64encode(helper).decode(), helper_sha256=helper_sha256,
                  sources={p:base64.b64encode(raw).decode() for p,raw in sources.items()},
                  pins={p:manifest['sources'][p] for p in sources})
    raw = json.dumps(packet,sort_keys=True).encode()
    if len(raw) > MAX_PACKET: raise ValueError('IMPORT_GATE_PACKET_BOUND')
    child = subprocess.run([sys.executable,'-I','-B','-c',CHILD], input=raw,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=15, check=False)
    if len(child.stdout) > 20000 or len(child.stderr) > 20000:
        raise ValueError('IMPORT_GATE_OUTPUT_BOUND')
    if child.returncode != 0:
        raise RuntimeError('IMPORT_GATE_CHILD_FAILED:' + child.stderr.decode('utf-8',errors='replace')[:2000])
    result = json.loads(child.stdout, object_pairs_hook=_unique)
    if (type(result) is not dict or set(result) != {'status','loaded_python_modules','origins',
            'namespaces_empty','heavy_ml_imports_blocked','actual_torch_fits',
            'production_package_reads','actual_linux_resource_proof','formal_training_release'}
            or result.get('status') != 'PASS_FROZEN_SOURCE_IMPORT_GATE_ONLY'
            or result.get('formal_training_release') is not False
            or type(result.get('loaded_python_modules')) is not int
            or not 1 <= result['loaded_python_modules'] <= 25
            or type(result.get('origins')) is not list
            or any(type(p) is not str or p not in {'sealed://' + path for path in sources}
                   for p in result['origins'])
            or len(set(result['origins'])) != result['loaded_python_modules']
            or len(result['origins']) != result['loaded_python_modules']
            or 'sealed://src/models/ranking_v5_single_fit_worker.py' not in result['origins']
            or result.get('namespaces_empty') is not True
            or result.get('heavy_ml_imports_blocked') is not True
            or type(result.get('actual_torch_fits')) is not int or result['actual_torch_fits'] != 0
            or type(result.get('production_package_reads')) is not int or result['production_package_reads'] != 0
            or result.get('actual_linux_resource_proof') is not False):
        raise ValueError('IMPORT_GATE_CHILD_RECEIPT')
    result.update(manifest_sha256=manifest_sha256, helper_sha256=helper_sha256,
                  child_exit_code=child.returncode, automatic_retries=0,
                  isolated_python_child=True, worker_count=1,
                  claim_boundary='Actual local source-import experiment only; not Linux RSS, installed ML runtime, consent or training')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-sha256',required=True)
    parser.add_argument('--helper-sha256',required=True)
    args = parser.parse_args()
    print(json.dumps(run(manifest_sha256=args.manifest_sha256,helper_sha256=args.helper_sha256),sort_keys=True))


if __name__ == '__main__': main()
