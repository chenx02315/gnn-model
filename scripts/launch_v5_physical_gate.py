"""Single bounded generated-fixture worker; real-data launch is not implemented."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

from src.models import ranking_v4_memory_guard as guard
from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_physical_worker as worker
from src.models.runtime_ranking_v3 import digest, freeze_ranking

INTERPRETER = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/venv/bin/python'
FILES = boundary.REQUIRED_SOURCE_BINDINGS | frozenset((
    'src/models/ranking_v5_physical_worker.py', 'src/models/ranking_v4_memory_guard.py',
    'src/models/preflight_runtime_v2.py', 'scripts/launch_v5_physical_gate.py'))


def allowed_root_text(text):
    path = PurePosixPath(text)
    return (str(path) == text and path.parent == PurePosixPath('/ssd/cjc')
            and re.fullmatch(r'gnn_model_ranking_v5_worker_gate_[0-9]{8}_r[1-9][0-9]*', path.name) is not None)


def bounded_read(path, cap):
    path = Path(path)
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError('V5_GATE_READ_SYMLINK')
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('V5_GATE_READ_NOT_REGULAR')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    if len(raw) > cap:
        raise ValueError('V5_GATE_READ_BOUND')
    return raw


def verify_packet(root, manifest_sha):
    if len(FILES) != 16:
        raise ValueError('V5_GATE_FILE_COUNT')
    if not boundary._sha(manifest_sha):
        raise ValueError('V5_GATE_MANIFEST_SHA')
    raw = bounded_read(root / 'packet_manifest.json', 20000)
    if hashlib.sha256(raw).hexdigest() != manifest_sha:
        raise ValueError('V5_GATE_MANIFEST_DRIFT')
    packet = json.loads(raw)
    if (set(packet) != {'schema', 'formal', 'sources'} or packet['schema'] != 'v5-generated-physical-sources-v1'
            or packet['formal'] is not False or not isinstance(packet['sources'], dict)
            or set(packet['sources']) != FILES):
        raise ValueError('V5_GATE_PACKET_SCHEMA')
    for name, sha in packet['sources'].items():
        if not boundary._sha(sha) or hashlib.sha256(bounded_read(root / name, 30000)).hexdigest() != sha:
            raise ValueError('V5_GATE_SOURCE_DRIFT:' + name)
    return packet


def validate_outputs(root):
    directory = root / 'worker_output'
    receipt_raw = bounded_read(directory / 'worker_receipt.json', 20000)
    receipt = json.loads(receipt_raw)
    if (receipt.get('artifact_scope') != worker.SYNTHETIC_PROVENANCE or receipt.get('formal') is not False
            or receipt.get('real_fits') != 0 or receipt.get('held_labels_replayed') is not False
            or receipt.get('worker_receipt_kind') != 'SYNTHETIC_ONLY'
            or digest({k:v for k,v in receipt.items() if k != 'worker_receipt_sha256'}) != receipt.get('worker_receipt_sha256')):
        raise ValueError('V5_GATE_WORKER_RECEIPT')
    request = worker.synthetic_request()
    fold, prepared, _, recipe = boundary.prepare_request(request)
    sources = worker.verify_source_files(root)
    expected = {'canonical_request_sha256':digest(request), 'head_recipe_sha256':digest(recipe),
                'release_sha256':digest(worker._test_release(sources)), 'source_binding_sha256':digest(sources),
                'seed':request['seed'], 'family':fold.family, 'scope':boundary.SCOPE}
    if any(receipt.get(key) != value for key,value in expected.items()):
        raise ValueError('V5_GATE_GENERATED_BINDING')
    model = bounded_read(directory / 'model.pt', worker.MAX_MODEL_BYTES)
    model_sha = hashlib.sha256(model).hexdigest()
    if any(receipt.get(key) != model_sha for key in ('model_sha256','model_ack_sha256','expected_model_sha256')):
        raise ValueError('V5_GATE_MODEL_READBACK')
    freeze_raw = bounded_read(directory / 'freeze.json', 20000)
    frozen = json.loads(freeze_raw)
    payload, canonical_sha = freeze_ranking(frozen['payload']['scores'], fold)
    if frozen != {'payload':payload, 'sha256':canonical_sha} or receipt.get('freeze_sha256') != canonical_sha:
        raise ValueError('V5_GATE_FREEZE_READBACK')
    logs_raw = bounded_read(directory / 'fitting.jsonl', worker.MAX_LOG_BYTES)
    if hashlib.sha256(logs_raw).hexdigest() != receipt.get('fitting_log_sha256'):
        raise ValueError('V5_GATE_LOG_SHA')
    lines = logs_raw.splitlines()
    if len(lines) != 122 or any(len(line) > worker.MAX_LOG_RECORD_BYTES for line in lines):
        raise ValueError('V5_GATE_LOG_BOUNDS')
    records = [json.loads(line) for line in lines]
    stages = [('INITIAL',0)] + [('EPOCH',i) for i in range(1,121)] + [('FINAL',120)]
    for row, stage in zip(records, stages):
        if ((row.get('phase'),row.get('epoch')) != stage or row.get('canonical_request_sha256') != digest(request)
                or row.get('recipe_sha256') != digest(recipe) or row.get('macro_family_count') != 5):
            raise ValueError('V5_GATE_LOG_STAGE_OR_BINDING')
        encoded = json.dumps(row,allow_nan=False)
        if any(uid in encoded for uid in prepared['fit_uids']):
            raise ValueError('V5_GATE_RAW_UID_LOG')
    return {'model_sha256':model_sha, 'freeze_file_sha256':hashlib.sha256(freeze_raw).hexdigest(),
            'freeze_canonical_sha256':canonical_sha, 'fitting_log_sha256':hashlib.sha256(logs_raw).hexdigest(),
            'worker_receipt_file_sha256':hashlib.sha256(receipt_raw).hexdigest(),
            'logs':len(records), 'actual_synthetic_fits':1, 'optimizer_steps':120,
            'initial_macro_head_loss':records[0]['macro_head_loss'],
            'final_macro_head_loss':records[-1]['macro_head_loss']}


def execute(root, manifest_sha):
    root = Path(root)
    if (sys.platform != 'linux' or not allowed_root_text(root.as_posix())
            or root != Path.cwd() or not root.is_dir() or sys.executable != INTERPRETER):
        raise ValueError('V5_GATE_FIXED_LINUX_ROOT_OR_INTERPRETER')
    packet = verify_packet(root, manifest_sha)
    if (root / 'worker_output').exists() or (root / 'launch_receipt.json').exists():
        raise ValueError('V5_GATE_CREATE_ONCE')
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', CUDA_VISIBLE_DEVICES='',
               OMP_NUM_THREADS='1', MKL_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', NUMEXPR_NUM_THREADS='1')
    env.pop('PYTHONPATH', None)
    argv = [INTERPRETER, '-B', '-m', 'src.models.ranking_v5_physical_worker', '--synthetic-gate',
            '--output', str(root / 'worker_output')]
    memory = guard.run_bounded(argv, root / 'worker.log', env)
    if memory['status'] != 'PASS_BOUNDED_WORKER' or memory['exit_code'] != 0 or memory['sample_count'] < 1:
        raise ValueError('V5_GATE_MEMORY_NO_PASS')
    artifacts = validate_outputs(root)
    log_raw = bounded_read(root / 'worker.log', 20000)
    receipt = {'status':'PASS_SYNTHETIC_PHYSICAL_WORKER_GATE', 'formal_training_release':False,
               'real_fits':0, 'retries':0, 'argv':argv, 'packet_manifest_sha256':manifest_sha,
               'source_sha256':packet['sources'], 'memory':memory, 'artifacts':artifacts,
               'worker_log_sha256':hashlib.sha256(log_raw).hexdigest(),
               'cuda_warning_observed':b'CUDA initialization' in log_raw,
               'claim_boundary':'Physical generated-fixture and sampled memory only; no real fitting/transfer/speedup claim'}
    raw = (json.dumps(receipt,sort_keys=True,allow_nan=False)+'\n').encode()
    if len(raw) > 20000:
        raise ValueError('V5_GATE_LAUNCH_RECEIPT_BOUND')
    worker._write_exclusive(root / 'launch_receipt.json', raw)
    if bounded_read(root / 'launch_receipt.json',20000) != raw:
        raise ValueError('V5_GATE_LAUNCH_RECEIPT_READBACK')
    print(raw.decode(),end='')
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--packet-manifest-sha256',required=True)
    args = parser.parse_args(argv)
    execute(Path(__file__).resolve().parents[1],args.packet_manifest_sha256)


if __name__ == '__main__': main()
