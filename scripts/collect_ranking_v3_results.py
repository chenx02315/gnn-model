"""Collect bounded TRAIN-only metrics and raw-byte hashes, never checkpoints."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess

REMOTE_ROOT = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1'
MAX_BYTES = 12 * 1024 * 1024
RELEASE_SHA = 'ad6b7721ae543cb0eb37765394d249922a6a114d49ecbb78d46b006d9a285205'
PACKAGE_SHA = '964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868'
REMOTE = r'''
import hashlib,json
from pathlib import Path
root=Path('/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1')
paths=[root/'exit_receipt.json',root/'execution_release.json',root/'train_folds/receipt.json',root/'experiment/summary.json']
evaluations=sorted((root/'experiment').glob('*/evaluation.json'))
assert len(evaluations)==72,'COMPLETE_GRID_REQUIRED'
paths+=evaluations
paths+=[p.parent/'worker_receipt.json' for p in evaluations]
records={}
freezes={}
for p in paths:
    assert not p.is_symlink() and all(not q.is_symlink() for q in p.parents)
    raw=p.read_bytes()
    assert len(raw)<=1024*1024,'ENTRY_TOO_LARGE'
    records[str(p.relative_to(root))]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'data':json.loads(raw)}
assert len(records)==148
for p in evaluations:
    evaluation=records[str(p.relative_to(root))]['data']
    freeze_path=p.parent/'freeze.json'
    assert not freeze_path.is_symlink()
    raw=freeze_path.read_bytes()
    value=json.loads(raw)
    assert value=={'payload':evaluation['freeze'],'sha256':evaluation['freeze_sha256']},'PERSISTED_FREEZE_MISMATCH'
    assert hashlib.sha256(json.dumps(value['payload'],sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()==value['sha256'],'PERSISTED_FREEZE_DIGEST'
    freezes[str(freeze_path.relative_to(root))]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
log=root/'experiment_driver.log'
assert not log.is_symlink()
exit_data=records['exit_receipt.json']['data']
assert exit_data['exit_code']==0 and exit_data['status']=='PROCESS_FINISHED' and exit_data['retries']==0
assert hashlib.sha256(log.read_bytes()).hexdigest()==exit_data['driver_log_sha256']
print(json.dumps({'schema_version':2,'persisted_freeze_files':freezes,'scope':'TRAIN_ONLY_REAL_SIX_FOLD_V3','remote_root':str(root),'entry_count':len(records),'records':records},sort_keys=True,separators=(',',':')))
'''


def validate_persisted_freezes(payload):
    entries=payload['records']
    frozen=payload['persisted_freeze_files']
    expected={k.replace('evaluation.json','freeze.json') for k in entries if k.endswith('/evaluation.json')}
    if set(frozen)!=expected or len(frozen)!=72:
        raise ValueError('RESULT_PERSISTED_FREEZE_INVENTORY')
    for key in expected:
        row=entries[key.replace('freeze.json','evaluation.json')]['data']
        raw=(json.dumps({'payload':row['freeze'],'sha256':row['freeze_sha256']},sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
        if frozen[key]!={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}:
            raise ValueError('RESULT_PERSISTED_FREEZE_SHA')


def validate(payload):
    if payload['remote_root'] != REMOTE_ROOT or payload['entry_count'] != 148 or len(payload['records']) != 148:
        raise ValueError('RESULT_INVENTORY')
    entries = payload['records']
    if entries['execution_release.json']['sha256'] != RELEASE_SHA or entries['train_folds/receipt.json']['sha256'] != PACKAGE_SHA:
        raise ValueError('RESULT_EXTERNAL_ANCHORS')
    exit_record = entries['exit_receipt.json']['data']
    if exit_record['status'] != 'PROCESS_FINISHED' or exit_record['exit_code'] != 0 or exit_record['retries'] != 0 or exit_record['release_sha256'] != RELEASE_SHA:
        raise ValueError('RESULT_PROCESS_EXIT')
    if payload.get('schema_version')==2:
        validate_persisted_freezes(payload)
    evaluation = [v['data'] for k, v in payload['records'].items() if k.endswith('/evaluation.json')]
    from src.models.runtime_ranking_v3 import FAMILIES, digest
    from src.models.run_runtime_ranking_v3 import SEEDS
    from src.models.run_runtime_ranking_v3_real import MODELS, aggregate_real
    expected = {(f, s, m) for f in FAMILIES.values() for s in SEEDS for m in MODELS}
    if len(evaluation) != 72 or {(r['family'], r['seed'], r['model']) for r in evaluation} != expected:
        raise ValueError('RESULT_GRID')
    release = payload['records']['execution_release.json']['data']
    source = payload['records']['train_folds/receipt.json']['data']['source_sha256']
    for k, v in payload['records'].items():
        if not k.endswith('/evaluation.json'):
            continue
        row = v['data']; worker = payload['records'][k.replace('evaluation.json', 'worker_receipt.json')]['data']
        if any(row[n] != worker[n] for n in ('family', 'seed', 'model', 'source_sha256', 'pair_sha256', 'freeze_sha256')):
            raise ValueError('RESULT_WORKER_BINDING')
        if worker['held_labels_supplied'] is not False or digest(row['freeze']) != row['freeze_sha256']:
            raise ValueError('RESULT_FREEZE')
    rebuilt = {m: aggregate_real([r for r in evaluation if r['model'] == m], m, release=release, source_sha256=source) for m in MODELS}
    stored = payload['records']['experiment/summary.json']['data']
    for model in MODELS:
        actual = dict(rebuilt[model]); expected_summary = dict(stored[model])
        a = actual.pop('family_seed_macro'); b = expected_summary.pop('family_seed_macro')
        # Python 3.12+ uses improved float summation, unlike the sealed Python 3.11 runner.
        # Only numeric macro reductions tolerate rounding; identity and grid remain exact.
        if actual != expected_summary or set(a) != set(b) or any(not math.isclose(a[k], b[k], rel_tol=1e-12, abs_tol=1e-12) for k in a):
            raise ValueError('RESULT_SUMMARY_MISMATCH')
    return rebuilt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    destination = Path(args.output)
    if destination.exists():
        raise ValueError('RESULT_CREATE_ONCE')
    command = '/usr/bin/python3 -c ' + "'" + REMOTE.replace("'", "'\"'\"'") + "'"
    result = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', 'cjc@10.161.89.11', command], capture_output=True, check=True, timeout=120)
    if len(result.stdout) > MAX_BYTES:
        raise ValueError('RESULT_PACKAGE_TOO_LARGE')
    payload = json.loads(result.stdout); validate(payload); validate_persisted_freezes(payload)
    with destination.open('xb') as stream:
        stream.write(result.stdout)
    print(json.dumps({'status':'PASS_COLLECTED_GRID_AND_AGGREGATE', 'bytes':len(result.stdout), 'sha256':hashlib.sha256(result.stdout).hexdigest(), 'evaluations':72, 'note':'Independent source replay audit remains separate.'}))


if __name__ == '__main__':
    main()
