"""Small code-only overlay into a fixed new low-memory TRAIN workspace."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_train_687c96d_20261005_r2')
BASE = Path('/ssd/cjc/gnn_model_ranking_v4_synthetic_445af8f_20261005_r1/code')
FILES = ('src/models/ranking_v4_memory_guard.py', 'src/models/ranking_v4_real_worker.py',
         'scripts/run_ranking_v4_real_experiment.py', 'tests/test_ranking_v4_memory_guard.py',
         'tests/test_ranking_v4_real_execution.py')


def build(path):
    base = Path(__file__).resolve().parents[1]
    records = {}
    with tarfile.open(path, 'x:gz') as archive:
        for name in FILES:
            source = base / name
            raw = source.read_bytes()
            if source.is_symlink() or len(raw) > 100000:
                raise ValueError('V4_CODE_FILE_BOUND')
            records[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            archive.add(source, arcname=name, recursive=False)
    raw = Path(path).read_bytes()
    if len(raw) > 100000:
        raise ValueError('V4_CODE_ARCHIVE_BOUND')
    receipt = dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), files=records)
    with Path(str(path) + '.json').open('x') as stream:
        json.dump(receipt, stream, sort_keys=True)
    return receipt


def deploy(path, expected_sha):
    path = Path(path)
    raw = path.read_bytes()
    if len(raw) > 100000 or hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError('V4_CODE_ARCHIVE_SHA')
    content = {}
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        if len(members) != len(FILES) or {m.name for m in members} != set(FILES):
            raise ValueError('V4_CODE_ENTRY_GATE')
        for member in members:
            if not member.isfile() or member.size > 100000:
                raise ValueError('V4_CODE_ENTRY_BOUND')
            content[member.name] = archive.extractfile(member).read()
    if sum(map(len, content.values())) > 500000:
        raise ValueError('V4_CODE_TOTAL_BOUND')
    originals = list(BASE.rglob('*'))
    if any(p.is_symlink() for p in originals) or sum(p.is_file() for p in originals) > 200:
        raise ValueError('V4_CODE_BASE_BOUND')
    code = ROOT / 'code'
    if code.exists():
        raise ValueError('V4_CODE_EXISTS')
    shutil.copytree(BASE, code)
    for name, value in content.items():
        target = code / name
        target.parent.mkdir(exist_ok=True, parents=True)
        with target.open('xb') as stream:
            stream.write(value)
    hashes = {str(p.relative_to(code)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in code.rglob('*') if p.is_file()}
    result = dict(status='PASS_CODE_ONLY_PREPARATION', archive_sha256=expected_sha,
                  code_sha256=hashes, real_training_started=False)
    with (ROOT / 'code_preparation.json').open('x') as stream:
        json.dump(result, stream, sort_keys=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build')
    parser.add_argument('--deploy')
    parser.add_argument('--sha256')
    args = parser.parse_args()
    if bool(args.build) == bool(args.deploy):
        parser.error('Choose exactly one of build/deploy')
    print(json.dumps(build(args.build) if args.build else deploy(args.deploy, args.sha256), sort_keys=True))
