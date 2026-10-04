"""Bounded synthetic deployment into one NEW B root; code-only old base clone."""
import hashlib
import json
from pathlib import Path
import shutil
import tarfile

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_synthetic_445af8f_20261005_r1')
BASE = Path('/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/code')
ARCHIVE = ROOT / 'ranking_v4_synthetic_20261005_r1.tar.gz'


def main():
    manifest = json.loads(Path(str(ARCHIVE) + '.json').read_text())
    raw = ARCHIVE.read_bytes()
    if len(raw) > 100000 or hashlib.sha256(raw).hexdigest() != manifest['archive_sha256']:
        raise ValueError('V4_ARCHIVE_SHA_SIZE')
    with tarfile.open(ARCHIVE, 'r:gz') as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        if len(members) != 5 or len(set(names)) != 5 or set(names) != set(manifest['files']):
            raise ValueError('V4_ENTRY_GATE')
        total = 0
        content = {}
        for member in members:
            path = Path(member.name)
            if not member.isfile() or path.is_absolute() or '..' in path.parts or member.size > 100000:
                raise ValueError('V4_ENTRY_TYPE_BOUND')
            value = archive.extractfile(member).read()
            total += len(value)
            if total > 500000 or hashlib.sha256(value).hexdigest() != manifest['files'][member.name]['sha256']:
                raise ValueError('V4_ENTRY_SHA')
            content[member.name] = value
    base_files = [p for p in BASE.rglob('*') if p.is_file()]
    if len(base_files) > 200 or any(p.is_symlink() for p in BASE.rglob('*')):
        raise ValueError('V4_BASE_CODE_BOUND')
    code = ROOT / 'code'
    if code.exists():
        raise ValueError('V4_CODE_ALREADY_EXISTS')
    shutil.copytree(BASE, code)
    original = {str(p.relative_to(BASE)): hashlib.sha256(p.read_bytes()).hexdigest() for p in base_files}
    for name, value in content.items():
        path = code / name
        if path.exists():
            raise ValueError('V4_OVERLAY_NOT_NEW:' + name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(value)
    receipt = dict(status='PASS_CODE_ONLY_BOUNDED_DEPLOYMENT', archive=manifest,
                   base_code_sha256=original, real_training_release=False)
    with (ROOT / 'deployment_receipt.json').open('x') as stream:
        json.dump(receipt, stream, sort_keys=True)
    print(json.dumps(dict(status=receipt['status'], base_file_count=len(original))))


if __name__ == '__main__':
    main()
