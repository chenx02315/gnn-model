"""Preserve audit-cache failure and create one immutable, source-hash-only snapshot."""
import hashlib
import json
from pathlib import Path

SOURCE = Path('/ssd/cjc/gnn_model_ranking_v4_integrated_dec61b0_20261005_r1')
ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_integrated_dec61b0_20261005_r2')
PREP_SHA = '0a79da62d68c0a6cb6b362acbe8cb0abadbc1dcfde59bf4be64a7a005df4534b'


def main():
    if ROOT.exists() or any(p.is_symlink() for p in (ROOT, *ROOT.parents, SOURCE, *SOURCE.parents)):
        raise ValueError('R3_SNAPSHOT_NEW_ROOT')
    if (SOURCE / 'code_preparation.json').is_symlink():
        raise ValueError('R3_SNAPSHOT_PREP_PATH')
    prep_raw = (SOURCE / 'code_preparation.json').read_bytes()
    if hashlib.sha256(prep_raw).hexdigest() != PREP_SHA:
        raise ValueError('R3_SNAPSHOT_PREP_SHA')
    prep = json.loads(prep_raw)
    expected = prep['code_sha256']
    if len(expected) != 43:
        raise ValueError('R3_SNAPSHOT_COUNT')
    payload = {}
    for name, sha in expected.items():
        path = SOURCE / 'code' / name
        if Path(name).is_absolute() or '..' in Path(name).parts or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('R3_SNAPSHOT_SOURCE_PATH')
        raw = path.read_bytes()
        if len(raw) > 100000 or hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError('R3_SNAPSHOT_SOURCE_SHA')
        payload[name] = raw
    if sum(map(len, payload.values())) > 2 * 1024 * 1024:
        raise ValueError('R3_SNAPSHOT_TOTAL_BOUND')
    actual = list((SOURCE / 'code').rglob('*'))
    if any(p.is_symlink() for p in actual):
        raise ValueError('R3_SNAPSHOT_SYMLINK')
    extras = [p.relative_to(SOURCE / 'code').as_posix() for p in actual
              if p.is_file() and p.relative_to(SOURCE / 'code').as_posix() not in expected]
    if any('__pycache__' not in Path(name).parts or not name.endswith('.pyc') for name in extras):
        raise ValueError('R3_SNAPSHOT_NON_CACHE_DRIFT')
    ROOT.mkdir()
    try:
        code = ROOT / 'code'
        code.mkdir()
        for name, raw in payload.items():
            path = code / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(raw)
            path.chmod(0o444)
        for path in sorted((p for p in code.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
            path.chmod(0o555)
        code.chmod(0o555)
        with (ROOT / 'code_preparation.json').open('xb') as stream:
            stream.write(prep_raw)
        value = dict(status='PASS_IMMUTABLE_SOURCE_SNAPSHOT', source=str(SOURCE), root=str(ROOT),
                     source_file_count=43, code_preparation_sha256=PREP_SHA, omitted_audit_caches=extras,
                     real_training_started=False, readonly_modes='files444 directories555')
        with (ROOT / 'snapshot_receipt.json').open('x') as stream:
            json.dump(value, stream, sort_keys=True)
        print(json.dumps(value, sort_keys=True))
    except Exception as error:
        with (ROOT / 'snapshot_failure.json').open('x') as stream:
            json.dump(dict(status='STOPPED_NO_RETRY', error=str(error)), stream, sort_keys=True)
        raise


if __name__ == '__main__': main()
