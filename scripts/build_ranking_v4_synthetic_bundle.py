"""Build a small code-only v4 overlay; never include data or checkpoints."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

FILES = ('src/models/ranking_v4_training_worker.py',
         'scripts/ranking_v4_near_optimal_pairs.py',
         'scripts/verify_ranking_v4_synthetic.py',
         'tests/test_ranking_v4_training_worker.py',
         'tests/test_ranking_v4_near_optimal_pairs.py')


def build(destination):
    root = Path(__file__).resolve().parents[1]
    destination = Path(destination)
    records = {}
    for name in FILES:
        path = root / name
        raw = path.read_bytes()
        if path.is_symlink() or len(raw) > 100000:
            raise ValueError('V4_BUNDLE_FILE_BOUND')
        records[name] = dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
    with tarfile.open(destination, 'x:gz') as archive:
        for name in FILES:
            archive.add(root / name, arcname=name, recursive=False)
    raw = destination.read_bytes()
    if len(raw) > 100000:
        raise ValueError('V4_BUNDLE_SIZE')
    value = dict(scope='CODE_ONLY_SYNTHETIC_OVERLAY', archive_sha256=hashlib.sha256(raw).hexdigest(),
                 archive_bytes=len(raw), entry_count=len(FILES), files=records)
    with Path(str(destination) + '.json').open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True)
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    print(json.dumps(build(parser.parse_args().output), sort_keys=True))
