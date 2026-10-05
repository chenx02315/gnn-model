"""Build/deploy a bounded code-only v4 integrated overlay; never read datasets."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_integrated_dec61b0_20261005_r1')
BASE = Path('/ssd/cjc/gnn_model_ranking_v4_synthetic_445af8f_20261005_r1/code')
OVERLAY = (
    'src/models/ranking_v4_memory_guard.py',
    'src/models/ranking_v4_real_worker.py',
    'scripts/run_ranking_v4_real_experiment.py',
    'tests/test_ranking_v4_memory_guard.py',
    'tests/test_ranking_v4_real_execution.py',
    'scripts/verify_ranking_v4_memory_ml.py',
    # Imported by the real-execution test only for ROOT/output consistency.
    'scripts/launch_ranking_v4_low_memory_experiment.py',
)
MAX_FILES = 200
MAX_FILE_BYTES = 100 * 1024
MAX_ARCHIVE_BYTES = 100000
MAX_OVERLAY_BYTES = 500000
MAX_BASE_TOTAL_BYTES = 2 * 1024 * 1024
BASE_SUFFIXES = frozenset(('.py', '.json', '.txt'))


def file_sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _reject_symlink(path):
    if any(part.is_symlink() for part in (Path(path), *Path(path).parents)):
        raise ValueError('V4_R3_SYMLINK')


def _base_files(base):
    base = Path(base); _reject_symlink(base)
    if not base.is_dir():
        raise ValueError('V4_R3_BASE')
    entries = list(base.rglob('*'))
    if any(path.is_symlink() for path in entries):
        raise ValueError('V4_R3_BASE_SYMLINK')
    all_files = sorted(path for path in entries if path.is_file())
    files = [path for path in all_files if '__pycache__' not in path.parts and path.suffix != '.pyc']
    if (len(all_files) > MAX_FILES or any(path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES for path in all_files) or
            sum(path.stat().st_size for path in all_files) > MAX_BASE_TOTAL_BYTES or
            any(path.suffix not in BASE_SUFFIXES for path in files)):
        raise ValueError('V4_R3_BASE_BOUND')
    return files


def build(destination):
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError('V4_R3_ARCHIVE_EXISTS')
    source_root = Path(__file__).resolve().parents[1]
    records = {}
    for name in OVERLAY:
        source = source_root / name; _reject_symlink(source)
        raw = source.read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError('V4_R3_OVERLAY_BOUND')
        records[name] = {'bytes': len(raw), 'sha256': file_sha(raw)}
    if sum(item['bytes'] for item in records.values()) > MAX_OVERLAY_BYTES:
        raise ValueError('V4_R3_OVERLAY_TOTAL')
    with tarfile.open(destination, 'x:gz') as archive:
        for name in OVERLAY:
            archive.add(source_root / name, arcname=name, recursive=False)
    raw = destination.read_bytes()
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError('V4_R3_ARCHIVE_BOUND')
    receipt = {'status': 'PASS_R3_CODE_ONLY_ARCHIVE', 'scope': 'CODE_ONLY_NO_DATA_NO_TRAINING',
               'archive_sha256': file_sha(raw), 'archive_bytes': len(raw), 'entry_count': len(OVERLAY),
               'entries': records}
    with Path(str(destination) + '.json').open('x', encoding='utf-8') as stream:
        json.dump(receipt, stream, sort_keys=True); stream.write('\n')
    return receipt


def _archive_entries(path, expected_sha):
    raw = Path(path).read_bytes()
    if file_sha(raw) != expected_sha or len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError('V4_R3_ARCHIVE_SHA')
    # Parse only the byte buffer that was just hash-verified.
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        members = archive.getmembers()
        if len(members) != len(OVERLAY) or {member.name for member in members} != set(OVERLAY):
            raise ValueError('V4_R3_ARCHIVE_ENTRIES')
        result = {}
        for member in members:
            if not member.isfile() or member.size > MAX_FILE_BYTES:
                raise ValueError('V4_R3_ARCHIVE_ENTRY_BOUND')
            result[member.name] = archive.extractfile(member).read()
    return result


def _failure(root, error):
    with (root / 'code_preparation_failure.json').open('x', encoding='utf-8') as stream:
        json.dump({'status': 'STOPPED_CODE_ONLY_PREPARATION', 'error': str(error),
                   'real_training_started': False}, stream, sort_keys=True); stream.write('\n')


def deploy_b(archive, expected_sha):
    """Deploy only to a new locally mounted B root; no network operation occurs here."""
    root, base = ROOT, BASE
    _reject_symlink(root.parent)
    if root.exists() or root.is_symlink():
        raise FileExistsError('V4_R3_ROOT_EXISTS')
    root.mkdir()
    try:
        content = _archive_entries(archive, expected_sha)
        base_files = _base_files(base)
        code = root / 'code'
        code.mkdir()
        for source in base_files:
            target = code / source.relative_to(base)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        for name, raw in content.items():
            target = code / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                raise ValueError('V4_R3_OVERLAY_SYMLINK')
            target.write_bytes(raw)  # Target exists only inside this new root.
        hashes = {str(path.relative_to(code)): file_sha(path.read_bytes())
                  for path in sorted(code.rglob('*')) if path.is_file()}
        receipt = {'status': 'PASS_R3_CODE_ONLY_DEPLOYMENT', 'scope': 'CODE_ONLY_NO_DATA_NO_TRAINING',
                   'archive_sha256': expected_sha, 'overlay': list(OVERLAY), 'code_sha256': hashes,
                   'base_code_sha256': {str(path.relative_to(base)): file_sha(path.read_bytes()) for path in base_files},
                   'code_file_count': len(hashes), 'real_training_started': False}
        with (root / 'code_preparation.json').open('x', encoding='utf-8') as stream:
            json.dump(receipt, stream, sort_keys=True); stream.write('\n')
        return receipt
    except Exception as error:
        _failure(root, error)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--build'); parser.add_argument('--deploy-b'); parser.add_argument('--sha256')
    args = parser.parse_args(argv)
    if bool(args.build) == bool(args.deploy_b):
        parser.error('choose exactly one of --build or --deploy-b')
    if args.build:
        result = build(args.build)
    else:
        if not args.sha256:
            parser.error('--sha256 is required with --deploy-b')
        result = deploy_b(args.deploy_b, args.sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
