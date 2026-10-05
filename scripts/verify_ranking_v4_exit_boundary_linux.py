"""Two-file Linux resource gate only; no model, dataset or training launcher."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import unittest

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_exit_boundary_gate_30664e2_20261005_r1')
FILES = ('src/models/ranking_v4_memory_guard.py', 'tests/test_ranking_v4_memory_guard.py')


def build(output):
    base = Path(__file__).resolve().parents[1]
    output = Path(output)
    with tarfile.open(output, 'x:gz') as archive:
        for name in FILES:
            source = base / name
            if source.is_symlink() or source.stat().st_size > 50000:
                raise ValueError('GUARD_GATE_SOURCE_BOUND')
            archive.add(source, arcname=name, recursive=False)
    raw = output.read_bytes()
    if len(raw) > 50000:
        raise ValueError('GUARD_GATE_ARCHIVE_BOUND')
    return dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), entries=2)


def run(archive_path, sha):
    if sys.platform != 'linux':
        raise ValueError('GUARD_GATE_LINUX_REQUIRED')
    if ROOT.exists() or ROOT.is_symlink() or any(p.is_symlink() for p in ROOT.parents):
        raise ValueError('GUARD_GATE_NEW_ROOT_REQUIRED')
    raw = Path(archive_path).read_bytes()
    if len(raw) > 50000 or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('GUARD_GATE_ARCHIVE_SHA')
    content = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        members = archive.getmembers()
        if len(members) != 2 or {m.name for m in members} != set(FILES):
            raise ValueError('GUARD_GATE_ENTRY_COUNT')
        for member in members:
            if not member.isfile() or member.size > 50000:
                raise ValueError('GUARD_GATE_ENTRY_BOUND')
            content[member.name] = archive.extractfile(member).read()
    ROOT.mkdir()
    for name, value in content.items():
        target = ROOT / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
    for name in ('src/__init__.py', 'src/models/__init__.py', 'tests/__init__.py'):
        (ROOT / name).write_bytes(b'')
    sys.path.insert(0, str(ROOT))
    from src.models import ranking_v4_memory_guard
    if Path(ranking_v4_memory_guard.__file__).resolve() != ROOT / FILES[0]:
        raise ValueError('GUARD_GATE_IMPORT_ORIGIN')
    # Test discovery imports only the two deployed code files.
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_ranking_v4_memory_guard.py')
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    log = stream.getvalue().encode()
    (ROOT / 'linux_gate.log').write_bytes(log)
    passed = result.testsRun >= 12 and not result.skipped and not result.failures and not result.errors
    receipt = dict(status='PASS_LINUX_EXIT_BOUNDARY_GATE' if passed else 'FAIL_LINUX_EXIT_BOUNDARY_GATE',
                   scope='RESOURCE_UNIT_TESTS_ONLY_NO_TRAINING', testsRun=result.testsRun,
                   skipped=len(result.skipped), failures=len(result.failures), errors=len(result.errors),
                   gate_pass=passed, exit_code=0 if passed else 1, real_training_release=False,
                   platform=platform.platform(), kernel=platform.release(), python=sys.version,
                   gnu_sort=subprocess.run(['sort', '--version'], capture_output=True, text=True, check=True).stdout.splitlines()[0],
                   archive_sha256=sha, log_sha256=hashlib.sha256(log).hexdigest(),
                   imported_guard=str(Path(ranking_v4_memory_guard.__file__).resolve()),
                   generated_empty_package_markers=['src/__init__.py', 'src/models/__init__.py', 'tests/__init__.py'],
                   files={name: hashlib.sha256(value).hexdigest() for name, value in content.items()})
    with (ROOT / 'receipt.json').open('x') as file:
        json.dump(receipt, file, sort_keys=True)
    print(json.dumps(receipt, sort_keys=True))
    return receipt['exit_code']


def run_with_failure_receipt(archive_path, sha):
    existed_before = ROOT.exists() or ROOT.is_symlink()
    try:
        return run(archive_path, sha)
    except Exception as error:
        failure = dict(status='FAIL_LINUX_EXIT_BOUNDARY_GATE', gate_pass=False, exit_code=1,
                       scope='RESOURCE_UNIT_TESTS_ONLY_NO_TRAINING', real_training_release=False,
                       error=f'{type(error).__name__}: {error}', archive_sha256=sha)
        # Never alter a pre-existing root; only seal this invocation's new root.
        if not existed_before and ROOT.is_dir() and not ROOT.is_symlink():
            receipt = ROOT / 'receipt.json'
            if not receipt.exists():
                with receipt.open('x') as file:
                    json.dump(failure, file, sort_keys=True)
        print(json.dumps(failure, sort_keys=True))
        return 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build')
    parser.add_argument('--run')
    parser.add_argument('--sha256')
    args = parser.parse_args()
    if bool(args.build) == bool(args.run):
        parser.error('Choose build or run')
    if args.build:
        print(json.dumps(build(args.build), sort_keys=True))
    else:
        sys.exit(run_with_failure_receipt(args.run, args.sha256))
