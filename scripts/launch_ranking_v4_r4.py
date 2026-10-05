"""One-shot r4 TRAIN supervisor with a parent/child launch handshake."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_train_af05de0_20261005_r4')
CODE = Path('/ssd/cjc/gnn_model_ranking_v4_exit_boundary_ml_fe67d2d_20261005_r1/code')
PACKAGE = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds'
PACKAGE_SHA = '964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868'
RECEIPT_WAIT_SECONDS = 5.0
RECEIPT_POLL_SECONDS = 0.05
MAX_HANDSHAKE_BYTES = 10 * 1024


def write_once(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, separators=(',', ':'))
        stream.flush()
        os.fsync(stream.fileno())


def _publish_receipt_once(value):
    """Publish only a fully closed receipt: readers never observe a partial JSON file."""
    pending = ROOT / 'launch_receipt.pending.json'
    final = ROOT / 'launch_receipt.json'
    write_once(pending, value)
    try:
        os.link(pending, final)
    except FileExistsError as error:
        raise ValueError('R4_LAUNCH_RECEIPT_EXISTS') from error


def _sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path):
    return _sha256_bytes(Path(path).read_bytes())


def _launcher_sha256():
    return _file_sha256(Path(__file__).resolve())


def _canonical_sha256(value):
    return _sha256_bytes(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8'))


def _read_handshake(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_HANDSHAKE_BYTES:
        raise ValueError('R4_HANDSHAKE_RECEIPT')
    try:
        return json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('R4_HANDSHAKE_RECEIPT') from error


def safe_env():
    if os.environ.get('PYTHONPATH'):
        raise ValueError('R4_PYTHONPATH_CONTAMINATED')
    return dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')


def _intent(sha):
    return {
        'release_sha256': sha, 'package': PACKAGE, 'package_sha256': PACKAGE_SHA,
        'output': str(ROOT / 'experiment'), 'code_root': str(CODE),
        'launcher_sha256': _launcher_sha256(), 'expected_evaluations': 18,
        'max_concurrent_workers': 1, 'retries': 0, 'started_unix': time.time(),
    }


def _valid_intent(intent, sha):
    expected = set(_intent(sha))
    return (isinstance(intent, dict) and set(intent) == expected and
            intent.get('release_sha256') == sha and intent.get('package') == PACKAGE and
            intent.get('package_sha256') == PACKAGE_SHA and intent.get('output') == str(ROOT / 'experiment') and
            intent.get('code_root') == str(CODE) and intent.get('launcher_sha256') == _launcher_sha256() and
            intent.get('expected_evaluations') == 18 and intent.get('max_concurrent_workers') == 1 and
            intent.get('retries') == 0 and isinstance(intent.get('started_unix'), (int, float)) and
            not isinstance(intent.get('started_unix'), bool))


def _valid_receipt(receipt, intent, pid):
    return (isinstance(receipt, dict) and set(receipt) == set(intent) | {'pid'} and
            receipt.get('pid') == pid and not isinstance(receipt.get('pid'), bool) and
            all(receipt.get(key) == value for key, value in intent.items()))


def _wait_for_parent_receipt(intent):
    receipt_path = ROOT / 'launch_receipt.json'
    failure_path = ROOT / 'launch_failure.json'
    deadline = time.monotonic() + RECEIPT_WAIT_SECONDS
    while time.monotonic() < deadline:
        if failure_path.exists():
            raise ValueError('R4_PARENT_LAUNCH_FAILURE')
        if receipt_path.exists():
            receipt = _read_handshake(receipt_path)
            if not _valid_receipt(receipt, intent, os.getpid()):
                raise ValueError('R4_SUPERVISOR_RECEIPT')
            return receipt
        time.sleep(RECEIPT_POLL_SECONDS)
    raise ValueError('R4_SUPERVISOR_RECEIPT_TIMEOUT')


def _claim(intent):
    claim = {'pid': os.getpid(), 'release_sha256': intent['release_sha256'],
             'intent_sha256': _canonical_sha256(intent)}
    try:
        write_once(ROOT / 'supervisor_claim.json', claim)
    except FileExistsError as error:
        raise ValueError('R4_SUPERVISOR_ALREADY_CLAIMED') from error
    return claim


def _failure(sha, error, pid=None):
    value = {'status': 'STOPPED_NO_RETRY', 'error': f'{type(error).__name__}: {error}',
             'release_sha256': sha, 'retries': 0}
    if pid is not None:
        value['pid'] = pid
    try:
        write_once(ROOT / 'launch_failure.json', value)
    except FileExistsError:
        pass


def main(sha, supervise=False):
    if len(sha) != 64 or any(char not in '0123456789abcdef' for char in sha):
        raise ValueError('R4_RELEASE_SHA_FORMAT')
    if any(path.is_symlink() for path in (ROOT, *ROOT.parents, CODE, *CODE.parents)):
        raise ValueError('R4_PATH_SYMLINK')
    if _file_sha256(ROOT / 'execution_release.json') != sha:
        raise ValueError('R4_RELEASE_SHA')
    env = safe_env()
    if not supervise:
        if any((ROOT / name).exists() for name in ('launch_intent.json', 'launch_receipt.pending.json', 'launch_receipt.json',
                                                    'launch_failure.json', 'supervisor_claim.json', 'experiment', 'exit_receipt.json')):
            raise ValueError('R4_ALREADY_LAUNCHED_NO_RETRY')
        intent = _intent(sha)
        write_once(ROOT / 'launch_intent.json', intent)
        process = None
        try:
            with (ROOT / 'supervisor.log').open('xb') as log:
                process = subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve()), '--supervise', '--release-sha256', sha],
                    cwd=CODE, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True, env=env)
            receipt = dict(intent, pid=process.pid)
            _publish_receipt_once(receipt)
        except Exception as error:
            _failure(sha, error, None if process is None else process.pid)
            raise
        print(json.dumps(receipt, sort_keys=True)); return
    intent = _read_handshake(ROOT / 'launch_intent.json')
    if not _valid_intent(intent, sha):
        raise ValueError('R4_SUPERVISOR_INTENT')
    _wait_for_parent_receipt(intent)
    _claim(intent)
    argv = [sys.executable, '-B', '-m', 'scripts.run_ranking_v4_real_experiment', '--package', PACKAGE,
            '--package-sha256', PACKAGE_SHA, '--release', str(ROOT / 'execution_release.json'),
            '--release-sha256', sha, '--output', str(ROOT / 'experiment')]
    with (ROOT / 'experiment_driver.log').open('xb') as log:
        result = subprocess.run(argv, cwd=CODE, stdout=log, stderr=subprocess.STDOUT, env=env)
    write_once(ROOT / 'exit_receipt.json', {'exit_code': result.returncode, 'release_sha256': sha,
               'retries': 0, 'finished_unix': time.time()})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--release-sha256', required=True); parser.add_argument('--supervise', action='store_true')
    args = parser.parse_args()
    main(args.release_sha256, args.supervise)
