"""One-shot fixed-grid TRAIN supervisor; requires independently reviewed release SHA."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_train_dec61b0_20261005_r3')
CODE = Path('/ssd/cjc/gnn_model_ranking_v4_integrated_dec61b0_20261005_r2/code')
PACKAGE = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds'
PACKAGE_SHA = '964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868'


def write_once(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True)


def main(sha, supervise=False):
    if len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
        raise ValueError('R3_RELEASE_SHA_FORMAT')
    if any(p.is_symlink() for p in (ROOT, *ROOT.parents, CODE, *CODE.parents)):
        raise ValueError('R3_PATH_SYMLINK')
    if hashlib.sha256((ROOT / 'execution_release.json').read_bytes()).hexdigest() != sha:
        raise ValueError('R3_RELEASE_SHA')
    if not supervise:
        if any((ROOT / name).exists() for name in ('launch_intent.json', 'launch_receipt.json', 'experiment', 'exit_receipt.json')):
            raise ValueError('R3_ALREADY_LAUNCHED_NO_RETRY')
        write_once(ROOT / 'launch_intent.json', dict(release_sha256=sha, retries=0,
                   code_root=str(CODE), expected_evaluations=18, started_unix=time.time()))
        try:
            with (ROOT / 'supervisor.log').open('xb') as log:
                process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--supervise',
                                            '--release-sha256', sha], cwd=CODE, stdin=subprocess.DEVNULL,
                                           stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1'))
        except Exception as error:
            write_once(ROOT / 'launch_failure.json', dict(status='STOPPED_NO_RETRY',
                       error=f'{type(error).__name__}: {error}', release_sha256=sha, retries=0))
            raise
        receipt = dict(pid=process.pid, release_sha256=sha, expected_evaluations=18, retries=0,
                       max_concurrent_workers=1, code_root=str(CODE), started_unix=time.time())
        write_once(ROOT / 'launch_receipt.json', receipt)
        print(json.dumps(receipt, sort_keys=True))
        return
    intent = json.loads((ROOT / 'launch_intent.json').read_bytes())
    if (set(intent) != {'release_sha256', 'retries', 'code_root', 'expected_evaluations', 'started_unix'} or
            intent.get('release_sha256') != sha or intent.get('retries') != 0 or
            intent.get('code_root') != str(CODE) or intent.get('expected_evaluations') != 18):
        raise ValueError('R3_SUPERVISOR_INTENT')
    argv = [sys.executable, '-m', 'scripts.run_ranking_v4_real_experiment', '--package', PACKAGE,
            '--package-sha256', PACKAGE_SHA, '--release', str(ROOT / 'execution_release.json'),
            '--release-sha256', sha, '--output', str(ROOT / 'experiment')]
    with (ROOT / 'experiment_driver.log').open('xb') as log:
        result = subprocess.run(argv, cwd=CODE, stdout=log, stderr=subprocess.STDOUT,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1'))
    write_once(ROOT / 'exit_receipt.json', dict(exit_code=result.returncode, release_sha256=sha,
               retries=0, finished_unix=time.time()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--release-sha256', required=True)
    parser.add_argument('--supervise', action='store_true')
    args = parser.parse_args()
    main(args.release_sha256, args.supervise)
