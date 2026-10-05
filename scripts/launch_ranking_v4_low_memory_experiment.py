"""One-shot supervisor for the fixed reviewed low-memory TRAIN experiment."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_train_687c96d_20261005_r2')
PACKAGE = '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds'
RELEASE_SHA = '70c458c9d4f70f87ab2fc12a220b46e325154480326051ae93fc7abc66127f31'
PACKAGE_SHA = '964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868'


def write_once(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True)


def main(supervise=False):
    if hashlib.sha256((ROOT / 'execution_release.json').read_bytes()).hexdigest() != RELEASE_SHA:
        raise ValueError('LAUNCH_RELEASE_SHA')
    if not supervise:
        if (ROOT / 'launch_receipt.json').exists() or (ROOT / 'experiment').exists():
            raise ValueError('LAUNCH_ALREADY_EXISTS_NO_RETRY')
        with (ROOT / 'supervisor.log').open('xb') as log:
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--supervise'],
                                       cwd=ROOT / 'code', stdout=log, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL, start_new_session=True,
                                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1'))
        receipt = dict(pid=process.pid, release_sha256=RELEASE_SHA, expected_evaluations=18,
                       retries=0, max_concurrent_workers=1, started_unix=time.time())
        write_once(ROOT / 'launch_receipt.json', receipt)
        print(json.dumps(receipt, sort_keys=True))
        return
    argv = [sys.executable, '-m', 'scripts.run_ranking_v4_real_experiment', '--package', PACKAGE,
            '--package-sha256', PACKAGE_SHA, '--release', str(ROOT / 'execution_release.json'),
            '--release-sha256', RELEASE_SHA, '--output', str(ROOT / 'experiment')]
    with (ROOT / 'experiment_driver.log').open('xb') as log:
        process = subprocess.run(argv, cwd=ROOT / 'code', stdout=log, stderr=subprocess.STDOUT,
                                 env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1'))
    write_once(ROOT / 'exit_receipt.json', dict(exit_code=process.returncode, retries=0,
                                               release_sha256=RELEASE_SHA, finished_unix=time.time()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--supervise', action='store_true')
    main(parser.parse_args().supervise)
