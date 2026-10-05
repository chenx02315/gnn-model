"""One generated-fixture neural fit under the actual low-memory guard."""
import argparse
import json
import os
from pathlib import Path
import sys
from scripts.verify_ranking_v4_synthetic import fixture, write_once
from src.models.runtime_ranking_v3 import digest, plan_folds, replay_frozen
from src.models.ranking_v3_freeze_io import read_freeze
from src.models.ranking_v4_memory_guard import run_bounded, THREAD_KEYS


def run(output):
    root = Path(output)
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError('V4_MEMORY_SMOKE_SYMLINK')
    root.mkdir(exist_ok=False)
    rows, labels = fixture()
    fold = plan_folds(rows)[0]
    request = dict(scope='RANKING_V4_SYNTHETIC_ONLY', source_sha256=digest(rows), family=fold.family,
                   seed=20260824, model='candidate_mlp', rows=rows,
                   fit_cycles={u: labels[u]['total_cycles'] for u in fold.fitting})
    path = root / 'request.json'
    sha = write_once(path, request)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', **{k: '1' for k in THREAD_KEYS})
    env.pop('PYTHONPATH', None)
    memory = run_bounded([sys.executable, '-m', 'src.models.ranking_v4_training_worker',
                          '--request', str(path), '--request-sha256', sha, '--output', str(root / 'worker')],
                         root / 'worker.log', env)
    worker = json.loads((root / 'worker' / 'worker_receipt.json').read_text())
    if worker['request_sha256'] != sha or worker['held_labels_supplied'] is not False:
        raise ValueError('V4_MEMORY_SMOKE_BINDING')
    freeze = read_freeze(root / 'worker' / 'freeze.json', worker['freeze_sha256'])
    evaluation = replay_frozen(freeze, worker['freeze_sha256'], fold, {u: labels[u] for u in fold.heldout})
    receipt = dict(status='PASS_GUARDED_SYNTHETIC_ML', scope='GENERATED_FIXTURE_ONLY', memory=memory,
                   request_sha256=sha, freeze_sha256=worker['freeze_sha256'], evaluation=evaluation,
                   real_training_release=False)
    receipt_sha = write_once(root / 'receipt.json', receipt)
    return dict(status=receipt['status'], receipt_sha256=receipt_sha, memory=memory)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    print(json.dumps(run(parser.parse_args().output), sort_keys=True))
