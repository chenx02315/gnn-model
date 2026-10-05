"""Bounded real TRAIN-only v4 worker.  No evaluator, BLIND, or synthetic receipt."""
import argparse
import hashlib
import json
from pathlib import Path
import time

from src.data.ranking_v3_real_fold_package import _read_json_once
from src.models.neural_ranking_v3 import fit_neural, predict_neural
from src.models.ranking_v3_freeze_io import persist_freeze
from src.models.ranking_v4_training_worker import MODEL, REQUEST_FIELDS, SCOPE as SYNTHETIC_SCOPE, prepare_request
from src.models.runtime_ranking_v3 import digest, feature_matrix, freeze_ranking, transform

SCOPE = 'REAL_TRAIN_ONLY_V4_WORKER'
SOURCE_SHA256 = 'b89b455ace9d545c0afd54fe9fded98e4db4abd56f58fe09a0cce28b88215d9c'
PACKAGE_SHA256 = '964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868'
REVIEWED_FILES = (
    'scripts/run_ranking_v4_real_experiment.py', 'src/models/ranking_v4_real_worker.py',
    'scripts/ranking_v4_near_optimal_pairs.py', 'src/models/ranking_v4_training_worker.py',
    'src/models/neural_ranking_v3.py', 'src/models/runtime_ranking_v3.py',
    'src/models/run_runtime_ranking_v3.py',
    'src/models/ranking_v3_freeze_io.py', 'src/data/ranking_v3_real_fold_package.py',
    'src/models/preflight_runtime_v2.py', 'src/models/runtime_training_v2.py',
    'requirements/runtime_v2.lock.txt', 'src/models/ranking_v4_memory_guard.py',
)


def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(char in '0123456789abcdef' for char in value)


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_release(release, source_sha256):
    if (not isinstance(release, dict) or release.get('status') != 'PASS_V4_TRAIN_ONLY_EXECUTION' or
            release.get('source_sha256') != source_sha256 or source_sha256 != SOURCE_SHA256 or
            release.get('package_receipt_sha256') != PACKAGE_SHA256 or release.get('roles') != ['TRAIN'] or
            release.get('seeds') != [20260824, 20260825, 20260826] or release.get('model') != MODEL or
            release.get('training_release') is not True or set(release.get('reviewed_sources', {})) != set(REVIEWED_FILES) or
            any(not _sha(value) for value in release['reviewed_sources'].values())):
        raise ValueError('V4_REAL_RELEASE')


def verify_reviewed_sources(release):
    for name, expected in release['reviewed_sources'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or not path.resolve().is_relative_to(Path.cwd().resolve()):
            raise ValueError('V4_REAL_SOURCE_PATH:' + name)
        if file_sha(path) != expected:
            raise ValueError('V4_REAL_SOURCE_DRIFT:' + name)


def prepare_real_request(request):
    if not isinstance(request, dict) or set(request) != REQUEST_FIELDS or request.get('scope') != SCOPE:
        raise ValueError('V4_REAL_REQUEST_SCHEMA')
    synthetic = dict(request, scope=SYNTHETIC_SCOPE)
    return prepare_request(synthetic)


def execute(request, release, output, torch, np, *, raw_request_sha256):
    if not _sha(raw_request_sha256):
        raise ValueError('V4_REAL_REQUEST_SHA')
    check_release(release, request.get('source_sha256'))
    verify_reviewed_sources(release)
    fold, prepared, held, packet = prepare_real_request(request)
    output = Path(output)
    if any(path.is_symlink() for path in (output, *output.parents)):
        raise ValueError('V4_REAL_OUTPUT_SYMLINK')
    output.mkdir(exist_ok=False)
    torch.set_num_threads(1); torch.set_num_interop_threads(1)
    started = time.monotonic()
    model = fit_neural(torch, np, prepared, request['seed'])
    scores = predict_neural(torch, model, tuple(row['action_uid'] for row in held),
                             transform(feature_matrix(held), prepared['normalizer']))
    torch.save(model.state_dict(), output / 'model.pt')
    payload, freeze_sha = freeze_ranking(scores, fold)
    persist_freeze(output / 'freeze.json', payload, freeze_sha)
    receipt = {'scope': SCOPE, 'source_sha256': request['source_sha256'], 'model': MODEL,
               'family': fold.family, 'seed': request['seed'], 'request_sha256': raw_request_sha256,
               'canonical_request_sha256': digest(request), 'pair_recipe_sha256': packet['recipe_sha256'],
               'freeze_sha256': freeze_sha, 'worker_wall_s': time.monotonic() - started,
               'runtime_semantics': 'worker_wall_s is model computation, NOT ATPG runtime',
               'held_labels_supplied': False}
    with (output / 'worker_receipt.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(receipt, stream, sort_keys=True, separators=(',', ':')); stream.write('\n')
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    for name in ('request', 'request-sha256', 'release', 'release-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    request = _read_json_once(Path(args.request), args.request_sha256, 'V4_REAL_REQUEST_SHA')
    release = _read_json_once(Path(args.release), args.release_sha256, 'V4_REAL_RELEASE_SHA')
    check_release(release, request.get('source_sha256'))
    verify_reviewed_sources(release)
    from src.models.preflight_runtime_v2 import parse_lock, validate_installed_dependencies
    validate_installed_dependencies(parse_lock(Path('requirements/runtime_v2.lock.txt')))
    import numpy as np
    import torch
    execute(request, release, args.output, torch, np, raw_request_sha256=args.request_sha256)


if __name__ == '__main__':
    main()
