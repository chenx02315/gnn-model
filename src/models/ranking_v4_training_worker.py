"""Synthetic-only v4 candidate-MLP worker; no real-data or release authority."""
import argparse
import json
import math
from pathlib import Path
import time

from scripts.ranking_v4_near_optimal_pairs import build_near_optimal_pair_recipe
from src.data.ranking_v3_real_fold_package import _read_json_once
from src.models.neural_ranking_v3 import fit_neural, predict_neural
from src.models.ranking_v3_freeze_io import persist_freeze
from src.models.run_runtime_ranking_v3 import SEEDS
from src.models.runtime_ranking_v3 import (
    FEATURES, digest, feature_matrix, fit_normalizer, freeze_ranking, plan_folds, transform,
)

SCOPE = 'RANKING_V4_SYNTHETIC_ONLY'
MODEL = 'candidate_mlp'
REQUEST_FIELDS = frozenset(('scope', 'source_sha256', 'family', 'seed', 'model', 'rows', 'fit_cycles'))
ROW_FIELDS = frozenset(('action_uid', 'circuit', 'family', 'role') + FEATURES)


def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(char in '0123456789abcdef' for char in value)


def prepare_request(request):
    """Validate the synthetic request and return fold, prepared fit data, held rows, recipe packet."""
    if not isinstance(request, dict) or set(request) != REQUEST_FIELDS:
        raise ValueError('V4_WORKER_REQUEST_SCHEMA')
    if request['scope'] != SCOPE or request['model'] != MODEL or request['seed'] not in SEEDS or not _sha(request['source_sha256']):
        raise ValueError('V4_WORKER_PROTOCOL')
    rows = request['rows']
    if not isinstance(rows, list) or any(not isinstance(row, dict) or set(row) != ROW_FIELDS for row in rows):
        raise ValueError('V4_WORKER_ROWS')
    folds = plan_folds(rows)  # validates six TRAIN families and all metadata.
    matches = [fold for fold in folds if fold.family == request['family']]
    if len(matches) != 1:
        raise ValueError('V4_WORKER_FAMILY')
    fold = matches[0]
    cycles = request['fit_cycles']
    if not isinstance(cycles, dict) or set(cycles) != set(fold.fitting):
        raise ValueError('V4_WORKER_FIT_CYCLES')
    fitting = sorted((row for row in rows if row['action_uid'] in set(fold.fitting)), key=lambda row: row['action_uid'])
    pair_rows = []
    for row in fitting:
        value = cycles[row['action_uid']]
        if type(value) is not int or value <= 0:
            raise ValueError('V4_WORKER_CYCLES')
        pair_rows.append({'action_uid': row['action_uid'], 'family': row['family'], 'total_cycles': value})
    packet = build_near_optimal_pair_recipe(pair_rows, heldout_family=fold.family)
    recipe = packet['recipe']
    pairs = {family: tuple((pair['positive_uid'], pair['negative_uid']) for pair in data['pairs'])
             for family, data in recipe['families'].items()}
    normalizer = fit_normalizer(feature_matrix(fitting))
    targets = {row['action_uid']: math.log(cycles[row['action_uid']] /
               recipe['families'][row['family']]['oracle_cycles']) for row in fitting}
    prepared = {'normalizer': normalizer, 'targets': targets, 'pairs': pairs,
                'fit_uids': tuple(row['action_uid'] for row in fitting),
                'fit_features': transform(feature_matrix(fitting), normalizer)}
    held = sorted((row for row in rows if row['action_uid'] in set(fold.heldout)),
                  key=lambda row: row['action_uid'])
    return fold, prepared, held, packet


def execute(request, output, torch, np, *, raw_request_sha256):
    """Fit only on synthetic fitting cycles; write freeze before the receipt."""
    if not _sha(raw_request_sha256):
        raise ValueError('V4_WORKER_REQUEST_SHA')
    fold, prepared, held, packet = prepare_request(request)
    held_uids = tuple(row['action_uid'] for row in held)
    held_matrix = transform(feature_matrix(held), prepared['normalizer'])
    output = Path(output)
    if any(path.is_symlink() for path in (output, *output.parents)):
        raise ValueError('V4_WORKER_OUTPUT_SYMLINK')
    output.mkdir(exist_ok=False)
    started = time.monotonic()
    model = fit_neural(torch, np, prepared, request['seed'])
    scores = predict_neural(torch, model, held_uids, held_matrix)
    torch.save(model.state_dict(), output / 'model.pt')
    payload, freeze_sha = freeze_ranking(scores, fold)
    persist_freeze(output / 'freeze.json', payload, freeze_sha)
    receipt = {'scope': SCOPE, 'source_sha256': request['source_sha256'], 'model': MODEL,
               'family': fold.family, 'seed': request['seed'], 'request_sha256': raw_request_sha256,
               'canonical_request_sha256': digest(request), 'pair_recipe_sha256': packet['recipe_sha256'],
               'freeze_sha256': freeze_sha, 'worker_wall_s': time.monotonic() - started,
               'runtime_semantics': 'worker_wall_s is model computation, NOT ATPG runtime',
               'held_labels_supplied': False, 'training_authority': 'SYNTHETIC_ONLY_NO_REAL_RELEASE'}
    with (output / 'worker_receipt.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(receipt, stream, sort_keys=True, separators=(',', ':')); stream.write('\n')
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', required=True); parser.add_argument('--request-sha256', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    request = _read_json_once(Path(args.request), args.request_sha256, 'V4_WORKER_REQUEST_SHA')
    from src.models.preflight_runtime_v2 import parse_lock, validate_installed_dependencies
    validate_installed_dependencies(parse_lock(Path('requirements/runtime_v2.lock.txt')))
    import numpy as np
    import torch
    execute(request, args.output, torch, np, raw_request_sha256=args.request_sha256)


if __name__ == '__main__':
    main()
