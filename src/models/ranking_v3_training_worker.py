"""Fixed subprocess worker: fit labels in, held features in, frozen scores out.

No held-label loader or path is part of the request. This is an audited
scientific data-flow boundary, not a sandbox against malicious same-user code.
"""
import argparse
import json
from pathlib import Path
import time
from src.data.ranking_v3_real_fold_package import _read_json_once
from src.models.runtime_ranking_v3 import digest, plan_folds, prepare_fold, feature_matrix, transform, freeze_ranking
from src.models.run_runtime_ranking_v3 import SEEDS
from src.models.ranking_v3_freeze_io import persist_freeze

def graph_tensor(raw, torch):
    from src.models.runtime_training_v2 import _hash_bucket
    if raw.get('schema_version') != 'runtime-graph-v1' or not raw.get('nodes'):
        raise ValueError('WORKER_GRAPH_SCHEMA')
    nodes = raw['nodes']; edges = raw['edge_index']
    x = torch.zeros((len(nodes), 81), dtype=torch.float32)
    for i, node in enumerate(nodes):
        x[i, _hash_bucket(str(node['node_type']), 16)] = 1.
        x[i, 16 + _hash_bucket(str(node['cell_type']), 64)] = 1.
        x[i, -1] = 1. if node['sequential_flag'] else 0.
    edge = torch.tensor(edges, dtype=torch.long).t().contiguous() if edges else torch.empty((2,0), dtype=torch.long)
    if edges and (edge.shape[0] != 2 or edge.min().item() < 0 or edge.max().item() >= len(nodes)):
        raise ValueError('WORKER_GRAPH_EDGE_RANGE')
    return x, edge

def execute(request, output, torch, np, xgb):
    required = {'scope', 'source_sha256', 'family', 'seed', 'model', 'rows', 'fit_outcomes', 'graphs', 'graph_contract'}
    if set(request) != required or request['scope'] != 'TRAIN_ONLY_WORKER_NO_HELD_LABELS':
        raise ValueError('WORKER_REQUEST_SCHEMA')
    if request['seed'] not in SEEDS or request['model'] not in ('candidate_mlp', 'graphsage', 'xgboost', 'fixed_heuristic'):
        raise ValueError('WORKER_PROTOCOL')
    rows = request['rows']
    fold = next(f for f in plan_folds(rows) if f.family == request['family'])
    prepared = prepare_fold(rows, request['fit_outcomes'], fold, request['seed'])
    held = sorted((r for r in rows if r['action_uid'] in fold.heldout), key=lambda r:r['action_uid'])
    uids = tuple(r['action_uid'] for r in held)
    matrix = transform(feature_matrix(held), prepared['normalizer'])
    output = Path(output)
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('WORKER_OUTPUT_SYMLINK')
    output.mkdir(exist_ok=False)
    started = time.monotonic()
    if request['model'] == 'fixed_heuristic':
        ordered = sorted(held, key=lambda r:(-int(r['action_scheme']=='HMF'), -int(r['h_limit']), -int(r['m_limit']), r['action_uid']))
        scores = {r['action_uid']:float(len(ordered)-i) for i,r in enumerate(ordered)}
    elif request['model'] == 'xgboost':
        from src.models.xgboost_ranking_v3 import pack_groups, fit_ranker
        fitting = [r for r in rows if r['action_uid'] in fold.fitting]
        model = fit_ranker(xgb, np, pack_groups(fitting, prepared['targets'], prepared['normalizer']), request['seed'])
        scores = dict(zip(uids, map(float, model.predict(np.asarray(matrix)))))
        model.save_model(output / 'model.json')
    else:
        from src.models.neural_ranking_v3 import fit_neural, predict_neural
        graphs = {}; kwargs = {}; prediction_kwargs = {}
        if request['model'] == 'graphsage':
            for graph in request['graphs']:
                raw = _read_json_once(graph['path'], graph['sha256'], 'WORKER_GRAPH_SHA')
                graphs[graph['graph_key']] = graph_tensor(raw, torch)
            fit_keys = {r['action_uid']:r['graph_key'] for r in rows if r['action_uid'] in fold.fitting}
            kwargs = dict(graphs=graphs, uid_graph_keys=fit_keys)
            prediction_kwargs = dict(graphs=graphs, uid_graph_keys={r['action_uid']:r['graph_key'] for r in held})
        model = fit_neural(torch, np, prepared, request['seed'], **kwargs)
        scores = predict_neural(torch, model, uids, matrix, **prediction_kwargs)
        torch.save(model.state_dict(), output / 'model.pt')
    payload, sha = freeze_ranking(scores, fold)
    persist_freeze(output / 'freeze.json', payload, sha)
    receipt = {'scope':'TRAIN_ONLY_WORKER_NO_HELD_LABELS', 'source_sha256':request['source_sha256'],
               'model':request['model'], 'seed':request['seed'], 'family':fold.family,
               'freeze_sha256':sha, 'pair_sha256':digest(prepared['pairs']),
               'worker_wall_s':time.monotonic()-started,
               'runtime_semantics':'worker_wall_s is model computation, NOT ATPG runtime',
               'held_labels_supplied':False}
    with (output / 'worker_receipt.json').open('x') as stream:
        json.dump(receipt, stream, sort_keys=True)
    return receipt

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', required=True)
    parser.add_argument('--request-sha256', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    request = _read_json_once(Path(args.request), args.request_sha256, 'WORKER_REQUEST_SHA')
    from src.models.preflight_runtime_v2 import parse_lock, validate_installed_dependencies
    validate_installed_dependencies(parse_lock(Path('requirements/runtime_v2.lock.txt')))
    import torch
    import numpy as np
    import xgboost as xgb
    execute(request, args.output, torch, np, xgb)

if __name__ == '__main__':
    main()
