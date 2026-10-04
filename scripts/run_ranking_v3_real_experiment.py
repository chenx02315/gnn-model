"""Fixed TRAIN-only subprocess training and freeze-gated evaluator.

The reviewed source release and exported package are externally hash-bound.
Held labels are never serialized into a worker request. Not an OS sandbox.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from src.data.ranking_v3_real_fold_package import RealFoldReader, _read_json_once, _write_once
from src.models.runtime_ranking_v3 import Fold, digest, replay_frozen, freeze_ranking
from src.models.run_runtime_ranking_v3 import SEEDS
from src.models.run_runtime_ranking_v3_real import MODELS, SCOPE, aggregate_real, check_release
from src.models.ranking_v3_freeze_io import read_freeze

REVIEWED_FILES = (
    'scripts/run_ranking_v3_real_experiment.py', 'scripts/export_ranking_v3_real_inputs.py',
    'src/data/ranking_v3_real_fold_package.py', 'src/models/ranking_v3_training_worker.py',
    'src/models/runtime_ranking_v3.py', 'src/models/run_runtime_ranking_v3_real.py',
    'src/models/neural_ranking_v3.py', 'src/models/xgboost_ranking_v3.py',
    'src/models/ranking_v3_freeze_io.py', 'src/models/runtime_training_v2.py',
    'src/models/preflight_runtime_v2.py', 'requirements/runtime_v2.lock.txt')
EXPECTED_ACTIONS = 1706

def validate_destination(output):
    if not str(Path(output).resolve()).startswith('/ssd/cjc/gnn_model_ranking_v3_train_'):
        raise ValueError('EXPERIMENT_NEW_B_ROOT_REQUIRED')

def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def run(package, package_sha, release_path, release_sha, output):
    release = _read_json_once(Path(release_path), release_sha, 'EXPERIMENT_RELEASE_SHA')
    receipt = _read_json_once(Path(package)/'receipt.json', package_sha, 'EXPERIMENT_PACKAGE_SHA')
    source = receipt['source_sha256']; check_release(release, source)
    if set(release.get('reviewed_sources', {})) != set(REVIEWED_FILES):
        raise ValueError('EXPERIMENT_REVIEWED_SOURCE_INVENTORY')
    # Verify reviewed working source identity before any label shard is opened.
    for name, sha in release['reviewed_sources'].items():
        if file_sha(name) != sha:
            raise ValueError('EXPERIMENT_SOURCE_CHANGED:' + name)
    package = Path(package); output = Path(output)
    if any(p.is_symlink() for p in (package, output, *package.parents, *output.parents)):
        raise ValueError('EXPERIMENT_SYMLINK')
    validate_destination(output)
    if receipt['train_action_count'] != EXPECTED_ACTIONS or receipt['train_outcome_count'] != EXPECTED_ACTIONS or receipt['graph_count'] != 6:
        raise ValueError('EXPERIMENT_TRAIN_ROSTER')
    output.mkdir(exist_ok=False)
    graphs_meta = _read_json_once(package/'family_metadata.json', receipt['family_metadata_sha256'], 'EXPERIMENT_GRAPH_METADATA_SHA')
    if graphs_meta['graph_sha256'] != receipt['graph_sha256'] or digest({'source_input_sha256':receipt['source_input_sha256'], 'graph_sha256':receipt['graph_sha256']}) != source:
        raise ValueError('EXPERIMENT_SOURCE_INVENTORY_BINDING')
    # Six graph hashes are also part of the externally bound source digest.
    graphs = [{'graph_key':key, 'path':str((package/'graphs'/ (key+'.json')).resolve()), 'sha256':sha}
              for key, sha in graphs_meta['graph_sha256'].items()]
    records = {model:[] for model in MODELS}
    for family, manifest_sha in sorted(receipt['fold_manifest_sha256'].items()):
        fold_root = package / ('fold_'+family)
        manifest = _read_json_once(fold_root/'manifest.json', manifest_sha, 'EXPERIMENT_FOLD_SHA')
        fold = Fold(family, tuple(manifest['fitting']), tuple(manifest['heldout']))
        reader = RealFoldReader(fold_root, manifest_sha, fold)
        if reader.manifest['source_sha256'] != source:
            raise ValueError('EXPERIMENT_FOLD_SOURCE')
        rows = reader.feature_rows()
        fitting = reader.fitting(fold.fitting)
        for seed in SEEDS:
            for model in MODELS:
                token = family+'_'+str(seed)+'_'+model
                request = {'scope':'TRAIN_ONLY_WORKER_NO_HELD_LABELS', 'source_sha256':source,
                           'family':family, 'seed':seed, 'model':model, 'rows':rows,
                           'fit_outcomes':fitting, 'graphs':graphs, 'graph_contract':{'features':{'node_type_buckets':16,'cell_type_hash_buckets':64}}}
                request_path = output/(token+'_request.json'); _write_once(request_path, request)
                request_sha = file_sha(request_path)
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1')
                env.pop('PYTHONPATH', None)
                worker_dir = output/token
                with (output/(token+'.log')).open('xb') as stream:
                    subprocess.run([sys.executable, '-m', 'src.models.ranking_v3_training_worker',
                        '--request', str(request_path), '--request-sha256', request_sha,
                        '--output', str(worker_dir)], env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
                worker = json.loads((worker_dir/'worker_receipt.json').read_bytes())
                if any(worker[k] != request[k] for k in ('source_sha256','family','seed','model')) or worker['held_labels_supplied'] is not False:
                    raise ValueError('EXPERIMENT_WORKER_BINDING')
                sha = worker['freeze_sha256']; payload = read_freeze(worker_dir/'freeze.json', sha)
                expected, expected_sha = freeze_ranking(payload['scores'], fold)
                if payload != expected or sha != expected_sha:
                    raise ValueError('EXPERIMENT_FREEZE_BINDING')
                outcomes = reader.heldout(fold.heldout, worker_dir/'freeze.json', sha)
                result = dict(scope=SCOPE, source_sha256=source, model=model, family=family, seed=seed,
                    freeze=payload, freeze_sha256=sha, pair_sha256=worker['pair_sha256'],
                    metrics=replay_frozen(payload, sha, fold, outcomes))
                _write_once(worker_dir/'evaluation.json', result); records[model].append(result)
    summary = {model:aggregate_real(items, model, release=release, source_sha256=source)
               for model,items in records.items()}
    _write_once(output/'summary.json', summary)
    return summary

def main():
    parser = argparse.ArgumentParser()
    for name in ('package','package-sha256','release','release-sha256','output'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.package, args.package_sha256, args.release, args.release_sha256, args.output), sort_keys=True))

if __name__ == '__main__':
    main()
