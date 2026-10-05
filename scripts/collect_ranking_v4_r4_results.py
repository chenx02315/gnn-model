"""Export only bounded, projected r4 results; never export requests, labels, graphs, or checkpoints."""
import hashlib
import json
from pathlib import Path

from src.models.runtime_ranking_v3 import FAMILIES
from src.models.run_runtime_ranking_v3 import SEEDS
from src.models.ranking_v4_real_worker import (MODEL, PACKAGE_SHA256, REVIEWED_FILES,
                                                SCOPE as WORKER_SCOPE, SOURCE_SHA256)
from scripts.run_ranking_v4_real_experiment import SCOPE as RUNNER_SCOPE

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_train_af05de0_20261005_r4')
OUTPUT_NAME = 'small_results.json'
MAX_RAW_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 200 * 1024
MAX_SERIALIZED_BYTES = 300 * 1024
TOP_FILES = ('exit_receipt.json', 'execution_release.json', 'independent_review.json',
             'launch_receipt.json', 'experiment/summary.json')
EVALUATION_FIELDS = ('family', 'seed', 'model', 'scope', 'source_sha256', 'freeze_sha256',
                     'pair_recipe_sha256', 'metrics', 'memory_guard')
METRIC_FIELDS = ('hit_at_10', 'hit_found', 'attempt_count', 'charged_runtime_s',
                 'best_cycle_regret_at_10', 'freeze_sha256')
WORKER_FIELDS = ('scope', 'source_sha256', 'model', 'family', 'seed', 'request_sha256',
                 'canonical_request_sha256', 'pair_recipe_sha256', 'freeze_sha256',
                 'worker_wall_s', 'runtime_semantics', 'held_labels_supplied')
MEMORY_FIELDS = ('status', 'exit_code', 'sample_count', 'peak_group_rss_bytes',
                 'peak_combined_rss_bytes', 'initial_available_bytes', 'effective_total_bytes',
                 'reserve_bytes', 'elapsed_seconds')
MEMORY_POLICY_FIELDS = ('max_concurrent_workers', 'combined_rss_cap_bytes',
                        'child_address_space_cap_bytes', 'reserve_min_bytes', 'reserve_fraction',
                        'poll_seconds', 'timeout_seconds', 'retries', 'limitation')
TOP_SCALARS = ('schema_version', 'status', 'exit_code', 'retries', 'release_sha256',
               'source_sha256', 'package_receipt_sha256', 'independent_review_sha256',
               'started_unix', 'finished_unix', 'pid', 'expected_evaluations',
               'max_concurrent_workers', 'receipt_count', 'nonexhaustive_count', 'model', 'scope')


def _sha(raw): return hashlib.sha256(raw).hexdigest()


def _reject_symlink(path):
    if any(item.is_symlink() for item in (Path(path), *Path(path).parents)):
        raise ValueError('V4_R4_COLLECTION_SYMLINK')


def _read(path, total):
    _reject_symlink(path)
    path = Path(path)
    if not path.is_file(): raise ValueError('V4_R4_COLLECTION_PATH')
    with path.open('rb') as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    total += len(raw)
    if len(raw) > MAX_FILE_BYTES or total > MAX_RAW_BYTES:
        raise ValueError('V4_R4_COLLECTION_BOUND')
    try:
        return {'sha256': _sha(raw), 'bytes': len(raw), 'data': json.loads(raw)}, total
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('V4_R4_COLLECTION_JSON') from error


def _paths(root):
    top = [root / name for name in TOP_FILES]
    experiment = root / 'experiment'; _reject_symlink(experiment)
    evaluations = sorted(experiment.glob('*/evaluation.json'))
    workers = sorted(experiment.glob('*/worker_receipt.json'))
    memory = sorted(experiment.glob('*.log.memory.json'))
    exits = list(root.glob('*exit_receipt*.json'))
    if len(evaluations) != 18 or len(workers) != 18 or len(memory) != 18 or exits != [root / 'exit_receipt.json']:
        raise ValueError('V4_R4_COLLECTION_GRID')
    paths = top[:]
    for evaluation in evaluations:
        paths.extend((evaluation.parent / 'worker_receipt.json',
                      experiment / (evaluation.parent.name + '.log.memory.json'), evaluation))
    return paths, evaluations


def _validate(root, records, evaluations):
    exit_data = records['exit_receipt.json']['data']
    if exit_data.get('exit_code') != 0 or exit_data.get('retries') != 0:
        raise ValueError('V4_R4_COLLECTION_EXIT')
    release = records['execution_release.json']
    review = records['independent_review.json']
    launch = records['launch_receipt.json']['data']
    launch_keys = {'pid', 'release_sha256', 'package', 'package_sha256', 'output', 'code_root', 'launcher_sha256',
                   'expected_evaluations', 'max_concurrent_workers', 'retries', 'started_unix'}
    if (set(launch) != launch_keys or not isinstance(launch.get('pid'), int) or isinstance(launch.get('pid'), bool) or
            launch.get('pid') <= 0 or not _sha_text(launch.get('launcher_sha256')) or
            release['sha256'] != launch.get('release_sha256') or release['sha256'] != exit_data.get('release_sha256') or
            release['data'].get('independent_review_sha256') != review['sha256'] or
            release['data'].get('status') != 'PASS_V4_TRAIN_ONLY_EXECUTION' or
            release['data'].get('source_sha256') != SOURCE_SHA256 or
            release['data'].get('package_receipt_sha256') != PACKAGE_SHA256 or
            release['data'].get('roles') != ['TRAIN'] or release['data'].get('seeds') != list(SEEDS) or
            release['data'].get('model') != MODEL or release['data'].get('training_release') is not True or
            launch.get('package') != '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds' or
            launch.get('package_sha256') != PACKAGE_SHA256 or launch.get('output') != str(root / 'experiment') or
            launch.get('expected_evaluations') != 18 or launch.get('max_concurrent_workers') != 1 or
            launch.get('retries') != 0):
        raise ValueError('V4_R4_COLLECTION_RELEASE_BINDING')
    summary = records['experiment/summary.json']['data']
    if (summary.get('scope') != RUNNER_SCOPE or summary.get('model') != MODEL or
            summary.get('receipt_count') != 18 or summary.get('nonexhaustive_count') != 15):
        raise ValueError('V4_R4_COLLECTION_SUMMARY')
    expected = {(family, seed, 'candidate_mlp') for family in FAMILIES.values() for seed in SEEDS}
    actual = []
    for path in evaluations:
        key = path.relative_to(root).as_posix(); data = records[key]['data']
        if not set(EVALUATION_FIELDS) <= set(data): raise ValueError('V4_R4_COLLECTION_EVALUATION_SCHEMA')
        if any(not _scalar(data[field]) for field in EVALUATION_FIELDS if field not in ('metrics', 'memory_guard')):
            raise ValueError('V4_R4_COLLECTION_EVALUATION_METADATA')
        if (data.get('scope') != RUNNER_SCOPE or data.get('source_sha256') != SOURCE_SHA256 or data.get('model') != MODEL):
            raise ValueError('V4_R4_COLLECTION_EVALUATION_SCHEMA')
        actual.append((data['family'], data['seed'], data['model']))
        worker = records[(path.parent / 'worker_receipt.json').relative_to(root).as_posix()]['data']
        memory = records[(root / 'experiment' / (path.parent.name + '.log.memory.json')).relative_to(root).as_posix()]['data']
        fields = ('family', 'seed', 'model', 'source_sha256', 'freeze_sha256', 'pair_recipe_sha256')
        if (worker.get('scope') != WORKER_SCOPE or any(worker.get(field) != data[field] for field in fields) or
                worker.get('held_labels_supplied') is not False or
                memory.get('status') != 'PASS_BOUNDED_WORKER' or memory.get('exit_code') != 0):
            raise ValueError('V4_R4_COLLECTION_BINDING')
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise ValueError('V4_R4_COLLECTION_GRID')


def _scalar(value): return value is None or type(value) in (str, int, float, bool)


def _sha_text(value):
    return isinstance(value, str) and len(value) == 64 and all(char in '0123456789abcdef' for char in value)


def _metrics(value):
    if not isinstance(value, dict): raise ValueError('V4_R4_COLLECTION_METRICS')
    return {key: value[key] for key in METRIC_FIELDS if key in value and _scalar(value[key])}


def _memory(value):
    if not isinstance(value, dict): raise ValueError('V4_R4_COLLECTION_MEMORY')
    result = {key: value[key] for key in MEMORY_FIELDS if key in value and _scalar(value[key])}
    policy = value.get('memory_policy')
    if isinstance(policy, dict):
        result['memory_policy'] = {key: policy[key] for key in MEMORY_POLICY_FIELDS if key in policy and _scalar(policy[key])}
    return result


def _top(value):
    if not isinstance(value, dict): raise ValueError('V4_R4_COLLECTION_TOP')
    result = {key: value[key] for key in TOP_SCALARS if key in value and _scalar(value[key])}
    for name in ('all_18_descriptive_joint', 'nonexhaustive_descriptive_joint'):
        if isinstance(value.get(name), dict): result[name] = _metrics(value[name])
    reviewed = value.get('reviewed_sources')
    if isinstance(reviewed, dict):
        result['reviewed_sources'] = {key: sha for key, sha in reviewed.items()
                                     if key in REVIEWED_FILES and isinstance(sha, str) and len(sha) == 64}
    return result


def _project(key, value):
    if key.endswith('/evaluation.json'):
        return {field: (_metrics(value[field]) if field == 'metrics' else _memory(value[field]) if field == 'memory_guard' else value[field])
                for field in EVALUATION_FIELDS}
    if key.endswith('/worker_receipt.json'):
        return {field: value[field] for field in WORKER_FIELDS if field in value and _scalar(value[field])}
    return _memory(value) if key.endswith('.memory.json') else _top(value)


def collect():
    root = ROOT; _reject_symlink(root)
    output = root / OUTPUT_NAME
    if output.exists() or output.is_symlink(): raise FileExistsError('V4_R4_COLLECTION_CREATE_ONCE')
    paths, evaluations = _paths(root); records, total = {}, 0
    for path in paths:
        item, total = _read(path, total); key = path.relative_to(root).as_posix()
        if key in records: raise ValueError('V4_R4_COLLECTION_DUPLICATE_PATH')
        records[key] = item
    _validate(root, records, evaluations)
    projected = {key: {'sha256': item['sha256'], 'bytes': item['bytes'], 'data': _project(key, item['data'])}
                 for key, item in records.items()}
    result = {'schema_version': 'ranking-v4-r4-small-results-v1',
              'scope': 'SMALL_RESULT_ONLY_NO_REQUEST_CHECKPOINT_LABEL_GRAPH_EXPORT',
              'root': str(root), 'entry_count': len(projected), 'raw_bytes': total, 'records': projected}
    raw = (json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
    if len(raw) > MAX_SERIALIZED_BYTES: raise ValueError('V4_R4_COLLECTION_SERIALIZED_BOUND')
    with output.open('xb') as stream: stream.write(raw)
    return {'entry_count': len(projected), 'bytes': len(raw), 'sha256': _sha(raw)}


if __name__ == '__main__': print(json.dumps(collect(), sort_keys=True))
