"""Sequential, memory-guarded v4 TRAIN-only fold execution driver."""
import argparse
import json
import math
import os
from pathlib import Path
import re
import sys

from src.data.ranking_v3_real_fold_package import RealFoldReader, _read_json_once, _write_once
from src.models.ranking_v3_freeze_io import read_freeze
from src.models.ranking_v4_real_worker import (MODEL, PACKAGE_SHA256, SOURCE_SHA256,
                                                check_release, file_sha, verify_reviewed_sources)
from src.models.runtime_ranking_v3 import FAMILIES, Fold, digest, freeze_ranking, replay_frozen
from src.models.run_runtime_ranking_v3 import SEEDS

EXPECTED_ACTIONS = 1706
SCOPE = 'TRAIN_ONLY_REAL_SIX_FOLD_V4'


def _valid_destination_value(value):
    return re.fullmatch(r'/ssd/cjc/gnn_model_ranking_v4_train_[^/]+/experiment', value) is not None


def validate_destination(output):
    output = Path(output)
    if '..' in output.parts:
        raise ValueError('V4_EXPERIMENT_NEW_B_ROOT_REQUIRED')
    value = str(output.resolve()).replace('\\', '/')
    if not _valid_destination_value(value):
        raise ValueError('V4_EXPERIMENT_NEW_B_ROOT_REQUIRED')


def experiment_output(root):
    """The only accepted experiment child for a v4 TRAIN root."""
    return Path(root) / 'experiment'


def integer_cycles(value):
    if isinstance(value, bool):
        raise ValueError('V4_EXPERIMENT_FIT_CYCLES')
    if type(value) is int:
        result = value
    elif type(value) is float and math.isfinite(value) and value.is_integer():
        result = int(value)
    else:
        raise ValueError('V4_EXPERIMENT_FIT_CYCLES')
    if result <= 0 or result > 2 ** 53:
        raise ValueError('V4_EXPERIMENT_FIT_CYCLES')
    return result


def validate_worker_receipt(worker, request, request_sha):
    if (any(worker.get(key) != request[key] for key in ('source_sha256', 'family', 'seed', 'model')) or
            worker.get('request_sha256') != request_sha or
            worker.get('canonical_request_sha256') != digest(request) or
            worker.get('held_labels_supplied') is not False):
        raise ValueError('V4_EXPERIMENT_WORKER_BINDING')


def _summary(records):
    expected = {(family, seed) for family in FAMILIES.values() for seed in SEEDS}
    if len(records) != 18 or {(record.get('family'), record.get('seed')) for record in records} != expected:
        raise ValueError('V4_EXPERIMENT_GRID')
    fields = ('hit_at_10', 'best_cycle_regret_at_10', 'charged_runtime_s', 'attempt_count')
    nonexhaustive = [record for record in records if len(record['freeze']['order']) > 10]
    if len(nonexhaustive) != 15:
        raise ValueError('V4_EXPERIMENT_NONEXHAUSTIVE_GRID')
    def mean(items): return {field: sum(item['metrics'][field] for item in items) / len(items) for field in fields}
    return {'scope': SCOPE, 'model': MODEL, 'receipt_count': 18,
            'all_18_descriptive_joint': mean(records), 'nonexhaustive_descriptive_joint': mean(nonexhaustive),
            'nonexhaustive_count': len(nonexhaustive)}


def run(package, package_sha, release_path, release_sha, output):
    release = _read_json_once(Path(release_path), release_sha, 'V4_EXPERIMENT_RELEASE_SHA')
    receipt = _read_json_once(Path(package) / 'receipt.json', package_sha, 'V4_EXPERIMENT_PACKAGE_SHA')
    if package_sha != PACKAGE_SHA256 or receipt.get('source_sha256') != SOURCE_SHA256:
        raise ValueError('V4_EXPERIMENT_PACKAGE_BINDING')
    check_release(release, SOURCE_SHA256); verify_reviewed_sources(release)
    package, output = Path(package), Path(output)
    if any(path.is_symlink() for path in (package, output, *package.parents, *output.parents)):
        raise ValueError('V4_EXPERIMENT_SYMLINK')
    validate_destination(output)
    if (receipt.get('train_action_count') != EXPECTED_ACTIONS or receipt.get('train_outcome_count') != EXPECTED_ACTIONS or
            set(receipt.get('fold_manifest_sha256', {})) != set(FAMILIES.values())):
        raise ValueError('V4_EXPERIMENT_ROSTER')
    output.mkdir(exist_ok=False)
    records = []
    for family, manifest_sha in sorted(receipt['fold_manifest_sha256'].items()):
        root = package / ('fold_' + family)
        manifest = _read_json_once(root / 'manifest.json', manifest_sha, 'V4_EXPERIMENT_FOLD_SHA')
        fold = Fold(family, tuple(manifest['fitting']), tuple(manifest['heldout']))
        reader = RealFoldReader(root, manifest_sha, fold)
        if reader.manifest.get('source_sha256') != SOURCE_SHA256:
            raise ValueError('V4_EXPERIMENT_FOLD_SOURCE')
        rows, fitting = reader.feature_rows(), reader.fitting(fold.fitting)
        worker_rows = [{field: row[field] for field in ('action_uid', 'circuit', 'family', 'role',
                                                         'scheme_hf', 'scheme_hmf', 'log1p_h_limit',
                                                         'log1p_m_limit', 'h_limit_fraction_of_circuit_max',
                                                         'm_limit_fraction_of_circuit_max', 'log1p_common_fault_count')}
                       for row in rows]
        for seed in SEEDS:
            token = family + '_' + str(seed) + '_' + MODEL
            request = {'scope': 'REAL_TRAIN_ONLY_V4_WORKER', 'source_sha256': SOURCE_SHA256,
                       'family': family, 'seed': seed, 'model': MODEL, 'rows': worker_rows,
                       'fit_cycles': {uid: integer_cycles(fitting[uid]['total_cycles']) for uid in fold.fitting}}
            request_path = output / (token + '_request.json'); _write_once(request_path, request)
            request_sha = file_sha(request_path); worker_dir = output / token; log = output / (token + '.log')
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', OMP_NUM_THREADS='1',
                       MKL_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', NUMEXPR_NUM_THREADS='1')
            env.pop('PYTHONPATH', None)
            from src.models.ranking_v4_memory_guard import run_bounded
            guard_metrics = run_bounded([sys.executable, '-m', 'src.models.ranking_v4_real_worker', '--request', str(request_path),
                                         '--request-sha256', request_sha, '--release', str(release_path),
                                         '--release-sha256', release_sha, '--output', str(worker_dir)], log, env)
            worker = json.loads((worker_dir / 'worker_receipt.json').read_bytes())
            validate_worker_receipt(worker, request, request_sha)
            freeze = read_freeze(worker_dir / 'freeze.json', worker['freeze_sha256'])
            expected, sha = freeze_ranking(freeze['scores'], fold)
            if freeze != expected or sha != worker['freeze_sha256']:
                raise ValueError('V4_EXPERIMENT_FREEZE')
            outcomes = reader.heldout(fold.heldout, worker_dir / 'freeze.json', sha)
            record = {'scope': SCOPE, 'source_sha256': SOURCE_SHA256, 'model': MODEL, 'family': family,
                      'seed': seed, 'freeze': freeze, 'freeze_sha256': sha,
                      'pair_recipe_sha256': worker['pair_recipe_sha256'],
                      'memory_guard': guard_metrics,
                      'metrics': replay_frozen(freeze, sha, fold, outcomes)}
            _write_once(worker_dir / 'evaluation.json', record); records.append(record)
    summary = _summary(records); _write_once(output / 'summary.json', summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser()
    for name in ('package', 'package-sha256', 'release', 'release-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(run(args.package, args.package_sha256, args.release, args.release_sha256, args.output), sort_keys=True))


if __name__ == '__main__':
    main()
