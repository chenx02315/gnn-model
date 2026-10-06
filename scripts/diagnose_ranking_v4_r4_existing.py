"""Read-only inference on existing r4 TRAIN weights; no fitting or held labels."""
import hashlib
import io
import json
import math
from pathlib import Path
import sys

ROOT = Path('/ssd/cjc/gnn_model_ranking_v4_train_af05de0_20261005_r4')
CODE = Path('/ssd/cjc/gnn_model_ranking_v4_exit_boundary_ml_fe67d2d_20261005_r1/code')
PACKAGE = Path('/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds')
RELEASE_SHA = 'ad5dd0e57459ee74ba018aebe72bc8e6f9f95dcc63cf8ce44941f167813e96cb'
EXIT_SHA = 'fd2454fa90c611b1e2ce91d0d5448c86ee2930a2d697dd46b6422a9e82851b26'
PACKAGE_SHA = '964703dc441fea95c3b1b301dfd6dd01a2cf38f817d82597ff00450287e43868'
MAX_FILE = 2 * 1024 * 1024
RSS_CAP = 1024 ** 3


def read_raw(path, expected=None):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('DIAGNOSTIC_SYMLINK')
    with path.open('rb') as stream:
        raw = stream.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise ValueError('DIAGNOSTIC_FILE_BOUND')
    sha = hashlib.sha256(raw).hexdigest()
    if expected is not None and sha != expected:
        raise ValueError('DIAGNOSTIC_INPUT_SHA:' + path.name)
    return raw, sha


def read_json(path, expected=None):
    raw, sha = read_raw(path, expected)
    return json.loads(raw), sha


def fitting_metrics(rows, cycles, scores, recipe):
    """Macro-fit quality, all positive/negative pairs, no held labels."""
    result = []
    for family, group in sorted(recipe['families'].items()):
        uids = [r['action_uid'] for r in rows if r['family'] == family]
        oracle = min(cycles[u] for u in uids)
        positive = [u for u in uids if 100 * cycles[u] <= 101 * oracle]
        negative = [u for u in uids if 100 * cycles[u] > 101 * oracle]
        if not positive or not negative or not set(uids) <= set(scores):
            raise ValueError('DIAGNOSTIC_FIT_CLASSES')
        if any(not math.isfinite(scores[u]) for u in uids):
            raise ValueError('DIAGNOSTIC_NONFINITE_SCORE')
        margins = [scores[p] - scores[n] for p in positive for n in negative]
        order = sorted(uids, key=lambda u: (-scores[u], u))
        rank = min(order.index(u) + 1 for u in positive)
        selected = [scores[p['positive_uid']] - scores[p['negative_uid']] for p in group['pairs']]
        result.append({'fitting_family': family, 'actions': len(uids),
            'positive_count': len(positive), 'negative_count': len(negative),
            'all_positive_negative_pair_count': len(margins),
            'pair_accuracy_ties_half': sum(1 if m > 0 else .5 if m == 0 else 0 for m in margins) / len(margins),
            'mean_positive_negative_margin': sum(margins) / len(margins),
            'min_positive_negative_margin': min(margins),
            'selected_pair_softplus_mean': sum(max(-m, 0) + math.log1p(math.exp(-abs(m))) for m in selected) / len(selected),
            'first_positive_rank': rank, 'fit_hit_at_10': int(rank <= 10),
            'best_fit_top10_regret': min(cycles[u] / oracle - 1 for u in order[:10])})
    return result


def range_metrics(fit, held, normalizer, feature_names):
    means, stds = normalizer
    result = []
    if not fit or not held:
        raise ValueError('DIAGNOSTIC_EMPTY_FEATURES')
    for i, name in enumerate(feature_names):
        a, b = [r[i] for r in fit], [r[i] for r in held]
        if any(not math.isfinite(v) for v in a + b):
            raise ValueError('DIAGNOSTIC_NONFINITE_FEATURE')
        outside = sum(v < min(a) or v > max(a) for v in b)
        result.append({'feature': name, 'fitting_min': min(a), 'fitting_max': max(a),
            'held_min': min(b), 'held_max': max(b), 'fitting_mean': means[i], 'fitting_std': stds[i],
            'held_count': len(b), 'outside_fitting_range_count': outside,
            'outside_fitting_range_fraction': outside / len(b),
            'max_abs_held_standardized': max(abs((v - means[i]) / stds[i]) for v in b)})
    return result


def check_rss():
    import resource
    # Linux ru_maxrss is KiB; peak enforcement is observed, not a hard RSS cap.
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    if peak > RSS_CAP:
        raise ValueError('DIAGNOSTIC_RSS_LIMIT')
    return peak


def run():
    if sys.platform != 'linux' or Path.cwd().resolve() != CODE:
        raise ValueError('DIAGNOSTIC_FIXED_LINUX_CWD')
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (8 * 1024 ** 3, 8 * 1024 ** 3))
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(CODE))
    release, _ = read_json(ROOT / 'execution_release.json', RELEASE_SHA)
    exit_receipt, _ = read_json(ROOT / 'exit_receipt.json', EXIT_SHA)
    if exit_receipt['exit_code'] != 0 or exit_receipt['retries'] != 0:
        raise ValueError('DIAGNOSTIC_INCOMPLETE_RUN')
    for name, sha in release['reviewed_sources'].items():
        read_raw(CODE / name, sha)
    from src.models.ranking_v4_real_worker import prepare_real_request
    from src.models.runtime_ranking_v3 import FEATURES, digest, feature_matrix, make_candidate_ranker, transform
    from src.models.neural_ranking_v3 import predict_neural
    from src.models.ranking_v3_freeze_io import read_freeze
    from src.models.preflight_runtime_v2 import parse_lock, validate_installed_dependencies
    validate_installed_dependencies(parse_lock(CODE / 'requirements/runtime_v2.lock.txt'))
    import torch
    torch.set_num_threads(1); torch.set_num_interop_threads(1)
    torch.use_deterministic_algorithms(True)
    check_rss()
    package, _ = read_json(PACKAGE / 'receipt.json', PACKAGE_SHA)
    results = []
    for family, manifest_sha in sorted(package['fold_manifest_sha256'].items()):
        manifest, _ = read_json(PACKAGE / ('fold_' + family) / 'manifest.json', manifest_sha)
        # Explicitly never read heldout_outcomes.json. Existing held metrics only.
        shardroot = PACKAGE / ('fold_' + family)
        physical_fit, _ = read_json(shardroot / 'fit_features.json', manifest['sha256']['fit_features.json'])
        physical_held, _ = read_json(shardroot / 'heldout_features.json', manifest['sha256']['heldout_features.json'])
        fit_outcomes, _ = read_json(shardroot / 'fit_outcomes.json', manifest['sha256']['fit_outcomes.json'])
        physical_rows = physical_fit + physical_held
        for seed in (20260824, 20260825, 20260826):
            token = family + '_' + str(seed) + '_candidate_mlp'
            target = ROOT / 'experiment' / token
            worker, worker_sha = read_json(target / 'worker_receipt.json')
            request, _ = read_json(ROOT / 'experiment' / (token + '_request.json'), worker['request_sha256'])
            if (digest(request) != worker['canonical_request_sha256'] or worker['held_labels_supplied'] is not False
                    or (worker['family'], worker['seed']) != (family, seed)):
                raise ValueError('DIAGNOSTIC_WORKER_BINDING')
            for r in physical_rows:
                expected = next(x for x in request['rows'] if x['action_uid'] == r['action_uid'])
                if any(expected[f] != r[f] for f in expected):
                    raise ValueError('DIAGNOSTIC_REQUEST_FEATURE_JOIN')
            if request['fit_cycles'] != {u: int(o['total_cycles']) for u, o in fit_outcomes.items()}:
                raise ValueError('DIAGNOSTIC_FIT_LABEL_JOIN')
            fold, prepared, held, packet = prepare_real_request(request)
            if (tuple(manifest['fitting']) != fold.fitting or tuple(manifest['heldout']) != fold.heldout
                    or packet['recipe_sha256'] != worker['pair_recipe_sha256']):
                raise ValueError('DIAGNOSTIC_RECIPE_JOIN')
            frozen = read_freeze(target / 'freeze.json', worker['freeze_sha256'])
            raw_model, model_sha = read_raw(target / 'model.pt')
            model = make_candidate_ranker(torch)
            model.load_state_dict(torch.load(io.BytesIO(raw_model), map_location='cpu', weights_only=True), strict=True)
            held_matrix = transform(feature_matrix(held), prepared['normalizer'])
            held_scores = predict_neural(torch, model, tuple(r['action_uid'] for r in held), held_matrix)
            if held_scores != frozen['scores']:
                raise ValueError('DIAGNOSTIC_MODEL_FREEZE_REPLAY')
            scores = predict_neural(torch, model, prepared['fit_uids'], prepared['fit_features'])
            fit_rows = [r for r in request['rows'] if r['action_uid'] in request['fit_cycles']]
            evaluation, eval_sha = read_json(target / 'evaluation.json')
            if (evaluation['freeze_sha256'] != worker['freeze_sha256'] or evaluation['family'] != family
                    or evaluation['seed'] != seed):
                raise ValueError('DIAGNOSTIC_EVAL_JOIN')
            results.append({'held_family': family, 'seed': seed, 'model_sha256': model_sha,
                'worker_sha256': worker_sha, 'evaluation_sha256': eval_sha,
                'request_sha256': worker['request_sha256'], 'freeze_sha256': worker['freeze_sha256'],
                'model_held_scores_exact': True,
                'fitting_families': fitting_metrics(fit_rows, request['fit_cycles'], scores, packet['recipe']),
                'feature_ranges': range_metrics(feature_matrix(fit_rows), feature_matrix(held), prepared['normalizer'], FEATURES),
                'existing_held_metrics': evaluation['metrics']})
            del model, scores, held_scores
            check_rss()
    if len(results) != 18:
        raise ValueError('DIAGNOSTIC_GRID')
    output = {'status': 'PASS_EXISTING_R4_READ_ONLY_DIAGNOSTIC', 'schema_version': 'r4-fit-transfer-diagnostic-v1',
        'role': 'TRAIN', 'new_fits': 0, 'optimizer_steps': 0, 'held_outcome_files_read': 0,
        'checkpoint_bytes_exported': 0, 'raw_labels_features_or_scores_exported': False,
        'release_sha256': RELEASE_SHA, 'package_sha256': PACKAGE_SHA,
        'peak_process_rss_bytes': check_rss(), 'threads': 1, 'workers': 1, 'retries': 0,
        'epoch_trajectory': 'UNAVAILABLE_NOT_PERSISTED_NO_REFIT', 'results': results}
    raw = json.dumps(output, sort_keys=True, allow_nan=False)
    if len(raw.encode()) > 200 * 1024:
        raise ValueError('DIAGNOSTIC_OUTPUT_BOUND')
    return raw


if __name__ == '__main__':
    print(run())
