"""Local evidence-only objective/context audit. No model, torch, or remote access."""
import ast
import hashlib
import json
from pathlib import Path

from scripts.ranking_v4_near_optimal_pairs import PAIR_CAP_PER_FAMILY, family_macro_pairwise_softplus
from src.models.runtime_ranking_v3 import FEATURES
from scripts.summarize_ranking_v4_r4_diagnostic import verify_model_identity, AUDIT

ROOT = Path(__file__).resolve().parents[1]
INPUTS = {
    'data/manifests/ranking_v3_train_feature_diagnostic_20261005.json': '4d875e54703d6ff3101357fe8325eb61238d7695823c8c10ef3c28fb82bef317',
    'data/manifests/ranking_v4_r4_fit_transfer_diagnostic_20261006.json': '0f5a5de2a5680e9a5ae14f416e18d54838236a727c4667769e1845aea5874f50',
}


def read_pinned(path, sha, bound=200*1024):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('AUDIT_SYMLINK')
    with path.open('rb') as stream:
        raw = stream.read(bound + 1)
    if len(raw) > bound or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('AUDIT_BOUND_OR_SHA')
    return json.loads(raw.decode('utf-8-sig'))


def objective_counterexample():
    # One positive, 100 negatives. This is synthetic arithmetic, NOT a model fit.
    pairs = [{'positive_uid': 'p', 'negative_uid': 'n'+str(i)} for i in range(100)]
    recipe = {'families': {'toy': {'family_macro_weight': 1., 'pairs': pairs}}}
    hit = dict(p=0., **{'n'+str(i): -1. for i in range(100)})
    miss = dict(p=0., **{'n'+str(i): .01 if i < 10 else -10. for i in range(100)})
    def measure(scores):
        rank = 1 + sum(scores[n] > scores['p'] for n in scores if n != 'p')
        return {'first_positive_rank': rank, 'hit_at_10': int(rank <= 10),
                'pair_softplus': family_macro_pairwise_softplus(scores, recipe)}
    return {'role': 'SYNTHETIC_COUNTEREXAMPLE_NOT_TRAINING', 'hit': measure(hit), 'miss': measure(miss)}


def source_checks(root):
    historical = json.loads((root / 'data/manifests/ranking_v4_r4_independent_review_20261005.json').read_bytes())
    names = ('scripts/ranking_v4_near_optimal_pairs.py', 'src/models/runtime_ranking_v3.py',
             'src/models/neural_ranking_v3.py', 'src/models/ranking_v4_training_worker.py',
             'src/models/ranking_v4_real_worker.py')
    hashes = {}
    for name in names:
        raw = (root / name).read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        if sha != historical['reviewed_sources'][name]:
            raise ValueError('AUDIT_HISTORICAL_SOURCE_DRIFT:' + name)
        hashes[name] = sha
    worker = ast.parse((root / names[-1]).read_text())
    execute = next(n for n in worker.body if isinstance(n, ast.FunctionDef) and n.name == 'execute')
    fits = [n for n in ast.walk(execute) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'fit_neural']
    if len(fits) != 1 or len(fits[0].args) != 4 or fits[0].keywords:
        raise ValueError('AUDIT_REAL_FIT_CALL_CHANGED')
    # Actual fit call has no graphs/uid_graph_keys; default branch is candidate MLP.
    kernel = ast.parse((root / names[1]).read_text())
    loss = next(n for n in kernel.body if isinstance(n, ast.FunctionDef) and n.name == 'torch_pairwise_loss')
    args = [arg.arg for arg in loss.args.args]
    if args != ['scores', 'index', 'pairs', 'torch']:
        raise ValueError('AUDIT_OBJECTIVE_CHANGED')
    return {'historical_source_sha256': hashes, 'real_fit_call_has_graph_arguments': False,
            'objective_arguments': args, 'runtime_cost_in_objective': False,
            'features': list(FEATURES), 'graph_signal_sufficiency': 'UNTESTED_NOT_IN_R4_INPUT'}


def audit(root=ROOT):
    objects = {name: read_pinned(root/name, sha) for name, sha in INPUTS.items()}
    counts, summary = objects.values()
    raw = read_pinned(root.parent/'runtime_training_staging_20260928/r4_fit_transfer_20261006_r1.json',
                      'd4c10136f72d2bd58004b3aa2354c8aba9a793394d133dab0041b9221b1d63c3')
    verify_model_identity(raw, (root/AUDIT).read_bytes())
    family_rows = []
    for family, data in sorted(counts['families'].items()):
        a, p = data['actions'], data['near_optimal']
        if not 0 < p < a:
            raise ValueError('AUDIT_CLASS_COVERAGE')
        pairs = p*(a-p)
        groups = [g for r in raw['results'] for g in r['fitting_families'] if g['fitting_family'] == family]
        if len(groups) != 15 or any((g['actions'],g['positive_count'],g['all_positive_negative_pair_count']) != (a,p,pairs) for g in groups):
            raise ValueError('AUDIT_FIT_COUNT_JOIN')
        old = next(r for r in summary['family_rows'] if r['family'] == family)
        family_rows.append({'family': family, 'actions': a, 'positives': p,
            'positive_fraction': p/a, 'all_pairs': pairs, 'selected_pairs': min(pairs,PAIR_CAP_PER_FAMILY),
            'all_pairs_covered': pairs <= PAIR_CAP_PER_FAMILY,
            'family_weight_per_fitting_fold': .2,
            'fit_hits': old['fit_hits_at_10'], 'fit_observations': 15,
            'first_positive_rank_min': min(old['fit_first_positive_ranks']),
            'first_positive_rank_max': max(old['fit_first_positive_ranks'])})
    checks = source_checks(root)
    toy = objective_counterexample()
    if not toy['miss']['pair_softplus'] < toy['hit']['pair_softplus']:
        raise ValueError('AUDIT_COUNTEREXAMPLE')
    return {'status': 'PASS_LOCAL_OBJECTIVE_CONTEXT_AUDIT_WITH_CAVEATS', 'as_of': '2026-10-07',
        'inputs_sha256': INPUTS, 'families': family_rows, 'source_checks': checks,
        'counterexample': toy, 'new_training_runs': 0, 'remote_access': False,
        'conclusions': ['No positive-negative pair truncation in any existing family.',
            'Pair-mean surrogate can improve while top-10 first-hit worsens; not causal proof for r4.',
            'r4 has no graph context and no runtime cost objective; scalar scale proxies still carry circuit information.',
            'Additional context sufficiency, convergence, and causal failure mechanism remain untested.'],
        'next_boundary': 'No new training, tuning, BLIND or circuit measurement release.'}


if __name__ == '__main__':
    print(json.dumps(audit(), ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False))
