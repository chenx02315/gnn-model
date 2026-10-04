"""TRAIN-only production fold execution; never relax the synthetic runner gate."""
import re
from src.models.ranking_v3_freeze_io import persist_freeze, read_freeze
from src.models.runtime_ranking_v3 import (
    FAMILIES, digest, feature_matrix, finite, freeze_ranking, plan_folds,
    prepare_fold, replay_frozen, transform)
from src.models.run_runtime_ranking_v3 import SEEDS

SCOPE = 'TRAIN_ONLY_REAL_SIX_FOLD_V3'
MODELS = ('candidate_mlp', 'graphsage', 'xgboost', 'fixed_heuristic')

def check_release(release, source_sha256):
    if (not isinstance(release, dict)
        or release.get('status') != 'PASS_TRAIN_ONLY_EXECUTION_RELEASE'
        or release.get('independent_review_pass') is not True
        or release.get('data_gate_pass') is not True
        or release.get('roles') != ['TRAIN']
        or not isinstance(source_sha256, str)
        or re.fullmatch('[0-9a-f]{64}', source_sha256) is None
        or release.get('source_sha256') != source_sha256):
        raise ValueError('REAL_EXECUTION_RELEASE_REQUIRED')

def run_real_fold(reader, fold, seed, model_kind, fit, predict, freeze_path,
                  *, release=None, source_sha256=None):
    # Validate release before reader or any caller-provided callback is invoked.
    check_release(release, source_sha256)
    if seed not in SEEDS or model_kind not in MODELS:
        raise ValueError('FROZEN_REAL_PROTOCOL')
    if reader.manifest['source_sha256'] != source_sha256:
        raise ValueError('REAL_READER_SOURCE_BINDING')
    rows = reader.feature_rows()
    if fold not in plan_folds(rows):
        raise ValueError('FORGED_REAL_FOLD')
    prepared = prepare_fold(rows, reader.fitting(fold.fitting), fold, seed)
    model = fit(prepared, seed)
    held = sorted((r for r in rows if r['action_uid'] in set(fold.heldout)),
                  key=lambda r: r['action_uid'])
    scores = predict(model, tuple(r['action_uid'] for r in held),
                     transform(feature_matrix(held), prepared['normalizer']))
    payload, sha = freeze_ranking(scores, fold)
    if persist_freeze(freeze_path, payload, sha) != sha or digest(payload) != sha:
        raise ValueError('REAL_FREEZE_ACK_REQUIRED')
    if read_freeze(freeze_path, sha) != payload:
        raise ValueError('REAL_FREEZE_READBACK_REQUIRED')
    metrics = replay_frozen(payload, sha, fold, reader.heldout(fold.heldout, freeze_path, sha))
    return {'scope': SCOPE, 'source_sha256': source_sha256,
            'model': model_kind, 'family': fold.family, 'seed': seed,
            'freeze': payload, 'freeze_sha256': sha,
            'pair_sha256': digest(prepared['pairs']), 'metrics': metrics}

def aggregate_real(receipts, model_kind, *, release=None, source_sha256=None):
    check_release(release, source_sha256)
    expected = {(f, s) for f in FAMILIES.values() for s in SEEDS}
    if (model_kind not in MODELS or len(receipts) != 18
        or {(r['family'], r['seed']) for r in receipts} != expected):
        raise ValueError('REAL_COMPLETE_GRID_REQUIRED')
    for record in receipts:
        if (record['scope'] != SCOPE or record['model'] != model_kind
            or record['source_sha256'] != source_sha256
            or record['freeze']['family'] != record['family']
            or record['freeze']['epsilon'] != .01 or record['freeze']['top_k'] != 10
            or digest(record['freeze']) != record['freeze_sha256']
            or record['metrics']['freeze_sha256'] != record['freeze_sha256']):
            raise ValueError('REAL_RECEIPT_BINDING')
    fields = ('hit_at_10', 'best_cycle_regret_at_10', 'charged_runtime_s', 'attempt_count')
    return {'scope': SCOPE, 'model': model_kind, 'source_sha256': source_sha256,
            'receipt_count': 18, 'seed_selection': False,
            'family_seed_macro': {f: sum(finite(r['metrics'][f]) for r in receipts) / 18
                                  for f in fields},
            'interpretation': 'Report hit and charged attempt cost together; no-hit lower cost is not faster near-optimal attainment.'}
