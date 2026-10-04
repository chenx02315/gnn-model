"""Fold orchestration with injectable I/O; formal execution intentionally closed.

Callbacks make the order of label access auditable. This is not an OS sandbox;
physical fold packaging and an independently reviewed release remain required.
"""
from src.models.runtime_ranking_v3 import (
    digest,feature_matrix,finite,plan_folds,prepare_fold,transform,
    freeze_ranking,replay_frozen)

SEEDS=(20260824,20260825,20260826)

def run_fold(rows,fold,seed,load_fitting,fit,predict,persist_freeze,load_heldout,
             *,mode='formal',fixture_attestation=None):
    # No formal release mechanism is implemented in this design version.
    if mode!='synthetic' or fixture_attestation!='GENERATED_SYNTHETIC_NO_EXTERNAL_DATA':
        raise ValueError('FORMAL_EXECUTION_CLOSED')
    if seed not in SEEDS or fold not in plan_folds(rows):
        raise ValueError('FOLD_OR_SEED')
    prepared=prepare_fold(rows,load_fitting(fold.fitting),fold,seed)
    # Fit callback sees only five-family data and no held-out feature rows.
    model=fit(prepared,seed)
    held_rows=sorted((r for r in rows if r['action_uid'] in set(fold.heldout)),key=lambda r:r['action_uid'])
    x=transform(feature_matrix(held_rows),prepared['normalizer'])
    scores=predict(model,tuple(r['action_uid'] for r in held_rows),x)
    payload,sha=freeze_ranking(scores,fold)
    # I/O must acknowledge the exact persisted digest, not mere write success.
    if persist_freeze(payload,sha)!=sha or digest(payload)!=sha:
        raise ValueError('FREEZE_PERSISTENCE_NOT_ACKNOWLEDGED')
    result=replay_frozen(payload,sha,fold,load_heldout(fold.heldout,sha))
    return {'family':fold.family,'seed':seed,'freeze':payload,'freeze_sha256':sha,
            'pair_sha256':digest(prepared['pairs']),'metrics':result,
            'scope':'SYNTHETIC_ONLY_NO_FORMAL_TRAINING'}

def run_six_folds(rows,seed,**callbacks):
    return [run_fold(rows,fold,seed,**callbacks) for fold in plan_folds(rows)]

def aggregate_three_seeds(receipts):
    """Equal family/seed macro; scores are not averaged across unrelated folds."""
    from src.models.runtime_ranking_v3 import FAMILIES
    expected={(f,s) for f in FAMILIES.values() for s in SEEDS}
    keys=[(r['family'],r['seed']) for r in receipts]
    if len(keys)!=18 or set(keys)!=expected:
        raise ValueError('ALL_SIX_FAMILIES_THREE_SEEDS_REQUIRED')
    fields=('hit_at_10','best_cycle_regret_at_10','charged_runtime_s','attempt_count')
    for r in receipts:
        if digest(r['freeze'])!=r['freeze_sha256']:
            raise ValueError('AGGREGATE_FREEZE_SHA')
        if r['metrics']['freeze_sha256']!=r['freeze_sha256']:
            raise ValueError('AGGREGATE_METRIC_FREEZE_BINDING')
        if r['freeze']['family']!=r['family'] or r['freeze']['epsilon']!=.01 or r['freeze']['top_k']!=10:
            raise ValueError('AGGREGATE_PROTOCOL')
        if r['scope']!='SYNTHETIC_ONLY_NO_FORMAL_TRAINING':
            raise ValueError('AGGREGATE_SCOPE')
    return {'scope':'SYNTHETIC_ONLY_NO_FORMAL_TRAINING',
            'family_seed_macro':{f:sum(finite(r['metrics'][f]) for r in receipts)/18 for f in fields},
            'receipt_count':18,'seed_selection':False,'quality_scores_ensembled':False}

def main():
    raise SystemExit('FORMAL_EXECUTION_CLOSED: design-stage runner has no production CLI')

if __name__=='__main__': main()
