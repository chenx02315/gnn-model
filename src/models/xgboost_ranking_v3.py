"""Non-graph XGBRanker adapter. Imports/fit are deferred, not used by CLI.

XGBoost generates its own pairs. This is a protocol baseline, not an identical
loss/sampler ablation of the neural rankers. Relevance and group weights are
derived solely from fitting targets.
"""
from src.models.runtime_ranking_v3 import FEATURES,FAMILIES,finite

CONFIG={'objective':'rank:pairwise','n_estimators':300,'max_depth':4,
        'learning_rate':.03,'subsample':1.0,'colsample_bytree':1.0,
        'n_jobs':1,'tree_method':'hist'}

def pack_groups(rows,targets,normalizer):
    from src.models.runtime_ranking_v3 import feature_matrix,transform
    if set(targets)!={r['action_uid'] for r in rows} or len(rows)!=len(targets):
        raise ValueError('XGB_FITTING_JOIN')
    grouped={}
    for r in rows:
        if r['role']!='TRAIN' or FAMILIES.get(r['circuit'])!=r['family']:
            raise ValueError('XGB_FITTING_ROLE')
        grouped.setdefault(r['family'],[]).append(r)
    ordered=[]; labels=[]; sizes=[]
    for family,group in sorted(grouped.items()):
        group=sorted(group,key=lambda r:r['action_uid'])
        values=sorted({finite(targets[r['action_uid']]) for r in group},reverse=True)
        # Nonnegative integer relevance; lower log regret gives higher relevance.
        relevance={value:i for i,value in enumerate(values)}
        ordered.extend(group); sizes.append(len(group))
        labels.extend(relevance[finite(targets[r['action_uid']])] for r in group)
    return {'x':transform(feature_matrix(ordered),normalizer),'y':labels,
            'group':sizes,'sample_weight':[1.0]*len(sizes),
            'uids':[r['action_uid'] for r in ordered],
            'features':FEATURES,'families':sorted(grouped)}

def make_ranker(xgb,seed):
    if seed not in (20260824,20260825,20260826):
        raise ValueError('XGB_SEED')
    return xgb.XGBRanker(**CONFIG,random_state=seed)

def fit_ranker(xgb,np,packed,seed):
    model=make_ranker(xgb,seed)
    model.fit(np.asarray(packed['x'],dtype=float),np.asarray(packed['y'],dtype=float),
              group=packed['group'],sample_weight=packed['sample_weight'],verbose=False)
    return model
