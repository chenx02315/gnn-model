"""Design-stage ranking kernels. No training CLI, remote access or BLIND loader."""
import hashlib
import heapq
import json
import math
from dataclasses import dataclass

FEATURES = ('scheme_hf','scheme_hmf','log1p_h_limit','log1p_m_limit',
            'h_limit_fraction_of_circuit_max','m_limit_fraction_of_circuit_max',
            'log1p_common_fault_count')
FAMILIES = {'aes_core':'iwls_aes_core','s13207':'iscas89_s13207',
            's15850':'iscas89_s15850','s35932':'iscas89_s35932',
            's38417':'iscas89_s38417','spi':'iwls_spi'}

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def finite(value, positive=False):
    value=float(value)
    if not math.isfinite(value) or (positive and value<=0):
        raise ValueError('NONFINITE_OR_NONPOSITIVE')
    return value

def validate_metadata(rows):
    if not rows or len({r['action_uid'] for r in rows})!=len(rows):
        raise ValueError('ACTION_UNIQUE')
    for r in rows:
        if r['role']!='TRAIN' or FAMILIES.get(r['circuit'])!=r['family']:
            raise ValueError('TRAIN_ONLY_EXACT_FAMILY')
    if {r['circuit'] for r in rows}!=set(FAMILIES):
        raise ValueError('SIX_TRAIN_FAMILIES_REQUIRED')

@dataclass(frozen=True)
class Fold:
    family: str
    fitting: tuple
    heldout: tuple

def plan_folds(rows):
    validate_metadata(rows)
    return tuple(Fold(f,tuple(sorted(r['action_uid'] for r in rows if r['family']!=f)),
                      tuple(sorted(r['action_uid'] for r in rows if r['family']==f)))
                 for f in sorted(FAMILIES.values()))

def feature_matrix(rows):
    """Allowlist projection: identifiers, predictions and outcomes never enter X."""
    return tuple(tuple(finite(r[f]) for f in FEATURES) for r in rows)

def fit_normalizer(matrix):
    if not matrix or any(len(r)!=len(FEATURES) for r in matrix):
        raise ValueError('FEATURE_SHAPE')
    columns=list(zip(*matrix))
    mean=tuple(sum(finite(v) for v in c)/len(c) for c in columns)
    std=tuple(max(math.sqrt(sum((finite(v)-m)**2 for v in c)/len(c)),1e-12)
              for c,m in zip(columns,mean))
    return mean,std

def transform(matrix, normalizer):
    mean,std=normalizer
    if len(mean)!=len(FEATURES) or len(std)!=len(FEATURES):
        raise ValueError('NORMALIZER_SHAPE')
    if any(len(r)!=len(FEATURES) for r in matrix):
        raise ValueError('FEATURE_SHAPE')
    return tuple(tuple((finite(v)-m)/s for v,m,s in zip(r,mean,std)) for r in matrix)

def fitting_targets(rows, outcomes, fold):
    """Reject rather than silently ignore held-out outcomes supplied to fitting."""
    if set(outcomes)!=set(fold.fitting):
        raise ValueError('FIT_OUTCOMES_EXACT_ONLY')
    fitting=sorted((r for r in rows if r['action_uid'] in set(fold.fitting)),key=lambda r:r['action_uid'])
    if len(fitting)!=len(fold.fitting) or any(r['family']==fold.family for r in fitting):
        raise ValueError('FOLD_MEMBERSHIP')
    oracle={}
    for r in fitting:
        o=outcomes[r['action_uid']]
        if o['execution_status']!='SUCCESS' or int(o['is_d95_feasible'])!=1:
            raise ValueError('SAFE_SUCCESS_REQUIRED')
        c=finite(o['total_cycles'],positive=True)
        finite(o['policy_charged_runtime_s'],positive=True)
        oracle[r['circuit']]=min(oracle.get(r['circuit'],c),c)
    return {r['action_uid']:math.log(finite(outcomes[r['action_uid']]['total_cycles'],True)/oracle[r['circuit']]) for r in fitting}

def prepare_fold(rows,outcomes,fold,seed):
    validate_metadata(rows)
    if fold not in plan_folds(rows):
        raise ValueError('FORGED_FOLD')
    fitting=sorted((r for r in rows if r['action_uid'] in set(fold.fitting)),key=lambda r:r['action_uid'])
    targets=fitting_targets(rows,outcomes,fold)
    normalizer=fit_normalizer(feature_matrix(fitting))
    return {'normalizer':normalizer,'targets':targets,
            'pairs':bounded_pairs(fitting,targets,seed),
            'fit_uids':tuple(r['action_uid'] for r in fitting),
            'fit_features':transform(feature_matrix(fitting),normalizer)}

def bounded_pairs(rows, targets, seed, cap=4096, tie_gap=1e-9):
    if seed not in (20260824,20260825,20260826) or cap!=4096 or tie_gap!=1e-9:
        raise ValueError('FROZEN_PAIR_PROTOCOL')
    fitting=[r for r in rows if r['action_uid'] in targets]
    if len(fitting)!=len(targets):
        raise ValueError('PAIR_TARGET_JOIN')
    groups={}
    for r in fitting:
        if r['role']!='TRAIN' or FAMILIES.get(r['circuit'])!=r['family']:
            raise ValueError('PAIR_ROLE')
        groups.setdefault(r['circuit'],[]).append(r['action_uid'])
    result={}
    for circuit,uids in sorted(groups.items()):
        uids=sorted(uids)
        def stream():
            for i,a in enumerate(uids):
                for b in uids[i+1:]:
                    ta,tb=finite(targets[a]),finite(targets[b])
                    if abs(ta-tb)<=tie_gap:
                        continue
                    better,worse=(a,b) if ta<tb else (b,a)
                    yield digest([seed,circuit,better,worse]),better,worse
        pairs=heapq.nsmallest(cap,stream())
        if not pairs:
            raise ValueError('NO_INFORMATIVE_PAIRS:'+circuit)
        result[FAMILIES[circuit]]=tuple((b,w) for _,b,w in pairs)
    return result

def pairwise_loss(scores,pairs):
    """Reference objective, macro mean across families, stable softplus."""
    if not pairs or any(not p for p in pairs.values()):
        raise ValueError('EMPTY_PAIR_GROUP')
    total=0.0
    for group in pairs.values():
        losses=[]
        for better,worse in group:
            x=finite(scores[worse])-finite(scores[better])
            losses.append(max(x,0)+math.log1p(math.exp(-abs(x))))
        total+=sum(losses)/len(losses)
    return total/len(pairs)

def torch_pairwise_loss(scores,index,pairs,torch):
    if not pairs or any(not p for p in pairs.values()):
        raise ValueError('EMPTY_PAIR_GROUP')
    return torch.stack([torch.nn.functional.softplus(torch.stack(
        [scores[index[w]]-scores[index[b]] for b,w in group])).mean()
        for group in pairs.values()]).mean()

def make_candidate_ranker(torch):
    class Ranker(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.layers=torch.nn.Sequential(torch.nn.Linear(len(FEATURES),32),torch.nn.ReLU(),
                torch.nn.Linear(32,32),torch.nn.ReLU(),torch.nn.Linear(32,1))
        def forward(self,x):
            return self.layers(x).squeeze(1)
    return Ranker()

def make_graph_ranker(torch):
    """Reuse v2 encoder only, discard classification/cycles/runtime heads."""
    from src.models.runtime_training_v2 import make_graphsage_model
    encoder=make_graphsage_model(torch,81,len(FEATURES),{'graphsage':{
        'hidden_dim':32,'candidate_mlp_hidden':[32,32],'fusion_mlp_hidden':[64,32]}})
    class Ranker(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.sage1,self.sage2=encoder.sage1,encoder.sage2
            self.candidate_encoder,self.shared=encoder.candidate_encoder,encoder.shared
            self.quality=torch.nn.Linear(32,1)
        def forward(self,graphs,graph_keys,x):
            embeddings={}
            for key,(nodes,edges) in graphs.items():
                nodes=torch.relu(self.sage1(nodes,edges))
                embeddings[key]=torch.relu(self.sage2(nodes,edges)).mean(dim=0)
            graph_x=torch.stack([embeddings[k] for k in graph_keys])
            return self.quality(self.shared(torch.cat([graph_x,self.candidate_encoder(x)],dim=1))).squeeze(1)
    return Ranker()

def freeze_ranking(scores,fold):
    if set(scores)!=set(fold.heldout):
        raise ValueError('HELDOUT_PREDICTIONS_EXACT')
    order=sorted(scores,key=lambda uid:(-finite(scores[uid]),uid))
    payload={'family':fold.family,'fitting_uids_sha256':digest(fold.fitting),
             'heldout_uids_sha256':digest(fold.heldout),'scores':{u:finite(scores[u]) for u in sorted(scores)},
             'order':order,'epsilon':.01,'top_k':10}
    return payload,digest(payload)

def replay_frozen(payload,freeze_sha,fold,outcomes):
    expected,sha=freeze_ranking(payload['scores'],fold)
    if payload!=expected or freeze_sha!=sha or set(outcomes)!=set(fold.heldout):
        raise ValueError('FREEZE_OR_HELDOUT_JOIN')
    for o in outcomes.values():
        if o['execution_status']!='SUCCESS' or int(o['is_d95_feasible'])!=1:
            raise ValueError('SAFE_SUCCESS_REQUIRED')
        finite(o['total_cycles'],True); finite(o['policy_charged_runtime_s'],True)
    oracle=min(finite(o['total_cycles'],True) for o in outcomes.values())
    selected=payload['order'][:10]
    cost=0.0; hit=False; attempted=[]
    for uid in selected:
        attempted.append(uid)
        cost+=finite(outcomes[uid]['policy_charged_runtime_s'],True)
        if finite(outcomes[uid]['total_cycles'],True)<=1.01*oracle:
            hit=True
            break
    return {'hit_at_10':int(hit),'hit_found':hit,'attempt_count':len(attempted),
            'charged_runtime_s':cost,'best_cycle_regret_at_10':min(finite(outcomes[u]['total_cycles'],True)/oracle-1 for u in selected),
            'freeze_sha256':freeze_sha}
