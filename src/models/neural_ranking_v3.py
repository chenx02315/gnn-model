"""Neural fit/predict adapters; no imports or training at module import time."""
from src.models.runtime_ranking_v3 import (make_candidate_ranker,make_graph_ranker,
                                         torch_pairwise_loss,finite)

def fit_neural(torch,np,prepared,seed,*,graphs=None,uid_graph_keys=None):
    from src.models.runtime_training_v2 import seed_everything
    if seed not in (20260824,20260825,20260826): raise ValueError('NEURAL_SEED')
    seed_everything(seed,torch,np)
    uids=prepared['fit_uids']; index={u:i for i,u in enumerate(uids)}
    if set(uids)!=set(prepared['targets']): raise ValueError('NEURAL_FIT_JOIN')
    x=torch.tensor(prepared['fit_features'],dtype=torch.float32,device='cpu')
    graph_keys=None; fit_graphs=None
    if graphs is None:
        if uid_graph_keys is not None: raise ValueError('UNEXPECTED_GRAPH_KEYS')
        model=make_candidate_ranker(torch)
    else:
        if uid_graph_keys is None or set(uid_graph_keys)!=set(uids): raise ValueError('FIT_GRAPH_UID_SET')
        graph_keys=[uid_graph_keys[u] for u in uids]
        fit_graphs={k:graphs[k] for k in sorted(set(graph_keys))}
        if any(node.device.type!='cpu' or edge.device.type!='cpu' for node,edge in fit_graphs.values()):
            raise ValueError('CPU_ONLY')
        model=make_graph_ranker(torch)
    optimizer=torch.optim.Adam(model.parameters(),lr=.001,weight_decay=.0001)
    model.train()
    for _ in range(120):
        optimizer.zero_grad()
        scores=model(x) if fit_graphs is None else model(fit_graphs,graph_keys,x)
        loss=torch_pairwise_loss(scores,index,prepared['pairs'],torch)
        if not torch.isfinite(loss).item(): raise ValueError('NONFINITE_LOSS')
        loss.backward(); optimizer.step()
    model.eval()
    return model

def predict_neural(torch,model,uids,matrix,*,graphs=None,uid_graph_keys=None):
    if len(uids)!=len(matrix) or len(set(uids))!=len(uids): raise ValueError('PREDICT_SHAPE')
    x=torch.tensor(matrix,dtype=torch.float32,device='cpu')
    model.eval()
    with torch.no_grad():
        if graphs is None: scores=model(x)
        else:
            if uid_graph_keys is None or set(uid_graph_keys)!=set(uids): raise ValueError('PREDICT_GRAPH_UID_SET')
            keys=[uid_graph_keys[u] for u in uids]
            selected={k:graphs[k] for k in sorted(set(keys))}
            scores=model(selected,keys,x)
    return {u:finite(value) for u,value in zip(uids,scores.tolist())}
