"""Explicit generated-data torch gate. Missing torch FAILS; no optimizer/training."""
import json
import math
from src.models.ranking_v5_head_objective import build_recipe, loss_reference, torch_loss


def verify(torch):
    torch.set_num_threads(1)
    rows=[{'action_uid':'p','family':'fit','total_cycles':100}]
    rows += [{'action_uid':f'n{i:02}','family':'fit','total_cycles':110} for i in range(10)]
    recipe=build_recipe(rows,heldout_family='held')
    uids=['p']+[f'n{i:02}' for i in range(10)]
    index={u:i for i,u in enumerate(uids)}
    values=[0.]+[float(i+1) for i in range(10)]
    x=torch.tensor(values,dtype=torch.float64,requires_grad=True)
    loss=torch_loss(x,index,recipe,torch)
    expected=loss_reference(dict(zip(uids,values)),recipe)
    if not math.isclose(loss.item(),expected,rel_tol=1e-12,abs_tol=1e-12):
        raise ValueError('HEAD_TORCH_REFERENCE_MISMATCH')
    gradient=torch.autograd.grad(loss,x)[0].tolist()
    magnitude=1/(1+math.exp(-1.))
    want=[-magnitude,magnitude]+[0.]*9
    if any(not math.isclose(g,w,rel_tol=1e-12,abs_tol=1e-12) for g,w in zip(gradient,want)):
        raise ValueError('HEAD_TORCH_GRADIENT_DIRECTION')
    small=build_recipe(rows[:-1],heldout_family='held')
    y=torch.tensor(values[:-1],dtype=torch.float64,requires_grad=True)
    zero=torch_loss(y,{u:i for i,u in enumerate(uids[:-1])},small,torch)
    if zero.item()!=0 or any(v!=0 for v in torch.autograd.grad(zero,y)[0].tolist()):
        raise ValueError('HEAD_TORCH_GUARANTEED_SIGNAL')
    return {'status':'PASS_GENERATED_TORCH_HEAD_GATE','generated_data_only':True,
            'forward_reference_match':True,'active_boundary_gradient_match':True,
            'guaranteed_hit_zero_signal':True,'optimizer_steps':0,'new_fits':0,
            'torch_version':torch.__version__,'device':'cpu','threads':1}


if __name__=='__main__':
    import torch  # No skip or substitute when prerequisite unavailable.
    print(json.dumps(verify(torch),sort_keys=True))
