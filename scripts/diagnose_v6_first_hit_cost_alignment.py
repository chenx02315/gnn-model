"""E15 fixed E14 score-policy continuation arithmetic, never a model replay.

Synthetic additive known charges + one guaranteed positive; full continuation
is hypothetical evaluation of recorded PL policies, not an executed search.
"""
import hashlib
import itertools
import json
import math
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]/'runtime_training_staging_20260928/v6_synthetic_fit_no_prior_container_20261014_r1'
PIN='dc8d09347592c7cc7c84eeb28a38467f883bfe5faa31c788178c1deffe2c9e44'

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')).hexdigest()

def stopped_and_complete_cost(scores,positive,costs,k):
    uids=sorted(scores)
    if set(costs)!=set(uids) or positive not in scores or type(k)is not int or not 1<=k<=len(uids) or len(uids)>7:
        raise ValueError('SMALL_FIXED_JOIN')
    if any(not math.isfinite(s) or abs(s)>20 for s in scores.values()) or any(not math.isfinite(c) or not 0<c<=1e9 for c in costs.values()):
        raise ValueError('FINITE_DOMAIN')
    weights={u:math.exp(scores[u]-max(scores.values())) for u in uids}
    negatives=[u for u in uids if u!=positive]
    branches=[]
    for length in range(len(negatives)+1):
        for prefix in itertools.permutations(negatives,length):
            order=prefix+(positive,)
            remaining=set(uids);p=1.
            for u in order:
                p*=weights[u]/math.fsum(weights[v] for v in sorted(remaining))
                remaining.remove(u)
            full=math.fsum(costs[u] for u in order)
            truncated=math.fsum(costs[u] for u in order[:k])
            hit=len(order)<=k
            branches.append((p,full,truncated,hit))
    mass=math.fsum(b[0] for b in branches)
    if abs(mass-1)>1e-12:raise ValueError('PROBABILITY_MASS')
    hit_probability=math.fsum(p for p,_,_,h in branches if h)
    miss_probability=math.fsum(p for p,_,_,h in branches if not h)
    hit_charge=math.fsum(p*c for p,_,c,h in branches if h)
    miss_charge=math.fsum(p*c for p,_,c,h in branches if not h)
    tail=math.fsum(p*(f-c) for p,f,c,_ in branches)
    complete=math.fsum(p*f for p,f,_,_ in branches)
    truncated=hit_charge+miss_charge
    if tail<-1e-12 or abs(complete-truncated-tail)>1e-11:
        raise ValueError('COST_DECOMPOSITION')
    penalty=k*max(costs.values())
    return dict(probability_mass=mass,hit_probability=hit_probability,miss_probability=miss_probability,
        truncated_cost=truncated,complete_first_hit_cost=complete,expected_continuation_tail=tail,
        hit_truncated_charge_component=hit_charge,miss_truncated_charge_component=miss_charge,
        conditional_cost_given_hit=hit_charge/hit_probability if hit_probability else None,
        conditional_cost_given_miss=miss_charge/miss_probability if miss_probability else None,
        conditional_tail_given_miss=tail/miss_probability if miss_probability else None,
        existing_equivalent_miss_penalty=penalty,
        existing_scalar_rescaled_cost_units=truncated+penalty*miss_probability,
        state_terminal_branch_count=len(branches),full_continuation_is_hypothetical=True)

def singleton_complete_cost_gradient(scores,positive,costs):
    """Independent pairwise PL identity, raw charge units, singleton positive."""
    if set(scores)!=set(costs) or positive not in scores or not 1<=len(scores)<=7:
        raise ValueError('SINGLETON_JOIN')
    if any(not math.isfinite(s) or abs(s)>20 for s in scores.values()) or any(not math.isfinite(c) or not 0<c<=1e9 for c in costs.values()):
        raise ValueError('FINITE_DOMAIN')
    shift=max(scores.values());weights={u:math.exp(s-shift) for u,s in scores.items()}
    contributions=[];gradient={u:0. for u in scores}
    for u in sorted(scores):
        if u==positive:continue
        probability=weights[u]/(weights[u]+weights[positive])
        contributions.append(costs[u]*probability)
        gradient[u]=costs[u]*probability*(1-probability)
    gradient[positive]=-math.fsum(gradient[u] for u in gradient if u!=positive)
    return dict(complete_first_hit_cost=costs[positive]+math.fsum(contributions),
                score_gradient=gradient,positive_cost_is_unavoidable_constant=True)

def diagnose():
    path=ROOT/'result.json'
    if path.is_symlink() or path.resolve()!=path or path.stat().st_size!=165324:raise ValueError('RECORD_PATH')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:raise ValueError('RECORD_PIN')
    child=json.loads(raw)['child'];config=child['config']
    if digest(config)!=child['config_sha256']:raise ValueError('CONFIG_PIN')
    tasks={t['case_id']:t for t in config['tasks']}
    reported={r['seed']:{t['task_id']:t for t in r['tasks']} for r in child['per_seed']}
    rows=[];errors=[];full_errors=[]
    for record in child['fit_freezes']:
        payload=record['payload']
        if digest(payload)!=record['freeze_sha256']:raise ValueError('FREEZE_PIN')
        for task_id,task in tasks.items():
            phases={}
            for phase in ('initial_prior','final_prior'):
                values=stopped_and_complete_cost(payload['score_states'][task_id][phase],task['positive_uids'][0],task['costs'],config['k'])
                actual=reported[payload['seed']][task_id]['metrics'][phase]
                bound=config['k']*max(task['costs'].values())
                errors.extend([abs(values['miss_probability']-actual['risk']),abs(values['truncated_cost']-actual['raw_static_cost']),
                    abs(values['existing_scalar_rescaled_cost_units']-2*bound*actual['objective'])])
                pair=singleton_complete_cost_gradient(payload['score_states'][task_id][phase],task['positive_uids'][0],task['costs'])
                full_errors.append(abs(pair['complete_first_hit_cost']-values['complete_first_hit_cost']))
                values['pairwise_complete_cost_score_gradient']=pair['score_gradient']
                phases[phase]=values
            before,after=phases['initial_prior'],phases['final_prior']
            rows.append(dict(seed=payload['seed'],task_id=task_id,split=task['split'],initial=before,final=after,
                truncated_cost_delta=after['truncated_cost']-before['truncated_cost'],
                complete_first_hit_cost_delta=after['complete_first_hit_cost']-before['complete_first_hit_cost'],
                continuation_tail_delta=after['expected_continuation_tail']-before['expected_continuation_tail'],
                miss_probability_delta=after['miss_probability']-before['miss_probability'],
                existing_scalar_cost_units_delta=after['existing_scalar_rescaled_cost_units']-before['existing_scalar_rescaled_cost_units']))
    expected={(seed,task) for seed in (11,29,47) for task in ('fit_cheap','fit_expensive','unseen_cheap','unseen_expensive')}
    if len(rows)!=12 or {(r['seed'],r['task_id']) for r in rows}!=expected or max(errors)>1e-11 or max(full_errors)>1e-11:
        raise ValueError('RECORDED_METRICS')
    return dict(status='COMPLETE_READ_ONLY_COST_ALIGNMENT',source_result_sha256=PIN,source_config_sha256=child['config_sha256'],
        max_record_metric_error=max(errors),max_pairwise_prefix_complete_cost_error=max(full_errors),per_seed_task=rows,
        truncated_cost_increased_count=sum(r['truncated_cost_delta']>0 for r in rows),
        full_cost_decreased_count=sum(r['complete_first_hit_cost_delta']<0 for r in rows),
        risk_decreased_count=sum(r['miss_probability_delta']<0 for r in rows),
        existing_penalized_scalar_decreased_count=sum(r['existing_scalar_cost_units_delta']<0 for r in rows),
        new_model_forwards=0,new_optimizer_steps=0,new_sampling_calls=0,remote_calls=0,train_release=False,
        assumptions=['Fixed recorded PL policy continued after K3, no reranking/cache/retries/timeouts',
                     'Known positive exists among all six actions; charges static additive synthetic, not measured seconds',
                     'Full first-hit cost is a hypothetical policy metric, not observed online completion cost',
                     'Existing .5R+.5C_K/B already has fixed miss penalty B; full tail is policy-dependent'],
        old_e14_scientific_status_unchanged=True)

if __name__=='__main__':print(json.dumps(diagnose(),indent=2,sort_keys=True,allow_nan=False))
