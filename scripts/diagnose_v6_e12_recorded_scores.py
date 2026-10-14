"""E13 fixed recorded-score diagnosis; stdlib only, never fit or replay models.

Exact score-space gradients differentiate original PL stopping branches.
Removing the known fixed offset is a record counterfactual, not a new model
forward or fit. Score-gradient angles are NOT parameter-gradient angles.
"""
import hashlib
import itertools
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / 'runtime_training_staging_20260928/v6_synthetic_fit_container_20261014_r1'
PIN = 'ab7f85e46d3edddab669f77fd876cd1b4a66f3ef905b7588ea0296a391adadfd'

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')).hexdigest()

def exact_score_values_gradients(scores, positive, costs, k):
    uids = sorted(scores)
    if set(costs)!=set(uids) or positive not in scores or not 1<=k<len(uids):
        raise ValueError('FIXED_SCORE_JOIN')
    if any(not math.isfinite(v) or abs(v)>20 for v in scores.values()) or any(not math.isfinite(c) or c<=0 for c in costs.values()):
        raise ValueError('FINITE_SCORE_COST_DOMAIN')
    shift = max(scores.values())
    weights = {u:math.exp(scores[u]-shift) for u in uids}
    negatives = [u for u in uids if u!=positive]
    bound = k*max(costs.values())
    def branch(order):
        remaining = set(uids)
        p = 1.
        log_gradient = {u:0. for u in uids}
        for selected in order:
            denominator = math.fsum(weights[u] for u in sorted(remaining))
            for u in sorted(remaining):
                log_gradient[u] += (1. if u==selected else 0.)-weights[u]/denominator
            p *= weights[selected]/denominator
            remaining.remove(selected)
        return p,log_gradient
    terms = []
    for order in itertools.permutations(negatives,k):
        p,g = branch(order)
        terms.append((p,g,1.,math.fsum(costs[u] for u in order)/bound))
    for length in range(k):
        for prefix in itertools.permutations(negatives,length):
            order = prefix+(positive,)
            p,g = branch(order)
            terms.append((p,g,0.,math.fsum(costs[u] for u in order)/bound))
    mass = math.fsum(p for p,_,_,_ in terms)
    risk = math.fsum(p*r for p,_,r,_ in terms)
    cost = math.fsum(p*c for p,_,_,c in terms)
    gr = {u:math.fsum(p*r*g[u] for p,g,r,_ in terms) for u in uids}
    gc = {u:math.fsum(p*c*g[u] for p,g,_,c in terms) for u in uids}
    mg = {u:math.fsum(p*g[u] for p,g,_,_ in terms) for u in uids}
    if abs(mass-1)>1e-12 or max(abs(v) for v in mg.values())>1e-12:
        raise ValueError('BRANCH_PROBABILITY_MASS')
    rank = sorted(uids,key=lambda u:(-scores[u],u)).index(positive)+1
    return dict(risk=risk,normalized_cost=cost,risk_score_gradient=gr,cost_score_gradient=gc,
                probability_mass=mass,positive_rank=rank,top_k_hit=int(rank<=k))

def dot(a,b):
    return math.fsum(a[u]*b[u] for u in sorted(a))

def norm(a):
    return math.sqrt(dot(a,a))

def margin(scores,positive,k):
    return scores[positive]-sorted((v for u,v in scores.items() if u!=positive),reverse=True)[k-1]

def hit_counts(rows):
    phases = ('prior_initial','prior_final','reconstructed_no_prior_initial','reconstructed_no_prior_final')
    for row in rows:
        if any(row[phase]['top_k_hit']!=int(row[phase]['positive_rank']<=3) for phase in phases):
            raise ValueError('TOP3_COUNT_RANK_MISMATCH')
    return {phase:{'all':sum(row[phase]['top_k_hit'] for row in rows),
                   'fit':sum(row[phase]['top_k_hit'] for row in rows if row['split']=='fit'),
                   'unseen':sum(row[phase]['top_k_hit'] for row in rows if row['split']=='unseen')}
            for phase in phases}

def diagnose():
    path = ROOT/'result.json'
    if path.is_symlink() or path.resolve()!=path or path.stat().st_size!=165209:
        raise ValueError('FIXED_ORDINARY_RECORD_REQUIRED')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:
        raise ValueError('FIXED_RESULT_PIN')
    child = json.loads(raw)['child']
    config = child['config']
    if digest(config)!=child['config_sha256']:
        raise ValueError('CONFIG_PIN')
    tasks = {t['case_id']:t for t in config['tasks']}
    reported = {r['seed']:{t['task_id']:t for t in r['tasks']} for r in child['per_seed']}
    rows,errors,step_summaries = [],[],[]
    for record in child['fit_freezes']:
        payload = record['payload']
        if digest(payload)!=record['freeze_sha256']:
            raise ValueError('FREEZE_PIN')
        seed = payload['seed']
        step_logs = payload['fit_step_logs']
        gradient_norms = [entry['gradient_norm'] for entry in step_logs]
        if len(step_logs)!=24 or any(not math.isfinite(v) or v<0 for v in gradient_norms):
            raise ValueError('FIXED_STEP_TRACE')
        step_summaries.append(dict(seed=seed,steps=24,learning_rate=config['learning_rate'],
            min_reported_parameter_gradient_norm=min(gradient_norms),
            max_reported_parameter_gradient_norm=max(gradient_norms),
            zero_reported_gradient_norm_count=sum(v==0 for v in gradient_norms),
            parameter_path_length_from_sgd_norms=config['learning_rate']*math.fsum(gradient_norms),
            path_length_is_not_net_displacement_or_score_change=True))
        for task_id,task in tasks.items():
            states = payload['score_states'][task_id]
            initial,final = states['initial_prior'],states['final_prior']
            pos = task['positive_uids'][0]
            before = exact_score_values_gradients(initial,pos,task['costs'],config['k'])
            after = exact_score_values_gradients(final,pos,task['costs'],config['k'])
            metric = reported[seed][task_id]['metrics']
            errors.extend(abs(value[which]-metric[phase][which]) for phase,value in (('initial_prior',before),('final_prior',after)) for which in ('risk','normalized_cost'))
            delta = {u:final[u]-initial[u] for u in initial}
            common_shift = math.fsum(delta.values())/len(delta)
            centered_delta_norm = math.sqrt(math.fsum((d-common_shift)**2 for d in delta.values()))
            gr,gc = before['risk_score_gradient'],before['cost_score_gradient']
            cosine = dot(gr,gc)/(norm(gr)*norm(gc))
            linear_risk,linear_cost = dot(gr,delta),dot(gc,delta)
            clean_initial = {u:initial[u]-task['offsets'][u] for u in initial}
            clean_final = {u:final[u]-task['offsets'][u] for u in final}
            clean0 = exact_score_values_gradients(clean_initial,pos,task['costs'],config['k'])
            clean1 = exact_score_values_gradients(clean_final,pos,task['costs'],config['k'])
            compact = lambda v:{key:v[key] for key in ('risk','normalized_cost','positive_rank','top_k_hit')}
            rows.append(dict(seed=seed,task_id=task_id,split=task['split'],risk_gradient_norm=norm(gr),cost_gradient_norm=norm(gc),
                score_gradient_cosine=cosine,risk_descent_predicted_cost_dot=-dot(gc,gr),
                score_gradient_scope='score_space_not_parameter_space',risk_score_gradient=gr,cost_score_gradient=gc,
                actual_risk_delta=after['risk']-before['risk'],actual_normalized_cost_delta=after['normalized_cost']-before['normalized_cost'],
                linearized_risk_delta=linear_risk,linearized_normalized_cost_delta=linear_cost,
                risk_linearization_residual=after['risk']-before['risk']-linear_risk,
                cost_linearization_residual=after['normalized_cost']-before['normalized_cost']-linear_cost,
                initial_top3_margin=margin(initial,pos,config['k']),final_top3_margin=margin(final,pos,config['k']),
                actual_relative_score_step=max(abs(delta[pos]-delta[u]) for u in delta if u!=pos),
                common_score_shift=common_shift,centered_score_delta_l2=centered_delta_norm,
                reconstructed_raw_initial_score_range=[min(clean_initial.values()),max(clean_initial.values())],
                reconstructed_raw_final_score_range=[min(clean_final.values()),max(clean_final.values())],
                prior_initial=compact(before),prior_final=compact(after),
                reconstructed_no_prior_initial=compact(clean0),reconstructed_no_prior_final=compact(clean1),
                no_prior_is_record_counterfactual_not_model_rerun=True,
                clairvoyant_positive_first_normalized_cost=task['costs'][pos]/(config['k']*max(task['costs'].values()))))
    if len(rows)!=12 or max(errors)>1e-12:
        raise ValueError('RECORD_OBJECTIVE_AGREEMENT')
    return dict(status='COMPLETE_READ_ONLY_E12_DIAGNOSTIC',source_result_sha256=PIN,
        source_config_sha256=child['config_sha256'],score_states_checked=48,initial_gradient_states=12,
        max_record_objective_error=max(errors),per_seed_task=rows,reported_step_summaries=step_summaries,
        deterministic_top3_hit_counts=hit_counts(rows),
        counters={'new_model_forwards':0,'new_optimizer_steps':0,'new_sampling_calls':0,'remote_calls':0,'real_label_reads':0},
        train_release=False,score_gradient_conflict_is_not_parameter_gradient_conflict=True,
        prior_removal_is_counterfactual_not_causal_ablation=True)

if __name__=='__main__':
    print(json.dumps(diagnose(),indent=2,sort_keys=True,allow_nan=False))
