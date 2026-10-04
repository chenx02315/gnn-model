"""Read-only, frozen TRAIN/VALIDATION ranking diagnosis; never reads BLIND."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

EXPECTED = {
    'train_outcomes.tsv': 'df3c9f370305027e895199049e4d282d6b2e76de3284abadd63e273dead21318',
    'validation_outcomes.tsv': '79d89734db89d478c8a5d81aad023a934253318d95e8f3f9db994d87ab3ff1c3',
    'ensemble_ranking.tsv': '66a0eac19a6cba0ced2fec7834f40f8e9d6bd4144eb1dedf4381efff15d0df29',
    'xgboost_ranking.tsv': '7e936e206b807e74c4926575c3b5f5a018d973438f55f91d2b81ef987c0c7762',
}

def read_verified(path, digest):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('SHA256 mismatch: ' + path.name)
    return list(csv.DictReader(raw.decode('utf-8').splitlines(), delimiter='\t'))

def auc(rows, field):
    pos = [float(r[field]) for r in rows if r['hit']]
    neg = [float(r[field]) for r in rows if not r['hit']]
    if not pos or not neg:
        return None
    return sum((p > n) + .5 * (p == n) for p in pos for n in neg) / (len(pos)*len(neg))

def ranks(values):
    result = [0.0]*len(values)
    order = sorted(range(len(values)), key=lambda i: values[i])
    i = 0
    while i < len(order):
        j = i+1
        while j < len(order) and values[order[j]] == values[order[i]]:
            j += 1
        for k in order[i:j]:
            result[k] = (i+j+1)/2
        i = j
    return result

def spearman(x, y):
    x, y = ranks(x), ranks(y)
    mx, my = sum(x)/len(x), sum(y)/len(y)
    denom = math.sqrt(sum((v-mx)**2 for v in x)*sum((v-my)**2 for v in y))
    return sum((a-mx)*(b-my) for a,b in zip(x,y))/denom if denom else None

def diagnose(root):
    inputs = {name: read_verified(root/name, digest) for name,digest in EXPECTED.items()}
    outcomes = {}
    for role, name in [('TRAIN','train_outcomes.tsv'),('VALIDATION','validation_outcomes.tsv')]:
        for row in inputs[name]:
            uid = row['action_uid']
            if uid in outcomes or row['execution_status'] != 'SUCCESS' or row['is_d95_feasible'] != '1':
                raise ValueError('duplicate or inadmissible outcome')
            outcomes[uid] = dict(row, role=role)
    summary = {'scope':'FROZEN_TRAIN_VALIDATION_DIAGNOSTIC_ONLY', 'epsilon':.01,'top_k':10,
               'input_sha256':EXPECTED, 'prevalence':[], 'models':[],
               'changes_to_models_or_formal_protocol':False}
    for model,name in [('GraphSAGE','ensemble_ranking.tsv'),('XGBoost','xgboost_ranking.tsv')]:
        groups = {}
        seen = set()
        for row in inputs[name]:
            uid = row['action_uid']
            if uid in seen or uid not in outcomes or row['role'] != outcomes[uid]['role']:
                raise ValueError('nonunique or inconsistent join')
            seen.add(uid)
            if row['role'] not in ('TRAIN','VALIDATION'):
                raise ValueError('forbidden role')
            outcome = outcomes[uid]
            row = dict(row,hit=int(outcome['epsilon_hit']),cycles=float(outcome['total_cycles']),
                       runtime=float(outcome['policy_charged_runtime_s']))
            for field in ('predicted_epsilon_hit_probability','predicted_cycles','predicted_runtime_s','cost_aware_score'):
                row[field] = float(row[field])
                if not math.isfinite(row[field]):
                    raise ValueError('nonfinite prediction')
            groups.setdefault((row['role'],row['circuit']),[]).append(row)
        if seen != set(outcomes):
            raise ValueError('incomplete join')
        for (role,circuit), rows in sorted(groups.items()):
            n,p = len(rows),sum(r['hit'] for r in rows)
            oracle = min(r['cycles'] for r in rows)
            if any(r['hit'] != int(r['cycles'] <= 1.01*oracle) for r in rows):
                raise ValueError('epsilon label mismatch')
            if model == 'GraphSAGE':
                summary['prevalence'].append({'role':role,'circuit':circuit,'actions':n,'positives':p,
                    'positive_rate':p/n,'random_top10_hit_probability':1-math.comb(n-p,10)/math.comb(n,10),
                    'within_2pct':sum(r['cycles']<=1.02*oracle for r in rows),
                    'within_5pct':sum(r['cycles']<=1.05*oracle for r in rows),
                    'oracle_cycles':oracle})
            metric = {'model':model,'role':role,'circuit':circuit,'auc_probability':auc(rows,'predicted_epsilon_hit_probability'),
                'cycles_spearman':spearman([r['cycles'] for r in rows],[r['predicted_cycles'] for r in rows]),
                'runtime_spearman':spearman([r['runtime'] for r in rows],[r['predicted_runtime_s'] for r in rows]),
                'cycles_mape':sum(abs(r['predicted_cycles']/r['cycles']-1) for r in rows)/n,
                'runtime_mape':sum(abs(r['predicted_runtime_s']/r['runtime']-1) for r in rows)/n,
                'positive_probability_mean':sum(r['predicted_epsilon_hit_probability'] for r in rows if r['hit'])/p if p else None,
                'negative_probability_mean':sum(r['predicted_epsilon_hit_probability'] for r in rows if not r['hit'])/(n-p),
                'ranking':{}}
            methods = {
                'fixed_heuristic':lambda r:(-int(r['action_scheme']=='HMF'),-int(r['h_limit']),-int(r['m_limit']),r['action_uid']),
                'predicted_cycles':lambda r:(r['predicted_cycles'],r['action_uid']),
                'cost_aware':lambda r:(-r['cost_aware_score'],r['predicted_cycles'],r['action_uid']),
                'diagnostic_probability_only':lambda r:(-r['predicted_epsilon_hit_probability'],r['action_uid']),
                'diagnostic_observed_cost_denominator':lambda r:(-r['predicted_epsilon_hit_probability']/r['runtime'],r['predicted_cycles'],r['action_uid']),
            }
            for method,key in methods.items():
                order = sorted(rows,key=key)
                hit_ranks = [i+1 for i,r in enumerate(order) if r['hit']]
                metric['ranking'][method] = {'first_hit_rank':min(hit_ranks) if hit_ranks else None,
                    'positive_ranks':hit_ranks,'top10_hits':sum(r['hit'] for r in order[:10]),
                    'top10_cost_s':sum(r['runtime'] for r in order[:10]),
                    'top10_best_cycle_regret':min(r['cycles']/oracle-1 for r in order[:10])}
            summary['models'].append(metric)
    return summary

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-dir',type=Path,required=True)
    args = parser.parse_args()
    print(json.dumps(diagnose(args.input_dir),ensure_ascii=False,indent=2,allow_nan=False))
