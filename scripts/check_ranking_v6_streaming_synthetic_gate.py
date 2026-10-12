"""Fixed synthetic gate: no model, remote call, real labels or trainer."""
import hashlib
import json
import math
from pathlib import Path
import sys
import tracemalloc

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.models.ranking_v6_first_hit_exact_gradient import enumerate_exact_gradient
from src.models.ranking_v6_streaming_estimator import estimate


def run():
    contract_path = ROOT / 'contracts' / 'ranking_v6_streaming_synthetic_gate_v1.json'
    raw = contract_path.read_bytes()
    contract = json.loads(raw)
    count = sum(2 + 2 * len(c['scores']) for c in contract['cases']) * len(contract['seeds'])
    if count != contract['comparison_count'] or count != 64:
        raise ValueError('COMPARISON_COUNT')
    base_radius = math.sqrt(math.log(2 * count / contract['alpha_familywise']) /
                            (2 * contract['main_samples']))
    rows = []
    for case in contract['cases']:
        scores, costs, positives, k = case['scores'], case['costs'], set(case['positives']), case['k']
        oracle = enumerate_exact_gradient(scores, positives, costs, k=k)
        scale = min(k, len(scores)) * max(costs.values())
        targets = {'risk': oracle['expected_miss_probability'],
                   'normalized_cost': oracle['expected_truncated_static_cost'] / scale}
        targets.update({'risk_gradient:' + uid: value for uid, value in oracle['miss_score_gradient'].items()})
        targets.update({'normalized_cost_gradient:' + uid: value / scale for uid, value in oracle['cost_score_gradient'].items()})
        for seed in contract['seeds']:
            result = estimate(scores, positives, costs, k=k, seed=seed, case_id=case['id'],
                              pilot_samples=contract['pilot_samples'], main_samples=contract['main_samples'])
            observed = {'risk': result['expected_miss_probability'],
                        'normalized_cost': result['expected_truncated_static_cost'] / scale}
            observed.update({'risk_gradient:' + uid: value for uid, value in result['miss_score_gradient'].items()})
            observed.update({'normalized_cost_gradient:' + uid: value / scale for uid, value in result['cost_score_gradient'].items()})
            for name, target in targets.items():
                radius = base_radius * (2 * k if 'gradient:' in name else 1)
                error = abs(observed[name] - target)
                rows.append({'case': case['id'], 'seed': seed, 'metric': name,
                             'absolute_error': error, 'radius': radius,
                             'inside_bound': error <= radius,
                             'precision_sufficient': radius <= contract['maximum_normalized_radius']})
    smoke = contract['allocation_smoke']
    scores = {str(i): float(i % 7) / 7 for i in range(smoke['actions'])}
    costs = {uid: 1. + int(uid) % 10 for uid in scores}
    tracemalloc.start()
    estimate(scores, {'17', '91'}, costs, k=smoke['k'], seed=smoke['seed'], case_id='allocation_smoke',
             pilot_samples=smoke['pilot_samples'], main_samples=smoke['main_samples'])
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    errors_pass = all(row['inside_bound'] for row in rows)
    precision_pass = all(row['precision_sufficient'] for row in rows)
    memory_pass = peak <= smoke['python_traced_peak_limit_bytes']
    status = ('FAIL_SYNTHETIC_GATE' if not errors_pass or not memory_pass else
              'INCONCLUSIVE_PRECISION' if not precision_pass else 'PASS_SYNTHETIC_ESTIMATOR_ONLY')
    return {'status': status, 'contract_sha256': hashlib.sha256(raw).hexdigest(),
            'comparisons': len(rows), 'errors_pass': errors_pass, 'precision_pass': precision_pass,
            'memory_pass': memory_pass, 'python_traced_peak_bytes': peak,
            'memory_metric': 'Python traced allocations only, not total RSS',
            'max_absolute_error': max(row['absolute_error'] for row in rows),
            'max_radius': max(row['radius'] for row in rows), 'results': rows,
            'real_label_reads': 0, 'training_runs': 0, 'remote_calls': 0}


if __name__ == '__main__':
    result = run()
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['status'] == 'PASS_SYNTHETIC_ESTIMATOR_ONLY' else 1)
