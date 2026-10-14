"""Independent E12 recorded-score audit; no model, optimizer, RNG or remote calls."""
import hashlib
import itertools
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / 'runtime_training_staging_20260928/v6_synthetic_fit_container_20261014_r1'
RESULT_PIN = 'ab7f85e46d3edddab669f77fd876cd1b4a66f3ef905b7588ea0296a391adadfd'

def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    return hashlib.sha256(raw).hexdigest()

def prefix_objectives(scores, positive_uids, costs, k):
    assert len(positive_uids) == 1 and 1 <= k <= len(scores) - 1
    positive = positive_uids[0]
    negatives = sorted(set(scores) - {positive})
    shift = max(scores.values())
    weights = {u: math.exp(s - shift) for u, s in scores.items()}
    def prefix(order):
        remaining = set(scores)
        probability = 1.0
        for uid in order:
            probability *= weights[uid] / math.fsum(weights[u] for u in sorted(remaining))
            remaining.remove(uid)
        return probability, remaining
    miss_terms, hit_terms, cost_terms = [], [], []
    for order in itertools.permutations(negatives, k):
        probability, _ = prefix(order)
        miss_terms.append(probability)
        cost_terms.append(probability * math.fsum(costs[u] for u in order))
    for length in range(k):
        for order in itertools.permutations(negatives, length):
            probability, remaining = prefix(order)
            probability *= weights[positive] / math.fsum(weights[u] for u in sorted(remaining))
            hit_terms.append(probability)
            cost_terms.append(probability * (math.fsum(costs[u] for u in order) + costs[positive]))
    return math.fsum(miss_terms), math.fsum(cost_terms), math.fsum(miss_terms + hit_terms)

def audit():
    path = ROOT / 'result.json'
    assert not path.is_symlink() and path.resolve() == path and path.stat().st_size == 165209
    raw = path.read_bytes()
    assert len(raw) == 165209 and hashlib.sha256(raw).hexdigest() == RESULT_PIN
    child = json.loads(raw)['child']
    config = child['config']
    assert digest(config) == child['config_sha256']
    tasks = {t['case_id']: t for t in config['tasks']}
    reported = {r['seed']: {t['task_id']: t for t in r['tasks']} for r in child['per_seed']}
    errors, comparisons, joint = [], 0, {'fit': 0, 'unseen': 0}
    for record in child['fit_freezes']:
        payload = record['payload']
        assert digest(payload) == record['freeze_sha256']
        seed = payload['seed']
        for task_id, task in tasks.items():
            result = reported[seed][task_id]
            states = payload['score_states'][task_id]
            assert set(states) == set(config['comparison_states'])
            for name, scores in states.items():
                risk, cost, mass = prefix_objectives(scores, task['positive_uids'], task['costs'], config['k'])
                norm = cost / (config['k'] * max(task['costs'].values()))
                actual = result['metrics'][name]
                errors.extend([abs(risk - actual['risk']), abs(cost - actual['raw_static_cost']),
                               abs(norm - actual['normalized_cost']),
                               abs(0.5 * (risk + norm) - actual['objective']), abs(mass - 1.0)])
                order = sorted(scores, key=lambda u: (-scores[u], u))
                rank = order.index(task['positive_uids'][0]) + 1
                assert rank == actual['deterministic_positive_position']
                assert int(rank <= config['k']) == actual['deterministic_top_k_hit']
                comparisons += 1
            initial, final = result['metrics']['initial_prior'], result['metrics']['final_prior']
            dr, dc = final['risk'] - initial['risk'], final['normalized_cost'] - initial['normalized_cost']
            assert abs(dr - result['risk_delta']) < 1e-15 and abs(dc - result['normalized_cost_delta']) < 1e-15
            improved = dr < -1e-8 and dc < -1e-8
            assert improved == result['jointly_improved']
            assert result['rare_initial_guard_pass'] == (initial['risk'] >= 0.9)
            joint[task['split']] += int(improved)
    assert comparisons == 72 and max(errors) < 1e-12 and joint == {'fit': 3, 'unseen': 3}
    return {'status': 'PASS_INDEPENDENT_RECORDED_OBJECTIVES_ONLY', 'states': comparisons,
            'max_absolute_error': max(errors), 'joint_counts': joint,
            'model_replay': False, 'resampling': False}

if __name__ == '__main__':
    print(json.dumps(audit(), sort_keys=True))
