"""One pre-registered synthetic risk/reference and allocation gate, no training."""
import hashlib
import json
from pathlib import Path
import sys
import tracemalloc

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.models.ranking_v6_risk_macro_reference import select_feasible_update
from src.models.ranking_v6_streaming_estimator_large import estimate

CONTRACT_SHA = '7a421bf1baba99adec527e7b9de848d43f79fe6786b6df81b54d5ad10c010ad7'


def run():
    raw = (ROOT / 'contracts/ranking_v6_risk_large_synthetic_gate_v1.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != CONTRACT_SHA:
        raise ValueError('CONTRACT_PIN')
    contract = json.loads(raw)
    old = (ROOT / 'src/models/ranking_v6_streaming_estimator.py').read_bytes()
    if hashlib.sha256(old).hexdigest() != contract['old_streaming_sha256']:
        raise ValueError('OLD_SOURCE_CHANGED')
    fixture = contract['risk_fixture']
    choice = select_feasible_update(fixture['current'], fixture['candidates'], fixture['risk_caps'])
    risk_pass = choice['selected_id'] == fixture['expected_selected_id']
    smoke = contract['large_smoke']
    scores = {str(i): float(i % 7) / 7 for i in range(smoke['n'])}
    costs = {uid: 1. + int(uid) % 10 for uid in scores}
    positives = {str(i) for i in smoke['positive_indices']}
    tracemalloc.start()
    try:
        result = estimate(scores, positives, costs, k=smoke['k'], seed=smoke['seed'],
                          case_id=smoke['case_id'], pilot_samples=smoke['pilot_samples'],
                          main_samples=smoke['main_samples'])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    memory_pass = peak <= smoke['python_traced_peak_limit_bytes']
    work_pass = result['work_bound'] <= contract['max_work']
    return {'status': 'PASS_SYNTHETIC_RISK_AND_LARGE_RESOURCE_ONLY' if risk_pass and memory_pass and work_pass
            else 'FAIL_SYNTHETIC_GATE', 'contract_sha256': CONTRACT_SHA, 'risk_pass': risk_pass,
            'selection': choice, 'actions': len(scores), 'k': smoke['k'], 'pilot_samples': smoke['pilot_samples'],
            'main_samples': smoke['main_samples'], 'seed': smoke['seed'], 'work_bound': result['work_bound'],
            'python_traced_peak_bytes': peak, 'memory_pass': memory_pass, 'work_pass': work_pass,
            'memory_measure': contract['memory_measure'], 'derived_seed_sha256': result['derived_seed_sha256'],
            'real_label_reads': 0, 'remote_calls': 0, 'training_runs': 0,
            'large_domain_statistical_precision_verified': False, 'formal_training_release': False}


if __name__ == '__main__':
    result = run()
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['status'].startswith('PASS_') else 1)
