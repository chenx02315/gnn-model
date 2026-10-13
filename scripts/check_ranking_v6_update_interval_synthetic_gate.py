"""Fixed synthetic shared-parameter proposal and independent interval gate."""
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.models.ranking_v6_linear_update_reference import propose_cost_steps
from src.models.ranking_v6_interval_risk_gate import select_certified_update
from src.models.ranking_v6_streaming_estimator import estimate

CONTRACT_SHA = 'c10b141733affcfabb9876c931b8feb637b2f5630590f577af35f226bbc4dab3'


def run():
    raw = (ROOT / 'contracts/ranking_v6_update_interval_synthetic_gate_v1.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != CONTRACT_SHA:
        raise ValueError('CONTRACT_PIN')
    contract = json.loads(raw)
    fixture, plan = contract['fixture'], contract['evaluation']
    proposals = propose_cost_steps(fixture['families'], fixture['parameters'],
                                  k=fixture['k'], steps=fixture['steps'])
    states = {'current': proposals['current'], **proposals['candidates']}
    count = 2 * len(fixture['families']) * len(states)
    if count != plan['comparison_count'] or count != 10:
        raise ValueError('COMPARISON_COUNT')
    radius = math.sqrt(math.log(2 * count / plan['alpha_familywise']) / (2 * plan['main_samples']))
    interval_states, evaluations = {}, {}
    for state_id, state in states.items():
        parameters = state['parameters']
        intervals, details = {}, {}
        for family_id, family in fixture['families'].items():
            scores = {uid: math.fsum(value * parameters[p] for p, value in vector.items())
                      for uid, vector in family['features'].items()}
            result = estimate(scores, family['positives'], family['costs'], k=fixture['k'],
                              seed=plan['seed'], case_id=plan['case_id_prefix'] + state_id + '_' + family_id,
                              pilot_samples=plan['pilot_samples'], main_samples=plan['main_samples'])
            if family['cost_scale'] != result['cost_normalization_B']:
                raise ValueError('NORMALIZATION_BOUND')
            intervals[family_id] = {'risk_mean': result['expected_miss_probability'], 'risk_radius': radius,
                                    'cost_mean': result['expected_truncated_static_cost'] / family['cost_scale'],
                                    'cost_radius': radius}
            details[family_id] = {'parameters': parameters, 'means_and_radii': intervals[family_id],
                                  'derived_seed_sha256': result['derived_seed_sha256']}
        interval_states[state_id], evaluations[state_id] = intervals, details
    decision = select_certified_update(interval_states['current'],
                                      {s: v for s, v in interval_states.items() if s != 'current'},
                                      fixture['risk_caps'], plan['maximum_radius'])
    selected = decision['selected_id']
    oracle_check = False
    if selected is not None:
        before, after = proposals['current'], proposals['candidates'][selected]
        oracle_check = (all(after['family_metrics'][f]['risk'] <= fixture['risk_caps'][f]
                            for f in fixture['families']) and
                        after['macro_metrics']['macro_normalized_cost'] < before['macro_metrics']['macro_normalized_cost'])
    passed = selected == contract['expected_selected_id'] and oracle_check
    return {'status': 'PASS_SYNTHETIC_UPDATE_INTERVAL_ONLY' if passed else 'FAIL_SYNTHETIC_GATE',
            'contract_sha256': hashlib.sha256(raw).hexdigest(), 'comparison_count': count, 'radius': radius,
            'evaluations': evaluations, 'interval_decision': decision, 'selected_id': selected,
            'exact_oracle_crosscheck': oracle_check, 'proposals': proposals,
            'update_applied': False, 'real_label_reads': 0, 'remote_calls': 0, 'training_runs': 0,
            'formal_training_release': False}


if __name__ == '__main__':
    result = run()
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['status'].startswith('PASS_') else 1)
