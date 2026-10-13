"""Once-only local fixed synthetic diagnostic, never a trainer or CI gate."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.models.ranking_v6_conditional_survival_reference import estimate
from src.models.ranking_v6_large_precision_reference import uniform_closed_form


def main():
    source = ROOT / 'src/models/ranking_v6_conditional_survival_reference.py'
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    if source_sha != 'e3352c3c08baaf119c34a60bbcb250ff585b3fd5b5e07e2657548627b646058a':
        raise ValueError('SOURCE_PIN')
    contract_path = ROOT / 'contracts/ranking_v6_positive_signal_diagnostic_v1.json'
    raw = contract_path.read_bytes()
    config = json.loads(raw)
    expected = {'actions': 736, 'k': 10, 'positive_uid': '17', 'seeds': [11, 29, 47, 83],
                'samples_per_seed': 32, 'formal_runs': 1, 'automatic_retries': 0,
                'max_nominal_work': 942080, 'absolute_positive_gradient_error_tolerance': 1e-12}
    if any(config.get(key) != value for key, value in expected.items()):
        raise ValueError('FIXED_CONFIG')
    if config.get('adaptive_samples') is not False or config.get('confidence_interval_claim') is not False:
        raise ValueError('SCOPE')
    staging = ROOT.parent / 'runtime_training_staging_20260928/v6_positive_signal_20261013_r1'
    staging.mkdir(exist_ok=False)
    with (staging / 'once.json').open('x', encoding='ascii') as marker:
        json.dump({'source_sha256': source_sha, 'contract_sha256': hashlib.sha256(raw).hexdigest(),
                   'formal_runs': 1, 'automatic_retries': 0}, marker, sort_keys=True)
    scores = {str(i): 0. for i in range(736)}
    costs = {uid: 1. for uid in scores}
    exact = uniform_closed_form(736, 10)
    truth = exact['miss_score_gradient']['17']
    rows = []
    for seed in config['seeds']:
        result = estimate(scores, {'17'}, costs, k=10, seed=seed, samples=32)
        observed = result['miss_score_gradient']['17']
        error = abs(observed - truth)
        rows.append({'seed': seed, 'samples': 32, 'positive_gradient': observed,
                     'exact_positive_gradient': truth, 'absolute_error': error,
                     'strictly_negative': observed < 0, 'nominal_work': result['work_bound'],
                     'gradient_map_sha256': hashlib.sha256(json.dumps(result['miss_score_gradient'],
                         sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()})
    passed = all(row['strictly_negative'] and row['absolute_error'] <= 1e-12 for row in rows)
    receipt = {'status': 'PASS_FIXED_UNIFORM_POSITIVE_SIGNAL_ONLY' if passed else 'FAIL_FIXED_POSITIVE_SIGNAL',
               'source_sha256': source_sha, 'contract_sha256': hashlib.sha256(raw).hexdigest(),
               'config': config, 'per_seed': rows, 'nominal_work': sum(r['nominal_work'] for r in rows),
               'uniform_positive_observation_order_independent_by_derivation': True,
               'negative_coordinate_precision_certified': False,
               'nonuniform_variance_dominance_certified': False,
               'confidence_interval_claim': False, 'training_release': False,
               'real_data_access': False, 'remote_runs': 0, 'torch_runs': 0}
    with (staging / 'result.json').open('x', encoding='ascii') as artifact:
        json.dump(receipt, artifact, sort_keys=True, allow_nan=False)
    print(json.dumps(receipt, sort_keys=True, allow_nan=False))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
