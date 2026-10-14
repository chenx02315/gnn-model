"""Create-once fixed local synthetic experiment, retain raw audit separately."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT.parent / 'runtime_training_staging_20260928/v6_nonuniform_precision_20261013_r1'
sys.path.insert(0, str(ROOT))


def main():
    raw_contract = (ROOT / 'contracts/ranking_v6_nonuniform_precision_gate_v1.json').read_bytes()
    if hashlib.sha256(raw_contract).hexdigest() != '19475a97cf6ab8ec5adf246cf2c717ea950f7e0877ecc8ccbbd155a14922b0ea':
        raise ValueError('CONTRACT_PIN')
    contract = json.loads(raw_contract)
    expected = {'actions': 6, 'k': 3, 'seeds': [11, 29, 47, 83], 'pilot_samples': 64,
                'main_samples': 16384, 'alpha': .01, 'max_absolute_radius': .02,
                'comparison_count': 144, 'formal_runs': 1, 'automatic_retries': 0,
                'nominal_total_work': 2368512, 'raw_result_max_bytes': 262144}
    if any(contract.get(k) != v for k, v in expected.items()) or contract.get('adaptive_sampling') is not False:
        raise ValueError('FIXED_CONTRACT')
    for name, pin in contract['sources'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != pin:
            raise ValueError('SOURCE_PIN_' + name)
    # No import of the numerical module until its pins have passed.
    from src.models.ranking_v6_nonuniform_precision_reference import run_nonuniform_precision
    destination = DESTINATION
    destination.mkdir(exist_ok=False)
    contract_sha = hashlib.sha256(raw_contract).hexdigest()
    with (destination / 'once.json').open('x', encoding='ascii') as marker:
        json.dump({'contract_sha256': contract_sha, 'sources': contract['sources'],
                   'formal_runs': 1, 'automatic_retries': 0}, marker, sort_keys=True)
    try:
        result = run_nonuniform_precision()
        result.update(contract_sha256=contract_sha, sources=contract['sources'],
                      formal_runs=1, automatic_retries=0)
        raw = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
        if len(raw) > 262144:
            raise ValueError('RAW_RESULT_BOUND')
        with (destination / 'result.json').open('xb') as artifact:
            artifact.write(raw)
        summary = {'status': result['status'], 'direction_status': result['direction_status'],
                   'comparisons': result['comparison_count'], 'error_bound_violations': result['error_bound_violations'],
                   'precision_violations': result['precision_violations'],
                   'direction_certified_cases': sum(s['same_objective_direction_certified'] for s in result['per_case_seed']),
                   'raw_result_sha256': hashlib.sha256(raw).hexdigest(), 'raw_result_bytes': len(raw),
                   'raw_result_path': str(destination / 'result.json'), 'formal_runs': 1,
                   'automatic_retries': 0, 'train_release': False}
        with (destination / 'summary.json').open('x', encoding='ascii') as artifact:
            json.dump(summary, artifact, sort_keys=True)
        print(json.dumps(summary, sort_keys=True))
        # INCONCLUSIVE is an honestly completed experiment, not execution failure.
        return 1 if result['status'] == 'FAIL_NUMERICAL' else 0
    except Exception as exc:
        with (destination / 'failure.json').open('x', encoding='ascii') as artifact:
            json.dump({'status': 'FAIL_EXECUTION', 'exception': type(exc).__name__,
                       'message': str(exc), 'formal_runs': 1, 'automatic_retries': 0}, artifact)
        raise


if __name__ == '__main__':
    raise SystemExit(main())
