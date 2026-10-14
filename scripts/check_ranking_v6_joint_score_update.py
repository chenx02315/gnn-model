"""Once-only E10 synthetic score-space check; not optimizer or TRAIN."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT.parent / 'runtime_training_staging_20260928/v6_joint_score_update_20261014_r1'
sys.path.insert(0, str(ROOT))


def main():
    raw_contract = (ROOT / 'contracts/ranking_v6_joint_score_update_gate_v1.json').read_bytes()
    pin = hashlib.sha256(raw_contract).hexdigest()
    if pin != 'e5571e88a33dfd7d91666391219f611bde58bdab151a44db2b3955774cbe3514':
        raise ValueError('CONTRACT_PIN')
    contract = json.loads(raw_contract)
    for name, expected in contract['sources'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError('SOURCE_PIN_' + name)
    from src.models.ranking_v6_joint_score_update_reference import run_joint_score_update
    DESTINATION.mkdir(exist_ok=False)
    with (DESTINATION / 'once.json').open('x', encoding='ascii') as artifact:
        json.dump({'contract_sha256': pin, 'sources': contract['sources'],
                   'formal_runs': 1, 'automatic_retries': 0}, artifact, sort_keys=True)
    try:
        result = run_joint_score_update()
        config = result['config']
        if (config['baseline_samples'] != 32 or config['gradient_samples'] != 32
                or result['total_work'] != 9216 or result['exact_oracle_calls'] > 16
                or len(result['per_case_seed']) != 8 or result['train_release'] is not False
                or result['actual_parameter_updates'] is not False):
            raise ValueError('RESULT_SCOPE')
        if result['status'] == 'PASS_FIXED_SCORE_SPACE_JOINT_UPDATES_ONLY' and (
                result['accepted_count'] != 8 or result['all_committed_updates_safe'] is not True):
            raise ValueError('FALSE_PASS')
        result.update(contract_sha256=pin, sources=contract['sources'], formal_runs=1, automatic_retries=0)
        raw = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
        if len(raw) > 262144:
            raise ValueError('RAW_RESULT_BOUND')
        with (DESTINATION / 'result.json').open('xb') as artifact:
            artifact.write(raw)
        summary = {key: result[key] for key in ('status', 'accepted_count', 'rejected_count',
                   'proposal_count', 'numerical_guard_failures', 'exact_oracle_calls',
                   'all_committed_updates_safe', 'total_work', 'train_release', 'actual_parameter_updates')}
        summary.update(raw_result_path=str(DESTINATION / 'result.json'), raw_result_bytes=len(raw),
                       raw_result_sha256=hashlib.sha256(raw).hexdigest(), formal_runs=1, automatic_retries=0)
        with (DESTINATION / 'summary.json').open('x', encoding='ascii') as artifact:
            json.dump(summary, artifact, sort_keys=True)
        print(json.dumps(summary, sort_keys=True))
        return 1 if result['status'] == 'FAIL_NUMERICAL' else 0
    except Exception as exc:
        with (DESTINATION / 'failure.json').open('x', encoding='ascii') as artifact:
            json.dump({'status': 'FAIL_EXECUTION', 'exception': type(exc).__name__,
                       'message': str(exc), 'formal_runs': 1, 'automatic_retries': 0}, artifact)
        raise


if __name__ == '__main__':
    raise SystemExit(main())
