"""E28 fixed local no-MC joint wiring and generated held-byte proof, NOT_TRAINER."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'contracts/ranking_v6_multi_positive_joint_stage_v1.json'
CONTRACT_SHA = 'ffdf312f1fcb34dfc4843cd5c6ec330b68e6cf18659e264e550c03159adc4b70'
OUTPUT = ROOT.parent / 'runtime_training_staging_20260928/v6_joint_wiring_20261015_r1'
CAP = 65536


def require(ok, code):
    if not ok:
        raise ValueError('E28_'+code)


def encode(value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()
    if len(raw) > CAP:
        raise ValueError('E28_JSON_CAP')
    return raw


def run_checks():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from src.models import ranking_v6_multi_positive_joint_caller as caller
    from src.models import ranking_v6_synthetic_joint_freeze as held
    features, outcomes = caller.generated_fixture()
    scores = dict(zip((f'u{i:03d}' for i in range(6)), [-.2, .3, -.1, .4, .1, -.3]))
    common = dict(k=3, risk_weight=.5, normalized_cost_weight=1., synthetic_only=True)
    baseline = caller.evaluate_exact_reference(features, outcomes, scores, **common)
    cases = []
    for name, cycles, count in [('two_positive', [100,101,130,150,175,200], 2),
                                ('singleton', [100,103,130,150,175,200], 1),
                                ('all_positive', [100]*6, 6)]:
        labels = [dict(row, total_cycles=cycle) for row, cycle in zip(outcomes, cycles)]
        evaluated = caller.evaluate_exact_reference(features, labels, scores, **common)
        require(len(evaluated['prepared_task']['positive_uids']) == count, 'POSITIVE_COUNT')
        require(evaluated['prepared_task']['features'] == baseline['prepared_task']['features'],
                'FEATURE_LABEL_ISOLATION')
        require(evaluated['cost_normalization_B'] == 60., 'FIXED_B')
        cases.append({'name': name, 'expected_positive_count': count, 'result': evaluated, 'pass': True})
    proofs = []
    for phase in ('risk', 'cost', 'joint'):
        gradient = (baseline['joint_score_gradient'] if phase == 'joint'
                    else baseline['gradient_maps'][phase])
        for uid in sorted(scores):
            changed = []
            for delta in (1e-6, -1e-6):
                perturbed = dict(scores)
                perturbed[uid] += delta
                result = caller.evaluate_exact_reference(features, outcomes, perturbed, **common)
                changed.append(result['joint_scalar'] if phase == 'joint' else
                               result['risk_component']['expected_miss_probability'] if phase == 'risk' else
                               result['cost_component']['normalized_complete_first_hit_cost'])
            fd = (changed[0]-changed[1])/2e-6
            error = abs(gradient[uid]-fd)
            require(error <= 1e-8, 'SCORE_FINITE_DIFFERENCE')
            proofs.append({'phase': phase, 'uid': uid, 'analytic': gradient[uid],
                           'finite_difference': fd, 'absolute_error': error})
    held_features = [dict(row, role='HELDOUT') for row in features]
    kwargs = dict(normalizer_bytes=held.identity_normalizer_bytes(), model_sha256='0'*64,
                  synthetic_only=True)
    frozen = held.freeze_snapshot(held_features, scores, **kwargs)
    calls = [0]

    def loader():
        calls[0] += 1
        return outcomes

    try:
        held.release_outcomes(frozen, frozen+b'!', held_features, scores,
                              outcome_loader=loader, **kwargs)
    except ValueError:
        pass
    else:
        raise AssertionError('E28_CORRUPT_READBACK_ACCEPTED')
    require(calls[0] == 0, 'HELD_EARLY_READ')
    released = held.release_outcomes(frozen, frozen, held_features, scores,
                                     outcome_loader=loader, **kwargs)
    require(calls[0] == 1, 'HELD_LOADER_COUNT')
    return {'status': 'PASS_GENERATED_JOINT_WIRING_AND_MEMORY_FREEZE_ONLY',
            'cases': cases, 'score_finite_difference_proofs': proofs,
            'max_score_finite_difference_error': max(p['absolute_error'] for p in proofs),
            'held_proof': released, 'corrupt_readback_loader_calls': 0,
            'model_identity_is_synthetic_placeholder': True,
            'mc_estimator_calls': 0, 'torch_calls': 0, 'model_instances': 0,
            'optimizer_calls': 0, 'real_label_reads': 0, 'training_runs': 0,
            'remote_calls': 0, 'real_heldout_release': False, 'real_training_release': False}


def sources():
    return [Path(__file__).resolve(), CONTRACT] + [ROOT/'src/models'/name for name in (
        'ranking_v6_multi_positive_joint_caller.py', 'ranking_v6_synthetic_joint_freeze.py',
        'ranking_v6_synthetic_real_bridge_adapter.py', 'runtime_ranking_v3.py',
        'ranking_v6_multi_positive_complete_cost.py', 'ranking_v6_multi_positive_conditional_risk.py',
        'ranking_v6_multi_positive_risk_control.py', 'ranking_v6_scorer_vjp_bridge.py')]


def execute_once(output, *, checks=run_checks):
    output.mkdir(parents=True, exist_ok=False)
    metadata = {'contract_sha256': CONTRACT_SHA, 'python': sys.version,
                'source_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources()}}
    with (output/'once.json').open('xb') as marker:
        marker.write(encode(metadata))
    try:
        result = dict(provenance=metadata, diagnostic=checks())
        raw = encode(result)
        with (output/'result.json').open('xb') as stream:
            stream.write(raw)
        return {'status': result['diagnostic']['status'], 'result_sha256': hashlib.sha256(raw).hexdigest(),
                'result_bytes': len(raw), 'artifact': str(output/'result.json')}
    except Exception as exc:
        with (output/'failure.json').open('xb') as stream:
            stream.write(encode({'error': str(exc)[:1000], 'retry_allowed': False}))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--contract-sha256', required=True)
    args = parser.parse_args(argv)
    if not args.execute or args.contract_sha256 != CONTRACT_SHA:
        parser.error('EXACT_EXECUTE_AND_CONTRACT_REQUIRED')
    if hashlib.sha256(CONTRACT.read_bytes()).hexdigest() != CONTRACT_SHA:
        raise ValueError('E28_CONTRACT_PIN')
    print(json.dumps(execute_once(OUTPUT), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
