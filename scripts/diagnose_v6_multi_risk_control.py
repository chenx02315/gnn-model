"""E26 fixed matched-path local diagnostic, NOT_TRAINER; inert on import.

Only --execute plus the byte-pinned contract permits the create-once run.
No adaptive sampling, automatic retries, model/data/remote work or CI claims.
"""
import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'contracts/ranking_v6_multi_risk_control_diagnostic_v1.json'
CONTRACT_SHA = '229807d5b84c0cf172fc9c342a37a528f10de7a84c1aeb3b28427b43bb269f37'
OUTPUT = ROOT.parent / 'runtime_training_staging_20260928/v6_multi_risk_control_20261015_r1'
MAX_JSON_BYTES = 2 * 1024 * 1024
PILOT_SEED_XOR = 0x9E3779B9
PASS = 'PASS_FIXED_UNIFORM_REDUCTION_ONLY'
FAIL = 'FAIL_FIXED_UNIFORM_REDUCTION'
FALSE_FLAGS = ('adaptive_samples', 'coefficient_tuning', 'confidence_interval_claim',
               'universal_variance_reduction_claim', 'nonuniform_large_precision_claim',
               'real_training_release', 'remote_allowed', 'torch_allowed',
               'optimizer_allowed', 'real_label_reads_allowed', 'blind_allowed',
               'lsf_tessent_allowed')
SMALL_CASES = [
    {'scores': [-.7, .4, 1.2, -.2, .8, -1.1], 'positive_indices': [1, 4], 'k': 3},
    {'scores': [-.7, .4, 1.2, -.2, .8, -1.1], 'positive_indices': [0, 3, 5], 'k': 2},
    {'scores': [0., 0., 0., 0.], 'positive_indices': [0, 1, 2, 3], 'k': 3},
    {'scores': [0., 0., 0., 0.], 'positive_indices': [0, 1, 2], 'k': 3}]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_contract(contract):
    if any(contract.get(key) is not False for key in FALSE_FLAGS):
        raise ValueError('CONTRACT_FORBIDDEN_FLAG')
    fixed = {'experiment_id': 'E26', 'formal_runs': 1, 'automatic_retries': 0,
             'large_cases': {'actions': 736, 'k': 10, 'scores': 'all zero',
                             'positive_counts': [1, 6], 'seeds': [83, 101, 137]},
             'raw_arm': {'samples': 512},
             'controlled_arm': {'pilot_samples': 32, 'main_samples': 480, 'coefficient': 1},
             'samples_per_arm_per_case': 512, 'large_pairs': 6,
             'total_large_paths': 6144, 'nominal_work_per_arm_per_case': 3768320,
             'total_nominal_large_work': 45219840, 'max_work_per_call': 20000000,
             'small_fixed_baselines': [0., .25, .9], 'small_cases': SMALL_CASES,
             'small_expectation_absolute_tolerance': 1e-11,
             'large_risk_and_positive_gradient_absolute_tolerance': 1e-12,
             'all_coordinate_outputs_required': True}
    for key, value in fixed.items():
        # JSON encoding also distinguishes bool from int and disallows NaN.
        if json.dumps(contract.get(key), sort_keys=True, allow_nan=False) != json.dumps(value, sort_keys=True):
            raise ValueError('CONTRACT_FIXED_' + key)


def load_contract(path, supplied_sha):
    if supplied_sha != CONTRACT_SHA:
        raise ValueError('CLI_CONTRACT_PIN')
    raw = path.read_bytes()
    if sha(raw) != CONTRACT_SHA:
        raise ValueError('CONTRACT_CONTENT_PIN')
    contract = json.loads(raw)
    validate_contract(contract)
    return contract


def _imports():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from scripts import diagnose_v6_multi_positive_risk as previous
    from src.models import ranking_v6_multi_positive_conditional_risk as raw
    from src.models import ranking_v6_multi_positive_risk_control as control
    return previous, raw, control


def small_expectation(scores, positives, k, baseline, *, trajectory_fn=None):
    """Stream every negative prefix; compare float path with Decimal80 oracle.

    Structural-zero cases have no proposal prefixes and do not enumerate.
    The fixed baseline is not differentiated; risk remains E_q[S].
    """
    _, raw, control = _imports()
    uids, weights, positive, negative = raw._validate(scores, positives, k, True, 7)
    if len(negative) < k:
        return {'risk': 0., 'gradient': dict.fromkeys(uids, 0.),
                'probability_mass': 1., 'prefix_count': 0, 'structural_zero': True}
    trajectory_fn = trajectory_fn or control._trajectory
    risk_terms, terms, masses = [], [[] for _ in uids], []
    for order in itertools.permutations(negative, k):
        probability, survival, ds, logq = trajectory_fn(weights, positive, negative, k, order=order)
        masses.append(probability)
        risk_terms.append(probability * survival)
        for i in range(len(uids)):
            terms[i].append(probability * (ds[i] + (survival - baseline) * logq[i]))
    mass = math.fsum(masses)
    if not math.isclose(mass, 1., rel_tol=0., abs_tol=1e-12):
        raise ValueError('SMALL_PROPOSAL_MASS')
    return {'risk': math.fsum(risk_terms),
            'gradient': dict(zip(uids, (math.fsum(values) for values in terms))),
            'probability_mass': mass, 'prefix_count': len(masses), 'structural_zero': False}


def check_arm(result, scores, seed, controlled):
    previous, _, _ = _imports()
    previous.check_result(result, scores)
    expected = {'seed': seed, 'samples': 480 if controlled else 512,
                'nominal_work': 3768320, 'trajectory_count': 480 if controlled else 512}
    if controlled:
        expected.update(pilot_samples=32, total_samples=512, main_seed=seed,
                        pilot_seed=seed ^ PILOT_SEED_XOR, main_trajectory_count=480,
                        pilot_trajectory_count=32, total_trajectory_count=512,
                        baseline_frozen_before_main=True, baseline_main_adaptation=False,
                        baseline_derivative_included=False, pilot_uses_all_samples=True,
                        independent_prng_stream_model=True,
                        prng_independence_empirically_certified=False,
                        confidence_interval_implemented=False,
                        universal_variance_reduction_claim=False)
        baseline = result.get('pilot_baseline')
        if type(baseline) not in (int, float) or not math.isfinite(baseline) or not 0 <= baseline <= 1:
            raise ValueError('CONTROL_BASELINE_RANGE')
    for key, value in expected.items():
        if type(result.get(key)) is not type(value) or result[key] != value:
            raise ValueError('ARM_METADATA_' + key)


def run_diagnostic(contract, *, raw_fn=None, control_fn=None, oracle_fn=None):
    """Fixed six pairs; injectable large calls allow tests without formal runs."""
    validate_contract(contract)
    previous, raw_kernel, control_kernel = _imports()
    raw_fn = raw_fn or raw_kernel.estimate
    control_fn = control_fn or control_kernel.estimate
    oracle_fn = oracle_fn or raw_kernel.enumerate_exact_gradient
    small, large = [], []
    for case in contract['small_cases']:
        scores = {str(i): value for i, value in enumerate(case['scores'])}
        positives = {str(i) for i in case['positive_indices']}
        oracle = oracle_fn(scores, positives, k=case['k'], synthetic_only=True)
        previous.check_result(oracle, scores)
        for baseline in contract['small_fixed_baselines']:
            result = small_expectation(scores, positives, case['k'], baseline)
            risk_error = abs(result['risk'] - oracle['expected_miss_probability'])
            gradient_error = max(abs(result['gradient'][u] - oracle['miss_score_gradient'][u]) for u in scores)
            passed = risk_error <= 1e-11 and gradient_error <= 1e-11
            small.append({'fixture': case, 'fixed_baseline': baseline, 'result': result,
                          'decimal80_oracle': oracle, 'risk_absolute_error': risk_error,
                          'gradient_max_absolute_error': gradient_error, 'pass': passed})
    scores = {str(i): 0. for i in range(736)}
    for count in (1, 6):
        positives = {str(i) for i in range(count)}
        reference = previous.uniform_reference(736, count, 10)
        for seed in (83, 101, 137):
            raw = raw_fn(scores, positives, k=10, seed=seed, samples=512, synthetic_only=True)
            controlled = control_fn(scores, positives, k=10, seed=seed, samples=480,
                                    pilot_samples=32, synthetic_only=True)
            check_arm(raw, scores, seed, False)
            check_arm(controlled, scores, seed, True)
            summaries = [previous.summarize_large(arm, scores, positives, reference, 1e-12)
                         for arm in (raw, controlled)]
            a, b = summaries
            passed = (all(s['risk_and_positive_signal_pass'] for s in summaries)
                      and b['negative_mean_absolute_error'] < a['negative_mean_absolute_error']
                      and b['negative_max_absolute_error'] < a['negative_max_absolute_error']
                      and b['negative_wrong_sign_count'] <= a['negative_wrong_sign_count'])
            large.append({'positive_count': count, 'seed': seed, 'analytic_reference': reference,
                          'raw': raw, 'controlled': controlled, 'raw_summary': a,
                          'controlled_summary': b, 'pass': passed})
    passed = all(row['pass'] for row in small + large)
    return {'status': PASS if passed else FAIL, 'small_cases': small, 'large_pairs': large,
            'total_large_paths': 6144, 'total_nominal_large_work': 45219840,
            'same_total_paths_per_arm_not_equal_runtime': True,
            'confidence_interval_claim': False, 'universal_variance_reduction_claim': False,
            'nonuniform_large_precision_claim': False, 'real_training_ready': False,
            'negative_direction_certified': False, 'full_gradient_precision_certified': False,
            'not_trainer': True, 'model_instances': 0, 'optimizer_instances': 0,
            'real_label_reads': 0, 'remote_calls': 0, 'torch_calls': 0, 'training_runs': 0,
            'blind_access': False, 'lsf_tessent_calls': 0, 'automatic_retries': 0, 'formal_runs': 1}


def encode_capped(value):
    raw = (json.dumps(value, sort_keys=True, allow_nan=False, separators=(',', ':')) + '\n').encode('utf-8')
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError('JSON_SIZE_CAP')
    return raw


def source_paths():
    return (Path(__file__).resolve(), CONTRACT,
            ROOT / 'scripts/diagnose_v6_multi_positive_risk.py',
            ROOT / 'src/models/ranking_v6_multi_positive_conditional_risk.py',
            ROOT / 'src/models/ranking_v6_multi_positive_risk_control.py')


def execute_once(contract, output, *, runner=run_diagnostic, sources=None):
    """Test seam only; CLI never accepts output/source/fixture overrides."""
    validate_contract(contract)
    output.mkdir(parents=True, exist_ok=False)
    metadata = {'contract_sha256': CONTRACT_SHA, 'python': sys.version,
                'platform': platform.platform(), 'once': True, 'automatic_retries': 0}
    try:
        metadata['source_sha256'] = {str(path): sha(path.read_bytes()) for path in
                                    (source_paths() if sources is None else sources)}
        with (output / 'once.json').open('xb') as stream:
            stream.write(encode_capped(metadata))
        result = runner(contract)
        if result.get('status') not in (PASS, FAIL):
            raise ValueError('DIAGNOSTIC_STATUS_SCHEMA')
        raw = encode_capped({'provenance': metadata, 'diagnostic': result})
        with (output / 'result.json').open('xb') as stream:
            stream.write(raw)
        digest = sha(raw)
        with (output / 'result.sha256').open('x', encoding='ascii') as stream:
            stream.write(digest + '\n')
        if result['status'] == FAIL:
            with (output / 'failure.json').open('xb') as stream:
                stream.write(encode_capped({'status': FAIL, 'reason': 'FIXED_CRITERION_NOT_MET',
                                           'result_sha256': digest, 'retry_allowed': False}))
        return {'status': result['status'], 'artifact_sha256': digest,
                'artifact': str(output / 'result.json')}, 0 if result['status'] == PASS else 1
    except Exception as exc:
        failure = {'status': FAIL, 'provenance': metadata, 'exception_type': type(exc).__name__,
                   'error': str(exc)[:2000], 'retry_allowed': False}
        with (output / 'failure.json').open('xb') as stream:
            stream.write(encode_capped(failure))
        return {'status': FAIL, 'failure': str(output / 'failure.json')}, 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--contract-sha256', required=True)
    args = parser.parse_args(argv)
    if not args.execute:
        parser.error('--execute is required')
    try:
        contract = load_contract(CONTRACT, args.contract_sha256)
        summary, code = execute_once(contract, OUTPUT)
    except Exception as exc:
        print(json.dumps({'status': 'FAIL_CLOSED_BEFORE_RUN', 'error': str(exc)[:500]}))
        return 1
    print(json.dumps(summary, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
