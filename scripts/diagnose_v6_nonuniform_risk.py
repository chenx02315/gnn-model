"""E27 fixed generated three-score-class diagnostic; NOT_TRAINER.

Inert on import. Only the fixed --execute/contract SHA CLI can create the
one-use output. No fitting, adaptive samples, retries or remote/data access.
Risk/positive stochastic errors are reported, not given invented thresholds.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'contracts/ranking_v6_nonuniform_risk_diagnostic_v1.json'
CONTRACT_SHA = '0177018f287312a251597172055a7b76c136943cf619ce63a295428879d92eea'
OUTPUT = ROOT.parent / 'runtime_training_staging_20260928/v6_nonuniform_risk_20261015_r1'
MAX_JSON_BYTES = 2 * 1024 * 1024
PILOT_SEED_XOR = 0x9E3779B9
PASS = 'PASS_FIXED_NONUNIFORM_REDUCTION_ONLY'
FAIL = 'FAIL_FIXED_NONUNIFORM_REDUCTION'
FALSE_FLAGS = ('adaptive_samples', 'coefficient_tuning', 'confidence_interval_claim',
               'universal_variance_reduction_claim', 'real_training_release',
               'remote_allowed', 'torch_allowed', 'optimizer_allowed',
               'real_label_reads_allowed', 'blind_allowed', 'lsf_tessent_allowed')
CONDITIONS = [{'name': 'rare', 'positive_score': -2.0, 'seed': 149},
              {'name': 'neutral', 'positive_score': 0.0, 'seed': 173},
              {'name': 'favored', 'positive_score': 2.0, 'seed': 197}]
SMALL_CASES = [{'counts': [1, 2, 2], 'scores': [-2.0, -1.0, 1.0], 'k': 2},
               {'counts': [2, 1, 2], 'scores': [0.0, -1.0, 1.0], 'k': 3},
               {'counts': [1, 2, 1], 'scores': [2.0, -1.0, 1.0], 'k': 2}]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_contract(contract):
    if any(contract.get(key) is not False for key in FALSE_FLAGS):
        raise ValueError('CONTRACT_FORBIDDEN_FLAG')
    fixed = {'experiment_id': 'E27', 'actions': 736, 'k': 10,
             'positive_counts': [1, 6],
             'negative_a_count': 'floor((actions-positive_count)/2)',
             'negative_b_count': 'actions-positive_count-negative_a_count',
             'negative_a_score': -1.0, 'negative_b_score': 1.0,
             'conditions': CONDITIONS, 'raw_samples': 512,
             'controlled_pilot_samples': 32, 'controlled_main_samples': 480,
             'control_coefficient': 1, 'pairs': 6, 'total_paths': 6144,
             'nominal_work_per_arm_per_case': 3768320,
             'total_nominal_work': 45219840, 'small_reference_cases': SMALL_CASES,
             'small_reference_absolute_tolerance': 1e-11,
             'gradient_sum_absolute_tolerance': 1e-12,
             'formal_runs': 1, 'automatic_retries': 0}
    for key, value in fixed.items():
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
    from src.models import ranking_v6_multi_positive_conditional_risk as raw
    from src.models import ranking_v6_multi_positive_risk_control as control
    from src.models import ranking_v6_grouped_risk_reference as grouped
    return raw, control, grouped


def fixture(counts, scores):
    """Return all generated UIDs, positives and explicit three-class join."""
    classes, values, positives = {}, {}, set()
    for label, prefix, count, score in zip(('positive', 'negative_a', 'negative_b'),
                                         ('p', 'a', 'b'), counts, scores):
        for index in range(count):
            uid = f'{prefix}{index:03d}'
            values[uid] = score
            classes[uid] = label
            if label == 'positive':
                positives.add(uid)
    return values, positives, classes


def check_result(result, scores):
    for key, value in {'synthetic_only': True, 'trainer_implemented': False,
                       'scalar_loss_implemented': False, 'real_data_access': False,
                       'online_cost_replay': False, 'trajectories_retained': False,
                       'positive_stopping_integrated': True,
                       'proposal_score_term_included': True}.items():
        if result.get(key) is not value:
            raise ValueError('KERNEL_FLAG_' + key)
    gradient = result.get('miss_score_gradient')
    risk = result.get('expected_miss_probability')
    if type(gradient) is not dict or set(gradient) != set(scores):
        raise ValueError('KERNEL_GRADIENT_JOIN')
    if (type(risk) not in (int, float) or not math.isfinite(risk) or not 0 <= risk <= 1
            or any(type(v) not in (int, float) or not math.isfinite(v) for v in gradient.values())):
        raise ValueError('KERNEL_NONFINITE_OR_RANGE')
    # Both public aliases are emitted by the frozen kernels: retain consistency.
    if result.get('uid_gradient') != gradient or result.get('mean_risk') != risk:
        raise ValueError('KERNEL_ALIAS_MISMATCH')


def check_arm(result, scores, seed, controlled):
    check_result(result, scores)
    expected = {'seed': seed, 'samples': 480 if controlled else 512,
                'action_count': len(scores),
                'positive_count': sum(u.startswith('p') for u in scores),
                'k': 10, 'temperature': 1, 'guaranteed_hit': False,
                'nominal_work': 3768320, 'work_bound': 3768320, 'max_work': 20000000,
                'trajectory_count': 480 if controlled else 512}
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


def reference_gradient(reference, uid_classes):
    """Expand the exchangeable class reference to every generated UID."""
    per_class = reference['miss_per_individual_score_gradient']
    if set(per_class) != {'positive', 'negative_a', 'negative_b'}:
        raise ValueError('REFERENCE_CLASSES')
    counts = reference.get('counts')
    if (type(counts) is not dict or set(counts) != set(per_class)
            or any(type(counts[label]) is not int
                   or counts[label] != sum(value == label for value in uid_classes.values())
                   for label in per_class)):
        raise ValueError('REFERENCE_COUNT_JOIN')
    risk = reference.get('expected_miss_probability')
    if (reference.get('synthetic_only') is not True
            or any(reference.get(key) is not False for key in
                   ('real_data_access', 'optimizer_implemented', 'trainer_implemented',
                    'trajectories_retained'))
            or type(risk) not in (int, float) or not math.isfinite(risk) or not 0 <= risk <= 1
            or any(type(v) not in (int, float) or not math.isfinite(v) for v in per_class.values())):
        raise ValueError('REFERENCE_SCHEMA')
    return {uid: per_class[label] for uid, label in uid_classes.items()}


def summarize(result, positives, expected, risk):
    gradient = result['miss_score_gradient']
    errors = {u: abs(gradient[u] - expected[u]) for u in expected}
    positive_errors = [errors[u] for u in expected if u in positives]
    negative_errors = [errors[u] for u in expected if u not in positives]
    gradient_sum = math.fsum(gradient.values())
    return {'risk_absolute_error': abs(result['expected_miss_probability'] - risk),
            'positive_mean_absolute_error': math.fsum(positive_errors) / len(positive_errors),
            'positive_max_absolute_error': max(positive_errors),
            'negative_mean_absolute_error': math.fsum(negative_errors) / len(negative_errors),
            'negative_max_absolute_error': max(negative_errors),
            'negative_nonpositive_count': sum(gradient[u] <= 0 for u in expected if u not in positives),
            'full_gradient_l2_error': math.sqrt(math.fsum(v*v for v in errors.values())),
            'gradient_sum': gradient_sum, 'gradient_sum_absolute_error': abs(gradient_sum),
            'schema_and_finiteness_pass': True,
            'shift_gradient_sum_pass': abs(gradient_sum) <= 1e-12}


def run_diagnostic(contract, *, raw_fn=None, control_fn=None, reference_fn=None, exact_fn=None):
    """Fixed cases; only injectable dependencies, never production CLI overrides."""
    validate_contract(contract)
    raw_kernel, control_kernel, grouped = _imports()
    raw_fn = raw_fn or raw_kernel.estimate
    control_fn = control_fn or control_kernel.estimate
    reference_fn = reference_fn or grouped.reference
    exact_fn = exact_fn or raw_kernel.enumerate_exact_gradient
    small, large = [], []
    for case in contract['small_reference_cases']:
        scores, positives, classes = fixture(case['counts'], case['scores'])
        reference = reference_fn(*case['counts'], *case['scores'], k=case['k'], synthetic_only=True)
        expected = reference_gradient(reference, classes)
        oracle = exact_fn(scores, positives, k=case['k'], synthetic_only=True)
        check_result(oracle, scores)
        risk_error = abs(reference['expected_miss_probability'] - oracle['mean_risk'])
        gradient_error = max(abs(expected[u] - oracle['uid_gradient'][u]) for u in scores)
        small.append({'fixture': case, 'reference': reference, 'uid_class': classes,
                      'reference_uid_gradient': expected, 'decimal80_oracle': oracle,
                      'risk_absolute_error': risk_error, 'gradient_max_absolute_error': gradient_error,
                      'pass': risk_error <= 1e-11 and gradient_error <= 1e-11})
    for m in contract['positive_counts']:
        a = (736 - m) // 2
        counts = [m, a, 736 - m - a]
        for condition in contract['conditions']:
            values = [condition['positive_score'], -1.0, 1.0]
            scores, positives, classes = fixture(counts, values)
            reference = reference_fn(*counts, *values, k=10, synthetic_only=True)
            expected = reference_gradient(reference, classes)
            seed = condition['seed']
            raw = raw_fn(scores, positives, k=10, seed=seed, samples=512, synthetic_only=True)
            controlled = control_fn(scores, positives, k=10, seed=seed, samples=480,
                                    pilot_samples=32, synthetic_only=True)
            check_arm(raw, scores, seed, False)
            check_arm(controlled, scores, seed, True)
            ar, ac = [summarize(arm, positives, expected, reference['expected_miss_probability'])
                      for arm in (raw, controlled)]
            passed = (ar['shift_gradient_sum_pass'] and ac['shift_gradient_sum_pass']
                      and ac['full_gradient_l2_error'] < ar['full_gradient_l2_error']
                      and ac['negative_mean_absolute_error'] < ar['negative_mean_absolute_error']
                      and ac['negative_max_absolute_error'] < ar['negative_max_absolute_error']
                      and ac['negative_nonpositive_count'] <= ar['negative_nonpositive_count'])
            large.append({'positive_count': m, 'condition': condition, 'class_counts': counts,
                          'class_scores': values, 'seed': seed, 'uid_class': classes,
                          'reference': reference, 'reference_uid_gradient': expected,
                          'raw': raw, 'controlled': controlled,
                          'raw_summary': ar, 'controlled_summary': ac, 'pass': passed})
    passed = all(row['pass'] for row in small + large)
    return {'status': PASS if passed else FAIL, 'small_reference_cases': small, 'large_pairs': large,
            'total_paths': 6144, 'total_nominal_work': 45219840,
            'same_total_paths_per_arm_not_equal_runtime': True,
            'coverage_limit': contract['coverage_limit'],
            'risk_and_positive_errors_thresholded': False,
            'confidence_interval_claim': False, 'universal_variance_reduction_claim': False,
            'arbitrary_nonuniformity_certified': False, 'real_training_ready': False,
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
            ROOT / 'src/models/ranking_v6_grouped_risk_reference.py',
            ROOT / 'src/models/ranking_v6_multi_positive_conditional_risk.py',
            ROOT / 'src/models/ranking_v6_multi_positive_risk_control.py')


def execute_once(contract, output, *, runner=run_diagnostic, sources=None):
    """Test seam only; production CLI cannot change output, sources or fixtures."""
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
