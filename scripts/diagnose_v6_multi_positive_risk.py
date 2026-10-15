"""One frozen local synthetic diagnostic. NOT_TRAINER; never auto-retry.

Importing is inert. Only main with both explicit CLI gates may create the
fixed create-once root. Raw gradients stay in capped local JSON, not stdout.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'contracts/ranking_v6_multi_positive_risk_diagnostic_v1.json'
OUTPUT = ROOT.parent / 'runtime_training_staging_20260928/v6_multi_positive_risk_20261015_r1'
KERNEL = ROOT / 'src/models/ranking_v6_multi_positive_conditional_risk.py'
CONTRACT_SHA = '3dc1b75cdd4752639b02354b586991d312311d2fa9cd3a514ab86a523b4ec970'
MAX_JSON_BYTES = 1024 * 1024
FALSE_FLAGS = ('adaptive_samples', 'confidence_interval_claim',
               'universal_variance_reduction_claim', 'real_training_release',
               'remote_allowed', 'torch_allowed', 'optimizer_allowed',
               'real_label_reads_allowed', 'blind_allowed', 'lsf_tessent_allowed')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_contract(contract):
    if any(contract.get(key) is not False for key in FALSE_FLAGS):
        raise ValueError('CONTRACT_FORBIDDEN_FLAG')
    if type(contract.get('formal_runs')) is not int or contract['formal_runs'] != 1:
        raise ValueError('CONTRACT_FORMAL_RUNS')
    if type(contract.get('automatic_retries')) is not int or contract['automatic_retries'] != 0:
        raise ValueError('CONTRACT_RETRIES')
    expected = {'actions': 736, 'k': 10, 'scores': 'all zero',
                'positive_counts': [1, 6], 'seeds': [11, 29, 47], 'samples_per_seed': 512}
    if contract.get('large_cases') != expected or len(contract.get('small_exact_cases', [])) != 5:
        raise ValueError('CONTRACT_FIXED_CASES')
    if (contract.get('small_exact_tolerance') != 1e-11
            or contract.get('large_risk_and_positive_gradient_absolute_tolerance') != 1e-12
            or contract.get('max_nominal_large_work') != 22609920
            or contract.get('max_nominal_work_per_call') != 20000000):
        raise ValueError('CONTRACT_FIXED_BOUNDS')


def load_contract(path, supplied_sha):
    if supplied_sha != CONTRACT_SHA:
        raise ValueError('CLI_CONTRACT_PIN')
    raw = path.read_bytes()
    if sha(raw) != CONTRACT_SHA:
        raise ValueError('CONTRACT_CONTENT_PIN')
    contract = json.loads(raw)
    validate_contract(contract)
    return contract


def uniform_reference(n, m, k):
    if n - m < k:
        return {'risk': 0., 'positive_gradient_each': 0., 'negative_gradient_each': 0.}
    risk = math.prod((n - m - t) / (n - t) for t in range(k))
    harmonic = math.fsum(1. / (n - t) for t in range(k))
    return {'risk': risk, 'positive_gradient_each': -risk * harmonic,
            'negative_gradient_each': risk * m / (n - m) * harmonic}


def check_result(result, scores):
    """Fail closed on missing safety flags or malformed numeric maps."""
    for name, value in {'synthetic_only': True, 'trainer_implemented': False,
                        'scalar_loss_implemented': False, 'real_data_access': False,
                        'online_cost_replay': False, 'trajectories_retained': False,
                        'positive_stopping_integrated': True,
                        'proposal_score_term_included': True}.items():
        if result.get(name) is not value:
            raise ValueError('KERNEL_FLAG_' + name)
    grad = result.get('miss_score_gradient')
    if type(grad) is not dict or set(grad) != set(scores):
        raise ValueError('KERNEL_GRADIENT_JOIN')
    risk = result.get('expected_miss_probability')
    if (type(risk) not in (int, float) or not math.isfinite(risk) or not 0 <= risk <= 1
            or any(type(v) not in (int, float) or not math.isfinite(v) for v in grad.values())):
        raise ValueError('KERNEL_NONFINITE_OR_RANGE')


def summarize_large(result, scores, positives, reference, tolerance):
    check_result(result, scores)
    grad = result['miss_score_gradient']
    pos_error = max(abs(grad[u] - reference['positive_gradient_each']) for u in positives)
    neg_errors = [abs(grad[u] - reference['negative_gradient_each']) for u in scores if u not in positives]
    risk_error = abs(result['expected_miss_probability'] - reference['risk'])
    positive_negative = all(grad[u] < 0 for u in positives)
    return {'risk_absolute_error': risk_error, 'positive_max_absolute_error': pos_error,
            'positive_strictly_negative': positive_negative,
            'risk_and_positive_signal_pass': risk_error <= tolerance and pos_error <= tolerance and positive_negative,
            'negative_max_absolute_error': max(neg_errors),
            'negative_mean_absolute_error': math.fsum(neg_errors) / len(neg_errors),
            'negative_wrong_sign_count': sum(grad[u] <= 0 for u in scores if u not in positives),
            'negative_direction_certified': False, 'full_gradient_precision_certified': False}


def run_diagnostic(contract, *, estimate_fn=None, exact_fn=None, oracle_fn=None):
    """Fixed fixtures only; dependencies injectable for bounded unit tests."""
    validate_contract(contract)
    if estimate_fn is None or exact_fn is None or oracle_fn is None:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from src.models import ranking_v6_multi_positive_conditional_risk as kernel
        from src.models.ranking_v6_first_hit_exact_gradient import enumerate_exact_gradient as old_oracle
        estimate_fn = estimate_fn or kernel.estimate
        exact_fn = exact_fn or kernel.enumerate_exact_gradient
        oracle_fn = oracle_fn or old_oracle
    small, large = [], []
    for case in contract['small_exact_cases']:
        scores = {str(i): v for i, v in enumerate(case['scores'])}
        positives = {str(i) for i in case['positive_indices']}
        result = exact_fn(scores, positives, k=case['k'], synthetic_only=True)
        check_result(result, scores)
        old = oracle_fn(scores, positives, {u: 1. for u in scores}, k=case['k'])
        risk_error = abs(result['expected_miss_probability'] - old['expected_miss_probability'])
        grad_error = max(abs(result['miss_score_gradient'][u] - old['miss_score_gradient'][u]) for u in scores)
        structural = len(scores) - len(positives) < case['k']
        zero_pass = (not structural or (result.get('guaranteed_hit') is True
                     and result['expected_miss_probability'] == 0.
                     and all(v == 0. for v in result['miss_score_gradient'].values())))
        small.append({'fixture': case, 'result': result,
                      'full_pl_oracle_risk': old['expected_miss_probability'],
                      'full_pl_oracle_miss_score_gradient': old['miss_score_gradient'],
                      'risk_absolute_error': risk_error, 'gradient_max_absolute_error': grad_error,
                      'structural_zero_required': structural, 'structural_zero_pass': zero_pass,
                      'pass': risk_error <= contract['small_exact_tolerance']
                      and grad_error <= contract['small_exact_tolerance'] and zero_pass})
    fixed = contract['large_cases']
    scores = {str(i): 0. for i in range(fixed['actions'])}
    for count in fixed['positive_counts']:
        positives = {str(i) for i in range(count)}
        reference = uniform_reference(len(scores), count, fixed['k'])
        for seed in fixed['seeds']:
            result = estimate_fn(scores, positives, k=fixed['k'], seed=seed,
                                 samples=fixed['samples_per_seed'], synthetic_only=True)
            summary = summarize_large(result, scores, positives, reference,
                                      contract['large_risk_and_positive_gradient_absolute_tolerance'])
            large.append({'positive_count': count, 'seed': seed, 'samples': fixed['samples_per_seed'],
                          'analytic_reference': reference, 'result': result, 'summary': summary})
    passed = all(row['pass'] for row in small) and all(row['summary']['risk_and_positive_signal_pass'] for row in large)
    return {'status': 'PASS_CORRECTNESS_AND_POSITIVE_SIGNAL_ONLY' if passed else 'FAIL_FIXED_DIAGNOSTIC',
            'small_exact_cases': small, 'large_cases': large,
            'negative_direction_certified': False, 'full_gradient_precision_certified': False,
            'confidence_interval_claim': False, 'universal_variance_reduction_claim': False,
            'not_trainer': True, 'model_instances': 0, 'optimizer_instances': 0,
            'real_label_reads': 0, 'remote_calls': 0, 'torch_calls': 0, 'training_runs': 0,
            'blind_access': False, 'lsf_tessent_calls': 0, 'formal_runs': 1, 'automatic_retries': 0}


def encode_capped(value):
    raw = (json.dumps(value, sort_keys=True, allow_nan=False, separators=(',', ':')) + '\n').encode('utf-8')
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError('JSON_SIZE_CAP')
    return raw


def execute_once(contract, output, *, runner=run_diagnostic, sources=None):
    """Private test seam; production main supplies only the fixed local root."""
    validate_contract(contract)
    if output.exists():
        raise FileExistsError('CREATE_ONCE_ROOT_EXISTS')
    output.mkdir(parents=True, exist_ok=False)
    metadata = {'contract_sha256': CONTRACT_SHA, 'python': sys.version,
                'platform': platform.platform(), 'once': True, 'automatic_retries': 0}
    try:
        metadata['source_sha256'] = {str(path): sha(path.read_bytes()) for path in
                                    (sources or (KERNEL, Path(__file__).resolve(), CONTRACT,
                                     ROOT / 'src/models/ranking_v6_first_hit_exact_gradient.py',
                                     ROOT / 'src/models/ranking_v6_first_hit_reference.py'))}
        with (output / 'once.json').open('xb') as stream:
            stream.write(encode_capped(metadata))
        result = runner(contract)
        raw = encode_capped({'provenance': metadata, 'diagnostic': result})
        with (output / 'result.json').open('xb') as stream:
            stream.write(raw)
        digest = sha(raw)
        with (output / 'result.sha256').open('x', encoding='ascii') as stream:
            stream.write(digest + '\n')
        return {'status': result['status'], 'artifact_sha256': digest,
                'artifact': str(output / 'result.json')}, 0 if result['status'].startswith('PASS_') else 1
    except Exception as exc:
        failure = {'status': 'FAIL_FIXED_DIAGNOSTIC', 'provenance': metadata,
                   'exception_type': type(exc).__name__, 'error': str(exc)[:2000], 'retry_allowed': False}
        with (output / 'failure.json').open('xb') as stream:
            stream.write(encode_capped(failure))
        return {'status': 'FAIL_FIXED_DIAGNOSTIC', 'failure': str(output / 'failure.json')}, 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--contract-sha256', required=True)
    args = parser.parse_args(argv)
    if not args.execute:
        parser.error('--execute is required; importing or checking help never runs fixtures')
    try:
        contract = load_contract(CONTRACT, args.contract_sha256)
        summary, exit_code = execute_once(contract, OUTPUT)
    except Exception as exc:
        print(json.dumps({'status': 'FAIL_CLOSED_BEFORE_RUN', 'error': str(exc)[:500]}))
        return 1
    print(json.dumps(summary, sort_keys=True))
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
