"""Fixed local evidence convergence; no datasets, subprocesses or remote calls."""
import hashlib
import json
from pathlib import Path
import sys

from src.data.prospective_pilot_budget_v1 import calculate_budget

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    'contracts/prospective_pilot_readiness_e79_v1.json',
    'data/manifests/ranking_v6_e67_preparation_20261021_r1.json',
    'data/manifests/ranking_v6_e68_template_summary_20261021_r1.json',
    'data/manifests/ranking_v6_e70_observation_summary_20261021_r1.json',
    'data/manifests/ranking_v6_e71_preparation_20261021_r1.json',
    'data/manifests/ranking_v6_e78_actual_validation_20261022_r1.json',
    'data/manifests/ranking_v6_e78_result_review_20261022_r1.json',
    'src/data/prospective_input_binding_v1.py',
    'src/data/prospective_pilot_budget_v1.py',
    '../phase4_closure_driver_v2_reference.py',
)
DRIVER_SHA = '4394d366098c7c64614dced1cade709373b315fc3749a8f93404d5c496ecfb94'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def prepare(root=ROOT):
    evidence, docs = {}, {}
    for name in SOURCES:
        path = Path(root) / name
        require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 65536,
                'FIXED_SMALL_REGULAR_SOURCE')
        raw = path.read_bytes()
        require(len(raw) <= 65536, 'SOURCE_CAP')
        evidence[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        if name.endswith('.json'):
            docs[name] = json.loads(raw)
    require(evidence[SOURCES[-1]]['sha256'] == DRIVER_SHA, 'REFERENCE_DRIVER_PIN')
    contract = docs[SOURCES[0]]
    require(contract['scope'] == dict(circuits=['aes_core', 'spi'], role='TRAIN_ONLY',
            mode_sizes=dict(H=64, M=16, F=4), quality_floor='D95', epsilon=0.01),
            'FIXED_RESEARCH_SCOPE')
    require(contract['execution_ready'] is False and contract['training_release'] is False,
            'NO_RELEASE')
    prior = docs[SOURCES[1]]
    require(len(prior['assessment']['missing_fields']) == 18, 'PRESERVE_E67_GAPS')
    actual = docs[SOURCES[5]]
    require(actual['status'] == 'PASS_FIXED_LINUX_JOURNAL_ONLY' and
            actual['real_atpg_jobs'] == 0 and actual['production_release'] is False,
            'SYNTHETIC_LINUX_NOT_ATPG')
    require(docs[SOURCES[6]]['verdict'] == 'PASS_FIXED_LINUX_JOURNAL_INTEGRATION_ONLY',
            'INDEPENDENT_LINUX_RECEIPT')
    observation = docs[SOURCES[3]]
    require(observation['actual_model_checkpoint_authenticated'] is False,
            'CHECKPOINT_REMAINS_UNVERIFIED')
    assessments = {c: calculate_budget(v) for c, v in
                   contract['conditional_budget']['real_caps_by_circuit'].items()}
    require(set(assessments) == {'aes_core', 'spi'} and
            all(v['status'] == 'INCOMPLETE_DESIGN' and
                v['total_physical_calls_upper'] is None for v in assessments.values()),
            'DO_NOT_INVENT_REAL_CAPS')
    example = calculate_budget(dict(f_full_pattern_bound=4, candidate_count_upper=2,
        sessions=3, endpoint_calls_per_session_upper=5, extra_calls_per_session_upper=7,
        prefix_rebuild_per_f_call=True, attempt_timeout_s=10, cleanup_timeout_s=2))
    return dict(schema='e79-pilot-convergence-result-v1',
        status='PASS_LOCAL_CONVERGENCE_ONLY_REAL_PILOT_BLOCKED', evidence=evidence,
        historical_e67_missing_fields_preserved=prior['assessment']['missing_fields'],
        known_fixed_linux_backend_is_not_tessent_adapter=True,
        work_packages=contract['work_packages'], current_budget_assessments=assessments,
        counts_declared_only_by_fault_manifests=observation[
            'common_fault_counts_declared_by_current_manifests'],
        synthetic_arithmetic_example=example,
        example_is_not_a_measured_or_authorized_pilot=True,
        reference_f_probe_formula='2+U+ceil(log2(U)); every additional future confirmation charged separately',
        semantic_checkpoint_compatibility_verified=False,
        real_candidate_count=None, real_atpg_memory_limit_bytes=None,
        real_atpg_timeout_s=None, actual_atpg_calls=0, new_remote_sessions=0,
        new_containers=0, new_training_runs=0, execution_ready=False, training_release=False)


def main():
    require(len(sys.argv) == 2, 'ONE_NEW_LOCAL_OUTPUT_DIRECTORY')
    output = Path(sys.argv[1]).resolve()
    staging = (ROOT.parent / 'runtime_training_staging_20260928').resolve()
    require(output.parent == staging and output.name.startswith('v6_e79_convergence_'),
            'FIXED_LOCAL_OUTPUT_SCOPE')
    result = prepare()
    output.mkdir(exist_ok=False)
    with (output / 'summary.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status=result['status'], execution_ready=False, training_release=False)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
