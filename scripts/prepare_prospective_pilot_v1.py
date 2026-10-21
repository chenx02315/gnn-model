"""Bounded offline preparation from fixed repository code/contracts; no datasets."""
import copy
import hashlib
import json
from pathlib import Path
import sys

from src.data.prospective_capture_plan_v1 import assess_plan

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    'contracts/prospective_capture_plan_v1.template.json',
    'contracts/prospective_capture_protocol_v1.json',
    'contracts/prospective_pilot_policy_v1.json',
    'contracts/data_split_v1.json',
    'contracts/formal_candidate_space_v2.json',
    'contracts/runtime_policy_v1.json',
    'contracts/runtime_policy_v2.json',
    'contracts/runtime_training_v2.json',
    'src/data/prospective_attempt_ledger_v1.py',
    'src/data/prospective_dummy_adapter_v1.py',
)


def require(ok, code):
    if not ok:
        raise ValueError(code)


def read_sources(root):
    evidence = {}
    documents = {}
    for name in SOURCES:
        path = root / name
        require(path.is_file() and not path.is_symlink(), 'FIXED_REGULAR_SOURCE_REQUIRED')
        require(path.stat().st_size <= 65536, 'SOURCE_SIZE_LIMIT')
        raw = path.read_bytes()
        require(len(raw) <= 65536, 'SOURCE_SIZE_LIMIT')
        evidence[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        if name.endswith('.json'):
            documents[name] = json.loads(raw)
    return evidence, documents


def prepare(root=ROOT):
    evidence, docs = read_sources(Path(root))
    original = docs['contracts/prospective_capture_plan_v1.template.json']
    before = assess_plan(original)
    plan = copy.deepcopy(original)
    split = docs['contracts/data_split_v1.json']
    train = {row['circuit']: row['family'] for row in split['formal_runtime_membership']['TRAIN']}
    require(all(train.get(c) == f for c, f in plan['scope']['family_by_circuit'].items()), 'TRAIN_MEMBERSHIP_MISMATCH')
    resolved = {
        'recorder_sha256': 'src/data/prospective_attempt_ledger_v1.py',
        'split_contract_sha256': 'contracts/data_split_v1.json',
    }
    for key, name in resolved.items():
        plan['freeze_components'][key] = evidence[name]['sha256']
    policy = docs['contracts/prospective_pilot_policy_v1.json']
    require(policy['comparison']['proposed_epsilon'] == docs['contracts/runtime_training_v2.json']['scope']['epsilon'] == 0.01,
            'PRESERVE_ONE_PERCENT_TARGET')
    plan['comparison']['epsilon'] = policy['comparison']['proposed_epsilon']
    after = assess_plan(plan)
    require(len(before['missing_fields']) == 21 and len(after['missing_fields']) == 18, 'EXPECTED_PARTIAL_RESOLUTION')
    require(policy['runtime']['automatic_retries'] == 0 and policy['reuse']['prefix_reuse_enabled'] is False, 'NEW_POLICY_BOUNDARY')
    require(policy['execution_ready'] is False and policy['training_release'] is False, 'NO_RELEASE')
    historical = docs['contracts/formal_candidate_space_v2.json']['eligible_measurement_rule']
    require(historical['result_status'] == 'PASS', 'HISTORICAL_SELECTION_CHANGED')
    old = docs['contracts/runtime_policy_v1.json']
    require(old['retry']['max_retry_per_stage'] == 1 and old['prefix_reuse']['enabled'] is True
            and old['timeouts']['timeout_cost_if_elapsed_missing'] == 'configured_stage_timeout_s', 'OLD_POLICY_DRIFT')
    return dict(schema='prospective-pilot-preparation-v1', status='PARTIAL_LOCAL_PREPARATION_NOT_EXECUTABLE',
        evidence=evidence, plan=plan, assessment=after,
        resolved_pin_sources=resolved, original_missing_count=21, remaining_missing_count=18,
        pins_mean='Current local bytes only; split membership checked, not historical recovery/release. Recorder is library only, not an actual ATPG adapter.',
        proposals=dict(policy_path='contracts/prospective_pilot_policy_v1.json',
            epsilon=policy['comparison']['proposed_epsilon'], seeds=policy['comparison']['proposed_seeds'],
            epsilon_carried_as_draft_only=True, seeds_applied_to_plan=False, actual_execution_allowed=False),
        historical_roster_not_reused='Historical formal_candidate_space_v2 selects PASS measurements. It cannot establish an outcome-independent prospective roster.',
        legacy_policy_conflicts=policy['old_policy_compatibility']['conflicts'],
        prohibited_substitutions=['E66 dummy as real runner','current driver hash as historical execution proof',
            'historical PASS table as prospective candidate freeze','training memory cap as ATPG cap',
            'configured timeout as missing wall time','filled SHA as authenticated preregistration'],
        next_work=['Freeze legal structural roster and exact three policy permutations without future outcomes',
            'Bind real ATPG atomic-process adapter, D95 fault set, inputs and driver/config',
            'Verify actual environment/storage/memory/time/attempt budgets',
            'Seal whole package with external preregistration and scope-specific authority'],
        remote_access=False, real_data_read=False, execution_ready=False, training_release=False)


def main():
    require(len(sys.argv) == 2, 'ONE_NEW_LOCAL_OUTPUT_DIRECTORY_REQUIRED')
    output = Path(sys.argv[1]).resolve()
    staging = ROOT.parent / 'runtime_training_staging_20260928'
    require(output.parent == staging.resolve() and output.name.startswith('v6_e67_preparation_'), 'LOCAL_OUTPUT_SCOPE')
    result = prepare()
    output.mkdir(exist_ok=False)
    with (output / 'preparation.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status=result['status'], remaining_missing_count=result['remaining_missing_count'], execution_ready=False)))


if __name__ == '__main__':
    main()
