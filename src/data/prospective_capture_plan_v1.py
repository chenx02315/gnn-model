"""Offline configuration assessment, never execution authority or artifact verification."""
import math
import re

PINS = (
    'candidate_domain_policy_sha256', 'candidate_roster_sha256',
    'policy_orders_sha256', 'seed_manifest_sha256', 'shared_prefix_policy_sha256',
    'cache_policy_sha256', 'driver_sha256', 'recorder_sha256',
    'runner_adapter_sha256', 'environment_manifest_sha256',
    'storage_manifest_sha256', 'd95_fault_universe_sha256',
    'split_contract_sha256', 'frozen_model_sha256',
    'external_preregistration_receipt_sha256', 'execution_authorization_receipt_sha256')
FAMILIES = {'aes_core': 'iwls_aes_core', 'spi': 'iwls_spi'}
KEYS = {'schema_version', 'status', 'scope', 'mode_sizes', 'quality_floor',
        'objective', 'freeze_components', 'limits', 'comparison', 'execution_ready'}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def assess_plan(plan):
    require(type(plan) is dict and set(plan) == KEYS, 'PLAN_SCHEMA')
    require(plan['schema_version'] == 'prospective_capture_plan_v1'
            and plan['status'] == 'DRAFT_NOT_REGISTERED', 'OFFLINE_DRAFT_ONLY')
    require(plan['execution_ready'] is False, 'NO_EXECUTION_AUTHORITY')
    scope = plan['scope']
    require(type(scope) is dict and set(scope) == {'circuits', 'family_by_circuit', 'role'}, 'SCOPE_SCHEMA')
    require(scope['circuits'] == ['aes_core', 'spi'] and scope['family_by_circuit'] == FAMILIES
            and scope['role'] == 'TRAIN_ONLY', 'FIXED_TRAIN_SCOPE')
    require(type(plan['mode_sizes']) is dict and set(plan['mode_sizes']) == {'H', 'M', 'F'}
            and all(type(plan['mode_sizes'][key]) is int for key in ('H', 'M', 'F'))
            and plan['mode_sizes'] == {'H': 64, 'M': 16, 'F': 4}, 'FIXED_MODE_SIZES')
    require(plan['quality_floor'] == 'D95'
            and plan['objective'] == 'cumulative_atomic_atpg_process_wall_ns', 'OBJECTIVE')
    pins = plan['freeze_components']
    require(type(pins) is dict and set(pins) == set(PINS), 'PIN_SCHEMA')
    missing = []
    for key in PINS:
        value = pins[key]
        if value is None:
            missing.append('freeze_components.' + key)
        else:
            require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None,
                    'PIN_SHA256')
    limits = plan['limits']
    require(type(limits) is dict and set(limits) == {
        'memory_limit_bytes', 'attempt_wall_timeout_s', 'max_physical_attempts',
        'candidate_count', 'workers', 'automatic_retries'}, 'LIMIT_SCHEMA')
    require(type(limits['workers']) is int and limits['workers'] == 1
            and type(limits['automatic_retries']) is int and limits['automatic_retries'] == 0,
            'SINGLE_WORKER_ZERO_RETRIES')
    for key in ('memory_limit_bytes', 'attempt_wall_timeout_s', 'max_physical_attempts', 'candidate_count'):
        value = limits[key]
        if value is None:
            missing.append('limits.' + key)
        else:
            require(type(value) is int and 0 < value <= 2**63-1, 'POSITIVE_LIMIT')
    comparison = plan['comparison']
    require(type(comparison) is dict and set(comparison) == {
        'policies', 'epsilon', 'epsilon_reference', 'online_elapsed_claim',
        'formal_generalization_claim'}, 'COMPARISON_SCHEMA')
    require(comparison['policies'] == ['fixed_rule', 'frozen_model', 'seeded_random']
            and comparison['epsilon_reference'] == 'frozen_pilot_roster_only'
            and comparison['online_elapsed_claim'] is False
            and comparison['formal_generalization_claim'] is False, 'PILOT_COMPARISON_ONLY')
    value = comparison['epsilon']
    if value is None:
        missing.append('comparison.epsilon')
    else:
        require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1,
                'EPSILON')
    return {'schema_valid': True, 'configuration_complete': not missing,
            'missing_fields': missing, 'artifact_contents_verified': False,
            'preregistration_authenticated': False, 'execution_authority_verified': False,
            'execution_ready': False, 'training_release': False,
            'status': 'OFFLINE_CONFIGURATION_ONLY_EXTERNAL_GATES_REQUIRED'}
