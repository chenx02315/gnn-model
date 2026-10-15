"""Bounded fixture-only adapter, NOT a real-data bridge or provenance detector.

``synthetic_only=True`` is the caller's declaration, not proof of provenance.
There is no I/O, Torch, RNG, optimizer, reader, remote access or training here.
The name describes a future interface shape, NOT authorization for real data.
Only already-materialized synthetic FIT fixtures are in scope. Outcome labels
and charged costs remain separate from the seven unstandardized input columns.
"""
import math
import re

from .runtime_ranking_v3 import FEATURES

SCHEMA = 'ranking_v6_synthetic_real_bridge_fixture_v1'
MAX_ROWS = 4096
MAX_ACTIONS_PER_CIRCUIT = 1024
_ID = re.compile(r'[A-Za-z0-9_.-]{1,64}')
_FEATURE_KEYS = frozenset(('action_uid', 'family', 'circuit', 'role', *FEATURES))
_OUTCOME_KEYS = frozenset(('action_uid', 'total_cycles',
                           'policy_charged_runtime_s', 'is_d95_feasible',
                           'execution_status'))


def _require(condition, code):
    if not condition:
        raise ValueError('SYNTHETIC_BRIDGE_' + code)


def _identifier(value):
    _require(type(value) is str and _ID.fullmatch(value) is not None, 'IDENTIFIER')


def _number(value):
    _require(type(value) in (int, float), 'BUILTIN_NUMBER')
    try:
        valid = math.isfinite(value)
    except OverflowError:
        valid = False
    _require(valid, 'FINITE_NUMBER')


def prepare_fit_fixture(feature_rows, outcome_rows, *, synthetic_only=False):
    """Validate synthetic FIT rows and return deterministic per-circuit tasks.

    Every feature row, including its role, is checked before even inspecting
    the outcome container. Unsupported roles and fields fail closed. Failures
    are rejected, never silently filtered. Epsilon positives use exact integer
    arithmetic: 100 * cycles <= 101 * per-task minimum cycles.
    """
    _require(synthetic_only is True, 'SYNTHETIC_ONLY_GATE')
    _require(type(feature_rows) in (list, tuple) and
             1 <= len(feature_rows) <= MAX_ROWS, 'FEATURE_CONTAINER')
    groups, by_uid = {}, {}
    for row in feature_rows:
        _require(type(row) is dict and row.keys() == _FEATURE_KEYS, 'FEATURE_SCHEMA')
        _require(type(row['role']) is str and row['role'] == 'FIT', 'FIT_ONLY')
        for field in ('action_uid', 'family', 'circuit'):
            _identifier(row[field])
        uid, circuit, family = row['action_uid'], row['circuit'], row['family']
        _require(uid not in by_uid, 'DUPLICATE_UID')
        for name in FEATURES:
            _number(row[name])
        _require(row['scheme_hf'] in (0, 1) and row['scheme_hmf'] in (0, 1)
                 and row['scheme_hf'] + row['scheme_hmf'] == 1, 'SCHEME_ONEHOT')
        for name in ('h_limit_fraction_of_circuit_max', 'm_limit_fraction_of_circuit_max'):
            _require(0 <= row[name] <= 1, 'FRACTION_DOMAIN')
        for name in ('log1p_h_limit', 'log1p_m_limit', 'log1p_common_fault_count'):
            _require(row[name] >= 0, 'LOG_DOMAIN')
        group = groups.setdefault(circuit, {'family': family, 'uids': []})
        _require(group['family'] == family, 'CIRCUIT_FAMILY')
        _require(len(group['uids']) < MAX_ACTIONS_PER_CIRCUIT, 'CIRCUIT_CAP')
        group['uids'].append(uid)
        by_uid[uid] = tuple(row[name] for name in FEATURES)

    # Deliberately no reference to outcome_rows above this barrier.
    _require(type(outcome_rows) in (list, tuple) and
             1 <= len(outcome_rows) <= MAX_ROWS, 'OUTCOME_CONTAINER')
    outcomes = {}
    for row in outcome_rows:
        _require(type(row) is dict and row.keys() == _OUTCOME_KEYS, 'OUTCOME_SCHEMA')
        uid = row['action_uid']
        _identifier(uid)
        _require(uid in by_uid and uid not in outcomes, 'OUTCOME_UID_JOIN')
        cycles, cost = row['total_cycles'], row['policy_charged_runtime_s']
        _require(type(cycles) is int and 0 < cycles <= 10**15, 'CYCLES_DOMAIN')
        _number(cost)
        _require(0 < cost <= 1e9, 'COST_DOMAIN')
        _require(type(row['is_d95_feasible']) is int and row['is_d95_feasible'] == 1,
                 'D95_FEASIBLE_REQUIRED')
        _require(type(row['execution_status']) is str and
                 row['execution_status'] == 'SUCCESS', 'SUCCESS_REQUIRED')
        outcomes[uid] = (cycles, cost)
    _require(outcomes.keys() == by_uid.keys(), 'OUTCOME_EXACT_JOIN')

    tasks = []
    for circuit in sorted(groups):
        group = groups[circuit]
        uids = tuple(sorted(group['uids']))
        oracle = min(outcomes[uid][0] for uid in uids)
        tasks.append({
            'circuit': circuit, 'family': group['family'], 'action_uids': uids,
            'features': tuple(by_uid[uid] for uid in uids),
            'costs': {uid: outcomes[uid][1] for uid in uids},
            'positive_uids': tuple(uid for uid in uids if 100 * outcomes[uid][0] <= 101 * oracle),
            'oracle_cycles': oracle,
        })
    return {
        'schema': SCHEMA, 'scope': 'synthetic_fit_fixture_only',
        'synthetic_only': True, 'synthetic_declaration_is_provenance_detector': False,
        'feature_names': FEATURES, 'features_standardized': False,
        'costs_are_features': False, 'oracle_is_feature': False,
        'actual_training': False, 'real_data_access': False,
        'online_cost_replay': False, 'tasks': tuple(tasks),
    }
