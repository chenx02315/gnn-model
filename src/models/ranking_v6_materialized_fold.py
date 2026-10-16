"""In-memory production-shaped fold preparation, not production permission.

All six TRAIN feature groups are validated before the fit-outcome container is
inspected. Only the five fitting groups determine the normalizer and targets.
No filesystem, reader, model, Torch, optimizer or held-outcome access exists.
Input attestation is a declaration, not a provenance or candidate-lineage proof.
"""
import hashlib
import json
import math
import re

from .runtime_ranking_v3 import FAMILIES, FEATURES


STATUS = 'IMPLEMENTATION_ONLY_NO_REAL_DATA_RELEASE'
SEEDS = (20260824, 20260825, 20260826)
MAX_ROWS = 6144
MAX_ACTIONS_PER_CIRCUIT = 1024
_IDENTIFIER = re.compile(r'[A-Za-z0-9_.-]{1,64}')
_FEATURE_KEYS = frozenset(('action_uid', 'circuit', 'family', 'role', *FEATURES))
_OUTCOME_KEYS = frozenset(('execution_status', 'is_d95_feasible', 'total_cycles',
                           'policy_charged_runtime_s'))


def _require(condition, code):
    if not condition:
        raise ValueError('MATERIALIZED_FOLD_' + code)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode('ascii')).hexdigest()


def _number(value, lower, upper, code, *, strict_lower=False):
    _require(type(value) in (int, float) and lower <= value <= upper
             and (not strict_lower or value > lower) and math.isfinite(value), code)


def _features(feature_rows, held_family, seed):
    _require(type(held_family) is str and held_family in FAMILIES.values(), 'HELD_FAMILY')
    _require(type(seed) is int and seed in SEEDS, 'SEED')
    _require(type(feature_rows) in (list, tuple) and 1 <= len(feature_rows) <= MAX_ROWS,
             'FEATURE_CONTAINER')
    by_uid, circuits = {}, {}
    for row in feature_rows:
        _require(type(row) is dict and row.keys() == _FEATURE_KEYS, 'FEATURE_SCHEMA')
        _require(type(row['role']) is str and row['role'] == 'TRAIN', 'TRAIN_ONLY')
        for name in ('action_uid', 'circuit', 'family'):
            _require(type(row[name]) is str and _IDENTIFIER.fullmatch(row[name]) is not None,
                     'IDENTIFIER')
        uid, circuit = row['action_uid'], row['circuit']
        _require(FAMILIES.get(circuit) == row['family'], 'EXACT_FAMILY_MAPPING')
        _require(uid not in by_uid, 'DUPLICATE_UID')
        for name in FEATURES:
            _number(row[name], -1e6, 1e6, 'RAW_FEATURE_DOMAIN')
        _require(row['scheme_hf'] in (0, 1) and row['scheme_hmf'] in (0, 1)
                 and row['scheme_hf'] + row['scheme_hmf'] == 1, 'SCHEME_ONEHOT')
        for name in ('h_limit_fraction_of_circuit_max', 'm_limit_fraction_of_circuit_max'):
            _require(0 <= row[name] <= 1, 'FRACTION_DOMAIN')
        for name in ('log1p_h_limit', 'log1p_m_limit', 'log1p_common_fault_count'):
            _require(row[name] >= 0, 'LOG_DOMAIN')
        members = circuits.setdefault(circuit, [])
        _require(len(members) < MAX_ACTIONS_PER_CIRCUIT, 'CIRCUIT_CAP')
        members.append(uid)
        by_uid[uid] = dict(row)
    _require(set(circuits) == set(FAMILIES), 'SIX_TRAIN_FAMILIES')
    return by_uid, circuits


def feature_split(feature_rows, *, held_family, seed, implementation_only=False):
    """Public feature-only barrier; returns detached UID-keyed metadata rows.

    No outcome/attempt container is accepted or inspected. Each row contains
    exactly the allowlisted metadata and seven raw input feature values.
    """
    _require(implementation_only is True, 'IMPLEMENTATION_OPT_IN')
    by_uid, _ = _features(feature_rows, held_family, seed)
    uids = sorted(by_uid)
    return dict(status=STATUS, implementation_only=True, held_family=held_family, seed=seed,
                fit_uids=[uid for uid in uids if by_uid[uid]['family'] != held_family],
                held_uids=[uid for uid in uids if by_uid[uid]['family'] == held_family],
                feature_rows_by_uid={uid: dict(by_uid[uid]) for uid in uids},
                real_data_release=False, held_outcomes_accessed=False)


def prepare_fold(feature_rows, fit_outcomes, *, held_family, seed,
                 implementation_only=False):
    """Prepare a bounded materialized fold; failures are rejected, never dropped.

    fit_outcomes must be an exact builtin dict keyed by fitting UIDs only. The
    feature/split barrier precedes even inspecting that object's type or keys.
    Production labels, failures ledger and physical freeze are not supported.
    """
    split = feature_split(feature_rows, held_family=held_family, seed=seed,
                          implementation_only=implementation_only)
    by_uid = split['feature_rows_by_uid']
    uids = list(by_uid)
    fit_uids, held_uids = split['fit_uids'], split['held_uids']
    circuits = {}
    for uid, row in by_uid.items():
        circuits.setdefault(row['circuit'], []).append(uid)
    # No reference to fit_outcomes before this full feature/split barrier.
    _require(type(fit_outcomes) is dict, 'FIT_OUTCOME_CONTAINER')
    _require(all(type(uid) is str for uid in fit_outcomes)
             and set(fit_outcomes) == set(fit_uids), 'FIT_ONLY_EXACT_UID_JOIN')
    outcomes = {}
    for uid in fit_uids:
        row = fit_outcomes[uid]
        _require(type(row) is dict and row.keys() == _OUTCOME_KEYS, 'OUTCOME_SCHEMA')
        _require(type(row['execution_status']) is str and row['execution_status'] == 'SUCCESS',
                 'SUCCESS_REQUIRED')
        _require(type(row['is_d95_feasible']) is int and row['is_d95_feasible'] == 1,
                 'D95_REQUIRED')
        cycles, cost = row['total_cycles'], row['policy_charged_runtime_s']
        _require(type(cycles) is int and 1 <= cycles <= 10**15, 'CYCLES_DOMAIN')
        _number(cost, 0, 1e9, 'COST_DOMAIN', strict_lower=True)
        outcomes[uid] = (cycles, cost)
    raw = {uid: [by_uid[uid][name] for name in FEATURES] for uid in uids}
    count = len(fit_uids)
    mean = [math.fsum(raw[uid][i] for uid in fit_uids) / count for i in range(7)]
    std = [max(math.sqrt(math.fsum((raw[uid][i] - mean[i])**2 for uid in fit_uids)
                          / count), 1e-12) for i in range(7)]
    normalizer = dict(feature_names=list(FEATURES), mean=mean, std=std)
    transformed = {uid: [(raw[uid][i] - mean[i]) / std[i] for i in range(7)] for uid in uids}
    _require(all(math.isfinite(v) for row in transformed.values() for v in row),
             'TRANSFORM_NONFINITE')
    tasks = []
    for circuit in sorted(circuits):
        if FAMILIES[circuit] == held_family:
            continue
        task_uids = sorted(circuits[circuit])
        oracle = min(outcomes[uid][0] for uid in task_uids)
        costs = {uid: outcomes[uid][1] for uid in task_uids}
        positives = [uid for uid in task_uids if 100*outcomes[uid][0] <= 101*oracle]
        tasks.append(dict(circuit=circuit, family=FAMILIES[circuit],
                          action_uids=task_uids, features=[transformed[uid][:] for uid in task_uids],
                          costs=costs, positive_uids=positives, oracle_cycles=oracle,
                          cost_normalization_B=len(task_uids)*max(costs.values()),
                          all_positive=len(positives) == len(task_uids),
                          features_standardized=True))
    max_raw = max(abs(v) for row in raw.values() for v in row)
    max_fit = max(abs(v) for uid in fit_uids for v in transformed[uid])
    max_held = max(abs(v) for uid in held_uids for v in transformed[uid])
    domain_pass = max(max_fit, max_held) <= 2
    return dict(status=STATUS, implementation_only=True, held_family=held_family, seed=seed,
                feature_names=list(FEATURES), fit_uids=fit_uids, held_uids=held_uids,
                fit_features=[transformed[uid][:] for uid in fit_uids],
                held_features=[transformed[uid][:] for uid in held_uids],
                normalizer=normalizer, normalizer_sha256=_digest(normalizer),
                feature_snapshot_sha256=_digest([by_uid[uid] for uid in uids]),
                fit_tasks=tasks, fitting_family_count=len(tasks),
                domain_diagnostics=dict(max_abs_raw_feature=max_raw,
                                        max_abs_fit_feature=max_fit,
                                        max_abs_held_feature=max_held),
                legacy_vjp_feature_domain_pass=domain_pass,
                features_standardized=True, features_clipped=False,
                normalizer_fit_only=True, identity_normalizer_used=False,
                costs_are_features=False, labels_are_features=False,
                fit_failure_support=False, failure_ledger_implemented=False,
                candidate_lineage_verified=False, real_data_provenance_verified=False,
                model_ready=False, real_data_release=False, real_training_release=False,
                real_data_access=False, held_outcomes_accessed=False,
                trainer_implemented=False, optimizer_implemented=False)
