"""Canonical in-memory attempt accounting, IMPLEMENTATION_ONLY / NOT_TRAINER.

This is a NEW schema, not a raw ATPG-log adapter or a production data release.
Every supplied attempt (including failed, timed-out and retried attempts) is
charged once. Missing wall elapsed is rejected; there is no CPU-time or timeout
imputation. The historical pilot policy and its fallback are not changed.

The action's supplied terminal outcome is separate from stage outcomes. A
successful H/M/F attempt never implies whole-action success. Scheme stage sets
and terminal-stage statuses are checked. Complete recovery of the attempt lineage,
measured outcomes, timing semantics,
source hashes and environment identity are NOT authenticated by this module.
Each action declares ONE canonical invocation with serial, exclusive, nonoverlapping
stage elapsed. These upstream declarations are not established by hash shape checks.

Shared attempts across actions are rejected, not allocated. These are fixed
additive historical proxy charges, NOT online prefix-reuse incremental costs.
Stdlib only, no files, model/data loading, remote execution or training.
"""
import hashlib
import json
import math
import re

SCHEMA = 'canonical_attempt_charges_v1'
MAX_ACTIONS = 6144
MAX_ATTEMPTS = 65536
MAX_CYCLES = 10**15
MAX_RUNTIME_S = 1e9
FAMILIES = {'aes_core': 'iwls_aes_core', 's13207': 'iscas89_s13207',
            's15850': 'iscas89_s15850', 's35932': 'iscas89_s35932',
            's38417': 'iscas89_s38417', 'spi': 'iwls_spi'}
STATUSES = ('SUCCESS', 'FAILED', 'TIMEOUT')
STAGES = ('H', 'M', 'F')
ACTION_FIELDS = frozenset(('action_uid', 'circuit', 'family', 'role',
                           'execution_status', 'is_d95_feasible', 'total_cycles',
                           'action_scheme', 'measurement_sha256', 'environment_cohort'))
ATTEMPT_FIELDS = frozenset(('attempt_id', 'action_uid', 'stage', 'retry_order',
                            'execution_status', 'wall_s', 'environment_cohort', 'source_sha256'))
DERIVED_FIELDS = frozenset(('attempt_rows', 'attempt_ids', 'attempt_count', 'status_counts',
                            'source_sha256s', 'action_sha256',
                            'attempts_sha256', 'policy_charged_runtime_s', 'record_sha256'))
_IDENTIFIER = re.compile(r'[A-Za-z0-9_.:-]{1,128}', re.ASCII)
_SHA = re.compile(r'[0-9a-f]{64}', re.ASCII)


def _require(condition, code):
    if not condition:
        raise ValueError('ATTEMPT_CHARGES_' + code)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode('ascii')).hexdigest()


def _schema(row, fields, code):
    _require(type(row) is dict, code)
    _require(all(type(key) is str for key in row) and set(row) == fields, code)


def _identifier(value, code):
    _require(type(value) is str and _IDENTIFIER.fullmatch(value) is not None, code)


def _action(row):
    _schema(row, ACTION_FIELDS, 'ACTION_SCHEMA')
    _identifier(row['action_uid'], 'ACTION_UID')
    _identifier(row['environment_cohort'], 'ENVIRONMENT_COHORT')
    _require(type(row['measurement_sha256']) is str
             and _SHA.fullmatch(row['measurement_sha256']) is not None, 'MEASUREMENT_SHA256')
    _require(type(row['action_scheme']) is str and row['action_scheme'] in ('HF', 'HMF'), 'ACTION_SCHEME')
    circuit = row['circuit']
    _require(type(circuit) is str and circuit in FAMILIES, 'TRAIN_CIRCUIT')
    _require(type(row['family']) is str and row['family'] == FAMILIES[circuit], 'TRAIN_FAMILY')
    _require(type(row['role']) is str and row['role'] == 'TRAIN', 'TRAIN_ROLE')
    status = row['execution_status']
    _require(type(status) is str and status in STATUSES, 'ACTION_STATUS')
    feasible = row['is_d95_feasible']
    _require(type(feasible) is int and feasible in (0, 1), 'D95_FLAG')
    if status == 'SUCCESS':
        _require(feasible == 1 and type(row['total_cycles']) is int
                 and 0 < row['total_cycles'] <= MAX_CYCLES, 'SUCCESS_OUTCOME')
    else:
        _require(row['total_cycles'] is None, 'FAILED_OUTCOME')
    return dict(row)


def _attempt(row):
    _schema(row, ATTEMPT_FIELDS, 'ATTEMPT_SCHEMA')
    _identifier(row['attempt_id'], 'ATTEMPT_ID')
    _identifier(row['action_uid'], 'ATTEMPT_ACTION_UID')
    _identifier(row['environment_cohort'], 'ENVIRONMENT_COHORT')
    _require(type(row['source_sha256']) is str and _SHA.fullmatch(row['source_sha256']) is not None,
             'SOURCE_SHA256')
    _require(type(row['stage']) is str and row['stage'] in STAGES, 'STAGE')
    _require(type(row['retry_order']) is int and 0 <= row['retry_order'] < MAX_ATTEMPTS,
             'RETRY_ORDER')
    _require(type(row['execution_status']) is str and row['execution_status'] in STATUSES,
             'ATTEMPT_STATUS')
    wall = row['wall_s']
    _require(type(wall) in (int, float), 'WALL_ELAPSED_REQUIRED')
    try:
        valid = math.isfinite(wall) and 0 <= wall <= MAX_RUNTIME_S
    except OverflowError:
        valid = False
    _require(valid, 'WALL_ELAPSED_FINITE_NONNEGATIVE')
    return dict(row)


def _sum(values):
    try:
        total = math.fsum(values)
    except (OverflowError, ValueError) as exc:
        raise ValueError('ATTEMPT_CHARGES_TOTAL_RUNTIME_NONFINITE') from exc
    _require(math.isfinite(total), 'TOTAL_RUNTIME_NONFINITE')
    return total


def _flags():
    return dict(implementation_only=True, provenance_not_verified=True,
                raw_log_adapter_implemented=False, stage_completeness_verified=False,
                canonical_scheme_stage_constraints_checked=True,
                upstream_single_invocation_serial_exclusive_elapsed_declared=True,
                action_terminal_outcome_supplied_not_inferred=True,
                shared_attempt_allocation_supported=False,
                fixed_additive_historical_proxy=True,
                online_prefix_reuse_equivalence_claim=False,
                real_training_release=False, real_data_access=False,
                file_io=False, remote_io=False, trainer_implemented=False,
                confidence_interval_claim=False)


def aggregate_charges(action_rows, attempt_rows, *, implementation_only=False):
    """Return UID records and totals for already materialized canonical lists.

    Action schema is exactly ACTION_FIELDS; attempt schema exactly ATTEMPT_FIELDS.
    Identifiers are 1..128 ASCII letters/digits/underscore/dot/colon/hyphen.
    Input order has no accounting meaning. Attempts are canonically ordered by
    action UID, H/M/F stage, then contiguous zero-based retry order. Partial
    subsets of the six TRAIN circuits are allowed for pure accounting.

    A per-action mixed environment, duplicate/shared attempt identity, missing
    attempt, orphan join or retry gap is a fail-closed ValueError. No inference
    of measured action outcomes or validation of source file contents is attempted.
    SUCCESS requires the full HF/HMF stage set with terminal SUCCESS in each.
    Failed actions may have an executed stage prefix. No SUCCESS may be retried.
    """
    _require(implementation_only is True, 'IMPLEMENTATION_ONLY_OPT_IN')
    _require(type(action_rows) is list and 1 <= len(action_rows) <= MAX_ACTIONS,
             'ACTION_LIST_BOUND')
    _require(type(attempt_rows) is list and 1 <= len(attempt_rows) <= MAX_ATTEMPTS,
             'ATTEMPT_LIST_BOUND')
    actions = {}
    for row in action_rows:
        action = _action(row)
        uid = action['action_uid']
        _require(uid not in actions, 'DUPLICATE_ACTION_UID')
        actions[uid] = action
    joined = {uid: [] for uid in actions}
    attempt_ids, stage_retries = set(), set()
    global_status = dict.fromkeys(STATUSES, 0)
    for row in attempt_rows:
        attempt = _attempt(row)
        uid, attempt_id = attempt['action_uid'], attempt['attempt_id']
        _require(uid in actions, 'ORPHAN_ATTEMPT')
        _require(attempt_id not in attempt_ids, 'DUPLICATE_OR_SHARED_ATTEMPT_ID_UNSUPPORTED')
        key = (uid, attempt['stage'], attempt['retry_order'])
        _require(key not in stage_retries, 'DUPLICATE_STAGE_RETRY')
        attempt_ids.add(attempt_id); stage_retries.add(key)
        joined[uid].append(attempt)
        global_status[attempt['execution_status']] += 1
    records = {}
    environments = set()
    for uid in sorted(actions):
        attempts = joined[uid]
        _require(bool(attempts), 'ACTION_WITHOUT_ATTEMPTS')
        cohorts = {attempt['environment_cohort'] for attempt in attempts}
        _require(len(cohorts) == 1, 'ACTION_ENVIRONMENTS_NOT_COMPARABLE')
        cohort = next(iter(cohorts)); environments.add(cohort)
        _require(cohort == actions[uid]['environment_cohort'], 'ACTION_ATTEMPT_ENVIRONMENT_JOIN')
        required_stages = tuple(actions[uid]['action_scheme'])
        present_stages = tuple(stage for stage in STAGES if any(a['stage'] == stage for a in attempts))
        _require(present_stages == required_stages[:len(present_stages)], 'SCHEME_STAGE_PREFIX')
        for stage in STAGES:
            stage_attempts = sorted((a for a in attempts if a['stage'] == stage), key=lambda a: a['retry_order'])
            retries = [a['retry_order'] for a in stage_attempts]
            _require(retries == list(range(len(retries))), 'RETRY_ORDER_GAP')
            _require(all(a['execution_status'] != 'SUCCESS' for a in stage_attempts[:-1]),
                     'RETRY_AFTER_SUCCESS_UNSUPPORTED')
            if stage in present_stages[:-1]:
                _require(stage_attempts[-1]['execution_status'] == 'SUCCESS', 'DOWNSTREAM_AFTER_STAGE_FAILURE')
            if actions[uid]['execution_status'] == 'SUCCESS' and stage in required_stages:
                _require(stage_attempts and stage_attempts[-1]['execution_status'] == 'SUCCESS',
                         'SUCCESS_REQUIRED_STAGE_TERMINAL')
        if actions[uid]['execution_status'] == 'SUCCESS':
            _require(present_stages == required_stages, 'SUCCESS_REQUIRED_STAGE_SET')
        attempts = sorted(attempts, key=lambda a: (STAGES.index(a['stage']), a['retry_order']))
        cost = _sum(a['wall_s'] for a in attempts)
        _require(0 < cost <= MAX_RUNTIME_S, 'ACTION_TOTAL_RUNTIME_POSITIVE_BOUNDED')
        counts = {status: sum(a['execution_status'] == status for a in attempts) for status in STATUSES}
        record = dict(actions[uid], attempt_rows=attempts,
                      attempt_ids=[a['attempt_id'] for a in attempts], attempt_count=len(attempts),
                      status_counts=counts, environment_cohort=cohort,
                      source_sha256s=sorted({a['source_sha256'] for a in attempts}),
                      action_sha256=_digest(actions[uid]), attempts_sha256=_digest(attempts),
                      policy_charged_runtime_s=cost)
        record['record_sha256'] = _digest(record)
        records[uid] = record
    canonical_actions = [actions[u] for u in sorted(actions)]
    canonical_attempts = [a for u in records for a in records[u]['attempt_rows']]
    total = _sum(a['wall_s'] for a in canonical_attempts)
    return dict(schema=SCHEMA, status='PASS_CANONICAL_ATTEMPT_ACCOUNTING_IMPLEMENTATION_ONLY',
                records=records, action_count=len(actions), attempt_count=len(attempt_ids),
                total_policy_charged_runtime_s=total, attempt_status_counts=global_status,
                action_status_counts={s: sum(a['execution_status'] == s for a in actions.values())
                                      for s in STATUSES},
                environment_cohorts=sorted(environments),
                cross_action_environment_comparability_verified=False,
                action_rows_sha256=_digest(canonical_actions),
                attempt_rows_sha256=_digest(canonical_attempts), records_sha256=_digest(records),
                **_flags())


def replay_prefix(records, ranking, *, k=10, implementation_only=False):
    """Charge first, then inspect explicit action outcomes until hit or fixed K10.

    Consume aggregate_charges(...)["records"], not raw logs. Revalidate EVERY
    record and its attempt ledger before evaluating a single ranking position.
    ranking must already be a complete materialized UID permutation for exactly
    one TRAIN circuit. Its pre-outcome freeze is not established by this API.
    Epsilon membership uses integer 100*cycles <= 101*minimum successful cycles.
    No hit-only averaging, inferred uncensored time, CI or online claim follows.
    """
    _require(implementation_only is True, 'IMPLEMENTATION_ONLY_OPT_IN')
    _require(type(k) is int and k == 10, 'FIXED_K10_REQUIRED')
    _require(type(records) is dict and 1 <= len(records) <= MAX_ACTIONS, 'RECORDS_SCHEMA')
    _require(all(type(uid) is str for uid in records), 'RECORD_UID')
    actions, attempts = [], []
    for uid, record in records.items():
        _schema(record, ACTION_FIELDS | DERIVED_FIELDS, 'RECORD_SCHEMA')
        _require(record['action_uid'] == uid, 'RECORD_UID_JOIN')
        actions.append({key: record[key] for key in ACTION_FIELDS})
        _require(type(record['attempt_rows']) is list
                 and 1 <= len(record['attempt_rows']) <= MAX_ATTEMPTS - len(attempts),
                 'ATTEMPT_LIST_BOUND')
        _require(type(record['attempt_count']) is int
                 and record['attempt_count'] == len(record['attempt_rows']), 'RECORD_ATTEMPT_COUNT')
        _require(type(record['attempt_ids']) is list
                 and len(record['attempt_ids']) == record['attempt_count']
                 and all(type(value) is str for value in record['attempt_ids']), 'RECORD_ATTEMPT_IDS')
        _schema(record['status_counts'], frozenset(STATUSES), 'RECORD_STATUS_COUNTS')
        _require(all(type(value) is int and 0 <= value <= MAX_ATTEMPTS
                     for value in record['status_counts'].values()), 'RECORD_STATUS_COUNTS')
        _identifier(record['environment_cohort'], 'ENVIRONMENT_COHORT')
        _require(type(record['source_sha256s']) is list
                 and 1 <= len(record['source_sha256s']) <= record['attempt_count'], 'RECORD_SOURCE_SHA256S')
        _require(all(type(value) is str and _SHA.fullmatch(value) is not None
                     for value in record['source_sha256s']), 'RECORD_SOURCE_SHA256S')
        for key in ('action_sha256', 'attempts_sha256', 'record_sha256'):
            _require(type(record[key]) is str and _SHA.fullmatch(record[key]) is not None, 'RECORD_HASH')
        cost = record['policy_charged_runtime_s']
        _require(type(cost) is float and math.isfinite(cost) and 0 < cost <= MAX_RUNTIME_S, 'RECORD_COST')
        attempts.extend(record['attempt_rows'])
    rebuilt = aggregate_charges(actions, attempts, implementation_only=True)['records']
    # Canonical JSON distinguishes bool/int/float and rejects nonfinite aliases.
    _require(_digest(records) == _digest(rebuilt), 'DERIVED_RECORD_MISMATCH')
    circuits = {row['circuit'] for row in rebuilt.values()}
    _require(len(circuits) == 1, 'EXACTLY_ONE_CIRCUIT_REQUIRED')
    _require(len({row['environment_cohort'] for row in rebuilt.values()}) == 1,
             'REPLAY_ENVIRONMENTS_NOT_COMPARABLE')
    _require(type(ranking) is list and len(ranking) == len(rebuilt), 'COMPLETE_RANKING_LIST')
    _require(all(type(uid) is str for uid in ranking)
             and len(set(ranking)) == len(ranking) and set(ranking) == set(rebuilt),
             'COMPLETE_RANKING_UID_PERMUTATION')
    feasible_cycles = [row['total_cycles'] for row in rebuilt.values()
                       if row['execution_status'] == 'SUCCESS' and row['is_d95_feasible'] == 1]
    _require(bool(feasible_cycles), 'UNSUPPORTED_NO_SAFE_REFERENCE_DO_NOT_SILENTLY_DROP_CIRCUIT')
    oracle = min(feasible_cycles)
    positives = {u for u, row in rebuilt.items() if row['execution_status'] == 'SUCCESS'
                 and row['is_d95_feasible'] == 1 and 100*row['total_cycles'] <= 101*oracle}
    visited, costs, attempt_ids = [], [], []
    hit_uid, hit_rank = None, None
    for rank, uid in enumerate(ranking[:k], 1):
        row = rebuilt[uid]
        # The selected action's entire supplied attempt ledger is charged FIRST.
        costs.append(row['policy_charged_runtime_s'])
        attempt_ids.extend(row['attempt_ids'])
        charged = _sum(costs)
        hit = uid in positives
        visited.append(dict(rank=rank, action_uid=uid,
                            action_charged_runtime_s=row['policy_charged_runtime_s'],
                            cumulative_charged_runtime_s=charged,
                            execution_status=row['execution_status'],
                            total_cycles=row['total_cycles'], epsilon_hit=hit))
        if hit:
            hit_uid, hit_rank = uid, rank
            break
    hit = hit_uid is not None
    return dict(schema='canonical_attempt_prefix_replay_v1',
                status='HIT_IMPLEMENTATION_ONLY' if hit else 'CENSORED_K_IMPLEMENTATION_ONLY',
                circuit=next(iter(circuits)), k=k, hit=hit, hit_action_uid=hit_uid,
                hit_rank=hit_rank, charged_prefix_s=_sum(costs), censored=not hit,
                visited=visited, visited_action_uids=[row['action_uid'] for row in visited],
                visited_attempt_ids=attempt_ids, oracle_min_successful_cycles=oracle,
                epsilon_numerator=101, epsilon_denominator=100,
                epsilon_action_uids=sorted(positives),
                hit_total_cycles=rebuilt[hit_uid]['total_cycles'] if hit else None,
                ranking_sha256=_digest(ranking), records_sha256=_digest(rebuilt),
                ranking_freeze_provenance_verified=False, hit_only_mean_reported=False,
                **_flags())
