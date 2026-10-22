"""Pure request/result joins, not a runner, OS proof, or legacy-model adapter."""
import hashlib
import json
import re
from decimal import Decimal

from . import prospective_request_features_v1 as features

REQUEST_KEYS = {'run_uid', 'action_uid', 'attempt_uid', 'stage', 'stage_index',
                'freeze_sha256', 'control', 'parent_attempt_uid', 'parent_result_sha256'}
RESULT_KEYS = {'run_uid', 'action_uid', 'attempt_uid', 'stage', 'stage_index',
               'request_sha256', 'process_identity', 'status', 'returncode',
               'generated_patterns', 'detected_common_faults', 'cycles',
               'elapsed_ns', 'result_sha256', 'termination_verified'}
UID = re.compile(r'[A-Za-z0-9_:.-]{1,128}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, code):
    if not ok:
        raise ValueError(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        allow_nan=False).encode('ascii')).hexdigest()


def integer(value, low=0, high=2**63-1):
    return type(value) is int and low <= value <= high


def control_valid(value, stage, row):
    require(type(value) is dict and set(value) == {'kind', 'value'}, 'CONTROL_SCHEMA')
    kind, number = value['kind'], value['value']
    if stage in ('H', 'M'):
        expected = row['h_request'] if stage == 'H' else row['m_request']
        require(kind == 'PATTERN_LIMIT' and integer(number, 1, 2**31-1) and
                number == expected, 'REQUEST_CONTROL_MISMATCH')
    elif kind == 'PATTERN_LIMIT':
        require(integer(number, 1, 2**31-1), 'F_PATTERN_LIMIT')
    elif kind == 'FULL':
        require(number is None, 'F_FULL_VALUE')
    elif kind == 'COVERAGE_PERCENT':
        require(type(number) is str and len(number) <= 12 and
                re.fullmatch(r'(?:0|[1-9][0-9]?|100)(?:\.[0-9]{1,6})?', number) and
                0 < Decimal(number) <= 100, 'F_COVERAGE_PERCENT')
    else:
        raise ValueError('UNKNOWN_F_CONTROL')


def join_stage_observations(freeze, run_uid, requests, observations):
    """Validate ordered caller assertions with fresh H/M prefix per F probe.

    Every physical call needs a distinct attempt ID and explicit control. Counts
    are not matched by equality. This does not authenticate report/process bytes,
    enforce resource limits, authorize reuse, or create a usable training label.
    """
    before = features.build_features(freeze)
    require(type(run_uid) is str and UID.fullmatch(run_uid), 'RUN_UID')
    require(type(requests) is list and type(observations) is list and
            1 <= len(requests) <= 64 and len(requests) == len(observations),
            'BOUNDED_PAIRED_OBSERVATIONS')
    roster = {row['action_uid']: row for row in freeze['requested_roster']}
    seen, latest, stage_counts, used_prefix, parents = {}, {}, {}, set(), {}
    process_ids, failed_actions, joined = set(), set(), []
    elapsed_total, cost_complete = 0, True
    for request, result in zip(requests, observations):
        require(cost_complete, 'UNRESOLVED_PRIOR_ATTEMPT')
        require(type(request) is dict and set(request) == REQUEST_KEYS, 'REQUEST_SCHEMA')
        require(type(result) is dict and set(result) == RESULT_KEYS, 'RESULT_SCHEMA')
        aid, uid, stage = request['action_uid'], request['attempt_uid'], request['stage']
        require(type(aid) is str and aid in roster and aid not in failed_actions and
                type(uid) is str and UID.fullmatch(uid) and uid not in seen,
                'ACTION_OR_ATTEMPT_ID')
        require(request['run_uid'] == run_uid and request['freeze_sha256'] ==
                freeze['freeze_sha256'] and type(stage) is str and stage in ('H', 'M', 'F'),
                'REQUEST_BINDING')
        row = roster[aid]
        require(stage != 'M' or row['scheme'] == 'HMF', 'HF_HAS_NO_M_STAGE')
        key = (aid, stage)
        require(integer(request['stage_index'], 1, 64) and request['stage_index'] ==
                stage_counts.get(key, 0) + 1, 'STAGE_SEQUENCE')
        control_valid(request['control'], stage, row)
        parent_stage = None if stage == 'H' else ('H' if stage == 'M' or row['scheme'] == 'HF' else 'M')
        if parent_stage is None:
            require(request['parent_attempt_uid'] is None and
                    request['parent_result_sha256'] is None, 'H_HAS_NO_PARENT')
        else:
            parent_id = latest.get((aid, parent_stage))
            parent = seen.get(parent_id)
            require(parent is not None and parent['status'] == 'SUCCESS' and
                    request['parent_attempt_uid'] == parent_id and
                    request['parent_result_sha256'] == parent['result_sha256'] and
                    parent_id not in used_prefix, 'EXACT_FRESH_SUCCESSFUL_PARENT')
            used_prefix.add(parent_id)
            if stage == 'F' and row['scheme'] == 'HMF':
                require(parents.get(parent_id) == latest.get((aid, 'H')), 'STALE_M_PREFIX')
        require(all(result[name] == request[name] for name in
                ('run_uid', 'action_uid', 'attempt_uid', 'stage', 'stage_index')) and
                type(result['stage_index']) is int and
                result['request_sha256'] == digest(request), 'UNIQUE_REQUEST_RESULT_JOIN')
        identity = result['process_identity']
        require(type(identity) is dict and set(identity) == {'host', 'boot_id', 'pid', 'start_ticks'}
                and type(identity['host']) is str and
                re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', identity['host']) and
                type(identity['boot_id']) is str and
                re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', identity['boot_id']) and
                integer(identity['pid'], 2, 2**31-1) and integer(identity['start_ticks'], 1),
                'PROCESS_IDENTITY')
        entity = tuple(identity[k] for k in ('host', 'boot_id', 'pid', 'start_ticks'))
        require(entity not in process_ids, 'DUPLICATE_PROCESS_OBSERVATION')
        require(not process_ids or entity[:2] == next(iter(process_ids))[:2], 'HOST_BOOT_MISMATCH')
        require(type(result['status']) is str and result['status'] in
                ('SUCCESS', 'FAILED', 'TIMEOUT', 'CANCELLED', 'UNKNOWN') and
                type(result['termination_verified']) is bool, 'RESULT_STATUS')
        success = result['status'] == 'SUCCESS'
        require((success and type(result['returncode']) is int and result['returncode'] == 0) or
                (result['status'] == 'UNKNOWN' and result['returncode'] is None) or
                (result['status'] in ('FAILED', 'TIMEOUT', 'CANCELLED') and
                 type(result['returncode']) is int and result['returncode'] != 0), 'EXIT_STATUS')
        for name in ('generated_patterns', 'detected_common_faults', 'cycles'):
            value = result[name]
            high = freeze['common_fault_count'] if name == 'detected_common_faults' else 2**63-1
            require((not success and value is None) or integer(value, 0, high), 'OBSERVED_COUNT')
        pin = result['result_sha256']
        require((not success and pin is None) or (type(pin) is str and SHA.fullmatch(pin)),
                'RESULT_SHA')
        require(result['elapsed_ns'] is None or integer(result['elapsed_ns']), 'OBSERVED_ELAPSED')
        cost_complete = (result['elapsed_ns'] is not None and result['termination_verified'] and
                         result['status'] != 'UNKNOWN')
        if cost_complete:
            elapsed_total += result['elapsed_ns']
        if not success:
            failed_actions.add(aid)
        equality = (result['generated_patterns'] == request['control']['value']
                    if request['control']['kind'] == 'PATTERN_LIMIT' and
                    result['generated_patterns'] is not None else None)
        joined.append(dict(attempt_uid=uid, request_sha256=digest(request),
            requested_control=dict(request['control']), generated_patterns=result['generated_patterns'],
            requested_equals_generated=equality, status=result['status'],
            meets_declared_d95_threshold=(success and result['detected_common_faults'] >=
                (95 * freeze['common_fault_count'] + 99)//100),
            acceptance_authenticated=False))
        seen[uid], latest[key], stage_counts[key] = dict(result), uid, request['stage_index']
        parents[uid] = request['parent_attempt_uid']
        process_ids.add(entity)
    after = features.build_features(freeze)
    require(before == after, 'OUTCOMES_MUST_NOT_CHANGE_FEATURES')
    return dict(schema='prospective-stage-observation-v1', run_uid=run_uid,
        freeze_sha256=freeze['freeze_sha256'], observation_count=len(joined), observations=joined,
        feature_bundle_sha256=digest(before), feature_bundle_unchanged=True,
        asserted_elapsed_ns_sum=elapsed_total if cost_complete else None,
        elapsed_is_not_authenticated_runtime_label=True, os_authenticated=False,
        requested_realized_equivalence_proved=False, legacy_checkpoint_compatible=False,
        processes_launched_by_this_function=0, source_observations_authenticated=False,
        execution_ready=False, training_release=False)
