"""Outcome-independent acquisition plan, before any model comparison.

No source dataset, graph, checkpoint, process, or remote filesystem is opened.
This small pilot measures a *new* fixed F-coverage policy; it does not reproduce
the historical integer F-boundary policy or define the formal training roster.
"""
import hashlib
import json

from .prospective_input_binding_v1 import IDENTITIES, bind_requests


CIRCUITS = ('aes_core', 'spi')
H_REQUESTS = (1, 4, 16)
M_REQUESTS = (1, 4)
F_CONTROL = {'kind': 'COVERAGE_PERCENT', 'value': '95'}


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii')
    return hashlib.sha256(raw).hexdigest()


def build_plan():
    """Return a fresh, exact DAG with budgets, not an executable release.

    Literal requests remove the need to collect full-H/conditional-M endpoints
    merely to validate the acquisition pipeline. Those endpoints are still
    required for any later endpoint-relative candidate domain.
    """
    phases = []
    for circuit in CIRCUITS:
        rows = []
        for h in H_REQUESTS:
            rows.append(dict(action_uid='%s:HF:h%d' % (circuit, h),
                             scheme='HF', h_request=h, m_request=None))
            for m in M_REQUESTS:
                rows.append(dict(action_uid='%s:HMF:h%d:m%d' % (circuit, h, m),
                                 scheme='HMF', h_request=h, m_request=m))
        binding = bind_requests(circuit, rows, dict.fromkeys(IDENTITIES))
        tasks = []
        for row in binding['payload']['requested_roster']:
            action = row['action_uid']
            stages = ('H', 'F') if row['scheme'] == 'HF' else ('H', 'M', 'F')
            previous = None
            for stage in stages:
                uid = action + ':' + stage
                dependencies = []
                if previous is not None:
                    translation_uid = uid + ':translate'
                    tasks.append(dict(task_uid=translation_uid, action_uid=action,
                        kind='TRANSLATION', target_mode=stage,
                        depends_on=[previous], parent_result_task_uid=previous,
                        parent_result_sha256=None, output_sha256=None))
                    dependencies = [previous, translation_uid]
                control = dict(F_CONTROL) if stage == 'F' else dict(
                    kind='PATTERN_LIMIT', value=row['h_request'] if stage == 'H'
                    else row['m_request'])
                tasks.append(dict(task_uid=uid, action_uid=action, kind='TESSENT',
                    stage=stage, control=control, depends_on=dependencies,
                    parent_result_task_uid=previous, parent_result_sha256=None,
                    stage_index=1, output_sha256=None))
                previous = uid
        phases.append(dict(circuit=circuit, requested_roster=binding['payload'][
            'requested_roster'], roster_sha256=binding['roster_sha256'],
            requested_max_h=16, requested_max_m=4, tasks=tasks,
            max_tessent_calls=24, max_translation_calls=15,
            max_total_tasks=39, declared_common_fault_count=None,
            authenticated_input_manifest_sha256=None,
            memory_limit_bytes=None, attempt_timeout_s=None,
            cleanup_timeout_s=None, disk_bytes_limit=None,
            output_bytes_per_attempt_limit=None))
    body = dict(schema='prospective-acquisition-pilot-v1',
        role='TRAIN_ACQUISITION_ONLY', circuits=list(CIRCUITS),
        mode_chain_counts=dict(H=64, M=16, F=4), phases=phases,
        action_count=18, max_tessent_calls=48, max_translation_calls=30,
        max_total_tasks=78, sessions_per_circuit=1, workers=1,
        automatic_retries=0, cross_action_prefix_reuse=False,
        f_policy='SINGLE_COVERAGE_TARGET_95_NO_FALLBACK_OR_BOUNDARY_SEARCH',
        f_target_is_not_d95_proof=True,
        f_boundary_minimality_proven=False, checkpoint_required=False,
        integer_endpoint_calibration_required=False,
        graph_required_to_launch_atpg=False,
        graph_required_before_structure_ablation=True,
        requested_feature_schema='REQUESTED_COUNT_V1',
        normalization_scope='ENTIRE_FROZEN_PILOT_ROSTER',
        epsilon=0.01, epsilon_reference='MEASURED_SAFE_PILOT_ROSTER_ONLY',
        late_binding=dict(
            receipt_fields=['parent_result_sha256', 'translation_result_sha256'],
            storage='Separate execution receipts; never mutate the frozen plan',
            implemented=False,
            rule='Match the exact frozen parent task and acknowledged verified output; '
                 'never substitute an old result, a guessed hash, or another action',
            immutable_fields=['action_uid', 'stage', 'control', 'depends_on']),
        accounting=dict(
            charge='Every started translation and Tessent attempt, including failures',
            record='Per-attempt monotonic interval and full session interval separately',
            unknown_elapsed='INCOMPLETE_NO_IMPUTATION',
            parent_failure='Stop the entire circuit phase under E83; retain charges '
                           'and all remaining actions as NOT_ATTEMPTED',
            unknown_termination='Stop the complete pilot; do not launch another task',
            setup_and_tsdb_copy='Record separately; include in session cost',
            no_hit='Report no-hit and incurred cost; do not drop the session'),
        acceptance=dict(
            d95='FU equals authenticated frozen N and 100 * DS_DI_union_count >= 95 * N',
            unique_faults='Use authenticated common-fault mapping and union across stages; '
                          'do not sum stage detections or trust Tessent target alone',
            cycles='Combined HF/HMF tester cycles from authenticated artifacts',
            zero_pattern_dialect='If zero-pattern output lacks TesterCycle, keep cycles '
                                 'unavailable pending dialect qualification; never invent zero',
            unsafe_or_failed='Keep all action rows with status; no positive label',
            incomplete='Keep missing fields null and block usable-label release',
            positive='Within 1 percent of measured safe roster best; not full-space optimal',
            graph='Join pre-execution structural descriptors by authenticated design identity'),
        execution_ready=False, training_release=False,
        formal_generalization_claim=False, actual_atpg_calls=0)
    return dict(body, plan_sha256=digest(body))


def validate_plan(plan):
    """Reject mutation and result-dependent alterations of this exact protocol."""
    expected = build_plan()
    if type(plan) is not dict or digest(plan) != digest(expected):
        raise ValueError('ACQUISITION_PROTOCOL_CHANGED')
    return dict(action_count=18, max_total_tasks=78,
                execution_ready=False, training_release=False)
