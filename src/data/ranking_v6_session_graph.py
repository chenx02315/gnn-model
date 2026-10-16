"""Materialized session-reference graph and Decimal50 cost diagnostics only.

Candidate-quality-label-free: no cycles, D95 or whole-action terminal status.
Supplied tool-session outcome classes are inspected to retain failures and
timeouts, not to derive candidate quality. Every identity, timing interpretation
and provenance field is an unverified caller declaration. No reader, physical
adapter, model, training labels or online/physical makespan estimate is created.
"""
from decimal import Decimal, localcontext
import re

from src.models.runtime_ranking_v3 import FAMILIES


MAX_ACTIONS = 6144
MAX_SESSIONS = 65536
MAX_EDGES = 131072
MAX_SOURCES = 16384
MAX_CHARACTERS = 16 * 1024 * 1024
MAX_STRING = 4096
_ID = re.compile(r'[A-Za-z0-9_.:|+\-]{1,256}')
_SHA = re.compile(r'[0-9a-f]{64}')
_INTEGER = re.compile(r'[1-9][0-9]{0,4}')
_WALL = re.compile(r'[0-9]{1,10}(?:\.[0-9]{1,9})?')
ACTION_FIELDS = frozenset(('action_uid', 'circuit', 'family', 'role', 'action_scheme',
                            'source_candidate_uids'))
SESSION_FIELDS = frozenset(('attempt_id', 'circuit', 'family', 'role', 'stage', 'mode',
    'retry_group_id', 'retry_order', 'retry_order_status', 'environment_cohort',
    'attempt_outcome_class', 'wall_s', 'semantics_status', 'semantics_contract',
    'elapsed_semantics', 'elapsed_source', 'source_artifact_sha256', 'source_log_sha256',
    'parent_attempt_id', 'session_index', 'session_count', 'order_evidence',
    'session_lineage_sha256', 'timing_scope'))
EDGE_FIELDS = frozenset(('action_uid', 'source_candidate_uid', 'circuit', 'stage', 'mode',
    'retry_group_id', 'retry_order', 'attempt_id', 'mapping_rule', 'action_scheme'))
_MODES = {'HF': frozenset(('H', 'F')), 'HMF': frozenset(('H', 'M', 'F'))}
_CLASSES = ('SUCCESS', 'FAILURE', 'TIMEOUT')
_ORDER_EVIDENCE = frozenset(('STRUCTURAL_SINGLETON', 'GNU_TIME_FOOTER_EMISSION_ORDER',
                             'EMBEDDED_SIEMENS_START_ORDER'))


def _require(condition, code):
    if not condition:
        raise ValueError('SESSION_GRAPH_' + code)


def _identifier(value):
    _require(_ID.fullmatch(value) is not None, 'IDENTIFIER')


def _index(value):
    _require(_INTEGER.fullmatch(value) is not None, 'CANONICAL_ONE_BASED_ORDER')
    result = int(value)
    _require(result <= 65536, 'ORDER_BOUND')
    return result


def _metadata(row):
    _require(row['role'] == 'TRAIN' and FAMILIES.get(row['circuit']) == row['family'],
             'TRAIN_FAMILY_MAPPING')


def _schema(action_rows, session_rows, edge_rows):
    """Exact types/schema and character budgets precede graph or Decimal work."""
    total_characters = source_count = 0
    for rows, fields, cap in ((action_rows, ACTION_FIELDS, MAX_ACTIONS),
                              (session_rows, SESSION_FIELDS, MAX_SESSIONS),
                              (edge_rows, EDGE_FIELDS, MAX_EDGES)):
        _require(type(rows) is list and 1 <= len(rows) <= cap, 'CONTAINER_BOUND')
        for row in rows:
            _require(type(row) is dict and all(type(key) is str for key in row)
                     and row.keys() == fields, 'EXACT_SCHEMA')
            for key, value in row.items():
                total_characters += len(key)
                if key == 'source_candidate_uids':
                    _require(type(value) is list and 1 <= len(value) <= MAX_SOURCES,
                             'SOURCE_CONTAINER')
                    source_count += len(value)
                    _require(source_count <= MAX_SOURCES, 'SOURCE_COUNT_BOUND')
                    values = value
                else:
                    values = (value,)
                for item in values:
                    _require(type(item) is str and len(item) <= MAX_STRING, 'BUILTIN_STRING_BOUND')
                    total_characters += len(item)
                _require(total_characters <= MAX_CHARACTERS, 'TOTAL_CHARACTERS_BOUND')


def audit_graph(action_rows, session_rows, edge_rows, *, implementation_only=False):
    """Audit declared graph joins; monetary/timing outputs are proxy strings.

    Source candidates are invocation-reference units, not authenticated E31
    action records. Retry groups and parent-session identities are never
    renumbered. Supplied unmapped sessions remain explicit audit nodes.
    """
    _require(implementation_only is True, 'IMPLEMENTATION_OPT_IN')
    _schema(action_rows, session_rows, edge_rows)
    actions, owners = {}, {}
    for row in action_rows:
        _metadata(row)
        _identifier(row['action_uid'])
        _require(row['action_uid'] not in actions, 'DUPLICATE_ACTION')
        _require(row['action_scheme'] in _MODES, 'ACTION_SCHEME')
        for source in row['source_candidate_uids']:
            _identifier(source)
            _require(source not in owners, 'DUPLICATE_SOURCE_OWNERSHIP')
            owners[source] = row['action_uid']
        actions[row['action_uid']] = row
    sessions, groups, parents, circuit_cohorts = {}, {}, {}, {}
    for row in session_rows:
        _metadata(row)
        for name in ('attempt_id', 'retry_group_id', 'parent_attempt_id'):
            _identifier(row[name])
        _require(bool(row['stage']) and bool(row['environment_cohort']), 'STAGE_COHORT')
        _require(row['mode'] in ('H', 'M', 'F'), 'MODE')
        _require(row['attempt_id'] not in sessions, 'DUPLICATE_ATTEMPT')
        _require(row['retry_order_status'] == 'KNOWN_ORDER', 'RETRY_ORDER_STATUS')
        order = _index(row['retry_order'])
        index, count = _index(row['session_index']), _index(row['session_count'])
        _require(index <= count, 'SESSION_INDEX_COUNT')
        _require(row['order_evidence'] in _ORDER_EVIDENCE, 'ORDER_EVIDENCE')
        _require(row['attempt_outcome_class'] in _CLASSES, 'ATTEMPT_OUTCOME_CLASS')
        _require(_SHA.fullmatch(row['source_artifact_sha256']) is not None
                 and (row['source_log_sha256'] == '' or _SHA.fullmatch(row['source_log_sha256']) is not None)
                 and _SHA.fullmatch(row['session_lineage_sha256']) is not None, 'SOURCE_HASH_SHAPE')
        _require(row['timing_scope'] == 'EXCLUSIVE_PROCESS_SESSION_ELAPSED', 'EXCLUSIVE_TIMING_SCOPE')
        _require(row['semantics_contract'] == 'tessent_process_wall_seconds'
                 and row['elapsed_semantics'] == 'tessent_process_wall_seconds', 'ELAPSED_SEMANTICS')
        _require((row['semantics_status'], row['elapsed_source']) in
                 (('CONTRACT_VERIFIED', 'phase2_csv.wall_time'), ('FOOTER_VERIFIED', 'gnu_time_footer')),
                 'SEMANTICS_SOURCE_PAIR')
        cohort = circuit_cohorts.setdefault(row['circuit'], row['environment_cohort'])
        _require(cohort == row['environment_cohort'], 'CIRCUIT_COHORT_MIX')
        group = groups.setdefault((row['circuit'], row['retry_group_id']), [])
        if group:
            previous = group[0]
            _require(all(row[name] == previous[name] for name in
                         ('circuit', 'family', 'stage', 'mode', 'environment_cohort', 'order_evidence')),
                     'GROUP_IDENTITY_MIX')
        group.append(row)
        parent = parents.setdefault(row['parent_attempt_id'], [])
        if parent:
            previous = parent[0]
            _require(all(row[name] == previous[name] for name in
                         ('circuit', 'family', 'stage', 'mode', 'retry_group_id', 'environment_cohort',
                          'source_artifact_sha256', 'source_log_sha256', 'session_lineage_sha256',
                          'session_count', 'order_evidence')), 'PARENT_IDENTITY_MIX')
        parent.append(row)
        sessions[row['attempt_id']] = row
    for members in groups.values():
        _require(sorted(_index(row['retry_order']) for row in members) == list(range(1, len(members)+1)),
                 'GROUP_ORDER_COMPLETENESS')
        _require((len(members) == 1 and members[0]['order_evidence'] == 'STRUCTURAL_SINGLETON')
                 or (len(members) > 1 and members[0]['order_evidence'] != 'STRUCTURAL_SINGLETON'),
                 'GROUP_ORDER_EVIDENCE')
        evidence = members[0]['order_evidence']
        if evidence == 'GNU_TIME_FOOTER_EMISSION_ORDER':
            _require(len({row['parent_attempt_id'] for row in members}) == 1
                     and all(row['source_log_sha256'] for row in members)
                     and len({row['source_log_sha256'] for row in members}) == 1
                     and all(row['retry_order'] == row['session_index'] for row in members),
                     'GNU_PARENT_SESSION_ORDER')
        elif evidence == 'EMBEDDED_SIEMENS_START_ORDER':
            # Legacy remediation reserves embedded global ordering for multiple
            # source files; same-file sessions use footer emission index order.
            _require(len({row['parent_attempt_id'] for row in members}) > 1
                     and all(row['source_log_sha256'] for row in members)
                     and len({row['source_log_sha256'] for row in members}) > 1,
                     'EMBEDDED_MULTI_FILE_REQUIRED')
    for members in parents.values():
        _require(len(members) == _index(members[0]['session_count'])
                 and sorted(_index(row['session_index']) for row in members) == list(range(1, len(members)+1)),
                 'PARENT_SESSION_COMPLETENESS')
    # Every action and every session identity/role/semantics declaration is
    # validated before any wall_s regex/Decimal parsing, including unmapped rows.
    referenced = {source: set() for source in owners}
    invocation_stages = {}
    reverse = {attempt: set() for attempt in sessions}
    pairs, copied_edges = set(), []
    for row in edge_rows:
        source, action, attempt = row['source_candidate_uid'], row['action_uid'], row['attempt_id']
        _require(source in owners and owners[source] == action and attempt in sessions, 'EDGE_JOIN')
        owner, session = actions[action], sessions[attempt]
        _require(bool(row['stage']), 'EDGE_STAGE')
        invocation_stage = invocation_stages.setdefault(source, row['stage'])
        _require(row['stage'] == invocation_stage, 'INVOCATION_STAGE_MIX')
        _require(row['circuit'] == owner['circuit'] == session['circuit']
                 and row['action_scheme'] == owner['action_scheme'], 'EDGE_OWNERSHIP')
        _require(row['mode'] in _MODES[owner['action_scheme']] and row['mode'] == session['mode'],
                 'EDGE_MODE')
        _require(row['retry_group_id'] == session['retry_group_id']
                 and row['retry_order'] == session['retry_order'], 'EDGE_GROUP_ORDER')
        _require(row['mapping_rule'] in ('DIRECT_RESULT_BASENAME', 'DIRECT_RESULT_BASENAME_CROSS_STAGE',
                                        'F_SEARCH_RUN_ID'), 'MAPPING_RULE')
        _require(row['stage'] == session['stage']
                 or row['mapping_rule'] == 'DIRECT_RESULT_BASENAME_CROSS_STAGE', 'CROSS_STAGE_RULE')
        _require(row['mapping_rule'] != 'F_SEARCH_RUN_ID' or row['mode'] == 'F', 'F_SEARCH_MODE')
        _require((source, attempt) not in pairs, 'DUPLICATE_SOURCE_ATTEMPT_EDGE')
        pairs.add((source, attempt))
        referenced[source].add(attempt)
        reverse[attempt].add(source)
        copied_edges.append(dict(row))
    multi_group = []
    for source, attempts in referenced.items():
        _require(bool(attempts), 'SOURCE_WITHOUT_EDGE')
        source_groups = {(sessions[attempt]['circuit'], sessions[attempt]['retry_group_id'])
                         for attempt in attempts}
        for group_id in source_groups:
            _require({row['attempt_id'] for row in groups[group_id]} <= attempts,
                     'PARTIAL_INVOCATION_RETRY_GROUP')
        cohorts = {sessions[attempt]['environment_cohort'] for attempt in attempts}
        _require(len(cohorts) == 1, 'INVOCATION_COHORT_MIX')
        for mode in ('H', 'M', 'F'):
            ids = sorted(g[1] for g in source_groups if groups[g][0]['mode'] == mode)
            if len(ids) > 1:
                multi_group.append(dict(source_candidate_uid=source, mode=mode, retry_group_ids=ids))
    with localcontext() as context:
        context.prec = 50
        zero = Decimal(0)
        elapsed = {}
        for attempt, row in sessions.items():
            _require(_WALL.fullmatch(row['wall_s']) is not None, 'WALL_ASCII_DECIMAL')
            value = Decimal(row['wall_s'])
            _require(zero <= value <= Decimal('1e9'), 'WALL_BOUND')
            elapsed[attempt] = value
        source_cost = {source: sum((elapsed[a] for a in sorted(attempts)), zero)
                       for source, attempts in sorted(referenced.items())}
        _require(all(value > zero for value in source_cost.values()), 'INVOCATION_POSITIVE_TOTAL')
        action_cost = {action: sum((source_cost[s] for s in sorted(row['source_candidate_uids'])), zero)
                       / len(row['source_candidate_uids']) for action, row in sorted(actions.items())}
        _require(all(value > zero for value in action_cost.values()), 'ACTION_POSITIVE_TOTAL')
        mapped = sorted(attempt for attempt in sessions if reverse[attempt])
        unmapped = sorted(set(sessions)-set(mapped))
        unmapped_counts = {kind: sum(sessions[a]['attempt_outcome_class'] == kind for a in unmapped)
                           for kind in _CLASSES}
        unmapped_elapsed = {kind: str(sum((elapsed[a] for a in unmapped
                                          if sessions[a]['attempt_outcome_class'] == kind), zero))
                            for kind in _CLASSES}
        totals = dict(all_supplied_session_elapsed_sum_s=str(sum((elapsed[a] for a in sorted(sessions)), zero)),
                      mapped_unique_session_elapsed_sum_s=str(sum((elapsed[a] for a in mapped), zero)),
                      edge_incidence_proxy_sum_s=str(sum((source_cost[s] for s in sorted(source_cost)), zero)),
                      per_source_elapsed_proxy_s={s: str(v) for s, v in source_cost.items()},
                      per_action_arithmetic_mean_source_proxy_s={a: str(v) for a, v in action_cost.items()},
                      unmapped_elapsed_by_status_s=unmapped_elapsed)
    action_nodes = [dict(actions[a], source_candidate_uids=sorted(actions[a]['source_candidate_uids']))
                    for a in sorted(actions)]
    session_nodes = [dict(sessions[a]) for a in sorted(sessions)]
    source_refs = [dict(source_candidate_uid=s, action_uid=owners[s], attempt_ids=sorted(referenced[s]),
                        invocation_stage=invocation_stages[s],
                        observed_modes=sorted({sessions[a]['mode'] for a in referenced[s]}),
                        unobserved_scheme_modes=sorted(_MODES[actions[owners[s]]['action_scheme']]
                            - {sessions[a]['mode'] for a in referenced[s]})) for s in sorted(owners)]
    action_refs = [dict(action_uid=a, source_candidate_uids=sorted(row['source_candidate_uids']),
                        attempt_ids=sorted(set().union(*(referenced[s] for s in row['source_candidate_uids']))))
                   for a, row in sorted(actions.items())]
    attempt_refs = [dict(attempt_id=a, source_candidate_uids=sorted(reverse[a]),
                         action_uids=sorted({owners[s] for s in reverse[a]})) for a in sorted(sessions)]
    copied_edges.sort(key=lambda row: (row['action_uid'], row['source_candidate_uid'], row['attempt_id']))
    return dict(status='PASS_MATERIALIZED_SESSION_GRAPH_PROXY_IMPLEMENTATION_ONLY',
                implementation_only=True, action_nodes=action_nodes, session_nodes=session_nodes,
                edges=copied_edges, source_references=source_refs, action_references=action_refs,
                attempt_references=attempt_refs,
                shared_attempt_count_across_sources=sum(len(reverse[a]) > 1 for a in sessions),
                shared_attempt_count_across_actions=sum(len({owners[s] for s in reverse[a]}) > 1 for a in sessions),
                multi_source_action_count=sum(len(row['source_candidate_uids']) > 1 for row in actions.values()),
                multiple_groups_per_mode=sorted(multi_group, key=lambda row: (row['source_candidate_uid'], row['mode'])),
                unmapped_attempt_ids=unmapped, unmapped_counts_by_status=unmapped_counts,
                decimal_precision=50, arithmetic='Decimal_50_significant_digit_diagnostic',
                action_proxy_reduction='arithmetic_mean_of_all_declared_source_costs_not_minimum',
                failed_and_timeout_sessions_included=True, original_one_based_orders_preserved=True,
                E31_direct_compatible=False,
                incompatibility_reasons=['legacy_source_invocation_identity_not_authenticated',
                    'attempt_role_and_terminal_reference_not_authenticated',
                    'exclusive_nonoverlap_elapsed_semantics_not_authenticated',
                    'no_whole_action_SUCCESS_D95_cycles_or_FIT_targets'],
                candidate_quality_labels_supplied=False, fit_targets_generated=False, fit_safe_certified=False,
                real_training_release=False, real_heldout_release=False, e31_records_emitted=False,
                real_data_access=False, source_authenticity_verified=False,
                mapped_subset_completeness_authenticated=False, nonoverlap_authenticated=False,
                source_cost_scope='provided_mapped_references_only_not_complete_execution_cost',
                elapsed_meaning_authenticated=False, reader_implemented=False,
                physical_adapter_implemented=False, model_implemented=False, trainer_implemented=False,
                online_actual_cost_claim=False, physical_wall_makespan_claim=False, **totals)
