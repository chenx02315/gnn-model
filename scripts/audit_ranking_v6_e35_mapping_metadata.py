"""Pinned mixed-role mapping METADATA audit; no action/quality tables.

Cost-vector hash encoding is UTF-8 JSON (ensure_ascii=False, allow_nan=False,
separators=(',', ':')) of list([originalUID, Decimal50 charge string]) sorted
by originalUID. It binds a provided mapping view, not certified invocations.
Examples are selected by ID hash, never elapsed cost or success. No rawgroup
is split, completed or reinterpreted as a whole action invocation.
"""
from __future__ import print_function
import csv
from decimal import Decimal, localcontext
import hashlib
import io
import json
import os
import re
import sys

_old_bytecode = sys.dont_write_bytecode
try:
    sys.dont_write_bytecode = True
    try:
        from scripts import diagnose_ranking_v6_e34_local_groups as local_reader
    except ImportError:
        import diagnose_ranking_v6_e34_local_groups as local_reader
finally:
    sys.dont_write_bytecode = _old_bytecode
reader = local_reader.reader

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 40 * 1024 * 1024
MAX_ROWS = 200000
MAX_OUTPUT_BYTES = 64 * 1024
MAX_GROUP_DETAILS, MAX_MEMBERS, MAX_REFS = 16, 4, 2
EDGE_FIELDS = ('action_uid', 'source_candidate_uid', 'circuit', 'stage', 'action_scheme',
               'h_patterns', 'm_patterns', 'mode', 'retry_group_id', 'retry_order', 'attempt_id', 'mapping_rule')
EXCLUSION_FIELDS = ('circuit', 'stage', 'mode', 'attempt_id', 'exclusion_reason')
VALIDATION_CIRCUITS = frozenset(('s5378', 'tv80'))
_LAYOUT = {'hf_coarse': ('02_hf_coarse', 'HF'), 'hmf_coarse': ('03_hmf_coarse', 'HMF'),
           'hf_refine': ('04_integer_refine', 'HF'), 'hmf_refine': ('04_integer_refine', 'HMF')}
_SOURCE = re.compile(r'([^:]+):(hf_coarse|hmf_coarse|hf_refine|hmf_refine):([^:]+):([0-9]+)\Z')
_CONTROL = re.compile(r'(?:0|[1-9][0-9]{0,9})\Z')
_OUTCOMES = ('SUCCESS', 'FAILURE', 'TIMEOUT', 'COLLECTED_SUCCESS_ONLY', 'UNKNOWN')
_REASONS = ('OUT_OF_SCOPE_STAGE', 'COARSE_M_FULL_PROBE', 'NON_ELIGIBLE_SOURCE_INVOCATION',
             'OUT_OF_SCOPE_EVIDENCE_VERSION', 'NON_TERMINAL_SEARCH_PROBE')
_LOCAL_BASE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..',
                                          'runtime_training_staging_20260928'))
_MANIFEST_ROOT = os.path.join(_LOCAL_BASE, 'runtime_attempt_remediation_v2_r1_remote', 'outputs_v2')
_MAPPING_ROOT = os.path.join(_LOCAL_BASE, 'runtime_action_attempt_mapping_v1_r5')
LOCAL_SPECS = tuple(dict(path=os.path.join(_MANIFEST_ROOT, circuit+suffix), sha256=sha,
                         kind=kind, circuit=circuit)
                    for circuit, msha, lsha in reader._PINS
                    for kind, suffix, sha in (('manifest', '_attempt_manifest_v2_remediated.tsv', msha),
                                             ('lineage', '_lineage_v2.tsv', lsha))) + (
    dict(path=os.path.join(_MAPPING_ROOT, 'invocation_attempt_edges_v1.tsv'), kind='edges', circuit='MIXED_METADATA',
         sha256='d5b25fdd934a18a352c286f572172ad8ba79fa064cf70dbe3f68e8e44e0fdfea'),
    dict(path=os.path.join(_MAPPING_ROOT, 'excluded_attempts_v1.tsv'), kind='exclusions', circuit='MIXED_METADATA',
         sha256='67d5fb154026583435e920ea97f68896542d78bebdd2ca3786f517df3ffa203d'))


class MappingAuditError(ValueError):
    pass


def _require(ok, code):
    if not ok:
        raise MappingAuditError(code)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _rows(rows, fields, mixed=False):
    _require(type(rows) is list and len(rows) <= MAX_ROWS, 'ROW_CONTAINER_BOUND')
    result, filtered = [], 0
    characters = 0
    for row in rows:
        _require(type(row) is dict and all(type(key) is str for key in row)
                 and set(row) == set(fields), 'EXACT_METADATA_SCHEMA')
        _require(all(type(value) is str and len(value) <= 65536 for value in row.values()), 'STRING_BOUND')
        characters += sum(len(value) for value in row.values())
        _require(characters <= MAX_TOTAL_BYTES, 'CHARACTER_CAP')
        circuit = row['circuit']
        _require(circuit in reader.FAMILIES or (mixed and circuit in VALIDATION_CIRCUITS), 'CIRCUIT_SCOPE')
        # VALIDATION metadata is discarded immediately after schema/circuit,
        # before any numeric, grouping, joins, costs or source UID processing.
        if mixed and circuit in VALIDATION_CIRCUITS:
            filtered += 1
            continue
        if fields == reader.MANIFEST_FIELDS:
            _require(row['role'] == 'TRAIN' and row['family'] == reader.FAMILIES[circuit], 'TRAIN_MEMBERSHIP')
        result.append(row)
    return result, filtered


def _mixed_parse(raw, fields):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_FILE_BYTES, 'FILE_BYTE_CAP')
    _require(all(len(line) <= 64*1024 for line in raw.splitlines(True)), 'LINE_BYTE_CAP')
    try:
        records = csv.reader(io.StringIO(raw.decode('utf-8'), newline=''), delimiter='\t', strict=True)
        _require(tuple(next(records)) == fields, 'EXACT_METADATA_HEADER')
        rows = []
        for values in records:
            _require(len(values) == len(fields) and len(rows) < MAX_ROWS, 'ROW_SHAPE_OR_CAP')
            _require(all('\x00' not in value and '\n' not in value and '\r' not in value for value in values),
                     'CONTROL_CHARACTER')
            row = dict(zip(fields, values))
            _require(row['circuit'] in reader.FAMILIES or row['circuit'] in VALIDATION_CIRCUITS, 'CIRCUIT_SCOPE')
            rows.append(row)
        return rows
    except MappingAuditError:
        raise
    except (UnicodeError, csv.Error, StopIteration):
        raise MappingAuditError('MIXED_TSV_PARSE')


def _counts(rows, field, allowed):
    counts = {key:0 for key in allowed}
    counts['OTHER'] = 0
    for row in rows:
        counts[row[field] if row[field] in allowed else 'OTHER'] += 1
    return counts


def _vector(costs):
    ordered = [[uid, str(value)] for uid, value in sorted(costs.items())]
    values = list(costs.values())
    total = sum(values, Decimal(0))
    examples = sorted(costs, key=lambda uid: _hash(uid))[:16]
    return dict(canonical_sha256=_hash(ordered), count=len(values), sum_s=str(total),
                minimum_s=str(min(values)) if values else None, maximum_s=str(max(values)) if values else None,
                mean_s=str(total/len(values)) if values else None,
                examples=[dict(id_sha256=_hash(uid), proxy_s=str(costs[uid])) for uid in examples],
                examples_selected_by='ascending_ID_SHA256_not_cost_or_success')


def audit(manifestrows, lineagerows, edges, exclusions):
    """Audit supplied references exactly, without importing the old mapper."""
    _require(sum(len(value) for value in (manifestrows, lineagerows, edges, exclusions)
                 if type(value) is list) <= MAX_ROWS, 'TOTAL_ROW_CAP')
    manifestrows, _ = _rows(manifestrows, reader.MANIFEST_FIELDS)
    lineagerows, _ = _rows(lineagerows, reader.LINEAGE_FIELDS)
    edges, val_edges = _rows(edges, EDGE_FIELDS, mixed=True)
    exclusions, val_exclusions = _rows(exclusions, EXCLUSION_FIELDS, mixed=True)
    attempts, lineage = {}, {}
    for rows, target in ((manifestrows, attempts), (lineagerows, lineage)):
        for row in rows:
            key = (row['circuit'], row['attempt_id'])
            _require(bool(key[1]) and key not in target, 'DUPLICATE_OR_EMPTY_ATTEMPT')
            target[key] = row
    _require(set(attempts) == set(lineage) and bool(attempts), 'FULL_LINEAGE_JOIN')
    for key, row in attempts.items():
        _require(row['mode'] in ('H','M','F') and reader._ORDER.match(row['retry_order']) is not None,
                 'ATTEMPT_MODE_ORDER')
        _require(reader._ORDER.match(lineage[key]['session_index']) is not None
                 and reader._ORDER.match(lineage[key]['session_count']) is not None, 'LINEAGE_SESSION_NUMERIC')
        _require(all(row[field] == lineage[key][field] for field in
                     ('retry_group_id', 'retry_order', 'attempt_outcome_class', 'timeout_status')), 'LINEAGE_VALUE_JOIN')
    sources, actions, refs = {}, {}, {key:set() for key in attempts}
    pairs, rules = set(), {rule:0 for rule in ('DIRECT_RESULT_BASENAME', 'DIRECT_RESULT_BASENAME_CROSS_STAGE', 'F_SEARCH_RUN_ID')}
    cross_stage_edges = cross_stage_rule_without_difference = 0
    for row in edges:
        key = (row['circuit'], row['attempt_id'])
        _require(key in attempts, 'EDGE_UNKNOWN_ATTEMPT')
        attempt = attempts[key]
        source, action = row['source_candidate_uid'], row['action_uid']
        match = _SOURCE.match(source)
        _require(match is not None and match.group(1) == row['circuit'], 'SOURCE_CIRCUIT_PREFIX')
        stage, scheme = _LAYOUT[match.group(2)]
        _require(row['stage'] == stage and row['action_scheme'] == scheme and bool(action), 'SOURCE_STAGE_SCHEME')
        _require(_CONTROL.match(row['h_patterns']) is not None
                 and (row['m_patterns'] == '' if scheme == 'HF' else _CONTROL.match(row['m_patterns']) is not None),
                 'CONTROL_PARAMETER_FORMAT')
        config = (row['circuit'], scheme, row['h_patterns'], row['m_patterns'])
        if source not in sources:
            sources[source] = dict(action=action, config=config, stage=stage, attempts=set())
        _require(sources[source]['action'] == action and sources[source]['config'] == config
                 and sources[source]['stage'] == stage, 'SOURCE_OWNERSHIP_CONFLICT')
        if action not in actions:
            actions[action] = dict(config=config, sources=set())
        _require(actions[action]['config'] == config, 'ACTION_CONFIGURATION_CONFLICT')
        _require(row['mode'] == attempt['mode'] and row['mode'] in (('H', 'F') if scheme == 'HF' else ('H', 'M', 'F')),
                 'EDGE_MODE_JOIN')
        _require(row['retry_group_id'] == attempt['retry_group_id']
                 and row['retry_order'] == attempt['retry_order'] and reader._ORDER.match(row['retry_order']) is not None,
                 'EDGE_GROUP_ORDER_JOIN')
        rule = row['mapping_rule']
        _require(rule in rules, 'MAPPING_RULE')
        _require(row['stage'] == attempt['stage'] or rule == 'DIRECT_RESULT_BASENAME_CROSS_STAGE', 'EDGE_STAGE_RULE')
        _require(rule != 'F_SEARCH_RUN_ID' or row['mode'] == 'F', 'F_SEARCH_MODE')
        _require((source, key) not in pairs, 'DUPLICATE_SOURCE_ATTEMPT_EDGE')
        pairs.add((source, key))
        rules[rule] += 1
        cross_stage_edges += row['stage'] != attempt['stage']
        cross_stage_rule_without_difference += (rule == 'DIRECT_RESULT_BASENAME_CROSS_STAGE'
                                               and row['stage'] == attempt['stage'])
        sources[source]['attempts'].add(key)
        actions[action]['sources'].add(source)
        refs[key].add(source)
    excluded = {}
    for row in exclusions:
        key = (row['circuit'], row['attempt_id'])
        _require(key in attempts and key not in excluded, 'EXCLUSION_JOIN_OR_DUPLICATE')
        _require(row['stage'] == attempts[key]['stage'] and row['mode'] == attempts[key]['mode'], 'EXCLUSION_STAGE_MODE')
        _require(row['exclusion_reason'] in _REASONS, 'EXCLUSION_REASON')
        excluded[key] = row['exclusion_reason']
    grouped, partitions = {}, {name:[] for name in ('mapped_only', 'excluded_only', 'both', 'neither')}
    wall = {}
    with localcontext() as context:
        context.prec = 50
        for key, row in sorted(attempts.items()):
            _require(reader._WALL.match(row['wall_s']) is not None, 'WALL_DECIMAL')
            value = Decimal(row['wall_s'])
            _require(0 <= value <= Decimal('1e9'), 'WALL_BOUND')
            wall[key] = value
            name = ('both' if key in excluded else 'mapped_only') if refs[key] else ('excluded_only' if key in excluded else 'neither')
            partitions[name].append(key)
            grouped.setdefault((row['circuit'], row['retry_group_id']), []).append(key)
        source_costs = {source:sum((wall[key] for key in sorted(record['attempts'])), Decimal(0))
                        for source, record in sorted(sources.items())}
        action_costs = {action:sum((source_costs[source] for source in sorted(record['sources'])), Decimal(0))/len(record['sources'])
                        for action, record in sorted(actions.items())}
        partition_summaries = {}
        for name, keys in partitions.items():
            rows = [attempts[key] for key in keys]
            partition_summaries[name] = dict(attempt_count=len(keys),
                declared_wall_sum_s=str(sum((wall[key] for key in keys), Decimal(0))),
                outcome_counts=_counts(rows, 'attempt_outcome_class', _OUTCOMES),
                declared_wall_by_outcome_s={outcome:str(sum((wall[key] for key in keys
                    if (attempts[key]['attempt_outcome_class'] if attempts[key]['attempt_outcome_class'] in _OUTCOMES else 'OTHER') == outcome), Decimal(0)))
                    for outcome in _OUTCOMES+('OTHER',)})
        all_wall = str(sum(wall.values(), Decimal(0)))
        mapped_wall = str(sum((wall[key] for key in wall if refs[key]), Decimal(0)))
        incidence_wall = str(sum(source_costs.values(), Decimal(0)))
        source_summary, action_summary = _vector(source_costs), _vector(action_costs)
        group_details, omitted_members, omitted_refs = [], 0, 0
        mixed_stage_count = 0
        ordered_groups = sorted(grouped, key=lambda group:_hash(list(group)))
        for group in ordered_groups:
            keys = grouped[group]
            if len({attempts[key]['stage'] for key in keys}) <= 1:
                continue
            mixed_stage_count += 1
            if len(group_details) >= MAX_GROUP_DETAILS:
                continue
            # Full supplied group, not display-selected members/references.
            # An unmapped member contributes an empty set, emptying the
            # all-member intersection rather than being silently skipped.
            source_sets = [set(refs[key]) for key in keys]
            action_sets = [{sources[source]['action'] for source in refs[key]} for key in keys]
            source_union = set().union(*source_sets)
            action_union = set().union(*action_sets)
            source_intersection = set(source_sets[0]).intersection(*source_sets[1:])
            action_intersection = set(action_sets[0]).intersection(*action_sets[1:])
            full_refs = [[list(key), sorted(refs[key]), sorted({sources[source]['action'] for source in refs[key]})]
                         for key in sorted(keys)]
            members = []
            selected_keys = sorted(keys, key=lambda key:_hash(list(key)))[:MAX_MEMBERS]
            omitted_members += len(keys)-len(selected_keys)
            for key in selected_keys:
                source_ids = sorted(refs[key], key=_hash)
                action_ids = sorted({sources[source]['action'] for source in refs[key]}, key=_hash)
                omitted_refs += max(0,len(source_ids)-MAX_REFS)+max(0,len(action_ids)-MAX_REFS)
                members.append(dict(attempt_sha256=_hash(list(key)),
                    parent_attempt_sha256=_hash([key[0], lineage[key]['parent_attempt_id']]),
                    stage_sha256=_hash(attempts[key]['stage']), mode=attempts[key]['mode'],
                    retry_order=attempts[key]['retry_order'], session_index=lineage[key]['session_index'],
                    session_count=lineage[key]['session_count'], declared_wall_s=str(wall[key]),
                    source_id_sha256=[_hash(value) for value in source_ids[:MAX_REFS]],
                    action_id_sha256=[_hash(value) for value in action_ids[:MAX_REFS]],
                    source_ref_count=len(source_ids), action_ref_count=len(action_ids),
                    excluded=key in excluded, exclusion_reason=excluded.get(key), mapped=bool(refs[key])))
            group_details.append(dict(circuit=group[0], raw_group_sha256=_hash(list(group)),
                supplied_member_count=len(keys), members=members,
                source_union_count=len(source_union), source_intersection_count_all_members=len(source_intersection),
                action_union_count=len(action_union), action_intersection_count_all_members=len(action_intersection),
                mapped_member_count=sum(bool(refs[key]) for key in keys),
                excluded_member_count=sum(key in excluded for key in keys),
                full_member_reference_canonical_sha256=_hash(full_refs),
                intersection_definition='all_supplied_members_including_empty_reference_sets',
                reference_statistics_scope='full_group_full_refs_not_display_subset'))
    omitted_groups = mixed_stage_count-len(group_details)
    truncated = bool(omitted_groups or omitted_members or omitted_refs)
    repeats, multiplicities = {}, {}
    for record in actions.values():
        value = str(len(record['sources']))
        repeats[value] = repeats.get(value,0)+1
    for value in refs.values():
        key = str(len(value))
        multiplicities[key] = multiplicities.get(key,0)+1
    return dict(status=('PARTIAL_MAPPING_METADATA_AUDIT' if partitions['both'] or partitions['neither']
                        or truncated or cross_stage_rule_without_difference else 'PASS_MAPPING_METADATA_PROXY_AUDIT_ONLY'),
        provided_train_attempt_count=len(attempts), filtered_validation_edge_count=val_edges,
        filtered_validation_exclusion_count=val_exclusions, train_edge_count=len(edges), train_exclusion_count=len(exclusions),
        attempt_partitions=partition_summaries, exclusion_reason_counts=_counts(exclusions,'exclusion_reason',_REASONS),
        mapping_rule_counts=rules, edge_cross_stage_reference_count=cross_stage_edges,
        cross_stage_rule_without_stage_difference_count=cross_stage_rule_without_difference,
        provided_attempt_partition_complete=not (partitions['both'] or partitions['neither']),
        source_count=len(sources), observed_action_count=len(actions), action_source_repeat_count_distribution=repeats,
        source_reference_multiplicity_distribution=multiplicities,
        shared_attempt_across_sources_count=sum(len(value)>1 for value in refs.values()),
        shared_attempt_across_actions_count=sum(len({sources[source]['action'] for source in value})>1 for value in refs.values()),
        all_supplied_unique_wall_sum_s=all_wall, mapped_unique_wall_sum_s=mapped_wall,
        source_edge_incidence_historical_proxy_sum_s=incidence_wall,
        all_source_actual_edge_sum_vector=source_summary, all_action_equal_source_mean_vector=action_summary,
        mixed_attempt_stage_group_count=mixed_stage_count, mixed_stage_group_adjacency=group_details,
        omitted_group_count=omitted_groups, omitted_member_count=omitted_members, omitted_reference_count=omitted_refs,
        decimal_precision=50, raw_group_is_invocation=False, group_members_autoadded=False, groups_split=False,
        proxy_classification='provided_mapping_references_only_not_real_candidate_cost_or_physical_makespan',
        all_sources_mean_scope='ALL_observed_mapping_sources_not_authenticated_declared_universe',
        complete_source_and_action_vectors_computed=True, quality_based_selection=False, fit_targets_generated=False,
        original_logs_or_action_tables_read=False, source_semantics_authenticated=False,
        invocation_identity_authenticated=False, candidate_cost_certified=False,
        live_A_attestation=False, snapshot_pins_only=True, real_training_release=False, real_heldout_release=False)


def main():
    try:
        _require(len(sys.argv)==1, 'CLI_ARGUMENTS_FORBIDDEN')
        limits = reader._limit_memory()
        merged = {kind:[] for kind in ('manifest','lineage','edges','exclusions')}
        total_bytes, total_rows, files = 0, 0, []
        for spec in LOCAL_SPECS:
            raw = local_reader._stable_bytes(spec['path'], spec['sha256'], min(MAX_FILE_BYTES, MAX_TOTAL_BYTES-total_bytes))
            total_bytes += len(raw)
            _require(total_bytes <= MAX_TOTAL_BYTES, 'TOTAL_BYTE_CAP')
            if spec['kind'] in ('manifest','lineage'):
                rows = reader._parse(raw,spec['kind'],spec['circuit'],MAX_ROWS-total_rows)
            else:
                rows = _mixed_parse(raw,EDGE_FIELDS if spec['kind']=='edges' else EXCLUSION_FIELDS)
            total_rows += len(rows)
            _require(total_rows<=MAX_ROWS,'TOTAL_ROW_CAP')
            merged[spec['kind']].extend(rows)
            files.append(dict(kind=spec['kind'],circuit=spec['circuit'],sha256=spec['sha256'],bytes=len(raw),rows=len(rows)))
            del raw, rows
        result = audit(merged['manifest'],merged['lineage'],merged['edges'],merged['exclusions'])
        result.update(files=files,total_bytes=total_bytes,resource=dict(limits,**reader._usage()))
        encoded = json.dumps(result,ensure_ascii=True,allow_nan=False,sort_keys=True,separators=(',',':'))
        _require(len(encoded.encode('ascii'))<=MAX_OUTPUT_BYTES,'OUTPUT_BYTE_CAP')
        print(encoded)
        return 0
    except (MappingAuditError,local_reader.DiagnosticError,reader.AuditError) as exc:
        print(json.dumps(dict(status='FAIL_CLOSED',code=str(exc)),sort_keys=True))
        return 2
    except Exception:
        print('{"code":"MAPPING_METADATA_FAILURE","status":"FAIL_CLOSED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
