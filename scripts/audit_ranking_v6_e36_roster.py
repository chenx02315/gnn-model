"""Pure-memory coverage of PROVIDED historical roster metadata only.

No reader or CLI exists. An inventory declaration is not historical or
pre-execution completeness evidence. Zero-row declared files remain explicit.
Candidate IDs follow the legacy projection: explicit nonnegative IDs (zero is
allowed), or one-based data-row fallback on any of the four aliases. Canonical
decimal representation is required here; legacy leading-zero inputs are not
silently rewritten or certified. No eligibility/quality/status/cost is accepted.
"""
import re


MAX_ROWS = 100000
MAX_STRING = 256
CIRCUITS = ('aes_core', 's13207', 's15850', 's35932', 's38417', 'spi')
ALIASES = ('hf_coarse', 'hmf_coarse', 'hf_refine', 'hmf_refine')
ROSTER_FIELDS = frozenset(('circuit', 'stage_alias', 'scheme', 'h_patterns', 'm_patterns',
    'candidate_id', 'candidate_id_origin', 'source_candidate_uid', 'action_uid',
    'source_file_sha256', 'source_row'))
EDGE_FIELDS = frozenset(('source_candidate_uid', 'action_uid', 'circuit'))
INVENTORY_FIELDS = frozenset(('circuit', 'stage_alias', 'source_file_sha256', 'data_row_count'))
_UINT = re.compile(r'(?:0|[1-9][0-9]*)\Z')
_SHA = re.compile(r'[0-9a-f]{64}\Z')


class RosterAuditError(ValueError):
    pass


def _require(ok, code):
    if not ok:
        raise RosterAuditError('E36_' + code)


def _rows(rows, fields, cap):
    _require(type(rows) is list and len(rows) <= cap, 'EXACT_LIST_OR_ROW_CAP')
    for row in rows:
        _require(type(row) is dict and all(type(key) is str for key in row)
                 and set(row) == fields, 'EXACT_METADATA_FIELDS')
        _require(all(type(value) is str and len(value) <= MAX_STRING for value in row.values()),
                 'BUILTIN_STRING_BOUND')
        _require(row['circuit'] in CIRCUITS, 'TRAIN_CIRCUIT_ONLY')


def _number(value, maximum, minimum=0):
    _require(bool(value) and len(value) <= 10 and _UINT.match(value) is not None,
             'CANONICAL_DECIMAL_REQUIRED')
    number = int(value)
    _require(minimum <= number <= maximum, 'COUNT_BOUND')
    return number


def audit(roster, edges, inventory):
    """Validate declaration rows and report mapped/unmapped without dropping any.

    Edges are source/action roster references, not session-attempt edges. Costs,
    source eligibility and whether inventory was frozen before outcomes cannot
    be inferred. The function performs no I/O and never mutates supplied rows.
    """
    _rows(roster, ROSTER_FIELDS, MAX_ROWS)
    _rows(edges, EDGE_FIELDS, MAX_ROWS)
    _rows(inventory, INVENTORY_FIELDS, 24)
    files = {}
    declared_count = 0
    for row in inventory:
        key = (row['circuit'], row['stage_alias'])
        _require(row['stage_alias'] in ALIASES and key not in files, 'INVENTORY_ALIAS_OR_DUPLICATE')
        _require(_SHA.match(row['source_file_sha256']) is not None, 'LOWERCASE_FILE_SHA256')
        count = _number(row['data_row_count'], MAX_ROWS)
        declared_count += count
        _require(declared_count <= MAX_ROWS, 'TOTAL_DECLARED_ROW_CAP')
        files[key] = dict(sha256=row['source_file_sha256'], count=count, rows=set(), sources=set())
    _require(set(files) == {(circuit, alias) for circuit in CIRCUITS for alias in ALIASES},
             'EXACT_24_FILE_INVENTORY')
    records, action_sources, origins = {}, {}, {'explicit_candidate':0, 'one_based_data_row':0}
    for row in roster:
        key = (row['circuit'], row['stage_alias'])
        _require(key in files, 'ROSTER_FILE_JOIN')
        file = files[key]
        _require(row['source_file_sha256'] == file['sha256'], 'FILE_SHA256_JOIN')
        index = _number(row['source_row'], MAX_ROWS+1, minimum=2)
        _require(index not in file['rows'] and index <= file['count']+1, 'SOURCE_ROW_DUPLICATE_OR_RANGE')
        candidate = _number(row['candidate_id'], 1000000000)
        h = _number(row['h_patterns'], 1000000000)
        scheme = 'HMF' if row['stage_alias'].startswith('hmf_') else 'HF'
        _require(row['scheme'] == scheme, 'ALIAS_SCHEME_JOIN')
        if scheme == 'HF':
            _require(row['m_patterns'] in ('', '0'), 'HF_M_MUST_BE_BLANK_OR_ZERO')
            modes, expected_action = 'H64-F4', row['circuit']+':HF:h'+str(h)
        else:
            m = _number(row['m_patterns'], 1000000000)
            modes = 'H64-M16-F4'
            expected_action = row['circuit']+':HMF:h'+str(h)+':m'+str(m)
        origin = row['candidate_id_origin']
        _require(origin in origins, 'CANDIDATE_ORIGIN')
        if origin == 'one_based_data_row':
            _require(candidate == index-1, 'DATA_ROW_FALLBACK_JOIN')
        expected_source = ':'.join((row['circuit'], row['stage_alias'], modes, str(candidate)))
        _require(row['source_candidate_uid'] == expected_source and row['action_uid'] == expected_action,
                 'CANONICAL_UID_CONFIGURATION_JOIN')
        _require(expected_source not in records, 'DUPLICATE_SOURCE_UID')
        records[expected_source] = (expected_action, row['circuit'], key)
        action_sources.setdefault(expected_action, set()).add(expected_source)
        file['rows'].add(index)
        file['sources'].add(expected_source)
        origins[origin] += 1
    _require(len(roster) == declared_count, 'INVENTORY_ROW_COUNT_JOIN')
    for file in files.values():
        _require(file['rows'] == set(range(2, file['count']+2)), 'SOURCE_ROW_COMPLETENESS')
    mapped = set()
    for row in edges:
        source = row['source_candidate_uid']
        _require(source in records, 'EDGE_SOURCE_ORPHAN')
        action, circuit, _ = records[source]
        _require(row['action_uid'] == action and row['circuit'] == circuit, 'EDGE_CONFIGURATION_JOIN')
        _require(source not in mapped, 'DUPLICATE_SOURCE_ACTION_EDGE')
        mapped.add(source)
    unmapped = set(records)-mapped
    mapped_actions = {records[source][0] for source in mapped}
    unmapped_source_actions = {records[source][0] for source in unmapped}
    file_summaries = []
    for key, file in sorted(files.items()):
        file_summaries.append(dict(circuit=key[0], stage_alias=key[1], declared_data_rows=file['count'],
            provided_rows=len(file['rows']), mapped_source_count=len(file['sources'] & mapped),
            unmapped_source_count=len(file['sources'] & unmapped),
            declared_empty_file=file['count'] == 0, inventory_hash_binding_pass=True))
    return dict(status='PASS_PROVIDED_ROSTER_METADATA_COVERAGE_ONLY',
        inventory_file_declaration_count=24, declared_empty_file_count=sum(file['count']==0 for file in files.values()),
        declared_row_count=declared_count, provided_roster_count=len(roster), provided_edge_count=len(edges),
        mapped_source_count=len(mapped), unmapped_source_count=len(unmapped),
        provided_action_count=len(action_sources), mapped_action_count=len(mapped_actions),
        unmapped_source_action_count=len(unmapped_source_actions),
        fully_unmapped_action_count=len(set(action_sources)-mapped_actions),
        partially_mapped_action_count=len(mapped_actions & unmapped_source_actions),
        fully_mapped_action_count=sum(sources <= mapped for sources in action_sources.values()),
        candidate_id_origin_counts=origins, files=file_summaries,
        hf_m_zero_normalization='blank_and_zero_are_equivalent_control_metadata_only',
        empty_declared_roster=not records, unreferenced_roster_rows_retained=True,
        pre_outcome_certified=False, inventory_origin_authenticated=False,
        historical_source_completeness_certified=False, training_release=False,
        physical_files_read=False, source_quality_or_eligibility_accessed=False,
        costs_or_outcomes_computed=False, fit_targets_generated=False, online_claim=False,
        coverage_scope='provided_24_file_inventory_declarations_not_historical_source_or_pre_outcome_certification')
