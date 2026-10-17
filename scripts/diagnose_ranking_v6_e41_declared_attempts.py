"""Pure declared result-to-attempt marker audit; no files or costs accessed.

Marker transform follows the historical mapper's basename() one-suffix rule.
Namespace, circuit, mode and stage remain separate diagnostic constraints.
Even one exact marker match is not original invocation/cost certification.
"""
import hashlib
from scripts import project_ranking_v6_e40_result_paths as projection

FIELDS = frozenset(('circuit', 'mode', 'attempt_id', 'stage', 'source_log_path'))
STAGE = '04_integer_refine'
MAX_ATTEMPTS = 20000


def _require(ok, code):
    if not ok: raise ValueError('E41_' + code)


def _string(value, limit=4096):
    _require(type(value) is str and 0 < len(value) <= limit
             and all(32 <= ord(c) < 127 for c in value), 'BOUNDED_ASCII_METADATA')


def marker(path):
    """Text-only historical one-suffix transform; no fuzzy search or I/O."""
    name = path.rstrip('/').rsplit('/', 1)[-1]
    for suffix in ('.driver.log', '.log', '.tsv', '.csv'):
        if name.endswith(suffix): return name[:-len(suffix)]
    return name


def diagnose(payload, attempts):
    _require(projection.validate_response(payload), 'PINNED_PROJECTION_SCHEMA')
    _require(type(attempts) is list and len(attempts) <= MAX_ATTEMPTS, 'ATTEMPT_BOUND')
    parsed = []
    ids = set()
    for row in attempts:
        _require(type(row) is dict and set(row) == FIELDS, 'EXACT_SELECTED_FIELDS')
        for value in row.values(): _string(value)
        _require(row['circuit'] in ('s35932', 's38417') and row['mode'] in ('H', 'M', 'F'), 'ATTEMPT_SCOPE')
        _require(row['attempt_id'] not in ids, 'DUPLICATE_ATTEMPT_ID')
        ids.add(row['attempt_id'])
        path = row['source_log_path']
        parts = path.split('/')
        _require(not path.startswith('/') and '\\' not in path and ':' not in path
                 and len(parts) >= 3 and all(p not in ('', '.', '..') for p in parts), 'RELATIVE_LOG_NAMESPACE')
        parsed.append(dict(row, namespace=parts[0], path_stage=parts[1], marker=marker(path)))
    declarations = []
    for item in payload['files']:
        root = item['coverage_root']
        namespace = root.rsplit('/', 1)[-1]
        for row in item['rows']:
            uid = '{}:hf_refine:H64-F4:{}'.format(item['circuit'], row['candidate'])
            for mode in ('H', 'F'):
                value = row[mode.lower() + '_result']
                lexical = value.startswith(root + '/' + STAGE + '/')
                selected = marker(value) if value else ''
                bins = {k: [] for k in ('strict_namespace_stage', 'same_namespace_stage_conflict',
                                        'other_namespace', 'other_circuit_or_mode')}
                for attempt in parsed:
                    if not selected or attempt['marker'] != selected: continue
                    if attempt['circuit'] != item['circuit'] or attempt['mode'] != mode:
                        bucket = 'other_circuit_or_mode'
                    elif attempt['namespace'] != namespace:
                        bucket = 'other_namespace'
                    elif not lexical or attempt['stage'] != STAGE or attempt['path_stage'] != STAGE:
                        bucket = 'same_namespace_stage_conflict'
                    else: bucket = 'strict_namespace_stage'
                    bins[bucket].append(attempt['attempt_id'])
                counts = {k: len(v) for k, v in bins.items()}
                count = counts['strict_namespace_stage']
                declarations.append(dict(source_candidate_uid=uid, coverage_version=namespace, mode=mode,
                    declaration_missing=not bool(value), declaration_inside_expected_lexical_namespace=lexical,
                    result_marker_sha256=hashlib.sha256(selected.encode('ascii')).hexdigest(),
                    classification='ZERO_STRICT_MATCH' if count == 0 else 'ONE_STRICT_MATCH' if count == 1 else 'MULTIPLE_STRICT_MATCHES',
                    provided_marker_match_counts=counts,
                    strict_attempt_id_sha256=sorted(hashlib.sha256(x.encode('ascii')).hexdigest()
                                                   for x in bins['strict_namespace_stage'])))
    _require(len(declarations) == 16, 'DECLARATION_COUNT')
    classifications = {key: sum(d['classification'] == key for d in declarations)
                       for key in ('ZERO_STRICT_MATCH', 'ONE_STRICT_MATCH', 'MULTIPLE_STRICT_MATCHES')}
    return dict(status='PARTIAL_DECLARED_MARKER_JOIN_NOT_CALL_CERTIFICATION', declarations=declarations,
                declaration_count=16, scoped_source_rows=8, provided_attempt_rows=len(attempts),
                strict_match_classifications=classifications,
                total_strict_declaration_attempt_references=sum(d['provided_marker_match_counts']['strict_namespace_stage'] for d in declarations),
                unique_strict_attempt_id_sha256_count=len({x for d in declarations for x in d['strict_attempt_id_sha256']}),
                preserved_reference_unit='declared scoped source row plus mode; not independent physical invocation',
                paths_followed_or_resolved=False, source_origin_assigned=False, quality_evaluated=False,
                wall_or_status_analyzed=False, costs_computed=False, invocation_identity_certified=False,
                candidate_universe_or_pre_outcome_freeze_certified=False, training_release=False)
