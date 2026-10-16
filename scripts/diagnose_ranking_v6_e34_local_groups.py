"""E34 focused metadata-group diagnostics; no repair, splitting or FIT labels.

CLI reads only the pinned local s38417 manifest/lineage pair. Definitions are
safe to import; no table, source-log, model or remote operation occurs on import.
"""
from __future__ import print_function
from decimal import Decimal, localcontext
import hashlib
import json
import os
import re
import stat
import sys

# Import definitions without creating bytecode artifacts. Never invoke the
# initial reader's CLI or relabel its PARTIAL result.
_old_bytecode = sys.dont_write_bytecode
try:
    sys.dont_write_bytecode = True
    try:
        from scripts import audit_ranking_v6_train_metadata_e34 as reader
    except ImportError:
        import audit_ranking_v6_train_metadata_e34 as reader
finally:
    sys.dont_write_bytecode = _old_bytecode


MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_ROWS = 200000
MAX_DETAILS = 256
MAX_FIELD_VALUES = 64
_LOCAL_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..',
    'runtime_training_staging_20260928', 'runtime_attempt_remediation_v2_r1_remote', 'outputs_v2'))
LOCAL_SPECS = (
    dict(path=os.path.join(_LOCAL_ROOT, 's38417_attempt_manifest_v2_remediated.tsv'),
         sha256='30aea1c23bc6751c3b17e1e2e32ae36fc3cbd7934f03df22fb78df1f7c962300', kind='manifest'),
    dict(path=os.path.join(_LOCAL_ROOT, 's38417_lineage_v2.tsv'),
         sha256='9b475306c7ad2260330a7da48ff0a690a90a8bf35eb8dc3ef4bebb6f9c873b38', kind='lineage'))
_ORDER = re.compile(r'[1-9][0-9]{0,5}\Z')
_CLASSES = ('SUCCESS', 'FAILURE', 'TIMEOUT', 'COLLECTED_SUCCESS_ONLY', 'UNKNOWN')


class DiagnosticError(ValueError):
    pass


def _require(ok, code):
    if not ok:
        raise DiagnosticError(code)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            getattr(info, 'st_mtime_ns', info.st_mtime), getattr(info, 'st_ctime_ns', info.st_ctime))


def _cross_api_identity(info):
    """Windows path/FD ctime conventions differ; same-API checks stay full.

    Only the measured cross-API ctime discrepancy is excluded on Windows.
    Device/inode/mode/link-count/size/mtime and exact bytes SHA remain bound.
    POSIX cross-API comparisons continue to include every identity field.
    """
    identity = _identity(info)
    return identity[:-1] if os.name == 'nt' else identity


def _ordinary(info, directory=False):
    _require(not stat.S_ISLNK(info.st_mode)
             and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'LINK_OR_REPARSE')
    _require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'ORDINARY_PATH_REQUIRED')
    if not directory:
        _require(info.st_nlink == 1, 'SINGLE_LINK_REQUIRED')


def _ancestors(path):
    paths, cursor = [], os.path.dirname(path)
    while True:
        paths.append(cursor)
        parent = os.path.dirname(cursor)
        if parent == cursor:
            break
        cursor = parent
    for item in reversed(paths):
        _ordinary(os.lstat(item), directory=True)


def _stable_bytes(path, expected_sha, remaining):
    """Bounded stable regular-file FD, no links/reparse and exact SHA first.

    Assumes trusted non-hostile local hierarchy. Windows lstat/fstat is not an
    adversarial-concurrency sandbox; no ACL or link policy is bypassed.
    """
    _require(type(path) is str and os.path.isabs(path) and path == os.path.normpath(path)
             and '\x00' not in path, 'LEXICAL_ABSOLUTE_PATH')
    if os.name == 'nt':
        drive, tail = os.path.splitdrive(path)
        _require(bool(drive) and not drive.startswith('\\\\') and ':' not in tail, 'DRIVE_OR_ADS')
    _require(type(expected_sha) is str and reader._SHA.match(expected_sha) is not None, 'SHA256_SHAPE')
    descriptor = None
    try:
        _ancestors(path)
        before = os.lstat(path)
        _ordinary(before)
        cap = min(MAX_FILE_BYTES, remaining)
        _require(0 < before.st_size <= cap, 'BYTE_CAP')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0)
                              | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        opened = os.fstat(descriptor)
        _ordinary(opened)
        _require(_cross_api_identity(opened) == _cross_api_identity(before), 'OPEN_IDENTITY_CHANGED')
        chunks, digest, count = [], hashlib.sha256(), 0
        while count <= cap:
            chunk = os.read(descriptor, min(65536, cap+1-count))
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            count += len(chunk)
        after = os.fstat(descriptor)
        _ordinary(after)
        _ancestors(path)
        last = os.lstat(path)
        _ordinary(last)
        _require(_identity(before) == _identity(last)
                 and _identity(opened) == _identity(after)
                 and _cross_api_identity(last) == _cross_api_identity(after)
                 and count == opened.st_size and count <= cap, 'READ_IDENTITY_OR_SIZE_CHANGED')
        _require(digest.hexdigest() == expected_sha, 'FILE_SHA256_MISMATCH')
        return b''.join(chunks)
    except DiagnosticError:
        raise
    except (OSError, ValueError, TypeError):
        raise DiagnosticError('LOCAL_METADATA_READ_FAILED')
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_rows(rows, fields):
    _require(type(rows) is list and 1 <= len(rows) <= MAX_ROWS, 'ROW_CONTAINER')
    characters = 0
    for row in rows:
        _require(type(row) is dict and all(type(key) is str for key in row)
                 and set(row) == set(fields), 'EXACT_SCHEMA')
        for value in row.values():
            _require(type(value) is str and len(value) <= 65536, 'STRING_BOUND')
            characters += len(value)
        _require(characters <= MAX_TOTAL_BYTES, 'CHARACTER_CAP')
        _require(row['circuit'] in reader.FAMILIES and bool(row['attempt_id']), 'TRAIN_CIRCUIT_ATTEMPT')
        if fields == reader.MANIFEST_FIELDS:
            _require(row['role'] == 'TRAIN' and row['family'] == reader.FAMILIES[row['circuit']], 'TRAIN_FAMILY')


def _counts(rows, field, allowed):
    result = {key: 0 for key in allowed}
    result['OTHER'] = 0
    for row in rows:
        result[row[field] if row[field] in allowed else 'OTHER'] += 1
    return result


def _order(value):
    if _ORDER.match(value) is None or int(value) > MAX_ROWS:
        return None
    return int(value)


def diagnose(manifestrows, lineagerows):
    """Diagnose supplied TRAIN metadata only; do not repair or regroup it."""
    _validate_rows(manifestrows, reader.MANIFEST_FIELDS)
    _validate_rows(lineagerows, reader.LINEAGE_FIELDS)
    _require(len(manifestrows)+len(lineagerows) <= MAX_ROWS, 'TOTAL_ROW_CAP')
    manifest, lineage = {}, {}
    for rows, target in ((manifestrows, manifest), (lineagerows, lineage)):
        for row in rows:
            key = (row['circuit'], row['attempt_id'])
            _require(key not in target, 'DUPLICATE_ATTEMPT_ID')
            target[key] = row
    grouped = {}
    for key, row in manifest.items():
        grouped.setdefault((row['circuit'], row['retry_group_id']), []).append(key)
    details, mixed_counts, homogeneous = [], {'stage': 0, 'mode': 0, 'environment_cohort': 0}, 0
    total_wall = Decimal(0)
    parent_fact_issues = 0
    with localcontext() as context:
        context.prec = 50
        for group, keys in sorted(grouped.items()):
            rows = [manifest[key] for key in sorted(keys)]
            values = {field: sorted({row[field] for row in rows})
                      for field in ('stage', 'mode', 'environment_cohort')}
            mismatches = [field for field in sorted(values) if len(values[field]) > 1]
            for field in mismatches:
                mixed_counts[field] += 1
            linked = [lineage[key] for key in keys if key in lineage]
            missing = len(keys)-len(linked)
            join_mismatch = sum(any(manifest[(row['circuit'], row['attempt_id'])][field] != row[field]
                                    for field in ('retry_group_id', 'retry_order', 'attempt_outcome_class', 'timeout_status'))
                                for row in linked)
            orders = [_order(row['retry_order']) for row in rows]
            complete = (all(order is not None for order in orders)
                        and sorted(orders) == list(range(1, len(rows)+1)))
            parents = {}
            for row in linked:
                parents.setdefault(row['parent_attempt_id'], []).append(row)
            parent_issues = multi_session_parents = cross_stage_parents = cross_mode_parents = 0
            for members in parents.values():
                counts = {row['session_count'] for row in members}
                indices = [_order(row['session_index']) for row in members]
                good = (len(counts) == 1 and _order(members[0]['session_count']) == len(members)
                        and all(index is not None for index in indices)
                        and sorted(indices) == list(range(1, len(members)+1)))
                parent_issues += not good
                multi_session_parents += len(members) > 1
                parent_rows = [manifest[(row['circuit'], row['attempt_id'])] for row in members]
                cross_stage_parents += len({row['stage'] for row in parent_rows}) > 1
                cross_mode_parents += len({row['mode'] for row in parent_rows}) > 1
            parent_fact_issues += parent_issues
            wall, outcome_wall = Decimal(0), {key: Decimal(0) for key in _CLASSES+('OTHER',)}
            for row in rows:
                _require(reader._WALL.match(row['wall_s']) is not None, 'WALL_DECIMAL')
                value = Decimal(row['wall_s'])
                _require(0 <= value <= Decimal('1e9'), 'WALL_BOUND')
                wall += value
                outcome = row['attempt_outcome_class'] if row['attempt_outcome_class'] in _CLASSES else 'OTHER'
                outcome_wall[outcome] += value
            total_wall += wall
            issues = bool(mismatches or missing or join_mismatch or not complete or parent_issues)
            homogeneous += not issues
            if issues:
                details.append(dict(circuit=group[0], retry_group_sha256=_hash(list(group)),
                    row_count=len(rows), field_specific_mismatches=mismatches,
                    stage_distinct_count=len(values['stage']),
                    stage_value_sha256=[_hash(v) for v in values['stage'][:MAX_FIELD_VALUES]],
                    omitted_stage_value_count=max(0, len(values['stage'])-MAX_FIELD_VALUES),
                    environment_cohort_distinct_count=len(values['environment_cohort']),
                    environment_cohort_value_sha256=[_hash(v) for v in values['environment_cohort'][:MAX_FIELD_VALUES]],
                    omitted_environment_cohort_value_count=max(0, len(values['environment_cohort'])-MAX_FIELD_VALUES),
                    mode_counts=_counts(rows, 'mode', ('H', 'M', 'F')),
                    parent_count=len(parents), parent_session_completeness_issue_count=parent_issues,
                    multi_session_parent_count=multi_session_parents,
                    cross_stage_parent_count=cross_stage_parents, cross_mode_parent_count=cross_mode_parents,
                    source_log_sha256_distinct_count=len({row['source_log_sha256'] for row in rows if row['source_log_sha256']}),
                    lineage_missing_count=missing, lineage_value_mismatch_count=join_mismatch,
                    retry_order_complete_one_based=complete,
                    retry_order_status_counts=_counts(rows, 'retry_order_status', ('KNOWN_ORDER', 'UNKNOWN_ORDER')),
                    order_evidence_counts=_counts(linked, 'order_evidence', ('STRUCTURAL_SINGLETON',
                        'GNU_TIME_FOOTER_EMISSION_ORDER', 'EMBEDDED_SIEMENS_START_ORDER')),
                    attempt_outcome_class_counts=_counts(rows, 'attempt_outcome_class', _CLASSES),
                    declared_wall_sum_s=str(wall), declared_wall_by_outcome_class_s={key:str(value) for key,value in outcome_wall.items()}))
    details.sort(key=lambda row: (row['circuit'], row['retry_group_sha256']))
    truncated = (len(details) > MAX_DETAILS or any(row['omitted_stage_value_count']
                    or row['omitted_environment_cohort_value_count'] for row in details[:MAX_DETAILS]))
    return dict(status=('PARTIAL_GROUP_DIAGNOSTIC_DETAILS_TRUNCATED' if truncated
                        else 'PASS_MATERIALIZED_METADATA_GROUP_DIAGNOSTIC_ONLY'),
        manifest_row_count=len(manifestrows), lineage_row_count=len(lineagerows), group_count=len(grouped),
        homogeneous_group_count=homogeneous, problem_group_count=len(details),
        field_mixed_group_counts=mixed_counts, parent_session_issue_count=parent_fact_issues,
        orphan_lineage_count=len(set(lineage)-set(manifest)),
        problem_groups=details[:MAX_DETAILS], omitted_problem_group_count=max(0, len(details)-MAX_DETAILS),
        declared_wall_sum_s=str(total_wall), decimal_precision=50,
        groups_repaired_or_split=False, original_reader_PARTIAL_reclassified=False,
        raw_ids_or_paths_emitted=False, source_logs_read=False, candidate_quality_accessed=False,
        fit_targets_generated=False, metadata_semantics_authenticated=False,
        timing_scope_authenticated=False, real_training_release=False, remote_access=False)


def main():
    try:
        _require(len(sys.argv) == 1, 'CLI_ARGUMENTS_FORBIDDEN')
        limits = reader._limit_memory()
        tables, files, count = {}, [], 0
        for spec in LOCAL_SPECS:
            raw = _stable_bytes(spec['path'], spec['sha256'], MAX_TOTAL_BYTES-count)
            count += len(raw)
            _require(count <= MAX_TOTAL_BYTES, 'TOTAL_BYTE_CAP')
            tables[spec['kind']] = reader._parse(raw, spec['kind'], 's38417', MAX_ROWS)
            files.append(dict(kind=spec['kind'], sha256=spec['sha256'], bytes=len(raw)))
            del raw
        result = diagnose(tables['manifest'], tables['lineage'])
        result.update(files=files, total_bytes=count, resource=dict(limits, **reader._usage()))
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return 0
    except (DiagnosticError, reader.AuditError) as exc:
        print(json.dumps(dict(status='FAIL_CLOSED', code=str(exc)), sort_keys=True))
        return 2
    except Exception:
        print('{"code":"LOCAL_DIAGNOSTIC_FAILURE","status":"FAIL_CLOSED"}')
        return 2


if __name__ == '__main__':
    sys.exit(main())
