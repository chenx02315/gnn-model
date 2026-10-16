"""E34 fixed-roster metadata-only audit; Python 3.6 stdlib, stdin-capable.

Never opens source-log/artifact paths contained in TSV rows. No candidates,
quality labels, graph construction, timing-scope authentication or training.
CONFIGURED_SPECS must be source-pinned before CLI execution; argv paths and
environment configuration are not accepted. Descriptor walking is POSIX-only.
"""
from __future__ import print_function

import csv
from decimal import Decimal, localcontext
import hashlib
import io
import json
import os
import re
import stat
import sys
try:
    import resource
except ImportError:
    resource = None


_PIN_ROOT = '/temp/jiangchuanc/runtime_attempt_remediation_v2_r1_bundle/outputs_v2'
_PINS = (
    ('aes_core', '4757b9dec478721c8bf7f3eccb7fd3dc81c54abdb42a5f07a73721df32a849ab', '7600ab8944ce690bdcc3729915fd830523afa204eff4280dd1dd96aa58555c10'),
    ('s13207', 'd0a014837317122a4ff96a0ba132d43107f42920b15850e8d2035a4aa62afbff', 'b8465f052eba40ecb2985c0545ba22312fecd31bb9560bff503500101ba8d23a'),
    ('s15850', '49dd17ee093bf09bb13fc81a2055cd8f37963e238a529def248b95b8b0a6745c', 'd07fbd4e8d4eaee09745c8fa562a18bf8c22a372b0bce451fcfbaaccb3a83a63'),
    ('s35932', 'af7236dc484e2a5e3a489787f98ec1ae5963ec34fe625585cd59820c48b4db36', 'ba107ddd150c05d3fcd6e8c74da6b5878fc4a3e73290b4b148fd17c575da0b24'),
    ('s38417', '30aea1c23bc6751c3b17e1e2e32ae36fc3cbd7934f03df22fb78df1f7c962300', '9b475306c7ad2260330a7da48ff0a690a90a8bf35eb8dc3ef4bebb6f9c873b38'),
    ('spi', 'ac8647816808ce0d8c9320fbaaad07fc3a99ff0b83b312292f29837d887f4e43', '0fdb6eb1f3d228a3faa0aafa391e67c64fda153a014bee8e68b17fe97e901e90'))
CONFIGURED_SPECS = tuple({'path': _PIN_ROOT + '/' + circuit + suffix, 'sha256': digest,
                          'circuit': circuit, 'kind': kind}
                         for circuit, manifest_sha, lineage_sha in _PINS
                         for kind, suffix, digest in (
                             ('manifest', '_attempt_manifest_v2_remediated.tsv', manifest_sha),
                             ('lineage', '_lineage_v2.tsv', lineage_sha)))
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ROWS = 200000
MAX_LINE_BYTES = 64 * 1024
FAMILIES = {'aes_core': 'iwls_aes_core', 's13207': 'iscas89_s13207',
            's15850': 'iscas89_s15850', 's35932': 'iscas89_s35932',
            's38417': 'iscas89_s38417', 'spi': 'iwls_spi'}
# Exact copies of the reviewed outcome-free schemas. Standalone execution must
# not import repository modules, site packages or a dynamically supplied schema.
MANIFEST_FIELDS = (
    'attempt_id', 'adapter', 'circuit', 'family', 'role', 'cohort', 'environment_cohort', 'phase', 'stage', 'mode', 'run_id',
    'run_id_source', 'wall_s', 'user_s', 'system_s', 'rss_kb', 'exit_status', 'atpg_status',
    'timeout_status', 'retry_order', 'retry_order_status', 'parse_status',
    'attempt_outcome_class', 'semantics_status', 'semantics_contract', 'elapsed_source', 'elapsed_semantics',
    'retry_group_id', 'source_artifact', 'source_artifact_sha256', 'source_row_number', 'source_log_path',
    'source_log_sha256', 'inventory_manifest_sha256')
LINEAGE_FIELDS = ('circuit', 'parent_attempt_id', 'attempt_id', 'retry_group_id', 'retry_order',
                  'order_evidence', 'session_index', 'session_count', 'attempt_outcome_class', 'timeout_status')
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_ORDER = re.compile(r'[1-9][0-9]{0,5}\Z')
_WALL = re.compile(r'[0-9]{1,10}(?:\.[0-9]{1,9})?\Z')
_OUTCOMES = ('SUCCESS', 'FAILURE', 'TIMEOUT', 'COLLECTED_SUCCESS_ONLY', 'UNKNOWN')


class AuditError(ValueError):
    pass


def _require(condition, code):
    if not condition:
        raise AuditError(code)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            getattr(info, 'st_mtime_ns', info.st_mtime), getattr(info, 'st_ctime_ns', info.st_ctime))


def _ordinary(info):
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'REGULAR_SINGLE_LINK_REQUIRED')


def _path(value):
    _require(type(value) is str and value.startswith('/') and not value.startswith('//')
             and '\\' not in value and '\x00' not in value and len(value) <= 4096,
             'ABSOLUTE_POSIX_PATH_REQUIRED')
    parts = value.split('/')[1:]
    _require(parts and all(part not in ('', '.', '..') for part in parts), 'PATH_COMPONENT')
    return parts


def _read_regular(path, expected_sha, remaining):
    """Walk each ancestor by descriptor, read/hash one bounded stable file FD."""
    parts = _path(path)
    _require(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY')
             and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd,
             'SECURE_POSIX_OPEN_UNAVAILABLE')
    parent = descriptor = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parent = os.open('/', flags)
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=parent)
            try:
                _require(stat.S_ISDIR(os.fstat(child).st_mode), 'ANCESTOR_DIRECTORY_REQUIRED')
            except Exception:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        _ordinary(before)
        cap = min(MAX_FILE_BYTES, remaining)
        _require(0 < before.st_size <= cap, 'FILE_OR_TOTAL_BYTE_CAP')
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0),
                             dir_fd=parent)
        opened = os.fstat(descriptor)
        _ordinary(opened)
        _require(_identity(opened) == _identity(before), 'OPEN_IDENTITY_CHANGED')
        chunks, count, digest = [], 0, hashlib.sha256()
        while count <= cap:
            chunk = os.read(descriptor, min(65536, cap + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            count += len(chunk)
        after = os.fstat(descriptor)
        last = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        _ordinary(after)
        _ordinary(last)
        _require(count <= cap and count == opened.st_size
                 and _identity(opened) == _identity(after) == _identity(last), 'READ_IDENTITY_OR_SIZE_CHANGED')
        _require(digest.hexdigest() == expected_sha, 'FILE_SHA256_MISMATCH')
        return b''.join(chunks)
    except AuditError:
        raise
    except (OSError, ValueError, TypeError, NotImplementedError):
        raise AuditError('SECURE_FILE_READ_FAILED')
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def _parse(raw, kind, circuit, remaining_rows):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_FILE_BYTES, 'FILE_BYTE_CAP')
    _require(all(len(line) <= MAX_LINE_BYTES for line in raw.splitlines(True)), 'LINE_BYTE_CAP')
    try:
        text = raw.decode('utf-8')
        reader = csv.reader(io.StringIO(text, newline=''), delimiter='\t', strict=True)
        fields = MANIFEST_FIELDS if kind == 'manifest' else LINEAGE_FIELDS
        _require(tuple(next(reader)) == fields, 'EXACT_SCHEMA_REQUIRED')
        rows = []
        for values in reader:
            _require(len(values) == len(fields) and all('\x00' not in v and '\n' not in v and '\r' not in v
                                                       for v in values), 'TSV_ROW_SHAPE')
            _require(len(rows) < remaining_rows, 'TOTAL_ROW_CAP')
            row = dict(zip(fields, values))
            _require(row['circuit'] == circuit, 'CIRCUIT_MEMBERSHIP')
            if kind == 'manifest':
                _require(row['role'] == 'TRAIN' and row['family'] == FAMILIES[circuit], 'TRAIN_FAMILY_MEMBERSHIP')
            _require(bool(row['attempt_id']), 'ATTEMPT_ID_REQUIRED')
            rows.append(row)
        _require(bool(rows), 'EMPTY_TABLE')
        return rows
    except AuditError:
        raise
    except (UnicodeError, csv.Error, StopIteration):
        raise AuditError('TSV_PARSE_FAILED')


def _index(value):
    _require(_ORDER.match(value) is not None and int(value) <= MAX_ROWS, 'CANONICAL_ORDER_REQUIRED')
    return int(value)


def _distribution(rows, field, allowed):
    counts = {value: 0 for value in allowed}
    counts['OTHER'] = 0
    for row in rows:
        key = row[field] if row[field] in allowed else 'OTHER'
        counts[key] += 1
    return counts


def _consistent_lineage(manifest, lineage):
    by_id, lineage_by_id = {}, {}
    for row in manifest:
        _require(row['attempt_id'] not in by_id, 'DUPLICATE_MANIFEST_ATTEMPT')
        by_id[row['attempt_id']] = row
    for row in lineage:
        _require(row['attempt_id'] not in lineage_by_id, 'DUPLICATE_LINEAGE_ATTEMPT')
        lineage_by_id[row['attempt_id']] = row
    _require(set(by_id) == set(lineage_by_id), 'EXACT_LINEAGE_JOIN')
    parents, groups = {}, {}
    for attempt, row in sorted(by_id.items()):
        linked = lineage_by_id[attempt]
        _require(all(row[name] == linked[name] for name in
                     ('retry_group_id', 'retry_order', 'attempt_outcome_class', 'timeout_status')), 'LINEAGE_VALUE_JOIN')
        _require(row['retry_order_status'] == 'KNOWN_ORDER' and bool(row['retry_group_id']), 'KNOWN_RETRY_ORDER_REQUIRED')
        _index(row['retry_order'])
        _index(linked['session_index'])
        _index(linked['session_count'])
        _require(bool(linked['parent_attempt_id']), 'PARENT_ID_REQUIRED')
        for name in ('source_artifact_sha256', 'source_log_sha256'):
            _require(_SHA.match(row[name]) is not None, 'SOURCE_SHA256_SHAPE')
        _require(row['mode'] in ('H', 'M', 'F'), 'MODE')
        parents.setdefault(linked['parent_attempt_id'], []).append(attempt)
        groups.setdefault(row['retry_group_id'], []).append(attempt)
    for parent, attempts in parents.items():
        first = by_id[attempts[0]]
        count = lineage_by_id[attempts[0]]['session_count']
        _require(len(attempts) == _index(count)
                 and sorted(_index(lineage_by_id[a]['session_index']) for a in attempts) == list(range(1, len(attempts)+1)),
                 'PARENT_SESSION_COMPLETENESS')
        for attempt in attempts:
            row, linked = by_id[attempt], lineage_by_id[attempt]
            _require(linked['session_count'] == count and all(row[name] == first[name] for name in
                      ('circuit', 'family', 'role', 'stage', 'mode', 'retry_group_id', 'environment_cohort',
                       'source_log_sha256', 'source_artifact_sha256')), 'PARENT_METADATA_JOIN')
            if _index(linked['session_index']) == len(attempts):
                _require(attempt == parent, 'TERMINAL_PARENT_REFERENCE')
    evidence_counts = {'STRUCTURAL_SINGLETON': 0, 'GNU_TIME_FOOTER_EMISSION_ORDER': 0,
                       'EMBEDDED_SIEMENS_START_ORDER': 0}
    for attempts in groups.values():
        first = by_id[attempts[0]]
        _require(sorted(_index(by_id[a]['retry_order']) for a in attempts) == list(range(1, len(attempts)+1)),
                 'RETRY_GROUP_ORDER_COMPLETENESS')
        evidences = {lineage_by_id[a]['order_evidence'] for a in attempts}
        _require(len(evidences) == 1, 'GROUP_ORDER_EVIDENCE_JOIN')
        evidence = next(iter(evidences))
        _require(evidence in evidence_counts, 'ORDER_EVIDENCE')
        evidence_counts[evidence] += 1
        _require(all(all(by_id[a][name] == first[name] for name in ('stage', 'mode', 'environment_cohort'))
                     for a in attempts), 'GROUP_METADATA_JOIN')
        if len(attempts) == 1:
            _require(evidence == 'STRUCTURAL_SINGLETON', 'SINGLETON_ORDER_EVIDENCE')
        elif evidence == 'GNU_TIME_FOOTER_EMISSION_ORDER':
            _require(len({lineage_by_id[a]['parent_attempt_id'] for a in attempts}) == 1
                     and len({by_id[a]['source_log_sha256'] for a in attempts}) == 1
                     and all(by_id[a]['retry_order'] == lineage_by_id[a]['session_index'] for a in attempts), 'GNU_SESSION_ORDER')
        elif evidence == 'EMBEDDED_SIEMENS_START_ORDER':
            _require(len({lineage_by_id[a]['parent_attempt_id'] for a in attempts}) > 1
                     and len({by_id[a]['source_log_sha256'] for a in attempts}) > 1, 'EMBEDDED_MULTI_LOG_ORDER')
        else:
            raise AuditError('MULTI_SESSION_ORDER_EVIDENCE')
    return dict(unique_parent_count=len(parents), retry_group_count=len(groups),
        multi_session_retry_group_count=sum(len(v) > 1 for v in groups.values()),
        maximum_retry_group_size=max(len(v) for v in groups.values()), order_evidence_group_counts=evidence_counts,
        parent_session_lineage_consistent=True, retry_order_consistent=True)


def _summarize(manifest, lineage):
    with localcontext() as context:
        context.prec = 50
        total = Decimal(0)
        status_seconds = {value: Decimal(0) for value in _OUTCOMES + ('OTHER',)}
        for row in manifest:
            _require(_WALL.match(row['wall_s']) is not None, 'WALL_ASCII_DECIMAL_REQUIRED')
            wall = Decimal(row['wall_s'])
            _require(0 <= wall <= Decimal('1e9'), 'WALL_BOUND')
            total += wall
            kind = row['attempt_outcome_class'] if row['attempt_outcome_class'] in _OUTCOMES else 'OTHER'
            status_seconds[kind] += wall
        seconds = {key: str(value) for key, value in status_seconds.items()}
    summary = dict(manifest_row_count=len(manifest), lineage_row_count=len(lineage),
        environment_cohort_distinct_count=len({row['environment_cohort'] for row in manifest}),
        environment_cohort_equality_is_authentication=False,
        stage_counts=_distribution(manifest, 'stage', ('H', 'M', 'F', 'phase1', 'phase2', 'phase3',
                                                       'phase4', 'phase_1', 'phase_2', 'phase_3', 'phase_4')),
        mode_counts=_distribution(manifest, 'mode', ('H', 'M', 'F')),
        source_hash_statistics={name: dict(empty_count=sum(not row[name] for row in manifest),
                                            distinct_nonempty_count=len({row[name] for row in manifest if row[name]}),
                                            malformed_nonempty_count=sum(bool(row[name]) and _SHA.match(row[name]) is None
                                                                          for row in manifest))
                                for name in ('source_artifact_sha256', 'source_log_sha256', 'inventory_manifest_sha256')},
        outcome_class_counts=_distribution(manifest, 'attempt_outcome_class', _OUTCOMES),
        semantics_status_counts=_distribution(manifest, 'semantics_status', ('CONTRACT_VERIFIED', 'FOOTER_VERIFIED', 'UNVERIFIED', 'UNKNOWN')),
        semantics_contract_counts=_distribution(manifest, 'semantics_contract', ('tessent_process_wall_seconds', '')),
        elapsed_semantics_counts=_distribution(manifest, 'elapsed_semantics', ('tessent_process_wall_seconds', '')),
        elapsed_source_counts=_distribution(manifest, 'elapsed_source', ('phase2_csv.wall_time', 'gnu_time_footer', '')),
        timeout_status_counts=_distribution(manifest, 'timeout_status', ('NO_TIMEOUT', 'NOT_TIMEOUT', 'TIMEOUT', 'UNKNOWN')),
        declared_session_wall_sum_s=str(total), declared_wall_sum_by_outcome_class_s=seconds,
        declared_elapsed_values_only=True, timing_scope_authenticated=False,
        exclusive_nonoverlap_authenticated=False, candidate_quality_accessed=False)
    try:
        summary.update(_consistent_lineage(manifest, lineage))
        summary.update(status='PASS_METADATA_INTERNAL_CONSISTENCY_ONLY', issues=[])
    except AuditError as exc:
        if str(exc) in ('DUPLICATE_MANIFEST_ATTEMPT', 'DUPLICATE_LINEAGE_ATTEMPT'):
            raise
        # Honest metadata join/order gaps are reported without silently
        # manufacturing evidence or discarding the other circuit summaries.
        summary.update(status='PARTIAL_METADATA_CONSISTENCY_GAP', issues=[str(exc)],
                       parent_session_lineage_consistent=False, retry_order_consistent=False)
    return summary


def audit_files(specs):
    """Read exactly six fixed TRAIN circuits x manifest/lineage, no log reads."""
    _require(type(specs) in (tuple, list) and len(specs) == 12, 'TWELVE_FILE_ROSTER_REQUIRED')
    seen, paths = set(), set()
    for spec in specs:
        _require(type(spec) is dict and all(type(k) is str for k in spec)
                 and set(spec) == {'path', 'sha256', 'circuit', 'kind'}, 'SPEC_SCHEMA')
        _require(all(type(value) is str for value in spec.values()), 'SPEC_STRING_TYPES')
        _path(spec['path'])
        _require(_SHA.match(spec['sha256']) is not None and spec['circuit'] in FAMILIES
                 and spec['kind'] in ('manifest', 'lineage'), 'SPEC_BINDING')
        suffix = ('_attempt_manifest_v2_remediated.tsv' if spec['kind'] == 'manifest'
                  else '_lineage_v2.tsv')
        _require(spec['path'] == _PIN_ROOT + '/' + spec['circuit'] + suffix,
                 'FIXED_METADATA_PATH_ALLOWLIST')
        key = (spec['circuit'], spec['kind'])
        _require(key not in seen and spec['path'] not in paths, 'SPEC_DUPLICATE')
        seen.add(key)
        paths.add(spec['path'])
    _require(seen == {(c, k) for c in FAMILIES for k in ('manifest', 'lineage')}, 'SIX_TRAIN_FILE_ROSTER')
    receipts, summaries = [], {}
    total_bytes = total_rows = 0
    for circuit in sorted(FAMILIES):
        tables = {}
        for spec in sorted((s for s in specs if s['circuit'] == circuit), key=lambda s: s['kind']):
            raw = _read_regular(spec['path'], spec['sha256'], MAX_TOTAL_BYTES-total_bytes)
            _require(hashlib.sha256(raw).hexdigest() == spec['sha256'], 'FILE_SHA256_MISMATCH')
            total_bytes += len(raw)
            _require(total_bytes <= MAX_TOTAL_BYTES, 'TOTAL_BYTE_CAP')
            rows = _parse(raw, spec['kind'], spec['circuit'], MAX_ROWS-total_rows)
            total_rows += len(rows)
            tables[spec['kind']] = rows
            receipts.append(dict(circuit=spec['circuit'], kind=spec['kind'], sha256=spec['sha256'],
                                 bytes=len(raw), rows=len(rows), exact_schema_pass=True))
            del raw, rows
        summaries[circuit] = _summarize(tables['manifest'], tables['lineage'])
        del tables
    partial = any(summary['issues'] for summary in summaries.values())
    return dict(status=('PARTIAL_PINNED_TRAIN_METADATA_AUDIT' if partial
                        else 'PASS_PINNED_TRAIN_METADATA_ONLY_AUDIT'), file_count=12,
                total_bytes=total_bytes, total_rows=total_rows, files=receipts, circuits=summaries,
                decimal_precision=50, original_logs_read=False, candidate_quality_accessed=False,
                candidate_metrics_computed=False, timing_scope_fabricated=False,
                source_semantics_authenticated=False, e33_records_emitted=False,
                model_or_optimizer_called=False, real_training_release=False,
                real_heldout_release=False, no_file_writes=True)


def _limit_memory():
    if resource is None or not hasattr(resource, 'RLIMIT_AS'):
        return dict(address_space_limit_imposed=False, reason='RLIMIT_AS_UNAVAILABLE')
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    limits = [1024**3]
    limits.extend(value for value in (soft, hard) if value != resource.RLIM_INFINITY)
    target = min(limits)
    resource.setrlimit(resource.RLIMIT_AS, (target, hard))
    return dict(address_space_limit_imposed=True, address_space_soft_bytes=target,
                existing_hard_limit_unchanged=True)


def _usage():
    if resource is None:
        return dict(maxrss_available=False)
    unit = 'KiB' if sys.platform.startswith('linux') else ('bytes' if sys.platform == 'darwin' else 'platform_native')
    return dict(maxrss_available=True, maxrss_raw=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                maxrss_unit=unit)


def main():
    try:
        _require(len(sys.argv) == 1, 'CLI_ARGUMENTS_FORBIDDEN')
        _require(bool(CONFIGURED_SPECS), 'UNCONFIGURED')
        limits = _limit_memory()
        _require(limits['address_space_limit_imposed'], 'MEMORY_LIMIT_REQUIRED')
        result = audit_files(CONFIGURED_SPECS)
        result['resource'] = dict(limits, **_usage())
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return 0
    except AuditError as exc:
        print(json.dumps({'status': 'FAIL_CLOSED', 'code': str(exc)}, sort_keys=True))
        return 2
    except Exception:
        print('{"code":"UNEXPECTED_AUDIT_FAILURE","status":"FAIL_CLOSED"}')
        return 2


if __name__ == '__main__':
    sys.exit(main())
