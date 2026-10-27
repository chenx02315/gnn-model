"""Exact E125-observed PT label repair, without changing E115 or raw bytes.

This is a supplied-statistics parser observation, not complete stage acceptance,
Tessent execution authorization, D95 qualification or a runtime/training label.
Only PT's observed label is corrected; no additional vendor aliases are added.
"""
import hashlib

from .prospective_report_dialect_e115 import ROW, PATTERNS, MAX_COUNT, require, scan_stil
from .prospective_report_dialect_e115 import LABELS as _E115_LABELS

LABELS = dict(_E115_LABELS, PT='posdet_testable')
SCHEMA = 'prospective-statistics-dialect-e126-v1'


def parse_statistics(raw, expected_common_count, patterns_required=True):
    """Preserve E115 validation and hash the unmodified complete input bytes."""
    require(type(raw) is bytes and 0 < len(raw) <= 65536, 'FULL_STATISTICS_BYTES_BOUND')
    require(type(expected_common_count) is int and 0 < expected_common_count <= MAX_COUNT, 'COMMON_COUNT')
    require(type(patterns_required) is bool, 'PATTERN_REQUIREMENT_TYPE')
    text = raw.decode('ascii')
    require('\x00' not in text, 'STATISTICS_NUL')
    classes, patterns = {}, None
    top_table, sub_table, complete = False, False, False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('Fault Classes'):
            require(not top_table, 'DUPLICATE_CLASS_TABLE')
            top_table = True
        if stripped == 'Fault Sub-classes':
            require(top_table and not sub_table, 'SUBCLASS_SECTION')
            sub_table = True
        if stripped == 'Coverage':
            require(top_table and not complete, 'COVERAGE_SECTION')
            complete = True
        if top_table and not sub_table and not complete:
            token = stripped.split(None, 1)[0] if stripped else ''
            if len(token) == 2 and token.isupper() and token.isalpha():
                match = ROW.fullmatch(line)
                require(match is not None, 'CLASS_ROW_DIALECT')
                key, label, value = match.groups()
                require(key in LABELS and label == LABELS[key] and key not in classes, 'CLASS_LABEL_OR_DUPLICATE')
                count = int(value)
                require(count <= MAX_COUNT, 'CLASS_COUNT_BOUND')
                classes[key] = count
        if stripped.startswith('#test_patterns'):
            match = PATTERNS.fullmatch(stripped)
            require(match is not None and patterns is None, 'PATTERN_ROW')
            patterns = int(match.group(1))
            require(patterns <= MAX_COUNT, 'PATTERN_COUNT_BOUND')
    require(top_table and complete and (not patterns_required or patterns is not None) and
            {'FU', 'DS', 'DI'} <= set(classes), 'REQUIRED_STATISTICS_FIELDS')
    require(classes['FU'] == expected_common_count and
            sum(value for key, value in classes.items() if key != 'FU') == expected_common_count,
            'CLASS_PARTITION_AND_COMMON_COUNT')
    return dict(schema=SCHEMA, status='PARSED_COMPLETE_SUPPLIED_BYTES_NOT_AUTHENTICATED',
        bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), generated_patterns=patterns,
        classes=classes, detected_common_faults=classes['DS'] + classes['DI'],
        detected_definition='DS_PLUS_DI_ONLY_PT_EXCLUDED', observation_scope='STATISTICS_PARSER_ONLY',
        complete_stage_acceptance_verified=False, actual_atpg_runtime_ns=None,
        d95_verified=False, execution_ready=False, training_release=False)
