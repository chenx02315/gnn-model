"""Pure complete-byte/stream observations, not D95 or wall-runtime labels.

Supports the top-level Tessent 2021.2 statistics table observed in E112.
STIL scanning reports only the maximum numeric TesterCycle annotation; duplicate
comment/Ann annotations do not add cycles. Full STIL semantics remain unproven.
No file opening, subprocess, authentication or execution release here.
"""
import hashlib
import re

MAX_COUNT = 2**63 - 1
LABELS = dict(FU='full', DS='det_simulation', DI='det_implication',
              UU='unused', TI='tied', RE='redundant', AU='atpg_untestable',
              PT='possibly_testable', UC='uncontrolled', UO='unobserved')
ROW = re.compile(r'^\s*([A-Z]{2})\s+\(([a-z_]+)\)\s+([0-9]+)(?:\s+\(\s*[0-9]+(?:\.[0-9]+)?%\))?\s*$')
PATTERNS = re.compile(r'^#test_patterns\s+([0-9]+)\s*$')
TOKEN = re.compile(rb'TesterCycle:([0-9]{1,19})(?=$|\s)')


def require(condition, code):
    if not condition:
        raise ValueError(code)


def parse_statistics(raw, expected_common_count):
    require(type(raw) is bytes and 0 < len(raw) <= 65536, 'FULL_STATISTICS_BYTES_BOUND')
    require(type(expected_common_count) is int and 0 < expected_common_count <= MAX_COUNT, 'COMMON_COUNT')
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
    require(top_table and complete and patterns is not None and
            {'FU', 'DS', 'DI'} <= set(classes), 'REQUIRED_STATISTICS_FIELDS')
    require(classes['FU'] == expected_common_count and
            sum(value for key, value in classes.items() if key != 'FU') == expected_common_count,
            'CLASS_PARTITION_AND_COMMON_COUNT')
    return dict(schema='prospective-statistics-dialect-e115-v1',
        status='PARSED_COMPLETE_SUPPLIED_BYTES_NOT_AUTHENTICATED',
        bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        generated_patterns=patterns, classes=classes,
        detected_common_faults=classes['DS'] + classes['DI'],
        actual_atpg_runtime_ns=None, d95_verified=False, execution_ready=False, training_release=False)


def scan_stil(chunks, expected_bytes, expected_sha256, tick=None):
    """Consume to EOF; malformed, truncated or mismatched input returns no summary."""
    require(type(expected_bytes) is int and 0 < expected_bytes <= 64 * 1024 * 1024,
            'STIL_WHOLE_FILE_BOUND')
    require(type(expected_sha256) is str and re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None,
            'STIL_SHA256')
    require(tick is None or callable(tick), 'BUDGET_HOOK')
    digest, total, pending = hashlib.sha256(), 0, b''
    maximum, markers, lines = None, 0, 0

    def parse_line(line):
        count = line.count(b'TesterCycle:')
        values = list(TOKEN.finditer(line))
        require(len(values) == count, 'MALFORMED_TESTER_CYCLE')
        numbers = [int(value.group(1)) for value in values]
        require(all(number <= MAX_COUNT for number in numbers), 'TESTER_CYCLE_BOUND')
        return numbers

    for chunk in chunks:
        if tick is not None:
            tick()
        require(type(chunk) is bytes and 0 < len(chunk) <= 65536, 'STIL_STREAM_CHUNK')
        total += len(chunk)
        require(total <= expected_bytes, 'STIL_DECLARED_SIZE')
        digest.update(chunk)
        parts = (pending + chunk).split(b'\n')
        pending = parts.pop()
        require(len(pending) <= 1048576, 'STIL_LINE_BOUND')
        for line in parts:
            require(len(line) <= 1048576, 'STIL_LINE_BOUND')
            lines += 1
            values = parse_line(line)
            markers += len(values)
            if values:
                maximum = max(max(values), maximum if maximum is not None else 0)
    if tick is not None:
        tick()
    if pending:
        lines += 1
        values = parse_line(pending)
        markers += len(values)
        if values:
            maximum = max(max(values), maximum if maximum is not None else 0)
    require(total == expected_bytes and digest.hexdigest() == expected_sha256, 'STIL_COMPLETE_BYTES_SHA')
    require(markers > 0, 'MISSING_TESTER_CYCLE')
    return dict(schema='prospective-stil-stream-e115-v1',
        status='FULL_SUPPLIED_STREAM_ANNOTATIONS_ONLY',
        bytes=total, sha256=digest.hexdigest(), whole_file_consumed=True,
        annotation_records=markers, lines=lines, maximum_reported_tester_cycle=maximum,
        annotation_count_is_not_cycles=True, combined_pattern_cycles_qualified=False,
        stil_semantics_qualified=False, actual_atpg_runtime_ns=None,
        execution_ready=False, training_release=False)
