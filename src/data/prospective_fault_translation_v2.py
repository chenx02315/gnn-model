"""Strict bounded in-memory common-fault state translation, no I/O or runner.

The accepted MTFI dialect is provisional and deliberately narrow. Successful
translation is not Tessent acceptance, OS provenance, or D95 evidence.
"""
import csv
import hashlib
import io
import json
import re

SCHEMA = 'prospective-fault-translation-v2'
MODES = ('H', 'M', 'F')
TRANSITIONS = {('H', 'M'), ('H', 'F'), ('M', 'F')}
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 24 * 1024 * 1024
MAX_COMMON = 100000
MAX_PATH = 1024
SHA_RE = re.compile(r'[0-9a-f]{64}\Z')
FLAT_RE = re.compile(r'(?<=/)U(\d+)(?=/)')
BASIC_RE = re.compile(r'^\s*([01])\s+(\S+)\s+(.+?)\s*$')
FAULT_RE = re.compile(r'^\s*([01])\s*,\s*([A-Z0-9_.]+)\s*,\s*"([^"\r\n]+)";\s*$')
DI_RE = re.compile(r'DI(?:_[1-9][0-9]?)?\Z')
# Exact observed E90 spellings, never a startswith('DI') wildcard.
DOTTED_DETECTED = frozenset(('DI.CLK', 'DI.SCAN', 'DI.SEN', 'DI.SR'))
# These are accepted but NOT carried. In particular EQ never inherits the
# previous row's detection here. This is a conservative transfer subset,
# not a claim that every excluded fault is physically undetected.
NONCARRIED = frozenset(('FU', 'PT', 'UU', 'TI', 'AU', 'UC', 'UO',
                       'AU.PC', 'AU.TC', 'EQ', 'RE'))
COLUMNS = {'stuck_value', 'canonical_core_path'} | {
    mode + '_native_path' for mode in MODES}
HEADER = ('FaultInformation {\n', ' version : 1;\n', ' FaultType (Stuck) {\n',
          '  FaultList {\n', '   FaultCollapsing : FALSE;\n',
          '   Format : Identifier, Class, Location;\n', '   Instance ("") {\n')
FOOTER = ('   }\n', '  }\n', ' }\n', '}\n')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def valid_path(value, reason):
    require(type(value) is str and 0 < len(value) <= MAX_PATH and
            value == value.strip() and not any(ch in value for ch in
            '\x00\r\n\t"') and not value.endswith('\\'), reason)
    return value


def detected(fault_class):
    return (fault_class == 'DS' or fault_class in DOTTED_DETECTED or
            DI_RE.fullmatch(fault_class) is not None)


def valid_class(fault_class):
    return fault_class in NONCARRIED or detected(fault_class)


def shift_f(location, offset):
    return FLAT_RE.sub(lambda match: 'U' + str(int(match.group(1)) + offset),
                       location)


def mapping_lookup(raw, count, offset, source_mode, target_mode):
    try:
        stream = io.StringIO(raw.decode('utf-8'), newline='')
        reader = csv.DictReader(stream, delimiter='\t', strict=True)
        header = reader.fieldnames
        require(header is not None and len(COLUMNS) <= len(header) <= 16 and
                len(set(header)) == len(header) and COLUMNS.issubset(set(header)) and
                all(type(name) is str and 0 < len(name) <= 128 and
                    name == name.strip() for name in header), 'MAPPING_HEADER')
        canonical_keys = set()
        native = {mode: set() for mode in MODES}
        lookup = {}
        rows = 0
        for row in reader:
            rows += 1
            require(rows <= count and None not in row and
                    all(type(row.get(name)) is str for name in header),
                    'MAPPING_ROW')
            stuck = row['stuck_value']
            require(stuck in ('0', '1'), 'MAPPING_STUCK')
            core = valid_path(row['canonical_core_path'], 'MAPPING_CORE_PATH')
            key = (stuck, core)
            require(key not in canonical_keys, 'MAPPING_DUPLICATE_CANONICAL')
            canonical_keys.add(key)
            by_mode = {}
            for mode in MODES:
                path = valid_path(row[mode + '_native_path'],
                                  'MAPPING_NATIVE_PATH')
                require(path == core if mode in ('H', 'M') else
                        shift_f(path, offset) == core,
                        'MAPPING_ROW_NAMESPACE_' + mode)
                native_key = (stuck, path)
                require(native_key not in native[mode],
                        'MAPPING_DUPLICATE_NATIVE_' + mode)
                native[mode].add(native_key)
                by_mode[mode] = native_key
            lookup[by_mode[source_mode]] = by_mode[target_mode]
        require(rows == count and len(lookup) == count, 'MAPPING_COUNT')
        return lookup, native[target_mode]
    except (UnicodeError, csv.Error) as exc:
        raise ValueError('MAPPING_FORMAT') from exc


def _lines(raw, reason):
    try:
        text = raw.decode('utf-8')
    except UnicodeError as exc:
        raise ValueError(reason) from exc
    require('\r' not in text and '\x00' not in text and text.endswith('\n'),
            reason)
    return text.splitlines(keepends=True)


def parse_source_mtfi(raw, count, source_keys):
    lines = _lines(raw, 'MTFI_ENCODING_OR_LINE_ENDINGS')
    require(len(lines) >= len(HEADER) + len(FOOTER) and
            tuple(lines[:len(HEADER)]) == HEADER and
            tuple(lines[-len(FOOTER):]) == FOOTER, 'MTFI_ENVELOPE')
    middle = lines[len(HEADER):-len(FOOTER)]
    require(len(middle) == count, 'SOURCE_COUNT')
    seen = set()
    detected_rows = []
    for line in middle:
        match = FAULT_RE.fullmatch(line.rstrip('\n'))
        require(match is not None, 'MTFI_FAULT_LINE')
        stuck, fault_class, location = match.groups()
        require(valid_class(fault_class), 'UNKNOWN_SOURCE_CLASS')
        key = (stuck, valid_path(location, 'MTFI_PATH'))
        require(key in source_keys, 'SOURCE_EXTRA_OR_WRONG_MODE')
        require(key not in seen, 'SOURCE_DUPLICATE')
        seen.add(key)
        if detected(fault_class):
            detected_rows.append((key, fault_class))
    require(seen == source_keys, 'SOURCE_MISSING')
    return detected_rows


def parse_target_basic(raw, count, target_keys):
    lines = _lines(raw, 'BASIC_ENCODING_OR_LINE_ENDINGS')
    seen = set()
    baseline = set()
    for line in lines:
        if not line.strip():
            continue
        match = BASIC_RE.fullmatch(line.rstrip('\n'))
        require(match is not None, 'BASIC_LINE')
        stuck, fault_class, location = match.groups()
        require(valid_class(fault_class), 'UNKNOWN_BASIC_CLASS')
        location = location.strip()
        if location.startswith('"') or location.endswith('"'):
            require(len(location) >= 2 and location.startswith('"') and
                    location.endswith('"'), 'BASIC_QUOTE')
            location = location[1:-1]
        key = (stuck, valid_path(location, 'BASIC_PATH'))
        require(key in target_keys, 'BASIC_EXTRA_OR_WRONG_MODE')
        require(key not in seen, 'BASIC_DUPLICATE')
        seen.add(key)
        require(len(seen) <= count, 'BASIC_COUNT')
        if detected(fault_class):
            baseline.add(key)
    require(seen == target_keys and len(seen) == count, 'BASIC_MISSING')
    return baseline


def translate(mapping_bytes, source_mtfi_bytes, target_basic_bytes,
              source_mode, target_mode, expected_common_count, f_offset,
              expected_sha256):
    """Return candidate MTFI/manifest bytes after exact in-memory validation."""
    require((source_mode, target_mode) in TRANSITIONS, 'MODE_TRANSITION')
    require(type(expected_common_count) is int and
            1 <= expected_common_count <= MAX_COMMON, 'COMMON_COUNT')
    require(type(f_offset) is int and -2048 <= f_offset <= 2048, 'F_OFFSET')
    inputs = {'mapping': mapping_bytes, 'source_mtfi': source_mtfi_bytes,
              'target_basic': target_basic_bytes}
    require(type(expected_sha256) is dict and set(expected_sha256) == set(inputs),
            'INPUT_SHA_SCHEMA')
    for name, raw in inputs.items():
        require(type(raw) is bytes and 0 < len(raw) <= MAX_FILE,
                'INPUT_BYTES_BOUND_' + name)
        pin = expected_sha256[name]
        require(type(pin) is str and SHA_RE.fullmatch(pin) is not None and
                sha(raw) == pin, 'INPUT_SHA_MISMATCH_' + name)
    require(sum(len(raw) for raw in inputs.values()) <= MAX_TOTAL,
            'INPUT_TOTAL_BOUND')
    lookup, target_keys = mapping_lookup(mapping_bytes, expected_common_count,
                                         f_offset, source_mode, target_mode)
    translated = parse_source_mtfi(source_mtfi_bytes, expected_common_count,
                                   set(lookup))
    baseline = parse_target_basic(target_basic_bytes, expected_common_count,
                                  target_keys)
    output_rows = {}
    class_counts = {}
    for source_key, fault_class in translated:
        target_key = lookup[source_key]
        require(target_key not in output_rows, 'TRANSLATED_DUPLICATE')
        output_rows[target_key] = fault_class
        class_counts[fault_class] = class_counts.get(fault_class, 0) + 1
    ordered = sorted(output_rows, key=lambda key: (key[1], key[0]))
    lines = list(HEADER)
    lines.extend('   %s, %s, "%s";\n' % (key[0], output_rows[key], key[1])
                 for key in ordered)
    lines.extend(FOOTER)
    output = ''.join(lines).encode('utf-8')
    require(len(output) <= MAX_FILE, 'OUTPUT_BYTES_BOUND')
    body = dict(schema=SCHEMA, status='IN_MEMORY_CANDIDATE_ONLY',
                policy='EXPLICIT_DS_DI_OBSERVED_DOTTED_WHITELIST_V2',
                path_policy='OPAQUE_INTERNAL_BACKSLASH_NO_UNESCAPE_V2',
                noncarried_classes=sorted(NONCARRIED),
                eq_adjacency_detection_inferred=False,
                excluded_faults_proven_undetected=False,
                source_mode=source_mode, target_mode=target_mode,
                expected_common_count=expected_common_count,
                f_flat_instance_offset=f_offset,
                input_sha256=dict(expected_sha256),
                parent_input_sha256=expected_sha256['source_mtfi'],
                output_mtfi_sha256=sha(output), mapping_rows=expected_common_count,
                source_entries=expected_common_count,
                target_basic_entries=expected_common_count,
                translated_detected_entries=len(output_rows),
                target_baseline_detected_entries=len(baseline),
                expected_minimum_pre_detected=len(baseline | set(output_rows)),
                translated_class_counts=class_counts,
                tessent_acceptance_verified=False, os_authenticated=False,
                d95_verified=False, execution_ready=False, training_release=False)
    manifest = canonical(body) + b'\n'
    return dict(output_mtfi_bytes=output, output_mtfi_sha256=sha(output),
                manifest_bytes=manifest, manifest_sha256=sha(manifest),
                translated_detected_entries=len(output_rows),
                expected_minimum_pre_detected=body['expected_minimum_pre_detected'],
                tessent_acceptance_verified=False, os_authenticated=False,
                execution_ready=False, training_release=False)
