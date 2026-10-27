"""Exact AU.SEQ noncarried extension, pure in-memory translation only.

E128 supplied a streamed inventory and bounded row samples, not the complete
2520140-byte MTFI. This module does not claim a replay of that whole real file,
namespace authentication, EQ-based detection, Tessent acceptance or D95 proof.
The unchanged v2 mapping/path/encoding guards are reused; source/target parsers
and translate below are local functions bound to this exact new classifier.
"""
from .prospective_fault_translation_v2 import (
    MODES, TRANSITIONS, MAX_FILE, MAX_TOTAL, MAX_COMMON, MAX_PATH, SHA_RE,
    FLAT_RE, BASIC_RE, FAULT_RE, DI_RE, DOTTED_DETECTED, COLUMNS, HEADER, FOOTER,
    require, canonical, sha, valid_path, shift_f, mapping_lookup, _lines)
from .prospective_fault_translation_v2 import NONCARRIED as _V2_NONCARRIED

SCHEMA = 'prospective-fault-translation-e129-v1'
NONCARRIED = _V2_NONCARRIED | frozenset(('AU.SEQ',))


def detected(fault_class):
    return (fault_class == 'DS' or fault_class in DOTTED_DETECTED or
            DI_RE.fullmatch(fault_class) is not None)


def valid_class(fault_class):
    return fault_class in NONCARRIED or detected(fault_class)


def parse_source_mtfi(raw, count, source_keys):
    lines = _lines(raw, 'MTFI_ENCODING_OR_LINE_ENDINGS')
    require(len(lines) >= len(HEADER) + len(FOOTER) and
            tuple(lines[:len(HEADER)]) == HEADER and
            tuple(lines[-len(FOOTER):]) == FOOTER, 'MTFI_ENVELOPE')
    middle = lines[len(HEADER):-len(FOOTER)]
    require(len(middle) == count, 'SOURCE_COUNT')
    seen, detected_rows = set(), []
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
    seen, baseline = set(), set()
    for line in lines:
        if not line.strip():
            continue
        match = BASIC_RE.fullmatch(line.rstrip('\n'))
        require(match is not None, 'BASIC_LINE')
        stuck, fault_class, location = match.groups()
        require(valid_class(fault_class), 'UNKNOWN_BASIC_CLASS')
        location = location.strip()
        if location.startswith('"') or location.endswith('"'):
            require(len(location) >= 2 and location.startswith('"') and location.endswith('"'), 'BASIC_QUOTE')
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
              source_mode, target_mode, expected_common_count, f_offset, expected_sha256):
    """Translate only explicit DS/strict DI rows; AU.SEQ and EQ never carry."""
    require((source_mode, target_mode) in TRANSITIONS, 'MODE_TRANSITION')
    require(type(expected_common_count) is int and 1 <= expected_common_count <= MAX_COMMON, 'COMMON_COUNT')
    require(type(f_offset) is int and -2048 <= f_offset <= 2048, 'F_OFFSET')
    inputs = {'mapping': mapping_bytes, 'source_mtfi': source_mtfi_bytes, 'target_basic': target_basic_bytes}
    require(type(expected_sha256) is dict and set(expected_sha256) == set(inputs), 'INPUT_SHA_SCHEMA')
    for name, raw in inputs.items():
        require(type(raw) is bytes and 0 < len(raw) <= MAX_FILE, 'INPUT_BYTES_BOUND_' + name)
        pin = expected_sha256[name]
        require(type(pin) is str and SHA_RE.fullmatch(pin) is not None and sha(raw) == pin, 'INPUT_SHA_MISMATCH_' + name)
    require(sum(len(raw) for raw in inputs.values()) <= MAX_TOTAL, 'INPUT_TOTAL_BOUND')
    lookup, target_keys = mapping_lookup(mapping_bytes, expected_common_count, f_offset, source_mode, target_mode)
    translated = parse_source_mtfi(source_mtfi_bytes, expected_common_count, set(lookup))
    baseline = parse_target_basic(target_basic_bytes, expected_common_count, target_keys)
    output_rows, class_counts = {}, {}
    for source_key, fault_class in translated:
        target_key = lookup[source_key]
        require(target_key not in output_rows, 'TRANSLATED_DUPLICATE')
        output_rows[target_key] = fault_class
        class_counts[fault_class] = class_counts.get(fault_class, 0) + 1
    ordered = sorted(output_rows, key=lambda key: (key[1], key[0]))
    lines = list(HEADER)
    lines.extend('   %s, %s, "%s";\n' % (key[0], output_rows[key], key[1]) for key in ordered)
    lines.extend(FOOTER)
    output = ''.join(lines).encode('utf-8')
    require(len(output) <= MAX_FILE, 'OUTPUT_BYTES_BOUND')
    body = dict(schema=SCHEMA, status='IN_MEMORY_CANDIDATE_ONLY',
        policy='EXPLICIT_DS_DI_WHITELIST_WITH_EXACT_AU_SEQ_NONCARRIED_E129',
        path_policy='OPAQUE_INTERNAL_BACKSLASH_NO_UNESCAPE_V2', noncarried_classes=sorted(NONCARRIED),
        eq_adjacency_detection_inferred=False, excluded_faults_proven_undetected=False,
        source_mode=source_mode, target_mode=target_mode, expected_common_count=expected_common_count,
        f_flat_instance_offset=f_offset, input_sha256=dict(expected_sha256),
        parent_input_sha256=expected_sha256['source_mtfi'], output_mtfi_sha256=sha(output),
        mapping_rows=expected_common_count, source_entries=expected_common_count,
        target_basic_entries=expected_common_count, translated_detected_entries=len(output_rows),
        target_baseline_detected_entries=len(baseline), expected_minimum_pre_detected=len(baseline | set(output_rows)),
        translated_class_counts=class_counts, full_real_e128_mtfi_replay_verified=False,
        tessent_acceptance_verified=False, os_authenticated=False, d95_verified=False,
        execution_ready=False, training_release=False)
    manifest = canonical(body) + b'\n'
    return dict(output_mtfi_bytes=output, output_mtfi_sha256=sha(output), manifest_bytes=manifest,
        manifest_sha256=sha(manifest), translated_detected_entries=len(output_rows),
        expected_minimum_pre_detected=body['expected_minimum_pre_detected'],
        full_real_e128_mtfi_replay_verified=False, tessent_acceptance_verified=False,
        os_authenticated=False, execution_ready=False, training_release=False)
