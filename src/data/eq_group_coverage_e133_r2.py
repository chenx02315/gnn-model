"""R2 candidate: balanced outer report-path quotes only; never a seal.

Groups are read ONLY from a provenance-bound uncollapsed report_faults report,
never from MTFI adjacency or a polarity assumption. Actual fault-mode settings
are not inferred from defaults. Old contracts/results and training stay closed.
"""
from collections import Counter
import base64
import json
import re

from . import prospective_fault_translation_e129 as faults
from . import prospective_report_dialect_e126 as statistics

SCHEMA = 'eq-group-coverage-candidate-e133-r2-v1'
PARSE_VERSION = 'E133_R2_BALANCED_OUTER_QUOTES_ONLY'
ORIGIN_R1_SHA256 = '393e919ab4e28ae8c782e29be6b98ce61b49e63ebba73bff94bae417f9e8f68a'
COMMON_COUNT = 71216
THRESHOLD = 67656
ROOT = '/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1'
UID = 'aes_core:HF:h1:F'
E128_SHA = 'd70818980f52ad17e9a1d7eb917d9618d1bf203d4ec29b7e780430529528189e'
TCL_SHA = '50982a3c1b9b93b452313ef503bbfe6d17a44f7f3a018334041244807587dafe'
DRIVER_SHA = '4c089a2410fcaebc6aed3167a8b4b14015cf8afad5d8e7a019078679d78d7d94'
MANUAL_SHA = '633932e0eb455a5d7e4a197b870348d8227b26f66fe48085562b8841eae97ee0'
SPEC_SHA = '047d021700608a2b05f50bbb3a5ef490b1268c910e6b05c246100f7b51a7e3e9'
PINS = {
    'manifest': (1554, 'c1239fb3ff04b6db8ef49265bf5902cfbaf058b229ad84214c4c8d21748a1f2f'),
    'mapping': (3385680, 'b81d0cd552645ef9ceae251a066e1483d098870c22a0e111ea0abbf4ed7867f8'),
    'F_basic': (2245666, '70b549870374c4b31f342d5a6fbd10db5d5d8f5eb3844c3eb8d28d45767fb566'),
    'F_mtfi': (2520140, '55f6850eee753e3aff90b7b2199a366cb635a7b6a00adae84b1f20fc049ded5f'),
    'F_statistics': (1576, '629b433cd87ad7e471834decf9cce0f47735268da7028215b0eed68f8c60fff4'),
    'F_pre_statistics': (1531, '35de9953800c5be1c792c2026040a2c53b0e88984b40cc9e32a6f4a2e9014911'),
    'F_faults_report': (2247877, '7f02656b2f78d818c2da4d2f58448fb48d202d167f8cd60a84155ee15a1e02d3')}
require, sha, canonical = faults.require, faults.sha, faults.canonical


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def _provenance(value):
    require(type(value) is dict and set(value) == {'e128_response_bytes'}, 'PINNED_SAME_STATE_PROVENANCE_REQUIRED')
    raw = value['e128_response_bytes']
    require(type(raw) is bytes and 0 < len(raw) <= 8*1048576 and sha(raw) == E128_SHA, 'E128_PROVENANCE_SHA')
    response = _json(raw)
    require(response.get('capture_complete') is True and response.get('error') is None, 'E128_CAPTURE_REQUIRED')
    def body(path, pin=None):
        found = [row for row in response['files'] if row['path'] == path]
        require(len(found) == 1, 'EXACT_PROVENANCE_ARTIFACT')
        row = found[0]
        data = base64.b64decode(row['body_base64'], validate=True)
        require(len(data) == row['bytes'] and sha(data) == row['sha256'] and
                (pin is None or row['sha256'] == pin), 'PROVENANCE_BODY_PIN')
        return data
    tcl = body(ROOT + '/code/incremental.tcl', TCL_SHA)
    log = body(ROOT + '/aes_core/runs/e116-aes_core/logs/F_' + UID + '.log', DRIVER_SHA)
    intent = _json(body(ROOT + '/journal/task_002_intent.json'))
    binding = intent['binding']
    require(binding['task_uid'] == UID and binding['action_uid'] == 'aes_core:HF:h1' and
            binding['parent_task_uid'] == 'aes_core:HF:h1:H' and binding['target_mode'] == 'F' and
            binding['request']['run_uid'] == 'e116-aes_core', 'EXACT_POST_H_TO_F_PREFIX')
    text = log.decode('ascii')
    require(re.search(r'^//  Tessent Shell\s+2021\.2\s', text, re.M) is not None, 'ACTUAL_TOOL_VERSION_CONTEXT')
    commands = [line[len('//  command: '):] for line in text.splitlines() if line.startswith('//  command: ')]
    ordered = [
        'report_statistics -detailed_analysis > [file join $out statistics.rpt]',
        'report_patterns > [file join $out patterns.rpt]',
        'report_scan_volume > [file join $out scan_volume.rpt]',
        'report_faults > [file join $out faults.rpt]',
        'report_procedures > [file join $out procedures.rpt]',
        'write_faults [file join $out faults.mtfi] -replace -format Mtfi']
    require(all(commands.count(command) == 1 for command in ordered), 'EXACT_REPORT_EXPORT_COMMANDS')
    start = commands.index(ordered[0])
    require(commands[start:start+len(ordered)] == ordered, 'SAME_STATE_REPORT_EXPORT_ORDER')
    create = 'create_patterns -compaction_effort High -coverage_effort High'
    merge = 'read_faults $status -merge -show_warnings'
    require(commands.count(create) == commands.count(merge) == commands.count('set_fault_type Stuck') == 1 and
            commands.index(merge) < commands.index(create) < start, 'POST_MERGE_GENERATION_STATE')
    for marker in ('MAPPED_INCREMENTAL_ATPG_STATUS=PASS', 'MAPPED_INCREMENTAL_MODE=F',
                   'MAPPED_INCREMENTAL_RUN_ID=' + UID, 'TOOL_DESIGN_ID_TOKEN=r' + UID.encode('ascii').hex()):
        require(text.splitlines().count(marker) == 1, 'EXACT_F_DRIVER_MARKERS')
    require(b'report_faults > [file join $out faults.rpt]' in tcl, 'TCL_REPORT_FAULTS_SOURCE')
    return dict(e128_response_sha256=E128_SHA, tcl_sha256=TCL_SHA, driver_sha256=DRIVER_SHA,
        report_command='report_faults', same_fault_state_command_sequence_verified=True,
        actual_fault_mode_setting_observed=any(command.startswith('set_fault_mode ') for command in commands),
        proof_does_not_use_default_mode=True)


def _native(raw, count, keys):
    # Reuse complete envelope/keyset/class validation, then retain every label.
    faults.parse_source_mtfi(raw, count, keys)
    result = {}
    for line in faults._lines(raw, 'MTFI_ENCODING_OR_LINE_ENDINGS')[len(faults.HEADER):-len(faults.FOOTER)]:
        stuck, label, path = faults.FAULT_RE.fullmatch(line.rstrip('\n')).groups()
        result[(stuck, path)] = label
    return result


def _report_groups(raw, count, native, tick):
    lines = faults._lines(raw, 'REPORT_ENCODING_OR_LINE_ENDINGS')
    index = 0
    while index < len(lines) and not lines[index].strip():
        index += 1
    require(index + 2 < len(lines) and re.fullmatch(r'\s*type\s+code\s+pin_pathname\s*\n', lines[index]) is not None and
            re.fullmatch(r'\s*-+\s+-+\s+-+\s*\n', lines[index+1]) is not None, 'EXACT_UNCOLLAPSED_REPORT_HEADER')
    groups, seen, current, ended = [], set(), None, False
    for line_number, line in enumerate(lines[index+2:], index+3):
        if not line.strip():
            ended = True
            continue
        require(not ended, 'REPORT_INTERRUPTED_ROWS')
        match = faults.BASIC_RE.fullmatch(line.rstrip('\n'))
        require(match is not None, 'REPORT_THREE_FIELD_ROW')
        stuck, label, path = match.groups()
        require(faults.valid_class(label), 'UNKNOWN_REPORT_CLASS')
        # report_faults quotes some opaque paths; remove only balanced outer
        # delimiters, exactly as the existing strict basic-file parser does.
        if path.startswith('"') or path.endswith('"'):
            require(len(path) >= 2 and path.startswith('"') and path.endswith('"'),
                    'REPORT_OUTER_QUOTE_BALANCE')
            path = path[1:-1]
        key = (stuck, faults.valid_path(path, 'REPORT_NATIVE_PATH'))
        require(key in native and key not in seen and len(seen) < count, 'REPORT_KEY_DUPLICATE_OR_OUTSIDE')
        require(native[key] == label, 'REPORT_NATIVE_CLASS_MISMATCH')
        seen.add(key)
        if label == 'EQ':
            require(current is not None, 'ORPHAN_EQ_REPORT_MEMBER')
            current['members'].append(key)
        else:
            current = dict(representative=key, fault_class=label, members=[key], line_number=line_number)
            groups.append(current)
        if len(seen) % 256 == 0:
            tick()
    require(len(seen) == count and seen == set(native), 'COMPLETE_REPORT_NATIVE_KEYSET_REQUIRED')
    require(any(len(group['members']) > 1 for group in groups), 'OBSERVED_EQ_ENUMERATION_REQUIRED')
    return groups


def analyze_bodies(bodies, expected_count=COMMON_COUNT, expected_mapping_sha=PINS['mapping'][1],
                   provenance=None, tick=None):
    """Return an unsealed candidate; malformed/insufficient evidence raises."""
    tick = (lambda: None) if tick is None else tick
    require(callable(tick) and type(bodies) is dict and set(bodies) == set(PINS), 'EXACT_SEVEN_BODIES_REQUIRED')
    require(type(expected_count) is int and 0 < expected_count <= faults.MAX_COMMON, 'COMMON_COUNT')
    require(type(expected_mapping_sha) is str and faults.SHA_RE.fullmatch(expected_mapping_sha) is not None, 'MAPPING_SHA')
    synthetic = expected_count != COMMON_COUNT
    receipts = {}
    total = 0
    for role, raw in bodies.items():
        cap = 65536 if role in ('manifest', 'F_statistics', 'F_pre_statistics') else faults.MAX_FILE
        require(type(raw) is bytes and 0 < len(raw) <= cap, 'INPUT_BYTES_BOUND_' + role)
        total += len(raw)
        receipts[role] = dict(bytes=len(raw), sha256=sha(raw))
        require(synthetic or (len(raw), sha(raw)) == PINS[role], 'FROZEN_SEVEN_INPUT_PIN_' + role)
    require(total <= 16*1048576, 'SEVEN_INPUT_TOTAL_BOUND')
    tick()
    lineage = _provenance(provenance)
    manifest = _json(bodies['manifest'])
    require(manifest.get('schema') == 'multimode_common_fault_universe_v1' and manifest.get('fault_model') == 'stuck-at' and
            manifest.get('common_fault_count') == expected_count and
            manifest.get('mapping', {}).get('sha256') == expected_mapping_sha == sha(bodies['mapping']), 'FROZEN_MANIFEST_MAPPING')
    offset = manifest.get('f_flat_instance_offset')
    require(type(offset) is int and -2048 <= offset <= 2048, 'F_OFFSET')
    lookup, canonical_keys = faults.mapping_lookup(bodies['mapping'], expected_count, offset, 'F', 'H')
    native_keys = set(lookup)
    faults.parse_target_basic(bodies['F_basic'], expected_count, native_keys)
    tick()
    native = _native(bodies['F_mtfi'], expected_count, native_keys)
    groups = _report_groups(bodies['F_faults_report'], expected_count, native, tick)
    post = statistics.parse_statistics(bodies['F_statistics'], expected_count)
    before = statistics.parse_statistics(bodies['F_pre_statistics'], expected_count, patterns_required=False)
    expanded, detected, group_rows = Counter(), set(), []
    for group in groups:
        label = group['fault_class']
        top = 'DI' if label != 'DS' and faults.detected(label) else label.split('.', 1)[0]
        expanded[top] += len(group['members'])
        canonical_members = [lookup[key] for key in group['members']]
        if faults.detected(label):
            detected.update(canonical_members)
        group_rows.append([list(lookup[group['representative']]), label, [list(key) for key in canonical_members]])
    wanted = {key: value for key, value in post['classes'].items() if key != 'FU'}
    require(sum(expanded.values()) == expected_count and all(expanded.get(key, 0) == wanted.get(key, 0)
            for key in set(expanded) | set(wanted)), 'PER_CLASS_GROUP_EXPANSION_MISMATCH')
    require(len(detected) == post['detected_common_faults'] and detected <= canonical_keys,
            'EXPANDED_DS_DI_COUNT_OR_CANONICAL_SET')
    require(before['detected_common_faults'] <= post['detected_common_faults'], 'PRE_POST_DETECTION_COUNT_ORDER')
    threshold = (95*expected_count + 99)//100
    require(synthetic or threshold == THRESHOLD, 'FROZEN_INTEGER_THRESHOLD')
    keys = [list(key) for key in sorted(detected, key=lambda key: (key[1], key[0]))]
    full_keys = [list(key) for key in sorted(canonical_keys, key=lambda key: (key[1], key[0]))]
    candidate = dict(schema=SCHEMA, status='CANDIDATE_ONLY_PENDING_INDEPENDENT_FINAL_REVIEW',
        policy_id='DOCUMENTED_UNCOLLAPSED_REPORT_GROUPS_POST_HF_PREFIX_V1',
        parse_version=PARSE_VERSION, origin_r1_source_sha256=ORIGIN_R1_SHA256,
        certificate_spec_sha256=SPEC_SHA,
        scope=('SYNTHETIC_TEST_ONLY_NOT_ACTUAL_AES' if synthetic else
               'OBSERVED_AES_CORE_HF_H1_TERMINAL_POST_H_TO_F_PREFIX_NOT_F_STANDALONE'),
        synthetic_only=synthetic, common_count=expected_count, d95_integer_threshold=threshold,
        percent_floor=95, possible_detection_credit=0,
        input_receipts=receipts, provenance=lineage, report_group_count=len(groups),
        report_EQ_members=sum(len(group['members']) - 1 for group in groups),
        expanded_top_class_counts=dict(expanded), detected_count=len(detected),
        detected_definition='QUALIFIED_DS_DI_GROUPS_ONLY_PT_PD_AU_UC_UO_EXCLUDED',
        detected_set_sha256=sha(canonical(keys)), detected_set_hash_format='SORTED_CANONICAL_STUCK_PATH_JSON',
        canonical_full_set_sha256=sha(canonical(full_keys)),
        complete_group_mapping_sha256=sha(canonical(group_rows)),
        candidate_meets_d95_math=len(detected) >= threshold,
        observed_report_uncollapsed_enumeration_verified=True,
        actual_fault_mode_setting_observed=lineage['actual_fault_mode_setting_observed'],
        report_native_basic_canonical_keysets_equal=True, non_EQ_native_classes_reconciled=True,
        group_source='PROVENANCE_BOUND_REPORT_FAULTS_NOT_MTFI_ADJACENCY',
        group_polarity_matching_assumed=False, per_class_statistics_reconciled=True,
        rule_document_sha256=MANUAL_SHA, rule_document_page=88,
        independent_final_reviewed=False, separate_coverage_only_certificate_sealed=False,
        frozen_contract_d95_pass=False, complete_stage_or_action_acceptance=False,
        actual_atpg_runtime_ns=None, training_release=False, execution_ready=False)
    candidate['candidate_sha256'] = sha(canonical(candidate))
    tick()
    return candidate
