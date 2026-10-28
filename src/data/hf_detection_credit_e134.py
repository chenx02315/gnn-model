"""Conservative physical-credit diagnostic, not an E133 state-count certificate.

H provenance and groups can establish H's own detections. Imported F labels do
not establish physical detection of F EQ neighbors. Without complete pre/post
partition-and-origin evidence, no independent new-F detections are credited.
Counts are diagnostics only; all sealing, old-contract and training flags stay
false. No I/O, process, mutable old globals or new collection grant is present.
"""
import base64
from collections import Counter

from . import eq_group_coverage_e133_r2 as groups
from . import prospective_fault_translation_v2 as frozen
from . import prospective_fault_translation_e129 as extension

SCHEMA = 'physical-hf-detection-credit-audit-e134-v1'
SPEC_SHA256 = '20aa71485e5c1911808ac8d8993c7c448614bf2ddc00fe12d4742b8ffebf2a4d'
N, THRESHOLD = 71216, 67656
H_UID = 'aes_core:HF:h1:H'
H_TCL_SHA = '1865b49c09203e0255ff5c5d019420a5e2b76f20f7ca8de5f5a3bdbd16eadd5c'
H_LOG_SHA = '0f7bb27c5f45b8eddfb5cd89ff2904deab7914aaa917bbddeafeefd2df23605b'
H_REFERENCE_SHA = '4028e89bc764337a1738c2991e0683b4cd12dc29c705fcfb8e3b74f1efec3349'
T_REFERENCE_SHA = '6a12896bb2c7e142594e29282d55c9fb076ced97d94a582a695fb5829000807a'
PINS = {
    'H_basic': (2245676, '6c1287af9af0b2c64a917f712d4eeaa88fdd510e3b3e878b95e856c0e22c7d0b'),
    'H_mtfi': (2520150, '105d53bb6fc918f57fa7ee101a804ff203df5ef4eb6cd1b663a9e531b91936f2'),
    'H_faults_report': (2247887, 'd510371972350c7117f246d0bc95505d03d9351e03fcc644ffea7e007a973f38'),
    'H_statistics': (2681, '874d865738afc4cbc122c50b4a0f05a924c3cbe1a02a856af7cf66d5c9571fc0'),
    'translation_status': (303747, '9852b09305259ff52972c237003f2cd4d2253294aebde307beccc77591cb2dcf'),
    'translation_manifest': (1285, 'cdb56ddeb07a5ad89a95d62dc73102416da5c049d1c0d37f256387ba9d650010')}
require, sha, canonical = groups.require, groups.sha, groups.canonical


def _ordered(keys):
    return [list(key) for key in sorted(keys, key=lambda key: (key[1], key[0]))]


def _set_hash(keys):
    return sha(canonical(_ordered(keys)))


def _pins(bodies, pins, synthetic):
    require(type(bodies) is dict and set(bodies) == set(pins), 'EXACT_BODY_ROLES')
    total, receipts = 0, {}
    for role, raw in bodies.items():
        cap = 65536 if role in ('manifest', 'H_statistics', 'translation_manifest',
                               'F_statistics', 'F_pre_statistics') else frozen.MAX_FILE
        require(type(raw) is bytes and 0 < len(raw) <= cap, 'BODY_BOUND_' + role)
        total += len(raw)
        receipts[role] = dict(bytes=len(raw), sha256=sha(raw))
        require(synthetic or (len(raw), sha(raw)) == pins[role], 'FROZEN_BODY_PIN_' + role)
    require(total <= 16*1048576, 'BODY_SET_TOTAL_BOUND')
    return receipts


def _h_provenance(provenance, h_bodies, synthetic):
    # The F provenance verifier authenticates the complete prior response first.
    f_lineage = groups._provenance(provenance)
    response = groups._json(provenance['e128_response_bytes'])
    def body(path, pin):
        matches = [row for row in response['files'] if row['path'] == path]
        require(len(matches) == 1, 'EXACT_H_PROVENANCE_ARTIFACT')
        row = matches[0]
        raw = base64.b64decode(row['body_base64'], validate=True)
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'] == pin, 'H_PROVENANCE_PIN')
        return raw
    tcl = body(groups.ROOT + '/code/common.tcl', H_TCL_SHA)
    log = body(groups.ROOT + '/journal/task_000_stdout.log', H_LOG_SHA)
    reference = groups._json(body(groups.ROOT + '/journal/task_000_reference.json', H_REFERENCE_SHA))
    translation = groups._json(body(groups.ROOT + '/journal/task_001_reference.json', T_REFERENCE_SHA))
    f_log = body(groups.ROOT + '/aes_core/runs/e116-aes_core/logs/F_' + groups.UID + '.log', groups.DRIVER_SHA)
    f_commands = [line[len('//  command: '):] for line in f_log.decode('ascii').splitlines()
                  if line.startswith('//  command: ')]
    f_order = ['read_faults $status -merge -show_warnings', 'reset_au_faults -reclassify',
               'report_statistics -detailed_analysis > [file join $out pre_atpg_statistics.rpt]']
    require(all(f_commands.count(command) == 1 for command in f_order) and
            [f_commands.index(command) for command in f_order] == sorted(f_commands.index(command) for command in f_order),
            'F_MERGE_RESET_RECLASSIFY_PRE_STATISTICS_ORDER')
    require(reference['task_uid'] == H_UID and reference['mode'] == 'H' and
            translation['parent_reference_sha256'] == H_REFERENCE_SHA and translation['mode'] == 'F', 'H_TO_F_REFERENCE_JOIN')
    if not synthetic:
        for role, artifact in (('H_mtfi', 'mtfi'), ('H_statistics', 'statistics')):
            require(reference['artifacts'][artifact]['sha256'] == sha(h_bodies[role]), 'H_REFERENCE_CURRENT_BODY_JOIN')
        require(translation['artifacts']['status']['sha256'] == sha(h_bodies['translation_status']) and
                translation['artifacts']['manifest']['sha256'] == sha(h_bodies['translation_manifest']), 'TRANSLATION_REFERENCE_BODY_JOIN')
    text = log.decode('ascii')
    commands = [line[len('//  command: '):] for line in text.splitlines() if line.startswith('//  command: ')]
    reads = [command for command in commands if command.startswith('read_faults ')]
    require(reads == ['read_faults $source -show_warnings'] and b'STATUS_FILE' not in tcl and
            b'read_faults $source -show_warnings' in tcl, 'H_NO_FOREIGN_MODE_IMPORT_REQUIRED')
    post_commands = ['report_statistics -detailed_analysis > [file join $out statistics.rpt]',
        'report_patterns > [file join $out patterns.rpt]', 'report_scan_volume > [file join $out scan_volume.rpt]',
        'report_faults > [file join $out faults.rpt]', 'report_procedures > [file join $out procedures.rpt]',
        'write_faults [file join $out faults.mtfi] -replace -format Mtfi']
    require(all(commands.count(command) == 1 for command in post_commands), 'H_SAME_STATE_COMMAND_COUNTS')
    start = commands.index(post_commands[0])
    require(commands[start:start+len(post_commands)] == post_commands and
            commands.index(reads[0]) < commands.index('create_patterns -compaction_effort High -coverage_effort High') < start,
            'H_FRESH_GENERATION_REPORT_ORDER')
    for marker in ('MAPPED_COMMON_ATPG_STATUS=PASS', 'MAPPED_COMMON_ATPG_MODE=H',
                   'MAPPED_COMMON_ATPG_RUN_ID=' + H_UID, 'TOOL_DESIGN_ID_TOKEN=r' + H_UID.encode('ascii').hex()):
        require(text.splitlines().count(marker) == 1, 'EXACT_H_DRIVER_MARKERS')
    return dict(H_tcl_sha256=H_TCL_SHA, H_driver_sha256=H_LOG_SHA,
        H_reference_sha256=H_REFERENCE_SHA, translation_reference_sha256=T_REFERENCE_SHA,
        H_has_single_source_read_and_no_foreign_merge=True, H_same_state_exports_verified=True,
        F_reset_AU_reclassify_observed_between_merge_and_pre_statistics=True,
        F_reclassification_does_not_prove_partition_or_origins=True,
        F_lineage=f_lineage)


def _basic_classes(raw, count, keys):
    extension.parse_target_basic(raw, count, keys)
    labels = {}
    for line in extension._lines(raw, 'BASIC_ENCODING_OR_LINE_ENDINGS'):
        if not line.strip():
            continue
        stuck, label, path = extension.BASIC_RE.fullmatch(line.rstrip('\n')).groups()
        path = path.strip()
        if path.startswith('"'):
            path = path[1:-1]
        labels[(stuck, path)] = label
    return labels


def _expanded(report_groups, lookup, stats):
    expanded, detected, canonical_groups = Counter(), set(), []
    for group in report_groups:
        label = group['fault_class']
        top = 'DI' if label != 'DS' and extension.detected(label) else label.split('.', 1)[0]
        members = {lookup[key] for key in group['members']}
        expanded[top] += len(members)
        if extension.detected(label):
            detected.update(members)
        canonical_groups.append(dict(representative=lookup[group['representative']],
            fault_class=label, members=members))
    wanted = {key: value for key, value in stats['classes'].items() if key != 'FU'}
    require(all(expanded.get(key, 0) == wanted.get(key, 0) for key in set(expanded) | set(wanted)), 'GROUP_CLASS_STATISTICS_MISMATCH')
    require(len(detected) == stats['detected_common_faults'], 'GROUP_DT_STATISTICS_MISMATCH')
    return detected, canonical_groups


def audit_credit_sets(h_physical, f_groups, imported, baseline, canonical_keys):
    """Combinatorial credit audit only; no bool can supply missing F origins."""
    require(all(type(value) is set and value <= canonical_keys for value in (h_physical, imported, baseline)), 'CREDIT_SET_DOMAIN')
    f_state, unsafe, any_seed_expansion, rep_seed_expansion = set(), set(), set(), set()
    examples, seeds, seen = [], imported | baseline, set()
    for group in f_groups:
        members = group['members']
        require(extension.valid_class(group['fault_class']) and group['fault_class'] != 'EQ', 'F_GROUP_REP_CLASS')
        require(type(members) is set and members <= canonical_keys and group['representative'] in members and not members & seen,
                'F_GROUP_CANONICAL_DOMAIN')
        seen.update(members)
        if group['representative'] in seeds:
            rep_seed_expansion.update(members)
        if members & seeds:
            any_seed_expansion.update(members)
        if not extension.detected(group['fault_class']):
            continue
        f_state.update(members)
        if members & imported:
            unproved = members - h_physical
            unsafe.update(unproved)
            if unproved and len(examples) < 8:
                examples.append(dict(representative=list(group['representative']), fault_class=group['fault_class'],
                    imported_members=_ordered(members & imported)[:8], unproven_members=_ordered(unproved)[:8],
                    unproven_member_count=len(unproved)))
    require(seen == canonical_keys, 'F_GROUP_COMPLETE_PARTITION')
    unproven = f_state - h_physical
    return dict(F_state_DT_count=len(f_state), F_state_DT_set_sha256=_set_hash(f_state),
        imported_explicit_all_H_physically_proven=imported <= h_physical,
        imported_expansion_unproven_count=len(unsafe), imported_expansion_unproven_sha256=_set_hash(unsafe),
        imported_expansion_counterexamples=examples, imported_expansion_credit_preserved=not unsafe,
        hypothetical_post_rep_seeded_expansion_count=len(rep_seed_expansion),
        hypothetical_post_any_seeded_expansion_count=len(any_seed_expansion),
        hypothetical_counts_do_not_prove_partition_stability=True,
        F_state_DT_not_H_proven_count=len(unproven), F_state_DT_not_H_proven_sha256=_set_hash(unproven),
        independent_new_F_physical_DT_count=0, F_pre_post_partition_stability_proven=False,
        F_new_detection_origins_proven=False,
        conservative_physical_union_count=len(h_physical), conservative_physical_union_sha256=_set_hash(h_physical),
        conservative_union_definition='H_PROVEN_DT_UNION_EMPTY_INDEPENDENT_NEW_F_SET',
        all_F_state_credit_already_justified_by_H=not unproven)


def analyze_bodies(h_bodies, f_bodies, provenance, expected_count=N,
                   expected_mapping_sha=groups.PINS['mapping'][1], tick=None):
    tick = (lambda: None) if tick is None else tick
    require(callable(tick) and type(expected_count) is int and 0 < expected_count <= frozen.MAX_COMMON, 'AUDIT_ARGUMENTS')
    synthetic = expected_count != N
    # Both sets are authenticated before parsing any source content.
    h_receipts = _pins(h_bodies, PINS, synthetic)
    f_receipts = _pins(f_bodies, groups.PINS, synthetic)
    lineage = _h_provenance(provenance, h_bodies, synthetic)
    f_state_candidate = groups.analyze_bodies(f_bodies, expected_count, expected_mapping_sha, provenance, tick)
    manifest = groups._json(f_bodies['manifest'])
    offset = manifest['f_flat_instance_offset']
    h_lookup, canonical_keys = extension.mapping_lookup(f_bodies['mapping'], expected_count, offset, 'H', 'H')
    f_lookup, f_canonical = extension.mapping_lookup(f_bodies['mapping'], expected_count, offset, 'F', 'H')
    require(canonical_keys == f_canonical and len(canonical_keys) == expected_count, 'H_F_CANONICAL_UNIVERSE')
    h_classes = _basic_classes(h_bodies['H_basic'], expected_count, set(h_lookup))
    baseline_non_DI_detection = {key for key, label in h_classes.items() if extension.detected(label) and label == 'DS'}
    h_native = groups._native(h_bodies['H_mtfi'], expected_count, set(h_lookup))
    h_groups = groups._report_groups(h_bodies['H_faults_report'], expected_count, h_native, tick)
    h_stats = groups.statistics.parse_statistics(h_bodies['H_statistics'], expected_count)
    h_observed_dt, _ = _expanded(h_groups, h_lookup, h_stats)
    # Foreign baseline DS would invalidate the H-own origin argument.
    h_proven = h_observed_dt if not baseline_non_DI_detection else set()
    tick()
    pins = {role: sha(raw) for role, raw in (('mapping', f_bodies['mapping']),
        ('source_mtfi', h_bodies['H_mtfi']), ('target_basic', f_bodies['F_basic']))}
    reproduced = frozen.translate(f_bodies['mapping'], h_bodies['H_mtfi'], f_bodies['F_basic'],
        'H', 'F', expected_count, offset, pins)
    require(reproduced['output_mtfi_bytes'] == h_bodies['translation_status'] and
            reproduced['manifest_bytes'] == h_bodies['translation_manifest'], 'EXACT_FROZEN_V2_TRANSLATION_REPLAY')
    alternate = extension.translate(f_bodies['mapping'], h_bodies['H_mtfi'], f_bodies['F_basic'],
        'H', 'F', expected_count, offset, pins)
    require(alternate['output_mtfi_bytes'] == reproduced['output_mtfi_bytes'], 'V2_E129_STATUS_DISAGREEMENT')
    h_explicit = frozen.parse_source_mtfi(h_bodies['H_mtfi'], expected_count, set(h_lookup))
    h_to_f, _ = extension.mapping_lookup(f_bodies['mapping'], expected_count, offset, 'H', 'F')
    imported_native = {h_to_f[key] for key, label in h_explicit}
    imported = {f_lookup[key] for key in imported_native}
    f_baseline_labels = _basic_classes(f_bodies['F_basic'], expected_count, set(f_lookup))
    baseline = {f_lookup[key] for key, label in f_baseline_labels.items() if extension.detected(label)}
    f_native = groups._native(f_bodies['F_mtfi'], expected_count, set(f_lookup))
    f_groups = groups._report_groups(f_bodies['F_faults_report'], expected_count, f_native, tick)
    f_stats = groups.statistics.parse_statistics(f_bodies['F_statistics'], expected_count)
    before = groups.statistics.parse_statistics(f_bodies['F_pre_statistics'], expected_count, patterns_required=False)
    _, canonical_groups = _expanded(f_groups, f_lookup, f_stats)
    credits = audit_credit_sets(set(h_proven), canonical_groups, imported, baseline, canonical_keys)
    threshold = (95*expected_count + 99)//100
    reasons = []
    if baseline_non_DI_detection:
        reasons.append('H_BASELINE_CONTAINS_UNJUSTIFIED_DS')
    if credits['F_state_DT_not_H_proven_count']:
        reasons.append('NEW_F_PHYSICAL_ORIGINS_AND_PRE_POST_PARTITION_UNPROVEN')
    if credits['imported_expansion_unproven_count']:
        reasons.append('IMPORTED_LABELS_EXPAND_TO_MEMBERS_NOT_H_PHYSICALLY_PROVEN')
    sufficient = credits['conservative_physical_union_count'] >= threshold
    if not sufficient:
        reasons.append('PROVEN_CONSERVATIVE_PHYSICAL_LOWER_BOUND_BELOW_D95')
    result = dict(schema=SCHEMA,
        semantic_spec_sha256=SPEC_SHA256, unproven_does_not_mean_physical_failure=True,
        status='CONDITIONAL_CANDIDATE_PENDING_INDEPENDENT_REVIEW' if sufficient else 'UNPROVEN',
        scope='SYNTHETIC_TEST_ONLY' if synthetic else 'AES_CORE_HF_H1_RETAINED_H_PLUS_F_PHYSICAL_CREDIT_AUDIT',
        synthetic_only=synthetic, common_count=expected_count, d95_integer_threshold=threshold,
        possible_detection_credit=0, H_observed_DT_count=len(h_observed_dt), H_physical_DT_count=len(h_proven),
        H_physical_DT_set_sha256=_set_hash(h_proven), H_baseline_non_DI_detected_count=len(baseline_non_DI_detection),
        frozen_v2_translation_exact_bytes_reproduced=True, E129_status_bytes_crosscheck=True,
        imported_explicit_key_count=len(imported), imported_explicit_key_set_sha256=_set_hash(imported),
        translated_explicit_minimum_pre_DT=reproduced['expected_minimum_pre_detected'],
        observed_F_pre_statistics_DT=before['detected_common_faults'],
        F_pre_count_at_least_explicit_minimum=before['detected_common_faults'] >= reproduced['expected_minimum_pre_detected'],
        pre_DT_matches_hypothetical_post_rep_seeded_expansion=(before['detected_common_faults'] == credits['hypothetical_post_rep_seeded_expansion_count']),
        pre_DT_count_alignment_proves_partition_or_physical_origins=False,
        state_candidate_e133_sha256=f_state_candidate['candidate_sha256'], H_input_receipts=h_receipts,
        F_input_receipts=f_receipts, provenance=lineage, reasons_unproven=reasons,
        conservative_lower_bound_meets_d95_math=sufficient, physical_HF_D95_verified=False,
        exact_physical_HF_union_proven=False,
        independent_final_reviewed=False, certificate_sealed=False, frozen_contract_d95_pass=False,
        complete_stage_or_action_acceptance=False, actual_atpg_runtime_ns=None,
        training_release=False, execution_ready=False, **credits)
    result['audit_sha256'] = sha(canonical(result))
    tick()
    return result
