"""Pure clean-F numerical audit; never a physical certificate or runtime grant.

Actual entry is fixed to the full pinned 71216-key mapping with F offset1 and
independently pinned E134 H sources. No historical F analyze result is reused.
Raw capture joins demonstrate bytes, not authentic OS/transport provenance.
External application report dialect has not been observed: it cannot be
qualified from guessed wording or supplied booleans, so final status remains
UNPROVEN even when the auditable numeric union meets the threshold.
"""
import base64
from collections import Counter
import re
import stat

from . import eq_group_coverage_e133_r2 as groups
from . import hf_detection_credit_e134 as history
from . import prospective_fault_translation_e129 as faults
from . import physical_f_replay_recipe_e135_r2 as recipe

require,sha,canonical = faults.require,faults.sha,faults.canonical
ROOT = recipe.ROOT
N, OFFSET, BASELINE_COUNT = 71216, 1, 3713
BASELINE_SHA = 'bbbf25513062cb7b6a0eccb23e9dc017529b84ff0080368701829d0fbab8bd74'
CANONICAL_SHA = 'faad8f3858b4af4384464fdc5e7f83bf4492faf3a3d2958141760e3e8d838978'
H_COUNT, H_SET_SHA = 18323, 'a844b4a8b500ea95a70e5487cb941be77990f60c69cef4fcd79a7beab86bbb00'
H_AUDIT_SHA = '0469bb1c0c18404c790efb3f0eeae89148d505549e1bf4b0809a0443b1e16e3a'
PATTERN_EXPECTED_SHA = '333d9f9bd359cf9066501a41e748b2182f5c787ffd46e112c7b5c5c2c6c5eae2'
COMMON_ROLES = ('manifest','mapping','F_basic')
H_ROLES = tuple(history.PINS)
STAGES = ('baseline','imported','simulated')
SNAPSHOT_ROLES = ('native','report','statistics')
EVIDENCE_PATHS = {
    'loaded_patterns': ROOT+'/snapshots/loaded.patterns.rpt',
    'simulated_patterns': ROOT+'/snapshots/simulated.patterns.rpt',
    'stdout': ROOT+'/journal/stdout.log', 'replay_tcl': ROOT+'/code/replay.tcl',
    'baseline_helper': ROOT+'/code/expected_baseline.tcl',
    'observation': ROOT+'/journal/observation.json', 'stdout_ack': ROOT+'/journal/stdout_ack.json',
}
READBACK_JOURNAL = ('recipe_artifacts.json','dependency_validation.json','launch_intent.json','spawn_identity.json',
    'observation.json','stdout.log','stdout_ack.json','observation_exception.json')+tuple(
    case+'_'+suffix for case in ('success','timeout','setsid_child') for suffix in
    ('intent.json','observation.json','output.log','receipt.json'))
READBACK_OUTPUTS = (ROOT+'.initial_intent.json',ROOT+'/code/replay.tcl',ROOT+'/code/expected_baseline.tcl',ROOT+'/tool.log')+tuple(
    ROOT+'/journal/'+name for name in READBACK_JOURNAL)+tuple(ROOT+'/snapshots/'+stage+'.'+suffix
    for stage in STAGES for suffix in ('statistics.rpt','faults.rpt','faults.mtfi'))+(
    ROOT+'/snapshots/loaded.patterns.rpt',ROOT+'/snapshots/simulated.patterns.rpt')
IDENTITY_FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_size','st_mtime_ns','st_ctime_ns')
PINNED_DEPENDENCIES = {
    'eq_group_coverage_e133_r2':'879b0d244e4d649c4a6be5a673bb1b566000cce69194d555634ad3d8037fc37e',
    'hf_detection_credit_e134':'35f791450023eef30dd68dcd3e59bc58387735a668917ec9f6ee73db19c3b4ac',
    'prospective_fault_translation_e129':'f659ca52bc6c48645736162223d1f6a931c343d4dd6cafac690aaeff90a2c681',
    'physical_f_replay_recipe_e135_r2':'63ab7aba869d9d755488cb8aaa4e5629b595d9e1672b1db35458e565771a62d2',
}
MAX_CAPTURE, MAX_NEW_BODIES = 24*1048576,16*1048576
MAX_LOCAL_BODIES = 48*1048576
DIAGNOSTIC = re.compile(rb'(?i)(?<![a-z0-9_])(warnings?|errors?|fatal)(?![a-z0-9_])')


def _receipt(raw,cap=8*1048576):
    require(type(raw) is bytes and 0 < len(raw) <= cap,'COMPLETE_BOUNDED_BODY_BYTES')
    return dict(bytes=len(raw),sha256=sha(raw))


def _set_hash(keys):
    return sha(canonical([list(k) for k in sorted(keys,key=lambda k:(k[1],k[0]))]))


def _body_inputs(common,h,snapshots,evidence,synthetic):
    require(type(common) is dict and set(common) == set(COMMON_ROLES) and
        type(h) is dict and set(h) == set(H_ROLES),'EXACT_COMMON_AND_H_ROLES')
    require(type(snapshots) is dict and set(snapshots) == set(STAGES) and
        type(evidence) is dict and set(evidence) == set(EVIDENCE_PATHS),'EXACT_CLEAN_SNAPSHOT_EVIDENCE_ROLES')
    receipts,new_paths,total,new_total = {},{},0,0
    for prefix,bodies in (('common',common),('H',h)):
        for role,raw in bodies.items():
            cap = 65536 if role in ('manifest','H_statistics','translation_manifest') else 8*1048576
            receipts[prefix+'/'+role] = _receipt(raw,cap)
            total += len(raw)
            if not synthetic:
                size,digest = groups.PINS[role] if prefix == 'common' else history.PINS[role]
                require((len(raw),sha(raw)) == (size,digest),'PINNED_INPUT_BODY_'+prefix+'_'+role)
    for stage in STAGES:
        require(type(snapshots[stage]) is dict and set(snapshots[stage]) == set(SNAPSHOT_ROLES),
            'EXACT_SNAPSHOT_TRIPLET')
        for role in SNAPSHOT_ROLES:
            raw = snapshots[stage][role]
            receipts[stage+'/'+role] = _receipt(raw,65536 if role == 'statistics' else 8*1048576)
            suffix = {'native':'.faults.mtfi','report':'.faults.rpt','statistics':'.statistics.rpt'}[role]
            new_paths[ROOT+'/snapshots/'+stage+suffix] = raw
            total += len(raw);new_total += len(raw)
    for role,path in EVIDENCE_PATHS.items():
        raw = evidence[role]
        cap = 16*1048576 if role == 'stdout' else (65536 if role in ('observation','stdout_ack') else 1048576)
        receipts['evidence/'+role] = _receipt(raw,cap)
        new_paths[path] = raw
        total += len(raw);new_total += len(raw)
    require(new_total <= MAX_NEW_BODIES and total <= MAX_LOCAL_BODIES,'TOTAL_BODY_BOUNDS')
    return receipts,new_paths


def _capture_join(provenance,new_paths,synthetic):
    keys = {'capture_response_bytes','transport_receipt_bytes'} | (
        {'synthetic_source_bytes'} if synthetic else {'e128_response_bytes','e134_audit_bytes'})
    require(type(provenance) is dict and set(provenance) == keys,'EXACT_RAW_PROVENANCE_BYTES_NOT_BOOL')
    raw = provenance['capture_response_bytes']
    _receipt(raw,MAX_CAPTURE)
    transport_raw = provenance['transport_receipt_bytes']
    _receipt(transport_raw,65536)
    capture,transport = groups._json(raw),groups._json(transport_raw)
    require(type(transport) is dict and type(transport.get('exit_code')) is int and transport['exit_code'] == 0 and
        all(transport.get(k) is False for k in ('timeout','overflow','write_failed','threads_incomplete')) and
        transport.get('remote_termination_verified') is False,'EXACT_SUCCESS_REPORTED_TRANSPORT_RECORD')
    # Exactly the existing controller's readback result, NOT a new success bool.
    # This protocol is still a prototype; source/ownership/clock authentication
    # remains outside this byte-join auditor and cannot be supplied as a flag.
    require(type(capture) is dict and set(capture) == {'role','files','boot_id','execution_ready'} and
        capture['role'] == 'readback' and capture['execution_ready'] is False and
        type(capture['boot_id']) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',capture['boot_id']) and
        type(capture['files']) is list and len(capture['files']) == len(READBACK_OUTPUTS),
        'EXACT_CONTROLLER_READBACK_SCHEMA')
    rows,total,metadata_rows = {},0,[]
    for row in capture['files']:
        require(type(row) is dict and type(row.get('path')) is str and row['path'] not in rows,
            'CAPTURE_DUPLICATE_OR_MALFORMED_PATH')
        path = row['path']
        require((path == ROOT+'.initial_intent.json' or path.startswith(ROOT+'/')) and
            all(p not in ('','.','..') for p in path.split('/')[1:]) and
            not any(c in path for c in ('\x00','\r','\n','\\')),'CAPTURE_OWNED_ROOT_PATHS_ONLY')
        require(path in READBACK_OUTPUTS,'FIXED_READBACK_ARTIFACT_ONLY')
        if row.get('missing') is True:
            require(set(row) in ({'path','missing'},{'path','missing','reason'}) and
                ('reason' not in row or row['reason'] == 'FIXED_PARENT_ABSENT'),'EXACT_MISSING_ARTIFACT_ROW')
        else:
            require(set(row) == {'path','bytes','sha256','identity','body_base64'},'EXACT_PRESENT_ARTIFACT_ROW')
            name = path.rsplit('/',1)[1]
            cap = 8388608 if name.endswith(('faults.rpt','faults.mtfi')) else 2097152 if name in ('tool.log','stdout.log') else 65536
            require(type(row['bytes']) is int and 0 <= row['bytes'] <= cap and
                type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) and
                type(row['body_base64']) is str and len(row['body_base64']) <= 4*((row['bytes']+2)//3),
                'BOUNDED_ARTIFACT_BODY_FIELDS')
            info = row['identity']
            require(type(info) is dict and set(info) == set(IDENTITY_FIELDS) and
                all(type(n) is int and 0 <= n < 2**64 for n in info.values()) and
                stat.S_ISREG(info['st_mode']) and info['st_uid'] == 1047 and info['st_nlink'] == 1 and
                info['st_size'] == row['bytes'],'OWNED_ARTIFACT_IDENTITY_FIELDS')
            decoded = base64.b64decode(row['body_base64'],validate=True)
            require(len(decoded) == row['bytes'] and sha(decoded) == row['sha256'],'EVERY_PRESENT_ARTIFACT_FULL_SHA')
            total += len(decoded)
            require(total <= MAX_NEW_BODIES,'ALL_EXPORT_BODY_BYTES_BOUND')
        metadata_rows.append({k:v for k,v in row.items() if k != 'body_base64'})
        rows[row['path']] = row
    require([row['path'] for row in capture['files']] == list(READBACK_OUTPUTS),'EXACT_ORDERED_READBACK_ROSTER')
    for path,body in new_paths.items():
        row = rows.get(path)
        require(type(row) is dict and type(row.get('bytes')) is int and row['bytes'] == len(body) and
            row.get('sha256') == sha(body) and type(row.get('body_base64')) is str,
            'CAPTURE_BODY_RECEIPT_JOIN')
        encoded = row['body_base64']
        require(len(encoded) <= 4*((len(body)+2)//3) and
            base64.b64decode(encoded,validate=True) == body,'CAPTURE_EXACT_BODY_BYTES')
    require(type(transport.get('stdout_bytes')) is int and transport['stdout_bytes'] == len(raw) and
        transport.get('stdout_sha256') == sha(raw) and type(transport.get('stderr_bytes')) is int and
        transport['stderr_bytes'] == 0 and transport.get('stderr_sha256') == sha(b''),
        'TRANSPORT_CAPTURE_RAW_SHA_AND_EMPTY_STDERR_JOIN')
    result = dict(capture_response_sha256=sha(raw),transport_receipt_sha256=sha(transport_raw),
        required_artifact_body_joins=len(new_paths),reported_success_is_not_transport_authentication=True,
        exported_artifact_receipts=metadata_rows,exported_body_bytes=total,
        readback_roster_sha256=sha(canonical(list(READBACK_OUTPUTS))),reported_boot_id=capture['boot_id'],
        readback_schema='CURRENT_CONTROLLER_ROLE_READBACK_NOT_FINAL_AUTHENTICATED_PROTOCOL',
        final_exporter_protocol_independently_reviewed=False,original_clock_and_root_ownership_authenticated=False,
        actual_transport_provenance_independently_authenticated=False)
    if synthetic:
        result['synthetic_source_sha256'] = _receipt(provenance['synthetic_source_bytes'],65536)['sha256']
    return result


def _observer_join(evidence):
    observation,ack = (groups._json(evidence[k]) for k in ('observation','stdout_ack'))
    raw = evidence['stdout']
    require(type(observation) is dict and type(observation.get('returncode')) is int and
        observation['returncode'] == 0 and observation.get('failure') is None and
        observation.get('cleaned') is True and observation.get('launch_attempted') is True and
        observation.get('cleanup_error') is None,'OBSERVER_REPORTED_CLEAN_SUCCESS_REQUIRED')
    require(type(observation.get('output_bytes')) is int and observation['output_bytes'] == len(raw) and
        observation.get('output_sha256') == sha(raw) and type(ack) is dict and
        set(ack) == {'bytes','sha256'} and type(ack['bytes']) is int and ack['bytes'] == len(raw) and
        ack['sha256'] == sha(raw),'OBSERVER_LOG_AND_ACK_EXACT_BYTES')
    return dict(observation_sha256=sha(evidence['observation']),stdout_ack_sha256=sha(evidence['stdout_ack']),
        observer_reports_clean_success=True,independent_OS_cleanup_authenticated=False)


def _snapshot(bodies,lookup,count,baseline,tick):
    native = groups._native(bodies['native'],count,set(lookup))
    partition = groups._report_groups(bodies['report'],count,native,tick)
    statistics = groups.statistics.parse_statistics(bodies['statistics'],count,patterns_required=False)
    counts,ds,di,unqualified_di,seen,group_rows = Counter(),set(),set(),set(),set(),[]
    ds_baseline_seeded_extra = set()
    for group in partition:
        label = group['fault_class']
        members = {lookup[k] for k in group['members']}
        require(not members & seen,'CANONICAL_GROUP_OVERLAP')
        seen.update(members)
        top = 'DI' if label != 'DS' and faults.detected(label) else label.split('.',1)[0]
        counts[top] += len(members)
        if label == 'DS':
            ds.update(members)
            if members & baseline:
                ds_baseline_seeded_extra.update(members-baseline)
        elif faults.detected(label):
            di.update(members & baseline)
            unqualified_di.update(members-baseline)
        group_rows.append([list(lookup[group['representative']]),label,
            [list(k) for k in sorted(members,key=lambda k:(k[1],k[0]))]])
    wanted = {k:v for k,v in statistics['classes'].items() if k != 'FU'}
    require(len(seen) == count and all(counts.get(k,0) == wanted.get(k,0) for k in set(counts)|set(wanted)),
        'GROUP_NATIVE_STATISTICS_ALL_CLASS_RECONCILIATION')
    require(len(ds)+len(di)+len(unqualified_di) == statistics['detected_common_faults'],
        'COMPLETE_REPORTED_DS_DI_RECONCILIATION')
    return dict(ds=ds,di=di,unqualified_di=unqualified_di,all_keys=seen,
        summary=dict(classes=dict(counts),DS_count=len(ds),qualified_DI_count=len(di),
            unqualified_DI_member_count=len(unqualified_di),unqualified_DI_set_sha256=_set_hash(unqualified_di),
            DS_members_also_baseline_DI_count=len(ds & baseline),
            DS_baseline_seeded_group_extra_member_count=len(ds_baseline_seeded_extra),
            DS_baseline_seeded_group_extra_set_sha256=_set_hash(ds_baseline_seeded_extra),
            DS_group_classification_is_not_new_physical_origin_proof=True,
            qualified_detected_count=len(ds|di),qualified_detected_set_sha256=_set_hash(ds|di),
            complete_group_mapping_sha256=sha(canonical(group_rows)),group_count=len(partition),
            internal_stored_pattern_count=statistics['generated_patterns'],internal_patterns_required=False))


def inspect_pattern_evidence(evidence):
    """Bounded observations only: actual external-application dialect UNREVIEWED.

    A '#test_patterns' count, chain count, echo, marker, rc0 or caller boolean
    cannot prove that 256 external test patterns were fully fault-simulated.
    No invented positive recognition grammar is installed here.
    """
    require(type(evidence) is dict and set(evidence) == set(EVIDENCE_PATHS),'EXACT_PATTERN_EVIDENCE_BYTES')
    for role,raw in evidence.items():
        _receipt(raw,16*1048576 if role == 'stdout' else 1048576)
    raw = evidence['stdout']
    require(b'\x00' not in raw,'LOG_NUL')
    lines = raw.splitlines()
    require(len(lines) <= 200000 and all(len(line) <= 65536 for line in lines),'LOG_LINE_BOUNDS')
    diagnostic_rows = []
    for line_number,line in enumerate(lines,1):
        if DIAGNOSTIC.search(line):
            require(len(diagnostic_rows) < 128,'DIAGNOSTIC_INVENTORY_BOUND')
            diagnostic_rows.append(dict(line_number=line_number,message_sha256=sha(line),reviewed=False))
    commands = [line[len(b'//  command: '):] for line in lines if line.startswith(b'//  command: ')]
    read = ('read_patterns '+ROOT+'/inputs/tester.stil').encode('ascii')
    simulate = b'simulate_patterns -source external -store_patterns none'
    expected = [read,simulate]
    command_order = (all(commands.count(cmd) == 1 for cmd in expected) and
        commands.index(read) < commands.index(simulate))
    has_forbidden = any(re.search(rb'(?i)(?:^|[;\s])(create_patterns|add_processors)(?:$|[;\s])',line) or
        re.search(rb'(?i)read_faults\s+.*\s-merge(?:$|\s)',line) for line in commands)
    count_observations = {}
    for role in ('loaded_patterns','simulated_patterns'):
        report = evidence[role]
        require(b'\x00' not in report and all(len(line) <= 65536 for line in report.splitlines()),'EXTERNAL_REPORT_LINE_BOUND')
        counts = [int(match.group(1)) for line in report.splitlines()
            for match in [re.fullmatch(rb'\s*#test_patterns\s+([0-9]{1,9})\s*',line)] if match]
        count_observations[role] = counts[:16]
        require(len(counts) <= 16,'COUNT_OBSERVATION_BOUND')
    return dict(external_pattern_reports_sha256={k:sha(evidence[k]) for k in ('loaded_patterns','simulated_patterns')},
        required_external_test_patterns=256,count_text_observations=count_observations,
        observed_count_text_exactly_256=all(count_observations[k] == [256] for k in count_observations),
        count_text_is_not_application_proof=True,command_echo_order_observed=command_order,
        forbidden_generation_or_foreign_merge_echo_observed=has_forbidden,
        tail_marker_count=lines.count(b'E135_REPLAY_FINISHED'),diagnostic_inventory=diagnostic_rows,
        warnings_not_automatically_accepted=True,external_application_dialect_reviewed=False,
        all_256_external_test_patterns_loaded_and_applied_verified=False,
        reason='UNREVIEWED_EXTERNAL_APPLICATION_REPORT_AND_LOG_DIALECT')


def _analyze(common,h,snapshots,evidence,provenance,count,offset,synthetic,tick):
    require(callable(tick),'AUDIT_TICK_REQUIRED')
    tick()
    receipts,new_paths = _body_inputs(common,h,snapshots,evidence,synthetic)
    raw_join = _capture_join(provenance,new_paths,synthetic)
    observer_join = _observer_join(evidence)
    tick()
    manifest = groups._json(common['manifest'])
    require(type(manifest) is dict and manifest.get('schema') == 'multimode_common_fault_universe_v1' and
        manifest.get('fault_model') == 'stuck-at' and type(manifest.get('common_fault_count')) is int and
        manifest['common_fault_count'] == count and type(manifest.get('f_flat_instance_offset')) is int and
        manifest['f_flat_instance_offset'] == offset and type(manifest.get('mapping')) is dict and
        manifest['mapping'].get('sha256') == sha(common['mapping']),
        'EXACT_COMMON_MANIFEST_MAPPING_OFFSET')
    h_lookup,keys = faults.mapping_lookup(common['mapping'],count,offset,'H','H')
    f_lookup,f_keys = faults.mapping_lookup(common['mapping'],count,offset,'F','H')
    require(keys == f_keys and len(keys) == count,'COMPLETE_CANONICAL_COMMON_KEYS')
    baseline_labels = history._basic_classes(common['F_basic'],count,set(f_lookup))
    require(not any(label == 'DS' for label in baseline_labels.values()),'F_BASIC_DS_FORBIDDEN')
    baseline = {f_lookup[k] for k,label in baseline_labels.items() if faults.detected(label)}
    h_baseline = history._basic_classes(h['H_basic'],count,set(h_lookup))
    require(not any(label == 'DS' for label in h_baseline.values()),'H_BASELINE_DS_INVALIDATES_PROOF')
    h_snapshot = _snapshot(dict(native=h['H_mtfi'],report=h['H_faults_report'],statistics=h['H_statistics']),
        h_lookup,count,keys,tick)
    h_detected = h_snapshot['ds']|h_snapshot['di']
    if not synthetic:
        _receipt(provenance['e134_audit_bytes'],65536)
        require(sha(provenance['e134_audit_bytes']) == H_AUDIT_SHA,'PINNED_E134_H_AUDIT_BYTES')
        old = groups._json(provenance['e134_audit_bytes'])
        require(old['H_physical_DT_count'] == H_COUNT and old['H_physical_DT_set_sha256'] == H_SET_SHA and
            len(h_detected) == H_COUNT and _set_hash(h_detected) == H_SET_SHA,'RECOMPUTED_PINNED_H_PHYSICAL_SET')
        lineage = history._h_provenance(dict(e128_response_bytes=provenance['e128_response_bytes']),h,False)
        require(_set_hash(keys) == CANONICAL_SHA and len(baseline) == BASELINE_COUNT and
            _set_hash(baseline) == BASELINE_SHA,'PINNED_COMMON_AND_QUALIFIED_BASELINE_DI_SET')
        response = groups._json(provenance['e128_response_bytes'])
        matches = [r for r in response['files'] if r['path'] == groups.ROOT+'/code/incremental.tcl']
        require(len(matches) == 1,'PINNED_RECIPE_PARENT_ROW')
        parent = base64.b64decode(matches[0]['body_base64'],validate=True)
        require(sha(parent) == groups.TCL_SHA,'PINNED_RECIPE_PARENT_BYTES')
        candidate = recipe.build_candidate(parent,recipe.legacy.EXPECTED_INIT.encode('ascii'))
        require(evidence['replay_tcl'] == candidate['body'] and
            evidence['baseline_helper'] == candidate['baseline_expectations_body'],'EXACT_CLEAN_RECIPE_AND_HELPER_BYTES')
    else:
        lineage = dict(synthetic_source_only=True,actual_H_provenance_verified=False)
    tick()
    summaries,post = {},None
    for stage in STAGES:
        parsed = _snapshot(snapshots[stage],f_lookup,count,baseline,tick)
        require(parsed['all_keys'] == keys,'SNAPSHOT_CANONICAL_KEYSET')
        if stage != 'simulated':
            require(not parsed['ds'] and not parsed['unqualified_di'] and parsed['di'] == baseline,
                'BASELINE_OR_IMPORTED_EXACT_DI_ONLY_NO_FOREIGN_DS')
        summaries[stage] = parsed['summary']
        if stage == 'simulated':
            post = parsed
        tick()
    f_detected = post['ds']|post['di']
    union = h_detected|f_detected
    threshold = (95*count+99)//100
    patterns = inspect_pattern_evidence(evidence)
    reasons = ['EXTERNAL_APPLICATION_DIALECT_AND_COMPLETION_UNPROVEN',
        'RUNTIME_SOURCE_AND_CAPTURE_PROVENANCE_REQUIRE_INDEPENDENT_FINAL_REVIEW',
        'FINAL_ROLE3_SOURCE_CLOCK_OWNERSHIP_PROTOCOL_NOT_INDEPENDENTLY_FROZEN',
        'POST_DS_GROUP_ORIGINS_AND_BASELINE_DI_TRANSITIONS_REQUIRE_PHYSICAL_REVIEW']
    if post['unqualified_di']:
        reasons.append('POST_DI_MEMBERS_OUTSIDE_INDEPENDENT_BASELINE_WHITELIST_EXCLUDED')
    if patterns['diagnostic_inventory']:
        reasons.append('EVERY_DIAGNOSTIC_REQUIRES_INDIVIDUAL_REVIEW')
    if patterns['forbidden_generation_or_foreign_merge_echo_observed']:
        reasons.append('FORBIDDEN_COMMAND_ECHO_OBSERVED')
    if not patterns['observed_count_text_exactly_256']:
        reasons.append('EXTERNAL_COUNT_TEXT_MISMATCH_MISSING_OR_AMBIGUOUS')
    if not patterns['command_echo_order_observed'] or patterns['tail_marker_count'] != 1:
        reasons.append('REQUIRED_COMMAND_ECHO_OR_COMPLETION_MARKER_NOT_OBSERVED')
    result = dict(schema='physical-clean-f-union-audit-e137-v1',status='UNPROVEN',
        scope='SYNTHETIC_TEST_ONLY' if synthetic else 'CURRENT_FIXED_F_STIL_NUMERIC_UNION_E134_H_ONLY',
        synthetic_only=synthetic,common_count=count,f_flat_instance_offset=offset,
        common_canonical_set_sha256=_set_hash(keys),d95_integer_threshold=threshold,
        H_proven_count=len(h_detected),H_proven_set_sha256=_set_hash(h_detected),
        qualified_baseline_DI_count=len(baseline),qualified_baseline_DI_set_sha256=_set_hash(baseline),
        F_numeric_candidate_DS_qualified_DI_count=len(f_detected),F_numeric_candidate_set_sha256=_set_hash(f_detected),
        F_post_unqualified_DI_count=len(post['unqualified_di']),
        numeric_union_count=len(union),numeric_union_set_sha256=_set_hash(union),
        numeric_d95_result='PASS' if len(union) >= threshold else 'FAIL',
        numeric_result_is_not_a_physical_certificate=True,possible_PT_PD_detection_credit=0,
        current_pattern_expected_sha256=PATTERN_EXPECTED_SHA,
        pattern_byte_identity_join_independently_authenticated=False,
        replay_recipe_bytes_verified_against_frozen_source=not synthetic,
        snapshot_summaries=summaries,input_receipts=receipts,raw_capture_join=raw_join,observer_log_join=observer_join,
        H_provenance=lineage,parser_source_pins=dict(PINNED_DEPENDENCIES),
        source_pins_are_review_bindings_not_runtime_authentication=True,
        pattern_evidence=patterns,reasons_unproven=reasons,
        physical_HF_union_verified=False,post_DS_detection_origins_authenticated=False,
        all_256_external_patterns_applied_verified=False,
        independent_final_reviewed=False,certificate_sealed=False,physical_D95_verified=False,
        frozen_contract_d95_pass=False,complete_stage_or_action_acceptance=False,
        historical_pattern_identity_verified=False,actual_atpg_runtime_ns=None,
        execution_ready=False,training_release=False)
    result['audit_sha256'] = sha(canonical(result))
    tick()
    return result


def analyze(common,h,snapshots,evidence,provenance,tick=None):
    """Actual fixed universe only. All actual H/common pins are mandatory."""
    return _analyze(common,h,snapshots,evidence,provenance,N,OFFSET,False,(lambda:None) if tick is None else tick)


def analyze_synthetic_for_tests(common,h,snapshots,evidence,provenance,expected_count,offset=0,tick=None):
    """Explicit small fixtures only; cannot produce an actual or sealed result."""
    require(type(expected_count) is int and 1 < expected_count < N and type(offset) is int and offset >= 0,
        'EXPLICIT_SMALL_SYNTHETIC_UNIVERSE_ONLY')
    return _analyze(common,h,snapshots,evidence,provenance,expected_count,offset,True,(lambda:None) if tick is None else tick)
