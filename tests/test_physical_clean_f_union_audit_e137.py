"""Small synthetic full-byte chains only; no actual replay/capture or I/O."""
import ast
import base64
import copy
from pathlib import Path
import unittest
from unittest import mock

from src.data import physical_clean_f_union_audit_e137 as m
from tests.test_eq_group_coverage_e133_r2 import fixture,stats,KEYS


def triplet(labels):
    f = fixture(labels)
    return dict(native=f['F_mtfi'],report=f['F_faults_report'],statistics=f['F_statistics'])


def fixture_chain():
    base = fixture()
    basic = base['F_basic'].replace(b'0 FU "/a"',b'0 DI.SCAN "/a"').replace(b'1 FU "/b"',b'1 DI.SCAN "/b"')
    common = dict(manifest=base['manifest'],mapping=base['mapping'],F_basic=basic)
    h_state = triplet(('DI.SCAN','EQ','DS','EQ','UC','EQ'))
    h = dict(H_basic=basic,H_mtfi=h_state['native'],H_faults_report=h_state['report'],
        H_statistics=h_state['statistics'],translation_status=b'synthetic unused pinned-role bytes',
        translation_manifest=b'{"synthetic":true}')
    snapshots = dict(baseline=triplet(('DI.SCAN','EQ','UC','EQ','UC','EQ')),
        imported=triplet(('DI.SCAN','EQ','UC','EQ','UC','EQ')),
        simulated=triplet(('DI.SCAN','EQ','UC','EQ','DS','EQ')))
    # Real clean-replay internal pattern storage may remain zero.
    for row in snapshots.values():
        row['statistics'] = row['statistics'].replace(b'#test_patterns 1',b'#test_patterns 0')
    commands = [('read_patterns '+m.ROOT+'/inputs/tester.stil').encode('ascii'),
        b'simulate_patterns -source external -store_patterns none']
    evidence = dict(loaded_patterns=b'#test_patterns 256\n',simulated_patterns=b'#test_patterns 256\n',
        stdout=b'\n'.join(b'//  command: '+c for c in commands)+b'\nE135_REPLAY_FINISHED\n',
        replay_tcl=b'SYNTHETIC ONLY NOT ACTUAL RECIPE\n',baseline_helper=b'SYNTHETIC HELPER\n')
    join_observer(evidence)
    return common,h,snapshots,evidence


def join_observer(evidence):
    raw=evidence['stdout']
    evidence['observation']=m.canonical(dict(returncode=0,failure=None,cleaned=True,launch_attempted=True,
        cleanup_error=None,output_bytes=len(raw),output_sha256=m.sha(raw)))
    evidence['stdout_ack']=m.canonical(dict(bytes=len(raw),sha256=m.sha(raw)))


def provenance(snapshots,evidence):
    bodies = {}
    for stage in m.STAGES:
        for role in m.SNAPSHOT_ROLES:
            suffix = {'native':'.faults.mtfi','report':'.faults.rpt','statistics':'.statistics.rpt'}[role]
            raw=snapshots[stage][role]
            bodies[m.ROOT+'/snapshots/'+stage+suffix] = raw
    for role,path in m.EVIDENCE_PATHS.items():
        raw=evidence[role]
        bodies[path] = raw
    rows = []
    for index,path in enumerate(m.READBACK_OUTPUTS):
        if path not in bodies:
            rows.append(dict(path=path,missing=True))
            continue
        raw = bodies[path]
        rows.append(dict(path=path,bytes=len(raw),sha256=m.sha(raw),body_base64=base64.b64encode(raw).decode('ascii'),
            identity=dict(st_dev=1,st_ino=index+10,st_mode=0o100600,st_nlink=1,st_uid=1047,
                st_size=len(raw),st_mtime_ns=101,st_ctime_ns=102)))
    capture=m.canonical(dict(role='readback',files=rows,boot_id='3ebeb9bb-410c-476c-a000-5c625f590473',execution_ready=False))
    return dict(capture_response_bytes=capture,
        transport_receipt_bytes=m.canonical(dict(exit_code=0,timeout=False,overflow=False,write_failed=False,
            threads_incomplete=False,remote_termination_verified=False,stdout_bytes=len(capture),stdout_sha256=m.sha(capture),
            stderr_bytes=0,stderr_sha256=m.sha(b''))),synthetic_source_bytes=b'EXPLICIT SMALL SYNTHETIC SOURCE')


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.common,self.h,self.snapshots,self.evidence=fixture_chain()

    def analyze(self,proof=None,**kwargs):
        proof=provenance(self.snapshots,self.evidence) if proof is None else proof
        return m.analyze_synthetic_for_tests(self.common,self.h,self.snapshots,self.evidence,proof,6,**kwargs)

    def test_complete_numeric_union_pass_is_still_unproven_and_internal_zero_allowed(self):
        original=copy.deepcopy((self.common,self.h,self.snapshots,self.evidence))
        with mock.patch('builtins.open',side_effect=AssertionError('IO')) as opened, \
                mock.patch('subprocess.Popen',side_effect=AssertionError('spawn')) as spawn:
            r=self.analyze()
        opened.assert_not_called();spawn.assert_not_called()
        self.assertEqual(r['numeric_union_count'],6)
        self.assertEqual(r['H_proven_count'],4)
        self.assertEqual(r['F_numeric_candidate_DS_qualified_DI_count'],4)
        self.assertEqual(r['qualified_baseline_DI_count'],2)
        self.assertEqual(r['numeric_d95_result'],'PASS')
        self.assertEqual(r['status'],'UNPROVEN')

        self.assertEqual(r['numeric_union_set_sha256'],m._set_hash(set(KEYS)))
        self.assertTrue(r['synthetic_only'])
        self.assertIsNot(r['parser_source_pins'],m.PINNED_DEPENDENCIES)
        self.assertEqual(r['snapshot_summaries']['simulated']['internal_stored_pattern_count'],0)
        for key in ('physical_HF_union_verified','all_256_external_patterns_applied_verified',
                    'certificate_sealed','physical_D95_verified','training_release','execution_ready'):
            self.assertIs(r[key],False)
        self.assertEqual((self.common,self.h,self.snapshots,self.evidence),original)
        self.assertEqual(r,self.analyze())

    def test_transport_hash_binding_is_not_just_exit_status(self):
        proof=provenance(self.snapshots,self.evidence)
        transport=m.groups._json(proof['transport_receipt_bytes']);transport['stdout_sha256']='0'*64
        proof['transport_receipt_bytes']=m.canonical(transport)
        with self.assertRaisesRegex(ValueError,'TRANSPORT_CAPTURE_RAW_SHA'):self.analyze(proof)

    def test_numeric_below_threshold_is_negative_math_not_false_physical_claim(self):
        self.snapshots['simulated']=triplet(('DI.SCAN','EQ','UC','EQ','PT','EQ'))
        r=self.analyze()
        self.assertEqual(r['numeric_union_count'],4)
        self.assertEqual(r['numeric_d95_result'],'FAIL')
        self.assertEqual(r['possible_PT_PD_detection_credit'],0)
        self.assertEqual(r['status'],'UNPROVEN')

    def test_di_class_and_eq_neighbors_outside_baseline_are_never_credited(self):
        self.snapshots['simulated']=triplet(('DI.SCAN','EQ','UC','EQ','DI.CLK','EQ'))
        r=self.analyze()
        self.assertEqual(r['F_post_unqualified_DI_count'],2)
        self.assertEqual(r['F_numeric_candidate_DS_qualified_DI_count'],2)
        self.assertEqual(r['numeric_union_count'],4)
        self.assertIn('POST_DI_MEMBERS_OUTSIDE_INDEPENDENT_BASELINE_WHITELIST_EXCLUDED',r['reasons_unproven'])

    def test_ds_group_transition_from_baseline_di_is_not_physical_origin_proof(self):
        self.snapshots['simulated']=triplet(('DS','EQ','EQ','UC','UC','EQ'))
        r=self.analyze()
        post=r['snapshot_summaries']['simulated']
        self.assertEqual(post['DS_members_also_baseline_DI_count'],2)
        self.assertEqual(post['DS_baseline_seeded_group_extra_member_count'],1)
        self.assertFalse(r['post_DS_detection_origins_authenticated'])
        self.assertFalse(r['physical_HF_union_verified'])
        self.assertEqual(r['status'],'UNPROVEN')

    def test_baseline_or_imported_ds_and_extra_di_stop_before_credit(self):
        for stage,labels in (('baseline',('DS','EQ','UC','EQ','UC','EQ')),
                             ('imported',('DI.SCAN','EQ','UC','EQ','DI.SR','EQ')),
                             ('imported',('UC','EQ','UC','EQ','UC','EQ'))):
            original=self.snapshots[stage]
            self.snapshots[stage]=triplet(labels)
            with self.assertRaisesRegex(ValueError,'EXACT_DI_ONLY_NO_FOREIGN_DS'):self.analyze()
            self.snapshots[stage]=original
        self.common['F_basic']=self.common['F_basic'].replace(b'DI.SCAN',b'DS')
        with self.assertRaisesRegex(ValueError,'F_BASIC_DS_FORBIDDEN'):self.analyze()

    def test_duplicate_or_missing_namespace_native_report_and_unknown_class_fail(self):
        native=self.snapshots['simulated']['native']
        for bad in (native.replace(b'"/a"',b'"/outside"'),native.replace(b'DS',b'ZZ'),
                    native.replace(b'"/b"',b'"/a"')):
            self.snapshots['simulated']['native']=bad
            with self.assertRaises(ValueError):self.analyze()
        self.snapshots['simulated']['native']=native
        self.snapshots['simulated']['report']=self.snapshots['simulated']['report'].replace(b'0 DS /e',b'0 UC /e')
        with self.assertRaisesRegex(ValueError,'REPORT_NATIVE_CLASS_MISMATCH'):self.analyze()

    def test_group_expanded_counts_not_native_representative_counts(self):
        self.snapshots['simulated']['statistics']=stats(dict(DS=1,DI=2,UC=3))
        with self.assertRaisesRegex(ValueError,'ALL_CLASS_RECONCILIATION'):self.analyze()

    def test_h_baseline_ds_invalidates_h_proof(self):
        self.h['H_basic']=self.h['H_basic'].replace(b'0 FU "/c"',b'0 DS "/c"')
        with self.assertRaisesRegex(ValueError,'H_BASELINE_DS_INVALIDATES_PROOF'):self.analyze()

    def test_full_actual_entry_never_promotes_small_synthetic_inputs(self):
        with mock.patch.object(m.history,'_h_provenance') as call:
            with self.assertRaisesRegex(ValueError,'PINNED_INPUT_BODY'):
                m.analyze(self.common,self.h,self.snapshots,self.evidence,provenance(self.snapshots,self.evidence))
        call.assert_not_called()
        with self.assertRaisesRegex(ValueError,'EXPLICIT_SMALL_SYNTHETIC'):
            m.analyze_synthetic_for_tests(self.common,self.h,self.snapshots,self.evidence,{},m.N)

    def test_boolean_provenance_false_exit_and_capture_body_forgery_rejected(self):
        with self.assertRaisesRegex(ValueError,'EXACT_RAW_PROVENANCE'):
            self.analyze(dict(H_physically_proven=True,external_patterns_applied=True))
        proof=provenance(self.snapshots,self.evidence)
        transport=m.groups._json(proof['transport_receipt_bytes']);transport['exit_code']=False
        proof['transport_receipt_bytes']=m.canonical(transport)
        with self.assertRaisesRegex(ValueError,'SUCCESS_REPORTED_TRANSPORT'):self.analyze(proof)
        proof=provenance(self.snapshots,self.evidence)
        capture=m.groups._json(proof['capture_response_bytes'])
        row=next(r for r in capture['files'] if 'body_base64' in r);row['sha256']='0'*64
        proof['capture_response_bytes']=m.canonical(capture)
        with self.assertRaisesRegex(ValueError,'EVERY_PRESENT_ARTIFACT_FULL_SHA'):self.analyze(proof)
        proof=provenance(self.snapshots,self.evidence)
        capture=m.groups._json(proof['capture_response_bytes']);capture['files'].append(capture['files'][0])
        proof['capture_response_bytes']=m.canonical(capture)
        with self.assertRaises(ValueError):self.analyze(proof)

    def test_external_256_or_marker_echo_never_proves_full_fault_application(self):
        r=self.analyze()
        pattern=r['pattern_evidence']
        self.assertEqual(pattern['count_text_observations'],dict(loaded_patterns=[256],simulated_patterns=[256]))
        self.assertTrue(pattern['command_echo_order_observed'])
        self.assertFalse(pattern['all_256_external_test_patterns_loaded_and_applied_verified'])
        self.evidence['simulated_patterns']=b'#test_patterns 4\n#chain_patterns 256\n'
        self.evidence['stdout']+=b'WARNING: 252 test patterns skipped\n'
        join_observer(self.evidence)
        r=self.analyze()
        self.assertFalse(r['all_256_external_patterns_applied_verified'])
        self.assertFalse(r['pattern_evidence']['observed_count_text_exactly_256'])
        self.assertIn('EXTERNAL_COUNT_TEXT_MISMATCH_MISSING_OR_AMBIGUOUS',r['reasons_unproven'])
        self.assertEqual(len(r['pattern_evidence']['diagnostic_inventory']),1)
        self.assertFalse(r['pattern_evidence']['diagnostic_inventory'][0]['reviewed'])
        self.assertEqual(r['status'],'UNPROVEN')

    def test_foreign_command_and_diagnostic_variants_remain_visible(self):
        self.evidence['stdout']+=b'//  command: read_faults foreign.mtfi -merge -show_warnings\n**Error: bad path\n'
        join_observer(self.evidence)
        r=self.analyze()
        self.assertTrue(r['pattern_evidence']['forbidden_generation_or_foreign_merge_echo_observed'])
        self.assertEqual(len(r['pattern_evidence']['diagnostic_inventory']),1)
        self.evidence['applied_patterns_verified']=True
        with self.assertRaisesRegex(ValueError,'EXACT_CLEAN_SNAPSHOT_EVIDENCE_ROLES'):self.analyze()

    def test_offset_manifest_corruption_limits_guard_and_ast(self):
        manifest=m.groups._json(self.common['manifest']);manifest['f_flat_instance_offset']=1
        self.common['manifest']=m.canonical(manifest)
        with self.assertRaisesRegex(ValueError,'EXACT_COMMON_MANIFEST'):self.analyze()
        self.common,self.h,self.snapshots,self.evidence=fixture_chain()
        with self.assertRaisesRegex(ValueError,'TICK_STOP'):
            self.analyze(tick=mock.Mock(side_effect=ValueError('TICK_STOP')))
        with mock.patch.object(m,'MAX_NEW_BODIES',1):
            with self.assertRaisesRegex(ValueError,'TOTAL_BODY_BOUNDS'):self.analyze()
        for path in (Path(m.__file__),Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'),feature_version=(3,6))

    def test_observer_boolean_returncode_wrong_ack_and_unknown_root_reject(self):
        self.evidence['observation']=self.evidence['observation'].replace(b'"returncode":0',b'"returncode":false')
        with self.assertRaisesRegex(ValueError,'OBSERVER_REPORTED'):self.analyze()
        join_observer(self.evidence)
        self.evidence['stdout_ack']=m.canonical(dict(bytes=len(self.evidence['stdout']),sha256='0'*64))
        with self.assertRaisesRegex(ValueError,'OBSERVER_LOG_AND_ACK'):self.analyze()
        join_observer(self.evidence)
        proof=provenance(self.snapshots,self.evidence)
        value=m.groups._json(proof['capture_response_bytes']);value['files'][0]=dict(path='/outside',missing=True)
        proof['capture_response_bytes']=m.canonical(value)
        with self.assertRaisesRegex(ValueError,'CAPTURE_OWNED_ROOT_PATHS_ONLY'):self.analyze(proof)
        with self.assertRaisesRegex(ValueError,'AUDIT_TICK_REQUIRED'):self.analyze(tick=False)

    def test_actual_controller_roster_and_private_worker_publish_interface(self):
        from scripts import run_physical_f_clean_replay_e137 as controller
        from src.data import physical_f_replay_execution_e137 as worker
        self.assertEqual(m.READBACK_OUTPUTS,controller.OUTPUTS)
        self.assertEqual(len(m.READBACK_OUTPUTS),35)
        raw=(Path(__file__).resolve().parents[1]/'src/data/physical_f_replay_execution_e135.py').read_bytes()
        services=worker.private_services(raw)
        files=services.Files(mock.Mock())
        for name,role in (('stdout.log','stdout'),('observation.json','observation'),('stdout_ack.json','stdout_ack')):
            with mock.patch.object(files,'directory',return_value=77) as directory, \
                    mock.patch.object(services.io,'_publish') as published, \
                    mock.patch.object(services.os,'close'):
                receipt=files.publish(name,b'synthetic')
            directory.assert_called_once_with(m.ROOT+'/journal')
            published.assert_called_once_with(77,name,b'synthetic')
            self.assertEqual(receipt['path'],m.EVIDENCE_PATHS[role])

    def test_old_capture_boolean_and_extra_or_partial_roster_cannot_qualify(self):
        for change in ('old_bool','extra_bool','missing_row','wrong_order','required_missing','wrong_uid','unknown_path'):
            proof=provenance(self.snapshots,self.evidence)
            value=m.groups._json(proof['capture_response_bytes'])
            if change=='old_bool':value=dict(capture_complete=True,files=value['files'])
            elif change=='extra_bool':value['capture_complete']=True
            elif change=='missing_row':value['files'].pop()
            elif change=='wrong_order':value['files'].reverse()
            elif change=='required_missing':
                index=next(i for i,r in enumerate(value['files']) if r['path']==m.EVIDENCE_PATHS['stdout'])
                value['files'][index]=dict(path=m.EVIDENCE_PATHS['stdout'],missing=True)
            elif change=='wrong_uid':
                next(r for r in value['files'] if 'identity' in r)['identity']['st_uid']=0
            else:value['files'][0]['path']=m.ROOT+'/journal/not-approved.json'
            proof['capture_response_bytes']=m.canonical(value)
            with self.assertRaises(ValueError,msg=change):self.analyze(proof)

    def test_non_science_auxiliary_body_is_also_hashed_and_duplicate_roster_rejected(self):
        proof=provenance(self.snapshots,self.evidence)
        value=m.groups._json(proof['capture_response_bytes'])
        info=copy.deepcopy(next(r for r in value['files'] if 'identity' in r)['identity'])
        info['st_size']=3
        value['files'][0]=dict(path=m.READBACK_OUTPUTS[0],bytes=3,sha256=m.sha(b'abc'),identity=info,
            body_base64=base64.b64encode(b'bad').decode('ascii'))
        proof['capture_response_bytes']=m.canonical(value)
        with self.assertRaisesRegex(ValueError,'EVERY_PRESENT_ARTIFACT_FULL_SHA'):self.analyze(proof)
        proof=provenance(self.snapshots,self.evidence)
        value=m.groups._json(proof['capture_response_bytes']);value['files'][1]=value['files'][0]
        proof['capture_response_bytes']=m.canonical(value)
        with self.assertRaisesRegex(ValueError,'CAPTURE_DUPLICATE'):self.analyze(proof)


if __name__ == '__main__':
    unittest.main()
