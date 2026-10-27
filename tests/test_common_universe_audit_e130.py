"""Tiny synthetic common-key sets and virtual IO only; no A access or tool run."""
import ast
import base64
import copy
from contextlib import redirect_stdout
import io as string_io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

from scripts import audit_common_universe_e130 as m
from scripts import acceptance_transport_e98 as control
from src.data import prospective_acceptance_materializer_v1 as physical
from src.data import direct_tessent_acceptance_e104 as direct
from src.data import prospective_report_dialect_e126 as reports
from tests.test_prospective_acquisition_result_integration_e107 import Outputs
from tests.test_generation_failure_readback_e122 import Files as VirtualFiles


def statistics(count,patterns=True):
    return ('Fault Classes #faults\n FU (full) 20\n DS (det_simulation) %d\n DI (det_implication) 1\n'
        ' RE (redundant) %d\nFault Sub-classes\nCoverage\n'%(count-1,20-count)+
        ('#test_patterns 2\n' if patterns else '')).encode('ascii')


def fixture():
    outputs = Outputs({})
    mapping = outputs.mapping
    manifest = dict(schema='multimode_common_fault_universe_v1',fault_model='stuck-at',common_fault_count=20,
        f_flat_instance_offset=1,mapping=dict(sha256=m.sha(mapping)))
    bodies = dict(manifest=m.canonical(manifest),mapping=mapping,H_mtfi=outputs.mtfi('H',10),
        F_mtfi=outputs.mtfi('F',19),F_statistics=statistics(19),F_pre_statistics=statistics(10,False),
        F_faults_report=b'Existing owned EQ relationship report excerpt\n'*1000)
    for mode in ('H','F'):
        bodies[mode+'_basic'] = ''.join('0 FU "/U%d/p"\n'%((9 if mode == 'F' else 10)+i) for i in range(20)).encode('ascii')
    h_stats = reports.parse_statistics(statistics(10),20)
    files = {role:dict(path=m.PATHS[role]) for role in m.ORDER}
    for role in m.ORDER:
        if role not in ('F_pre_statistics','F_faults_report'):
            files[role]['pin'] = dict(bytes=len(bodies[role]),sha256=m.sha(bodies[role]))
    return bodies,dict(files=files,common_count=20,H_statistics=h_stats,minimum_pre_detected=10)


class PureTests(unittest.TestCase):
    def setUp(self):
        self.bodies,self.plan = fixture()

    def audit(self,bodies=None):
        return m.audit_bodies(bodies or self.bodies,20,m.sha(self.bodies['mapping']),self.plan['H_statistics'],10,mock.Mock())

    def test_complete_canonical_keysets_union_not_aggregate_substitution(self):
        value = self.audit()
        self.assertTrue(value['namespace_keyset_verified'])
        self.assertTrue(value['H_v2_source_parser_passed'])
        self.assertEqual((value['H_explicit_detected'],value['F_explicit_detected'],value['H_F_explicit_union']),(10,19,19))
        self.assertEqual(value['H_F_explicit_intersection'],10)
        self.assertTrue(value['explicit_union_meets_d95_math'])
        for key in ('coverage_semantics_proven','frozen_contract_d95_pass','training_release',
                    'eq_adjacency_detection_inferred','aggregate_counts_replace_explicit_union_contract'):
            self.assertFalse(value[key])

    def test_eq_rows_excluded_and_expanded_delta_not_detection_certificate(self):
        lines = self.bodies['F_mtfi'].splitlines(keepends=True)
        for index in range(10,19):
            lines[7+index] = lines[7+index].replace(b', DS,',b', EQ,')
        self.bodies['F_mtfi'] = b''.join(lines)
        value = self.audit()
        self.assertEqual(value['F_EQ_rows'],9)
        self.assertEqual(value['F_explicit_detected'],10)
        self.assertEqual(value['H_F_explicit_union'],10)
        self.assertEqual(value['F_reported_DS_DI'],19)
        self.assertEqual(value['expanded_statistics_delta_sum'],9)
        self.assertEqual(value['statistics_minus_native_explicit_top_class_delta']['DS'],9)
        self.assertTrue(value['necessary_conditions']['expanded_delta_sum_equals_EQ_rows'])
        self.assertFalse(value['frozen_contract_d95_pass'])

    def test_missing_duplicate_or_wrong_mode_mtfi_rejected(self):
        for transform in (lambda raw:raw.replace(b'"/U10/p"',b'"/U9/p"'),
                          lambda raw:b''.join(raw.splitlines(keepends=True)[:8]+raw.splitlines(keepends=True)[9:]),
                          lambda raw:self.bodies['H_mtfi']):
            bodies = copy.deepcopy(self.bodies)
            bodies['F_mtfi'] = transform(bodies['F_mtfi'])
            with self.assertRaises(ValueError):
                self.audit(bodies)

    def test_basic_full_keysets_mapping_pin_and_unknown_class_fail_closed(self):
        for role,transform in (('F_basic',lambda raw:raw.replace(b'/U10/p',b'/U9/p')),
            ('H_basic',lambda raw:raw.split(b'\n',1)[1]),
            ('manifest',lambda raw:raw.replace(m.sha(self.bodies['mapping']).encode('ascii'),b'0'*64)),
            ('F_mtfi',lambda raw:raw.replace(b', RE,',b', AU.OTHER,')),
            ('H_mtfi',lambda raw:raw.replace(b', RE,',b', AU.SEQ,'))):
            bodies = copy.deepcopy(self.bodies)
            bodies[role] = transform(bodies[role])
            with self.subTest(role=role),self.assertRaises(ValueError):
                self.audit(bodies)
        bodies = copy.deepcopy(self.bodies)
        bodies['F_mtfi'] = bodies['F_mtfi'].replace(b', RE,',b', AU.SEQ,')
        self.assertEqual(self.audit(bodies)['F_class_counts']['AU.SEQ'],1)


class Files(VirtualFiles):
    def __init__(self,bodies):
        self.info,self.body,self.handles = {},{},{}
        self.next_fd,self.next_ino = 100,10
        self.opened,self.read_hook = [],None
        for role in m.ORDER:
            path = m.PATHS[role]
            self.add(path.rsplit('/',1)[0],directory=True)
            self.add(path,raw=bodies[role])


class PhysicalTests(unittest.TestCase):
    def setUp(self):
        self.bodies,self.plan = fixture()
        self.fs = Files(self.bodies)
        self.domain = mock.Mock(peak=123)
        self.domain.sample.return_value = {}
        self.clock = mock.Mock(return_value=m.START+100)
        patches = [mock.patch.object(physical,'_directory',side_effect=self.fs.directory),
            mock.patch.object(m.os,'stat',side_effect=self.fs.stat),mock.patch.object(m.os,'fstat',side_effect=self.fs.fstat),
            mock.patch.object(m.os,'open',side_effect=self.fs.open),mock.patch.object(m.os,'read',side_effect=self.fs.read),
            mock.patch.object(m.os,'close',side_effect=self.fs.close),mock.patch.object(m.os,'getuid',return_value=1047,create=True),
            mock.patch.object(m.os,'O_NOFOLLOW',131072,create=True),mock.patch.object(m.os,'O_NONBLOCK',262144,create=True),
            mock.patch.object(m.sys,'platform','linux'),mock.patch.object(m.platform,'node',return_value='bupt-vncs2'),
            mock.patch.object(m.time,'monotonic',self.clock),mock.patch.object(direct,'Descendants',return_value=self.domain),
            mock.patch.object(direct.base,'_small',return_value=m.BOOT.encode('ascii')),mock.patch.object(m,'COMMON_COUNT',20)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(lambda:self.assertEqual(self.fs.handles,{}))

    def test_exact_nine_owned_files_full_hash_prefix_only_no_tool_or_scan(self):
        with mock.patch('subprocess.Popen') as spawn,mock.patch.object(m.os,'scandir') as scan:
            value = m.collect(self.plan)
        spawn.assert_not_called()
        scan.assert_not_called()
        self.assertTrue(value['capture_complete'],value['error'])
        self.assertEqual(self.fs.opened,[m.PATHS[role] for role in m.ORDER])
        for role,row in zip(m.ORDER,value['files']):
            self.assertEqual(row['sha256'],m.sha(self.bodies[role]))
            self.assertNotIn('body_base64',row)
        excerpt = value['files'][-1]
        self.assertEqual(base64.b64decode(excerpt['prefix_base64']),self.bodies['F_faults_report'][:32768])
        self.assertEqual(excerpt['prefix_bytes'],32768)
        m.validate_response(m.canonical(value),self.plan)

    def test_symlink_hardlink_owner_size_pin_and_missing_rejected(self):
        path = m.PATHS['manifest']
        for key,bad in (('st_mode',stat.S_IFLNK),('st_nlink',2),('st_uid',999),('st_size',65537)):
            original = getattr(self.fs.info[path],key)
            setattr(self.fs.info[path],key,bad)
            self.assertFalse(m.collect(self.plan)['capture_complete'])
            setattr(self.fs.info[path],key,original)
        self.assertEqual(self.fs.opened,[])
        self.plan['files']['manifest']['pin']['sha256'] = '0'*64
        value = m.collect(self.plan)
        self.assertEqual(value['error']['code'],'PINNED_SOURCE_SHA_CHANGED')
        del self.fs.info[path]
        self.assertFalse(m.collect(self.plan)['capture_complete'])

    def test_mutation_short_read_total_limit_and_first_failure_prefix(self):
        def mutate(path):
            self.fs.info[path].st_mtime_ns += 1
        self.fs.read_hook = mutate
        value = m.collect(self.plan)
        self.assertEqual(value['error']['code'],'AUDIT_SOURCE_CHANGED')
        self.assertEqual(value['files'],[])
        self.fs.read_hook = None
        self.fs.body[m.PATHS['manifest']] = b''
        value = m.collect(self.plan)
        self.assertEqual(value['error']['code'],'AUDIT_SHORT_READ')
        self.fs.body[m.PATHS['manifest']] = self.bodies['manifest']
        with mock.patch.object(m,'MAX_TOTAL',len(self.bodies['manifest'])):
            value = m.collect(self.plan)
        self.assertFalse(value['capture_complete'])
        self.assertEqual(len(value['files']),1)

    def test_clock_memory_child_guards_before_owned_reads(self):
        self.clock.return_value = m.END
        self.assertFalse(m.collect(self.plan)['capture_complete'])
        self.clock.return_value = m.START+100
        self.domain.peak = 536870913
        self.assertFalse(m.collect(self.plan)['capture_complete'])
        self.domain.peak = 0
        self.domain.sample.return_value = {999:'child'}
        self.assertFalse(m.collect(self.plan)['capture_complete'])
        self.assertEqual(self.fs.opened,[])

    def test_validator_no_d95_promotion_union_forgery_or_changed_pin(self):
        original = m.collect(self.plan)
        for mutate in (lambda v:v['metrics'].update(frozen_contract_d95_pass=True),
                       lambda v:v['metrics'].update(H_F_explicit_union=20),
                       lambda v:v['files'][0].update(sha256='0'*64,expected_sha256='0'*64)):
            value = copy.deepcopy(original)
            mutate(value)
            with self.assertRaises(ValueError):
                m.validate_response(m.canonical(value),self.plan)

    def test_complete_metrics_cannot_omit_fields_or_forge_classes_deltas_conditions(self):
        original = m.collect(self.plan)
        def missing(value):
            del value['metrics']['F_statistics']
        def unknown(value):
            value['metrics']['H_class_counts'] = {'ZZ':20}
            value['metrics']['F_class_counts'] = {'ZZ':20}
            value['metrics']['unknown_classes'] = []
        def delta(value):
            value['metrics']['statistics_minus_native_explicit_top_class_delta']['DS'] += 1
        def condition(value):
            value['metrics']['necessary_conditions']['expanded_delta_sum_equals_EQ_rows'] = False
        for mutate in (missing,unknown,delta,condition):
            value = copy.deepcopy(original)
            mutate(value)
            with self.assertRaises(ValueError):
                m.validate_response(m.canonical(value),self.plan)

    def test_necessary_condition_can_be_false_in_a_completed_diagnostic(self):
        raw = statistics(18)
        path = m.PATHS['F_statistics']
        self.fs.body[path] = raw
        self.fs.info[path].st_size = len(raw)
        self.plan['files']['F_statistics']['pin'] = dict(bytes=len(raw),sha256=m.sha(raw))
        value = m.collect(self.plan)
        self.assertTrue(value['capture_complete'],value['error'])
        self.assertFalse(value['metrics']['necessary_conditions']['expanded_class_deltas_nonnegative'])
        self.assertFalse(value['metrics']['frozen_contract_d95_pass'])
        m.validate_response(m.canonical(value),self.plan)


class ControllerTests(unittest.TestCase):
    def test_prepare_real_proof_chain_offline_sources_and_inert_payload(self):
        with mock.patch.object(control,'load_transport',side_effect=AssertionError('NO NETWORK')):
            plan = m.prepare()
        self.assertEqual(plan['e128_response_sha256'],m.E128_SHA)
        self.assertEqual(plan['audit_plan_sha256'],m.sha(m.canonical(plan['audit_plan'])))
        self.assertEqual(len(plan['audit_plan']['files']),9)
        self.assertEqual(len(plan['source_sha256']),18)
        payload = plan['payload'].decode('ascii')
        target = 'result=sys.modules["src.data.e130_common_audit"].collect(p["plan"],bootstrap_started)'
        self.assertEqual(payload.count(target),1)
        payload = payload.replace(target,'result={"inert_load_only":True}')
        with mock.patch.dict(sys.modules),redirect_stdout(string_io.StringIO()),mock.patch('subprocess.Popen') as spawn:
            exec(compile(payload,'<inert-auditor-only>','exec'),{})
        spawn.assert_not_called()
        for path in (Path(m.__file__),Path(__file__)):
            ast.parse(path.read_text(),feature_version=(3,6))
        ast.parse(plan['payload'].decode('ascii'),feature_version=(3,6))

    def test_fresh_review_raw_before_validation_create_once_no_old_grant(self):
        from scripts import read_pt_label_failure_e128 as proof
        with tempfile.TemporaryDirectory() as temp:
            staging = Path(temp)
            plan = {key:'a'*64 for key in m.REVIEW_KEYS}
            plan.update(payload=b'inert',source_sha256={},execution_source_sha256={},audit_plan={})
            review = staging/'review.json'
            review.write_bytes(m.canonical(dict(status='PASS',reviewed={k:plan[k] for k in m.REVIEW_KEYS})))
            helper = mock.Mock()
            helper.verify_cached_host.return_value = 'cached-A'
            helper.transport.return_value = dict(stdout=b'raw invalid',stderr=b'stderr',exit_code=0,
                timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
            phase = staging/'v6_e130_common_universe_audit_20261027_r1'
            def validate(raw,expected):
                self.assertEqual((phase/'stdout.json').read_bytes(),b'raw invalid')
                self.assertTrue((phase/'stderr.log').is_file())
                self.assertTrue((phase/'transport.json').is_file())
                raise ValueError('MOCK_VALIDATION_REJECT')
            with mock.patch.object(m,'prepare',return_value=plan),mock.patch.object(control,'STAGING',staging), \
                    mock.patch.object(control,'load_transport',return_value=helper), \
                    mock.patch.object(proof,'_local_remaining',return_value=100), \
                    mock.patch.object(control,'execute_phase',side_effect=AssertionError('OLD GRANT')), \
                    mock.patch.object(m,'validate_response',side_effect=validate):
                with self.assertRaisesRegex(ValueError,'MOCK_VALIDATION_REJECT'):
                    m.execute(review,plan['payload_sha256'])
                with self.assertRaises(FileExistsError):
                    m.execute(review,plan['payload_sha256'])
            self.assertEqual(helper.transport.call_count,1)


if __name__ == '__main__':
    unittest.main()
