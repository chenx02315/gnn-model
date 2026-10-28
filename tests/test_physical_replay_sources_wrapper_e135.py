"""Initial read wrapper tests: virtual files and mocked transport only."""
import ast
import base64
import copy
import datetime
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock

from scripts import read_physical_replay_sources_e135 as m
from scripts import acceptance_transport_e98 as control
from src.data import direct_tessent_acceptance_e104 as direct
from tests.test_physical_replay_source_inventory_e135 import install

BOOT = '3ebeb9bb-410c-476c-a000-5c625f590473'


class PhysicalTests(unittest.TestCase):
    def setUp(self):
        self.fs = install(self)
        self.domain = mock.Mock(peak=123)
        self.domain.sample.return_value = {}
        for patch in (mock.patch.object(m,'check_authority'),mock.patch.object(m.platform,'node',return_value='bupt-vncs2'),
                mock.patch.object(m.os,'getuid',return_value=1047,create=True),mock.patch.object(m.sys,'platform','linux'),
                mock.patch.object(m.time,'monotonic',return_value=1001.0),
                mock.patch.object(direct,'Descendants',return_value=self.domain),
                mock.patch.object(direct.base,'_small',return_value=BOOT.encode('ascii'))):
            patch.start()
            self.addCleanup(patch.stop)

    def capture(self):
        return m.collect(dict(authority='YQ==',proposal='Yg=='),1000.0)

    def test_complete_hashonly_sources_fullpdf_and_inventory(self):
        with mock.patch('subprocess.Popen') as launch:
            value = self.capture()
        launch.assert_not_called()
        self.assertTrue(value['capture_complete'],value['error'])
        checked,pdf = m.validate_response(m.canonical(value))
        self.assertEqual(pdf,self.fs.body[m.core.FILES[1]['path']])
        self.assertNotIn('body_base64',checked['source_receipt']['files'][0])
        self.assertFalse(checked['execution_ready'])
        self.assertEqual(len(checked['inputs']),2)

    def test_runtime_deadline_memory_children_and_first_failure(self):
        with mock.patch.object(m.time,'monotonic',return_value=1061):
            self.assertEqual(self.capture()['error']['code'],'INITIAL_READ_DEADLINE')
        self.domain.peak = 536870913
        self.assertEqual(self.capture()['error']['code'],'MEMORY_OR_CHILD_STOP')
        self.domain.peak = 123
        self.domain.sample.return_value = {3:'child'}
        self.assertFalse(self.capture()['capture_complete'])
        self.domain.sample.return_value = {}
        self.fs.info[m.core.FILES[1]['path']].st_uid = 1047
        value = self.capture()
        self.assertFalse(value['capture_complete'])
        self.assertEqual(value['stage'],'READ_REFERENCE')
        self.assertEqual(len(value['source_receipt']['files']),1)
        self.assertEqual(value['inputs'],[])

    def test_validator_rejects_corruption_scope_and_incomplete_tree(self):
        value = self.capture()
        changes = [lambda v:v['source_receipt']['files'][1].update(sha256='0'*64),
            lambda v:v['source_receipt']['files'][0].update(body_base64='YQ=='),
            lambda v:v['tree'].update(sha256='0'*64),lambda v:v['tree'].update(entries=99),
            lambda v:v['tree']['rows'][2].update(relative='../escape'),
            lambda v:v['tree']['rows'][2]['identity'].update(st_nlink=2),
            lambda v:v['tree'].update(original_tree_matches=True),
            lambda v:v['inputs'][0].update(sha256='0'*64),lambda v:v.update(python_version=[3,True,8]),
            lambda v:v.update(semantics_verified=True),lambda v:v.update(remote_end_monotonic=1060)]
        for change in changes:
            changed = copy.deepcopy(value)
            change(changed)
            with self.assertRaises(ValueError):
                m.validate_response(m.canonical(changed))

class LocalTests(unittest.TestCase):
    def capture(self):
        case = PhysicalTests()
        case.setUp()
        try:
            value = case.capture()
        finally:
            case.doCleanups()
        patch = mock.patch.object(m.inv,'INPUTS',tuple({k:r[k] for k in ('role','path','bytes','sha256')} for r in value['inputs']))
        patch.start()
        self.addCleanup(patch.stop)
        return value

    def test_execute_consumes_once_raw_before_full_validation_pdf_hash_filename(self):
        value = self.capture()
        plan = {key:'synthetic-pin' for key in m.REVIEW_KEYS}
        plan['authorization_sha256'] = m.AUTH_SHA
        plan['payload'] = b'inert-test-payload'
        helper = mock.Mock()
        helper.verify_cached_host.return_value = 'cached-A'
        helper.transport.return_value = dict(stdout=m.canonical(value),stderr=b'',exit_code=0,
            timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root/'review.json'
            control.write_new(review,control.encode(dict(status='PASS',reviewed={k:plan[k] for k in m.REVIEW_KEYS})))
            with mock.patch.object(m,'prepare',return_value=plan),mock.patch.object(control,'STAGING',root),\
                    mock.patch.object(control,'load_transport',return_value=helper):
                result = m.execute(review,plan['payload_sha256'])
                phase = root/m.PHASE_NAME
                self.assertTrue((phase/'start.json').exists())
                self.assertTrue((phase/'read1/intent.json').exists())
                self.assertTrue((phase/'read1/stdout.json').exists())
                self.assertEqual(Path(result['pdf_file']).name,value['source_receipt']['files'][1]['sha256'])
                with self.assertRaises(FileExistsError):
                    m.execute(review,plan['payload_sha256'])
            self.assertEqual(helper.transport.call_count,1)
            first = m.decode((phase/'start.json').read_bytes())
            self.assertEqual(first['local_monotonic_deadline'],first['local_monotonic_start']+3600.)
            clockraw = (phase/'package_clock.json').read_bytes()
            clock = m.decode(clockraw)
            self.assertEqual(clock['schema'],'physical-f-replay-package-clock-e135-v1')
            self.assertEqual(clock['initial_response_sha256'],m.sha(m.canonical(value)))
            self.assertEqual(clock['start_file_sha256'],m.sha((phase/'start.json').read_bytes()))
            self.assertEqual(clock['local_utc_start'],first['local_utc_start'])
            self.assertEqual(clock['remote_deadline_monotonic'],4600.)
            self.assertEqual(clock['boot_id'],BOOT)
            self.assertLess(len(clockraw),4096)

    def test_bad_pdf_raw_retained_without_body_writes(self):
        value = self.capture()
        value['source_receipt']['files'][1]['sha256'] = '0'*64
        plan = {key:'pin' for key in m.REVIEW_KEYS}
        plan['authorization_sha256'] = m.AUTH_SHA
        plan['payload'] = b'inert'
        helper = mock.Mock()
        helper.transport.return_value = dict(stdout=m.canonical(value),stderr=b'',exit_code=0,
            timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
        helper.verify_cached_host.return_value = 'A'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root/'review.json'
            control.write_new(review,control.encode(dict(status='PASS',reviewed={k:plan[k] for k in m.REVIEW_KEYS})))
            with mock.patch.object(m,'prepare',return_value=plan),mock.patch.object(control,'STAGING',root),\
                    mock.patch.object(control,'load_transport',return_value=helper):
                with self.assertRaisesRegex(ValueError,'FULL_REFERENCE_SHA'):
                    m.execute(review,plan['payload_sha256'])
            self.assertTrue((root/m.PHASE_NAME/'read1/stdout.json').exists())
            self.assertFalse((root/m.PHASE_NAME/'read1/files').exists())

    def test_review_rejection_and_post_transport_clock_no_retry(self):
        value = self.capture()
        plan = {key:'pin' for key in m.REVIEW_KEYS}
        plan.update(payload=b'inert',authorization_sha256=m.AUTH_SHA)
        helper = mock.Mock()
        helper.verify_cached_host.return_value = 'A'
        helper.transport.return_value = dict(stdout=m.canonical(value),stderr=b'',exit_code=0,
            timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root/'review.json'
            control.write_new(review,control.encode(dict(status='PASS',reviewed={})))
            with mock.patch.object(m,'prepare',return_value=plan),mock.patch.object(control,'STAGING',root),\
                    mock.patch.object(control,'load_transport',return_value=helper) as load:
                with self.assertRaisesRegex(ValueError,'INDEPENDENT_EXACT_NEW_REVIEW_REQUIRED'):
                    m.execute(review,plan['payload_sha256'])
                load.assert_not_called()
                review2 = root/'exact.json'
                control.write_new(review2,control.encode(dict(status='PASS',reviewed={k:plan[k] for k in m.REVIEW_KEYS})))
                def observed(*args):
                    self.assertTrue((root/m.PHASE_NAME/'read1/intent.json').exists())
                    return helper.transport.return_value
                helper.transport.side_effect = observed
                with mock.patch.object(m,'_remaining',side_effect=[3599.,ValueError('EXPIRED_AFTER_TRANSPORT')]):
                    with self.assertRaisesRegex(ValueError,'EXPIRED_AFTER_TRANSPORT'):
                        m.execute(review2,plan['payload_sha256'])
            self.assertEqual(helper.transport.call_count,1)
            self.assertTrue((root/m.PHASE_NAME/'read1/stdout.json').exists())
            self.assertFalse((root/m.PHASE_NAME/'read1/files').exists())


class PacketTests(unittest.TestCase):
    def test_actual_authority_and_offline_proof_payload_ast_inert(self):
        repo = Path(__file__).resolve().parents[1]
        authority,proposal = (repo/m.AUTH).read_bytes(),(repo/m.PROPOSAL).read_bytes()
        self.assertEqual(m.decode(authority)['user_reply'],'\u6279\u51c6 E135 \u6574\u5305')
        self.assertNotIn('\ufffd',m.decode(authority)['user_reply'])
        m.check_authority(authority,proposal)
        with self.assertRaises(ValueError):
            m.check_authority(authority+b' ',proposal)
        with mock.patch('subprocess.Popen') as launched,mock.patch.object(control,'load_transport') as load:
            plan = m.prepare()
        launched.assert_not_called()
        load.assert_not_called()
        self.assertEqual(len(plan['source_sha256']),17)
        self.assertEqual(plan['source_sha256']['physical_replay_source_reader_e135'],m.CORE_SHA)
        self.assertIsNone(m.core.AUTH_SHA)
        ast.parse(plan['payload'].decode('ascii'),feature_version=(3,6))
        saved = {name:module for name,module in sys.modules.items() if name == 'src' or name.startswith('src.')}
        try:
            with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as launched:
                exec(compile(plan['payload'].decode('ascii').split('result=sys.modules')[0],'<inert-exact-source-bundle>','exec'),{})
            opened.assert_not_called()
            launched.assert_not_called()
        finally:
            for name in list(sys.modules):
                if name == 'src' or name.startswith('src.'):
                    del sys.modules[name]
            sys.modules.update(saved)
        for path in (Path(m.__file__),repo/'src/data/physical_replay_source_inventory_e135.py',Path(__file__),
                repo/'tests/test_physical_replay_source_inventory_e135.py'):
            ast.parse(path.read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as launched:
            exec(compile(Path(m.__file__).read_bytes(),'<inert-wrapper>','exec'),{})
        opened.assert_not_called()
        launched.assert_not_called()

    def test_package_clock_cannot_renew_or_change_process_domain(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        first = dict(authorization_sha256=m.AUTH_SHA,local_monotonic_start=100.,local_monotonic_deadline=3700.,
            local_utc_start=(now-datetime.timedelta(seconds=100)).isoformat(timespec='microseconds'),
            local_utc_deadline=(now+datetime.timedelta(seconds=3500)).isoformat(timespec='microseconds'),
            local_clock_domain=dict(host=m.platform.node(),clock=m.time.get_clock_info('monotonic').implementation))
        with mock.patch.object(m.time,'monotonic',return_value=200):
            self.assertGreater(m._remaining(first),1)
            with self.assertRaises(ValueError):
                m._remaining(dict(first,local_monotonic_deadline=3800.))
            with self.assertRaises(ValueError):
                m._remaining(dict(first,local_clock_domain={}))
            with self.assertRaises(ValueError):
                m._remaining(dict(first,local_utc_deadline=(now-datetime.timedelta(seconds=1)).isoformat(timespec='microseconds')))
        with mock.patch.object(m.time,'monotonic',return_value=3700):
            with self.assertRaises(ValueError):
                m._remaining(first)


if __name__ == '__main__':
    unittest.main()
