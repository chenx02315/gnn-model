"""Synthetic owned files and mocked transport only; never launch or contact A."""
import ast
import base64
import copy
from contextlib import redirect_stdout
import datetime
import io as string_io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

from scripts import read_eq_group_artifacts_e133 as m
from scripts import acceptance_transport_e98 as control
from src.data import prospective_acceptance_materializer_v1 as anchored
from src.data import direct_tessent_acceptance_e104 as direct
from tests.test_generation_failure_readback_e122 import Files as VirtualFiles

BOOT = '3ebeb9bb-410c-476c-a000-5c625f590473'


def fixture():
    bodies = [('synthetic owned file %d\n'%index).encode('ascii') for index in range(7)]
    pins = tuple(dict(path=original['path'],bytes=len(body),sha256=m.sha(body)) for original,body in zip(m.FILES,bodies))
    return pins,bodies


def response(pins,bodies):
    rows = []
    for index,(pin,body) in enumerate(zip(pins,bodies)):
        info = dict(st_dev=1,st_ino=10+index,st_mode=stat.S_IFREG|0o600,st_nlink=1,
                    st_uid=1047,st_size=len(body),st_mtime_ns=1,st_ctime_ns=1)
        rows.append(dict(pin,identity=info,whole_file_hashed=True,body_base64=base64.b64encode(body).decode('ascii')))
    return dict(schema=m.SCHEMA,capture_complete=True,error=None,stage='COMPLETE',hostname='bupt-vncs2',uid=1047,
        boot_id=BOOT,python_version=[3,6,8],remote_start_monotonic=1000.0,remote_end_monotonic=1001.0,
        capture_deadline_monotonic=1300.0,files=rows,body_bytes_hashed=sum(map(len,bodies)),sampled_peak_rss_swap_bytes=123,
        filesystem_writes=0,child_launches=0,environment_reads=0,tessent_launches=0,atpg_launches=0,
        training_runs=0,old_experiment_clock_changed=False,parse_or_analysis_performed=False,
        coverage_semantics_proven=False,frozen_contract_d95_pass=False,training_release=False)


class Files(VirtualFiles):
    def __init__(self,pins,bodies):
        self.info,self.body,self.handles = {},{},{}
        self.next_fd,self.next_ino = 100,10
        self.opened,self.read_hook = [],None
        for pin,body in zip(pins,bodies):
            self.add(pin['path'].rsplit('/',1)[0],directory=True)
            self.add(pin['path'],raw=body)


class PhysicalTests(unittest.TestCase):
    def setUp(self):
        self.pins,self.bodies = fixture()
        self.fs = Files(self.pins,self.bodies)
        self.domain = mock.Mock(peak=123)
        self.domain.sample.return_value = {}
        self.clock = mock.Mock(return_value=1001.0)
        patches = [mock.patch.object(m,'FILES',self.pins),mock.patch.object(m,'check_authority'),
            mock.patch.object(anchored,'_directory',side_effect=self.fs.directory),
            mock.patch.object(m.os,'stat',side_effect=self.fs.stat),mock.patch.object(m.os,'fstat',side_effect=self.fs.fstat),
            mock.patch.object(m.os,'open',side_effect=self.fs.open),mock.patch.object(m.os,'read',side_effect=self.fs.read),
            mock.patch.object(m.os,'close',side_effect=self.fs.close),mock.patch.object(m.os,'getuid',return_value=1047,create=True),
            mock.patch.object(m.os,'O_NOFOLLOW',131072,create=True),mock.patch.object(m.os,'O_NONBLOCK',262144,create=True),
            mock.patch.object(m.sys,'platform','linux'),mock.patch.object(m.platform,'node',return_value='bupt-vncs2'),
            mock.patch.object(m.time,'monotonic',self.clock),mock.patch.object(direct,'Descendants',return_value=self.domain),
            mock.patch.object(direct.base,'_small',return_value=BOOT.encode('ascii'))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(lambda:self.assertEqual(self.fs.handles,{}))

    def collect(self):
        return m.collect(dict(authority='YQ==',proposal='Yg=='),1000.0)

    def test_exact_seven_whole_hash_and_bodies_no_parsing_or_directory_scan(self):
        with mock.patch('subprocess.Popen') as spawn,mock.patch.object(m.os,'scandir') as scan:
            value = self.collect()
        spawn.assert_not_called()
        scan.assert_not_called()
        self.assertTrue(value['capture_complete'],value['error'])
        self.assertEqual(self.fs.opened,[pin['path'] for pin in self.pins])
        checked,bodies = m.validate_response(m.canonical(value))
        self.assertEqual(bodies,self.bodies)
        self.assertFalse(checked['parse_or_analysis_performed'])
        self.assertLessEqual(len(m.canonical(m.metadata_only(value))),65536)

    def test_wrong_path_and_preopen_special_link_or_owner_rejected(self):
        with self.assertRaisesRegex(ValueError,'EXACT_APPROVED_FILE_PIN'):
            m.read_file(dict(self.pins[0],path='/not/approved'),mock.Mock(),[0])
        path = self.pins[0]['path']
        for key,bad in (('st_mode',stat.S_IFCHR),('st_mode',stat.S_IFLNK),('st_nlink',2),('st_uid',999)):
            original = getattr(self.fs.info[path],key)
            setattr(self.fs.info[path],key,bad)
            self.assertFalse(self.collect()['capture_complete'])
            setattr(self.fs.info[path],key,original)
        self.assertEqual(self.fs.opened,[])

    def test_sha_mutation_short_read_and_total_bound_stop_no_retry(self):
        path = self.pins[1]['path']
        self.fs.body[path] = b'x'*len(self.fs.body[path])
        value = self.collect()
        self.assertEqual(value['error']['code'],'FULL_APPROVED_SHA_MISMATCH')
        self.assertEqual(len(value['files']),1)
        self.fs.body[path] = self.bodies[1]
        self.fs.body[self.pins[0]['path']] = b''
        self.assertEqual(self.collect()['error']['code'],'PINNED_FILE_SHORT_READ')
        self.fs.body[self.pins[0]['path']] = self.bodies[0]
        with mock.patch.object(m,'MAX_TOTAL',len(self.bodies[0])):
            self.assertEqual(len(self.collect()['files']),1)

    def test_size_identity_changes_deadline_memory_and_child_guards(self):
        path = self.pins[0]['path']
        self.fs.info[path].st_size += 1
        self.assertFalse(self.collect()['capture_complete'])
        self.assertEqual(self.fs.opened,[])
        self.fs.info[path].st_size -= 1
        def mutate(path): self.fs.info[path].st_mtime_ns += 1
        self.fs.read_hook = mutate
        self.assertEqual(self.collect()['error']['code'],'PINNED_FILE_CHANGED')
        self.fs.read_hook = None
        self.fs.opened.clear()
        self.clock.return_value = 1061.0
        self.assertFalse(self.collect()['capture_complete'])
        self.clock.return_value = 1001.0
        self.domain.peak = 536870913
        self.assertFalse(self.collect()['capture_complete'])
        self.domain.peak = 0
        self.domain.sample.return_value = {9:'child'}
        self.assertFalse(self.collect()['capture_complete'])
        self.assertEqual(self.fs.opened,[])

    def test_base64_stream_chunk_boundaries_do_not_corrupt_complete_export(self):
        original = self.fs.read
        with mock.patch.object(m.os,'read',side_effect=lambda fd,n:original(fd,min(n,4))):
            value = self.collect()
        self.assertTrue(value['capture_complete'],value['error'])
        self.assertEqual(m.validate_response(m.canonical(value))[1],self.bodies)


class LocalTests(unittest.TestCase):
    def test_actual_authority_proposal_exact_utf8_and_offline_packet_ast_inert(self):
        with mock.patch.object(control,'load_transport',side_effect=AssertionError('NO NETWORK')):
            plan = m.prepare()
        repo = Path(m.__file__).resolve().parents[1]
        auth,proposal = (repo/m.AUTH).read_bytes(),(repo/m.PROPOSAL).read_bytes()
        self.assertEqual(json.loads(auth)['user_reply'],'\u6279\u51c6 E133 \u6574\u5305')
        self.assertEqual(m.sha(auth),m.AUTH_SHA)
        self.assertEqual(m.sha(proposal),m.PROPOSAL_SHA)
        self.assertEqual(sum(pin['bytes'] for pin in m.FILES),10404024)
        self.assertEqual(len(plan['source_sha256']),15)
        for path in (Path(m.__file__),Path(__file__)):
            ast.parse(path.read_text(),feature_version=(3,6))
        payload = plan['payload'].decode('ascii')
        ast.parse(payload,feature_version=(3,6))
        target = 'result=sys.modules["src.data.e133_artifact_reader"].collect(p["spec"],bootstrap_started)'
        self.assertEqual(payload.count(target),1)
        with mock.patch.dict(sys.modules),redirect_stdout(string_io.StringIO()),mock.patch('subprocess.Popen') as spawn:
            exec(compile(payload.replace(target,'result={"inert_source_load_only":True}'),'<inert-reader>','exec'),{})
        spawn.assert_not_called()

    def test_validator_wrong_path_sha_body_caps_python_version_and_no_analysis_flags(self):
        pins,bodies = fixture()
        with mock.patch.object(m,'FILES',pins):
            self.assertEqual(m.validate_response(m.canonical(response(pins,bodies)))[1],bodies)
            for mutate in (lambda v:v['files'][0].update(path='/unknown'),
                lambda v:v['files'][0].update(sha256='0'*64),
                lambda v:v['files'][-1].update(body_base64='eA=='),
                lambda v:v.update(python_version=[3,True,8]),
                lambda v:v.update(python_version=[3,6]),
                lambda v:v.update(parse_or_analysis_performed=True),
                lambda v:v.update(capture_deadline_monotonic=1600),
                lambda v:v.update(files=v['files'][:6])):
                value = response(pins,bodies)
                mutate(value)
                with self.assertRaises(ValueError):
                    m.validate_response(m.canonical(value))
        with mock.patch.object(m,'MAX_RESPONSE',2):
            with self.assertRaisesRegex(ValueError,'EXPORT_RESPONSE_BOUND'):
                m.validate_response(b'long')

    def setup_execution(self,root,pins,bodies,corrupt=False):
        plan = {key:'a'*64 for key in m.REVIEW_KEYS}
        plan.update(payload=b'inert',source_sha256={})
        review = root/'review.json'
        review.write_bytes(m.canonical(dict(status='PASS',reviewed={key:plan[key] for key in m.REVIEW_KEYS})))
        value = response(pins,bodies)
        if corrupt:
            value['files'][-1]['body_base64'] = 'eA=='
        helper = mock.Mock()
        helper.verify_cached_host.return_value = 'cached-A'
        helper.transport.return_value = dict(stdout=m.canonical(value),stderr=b'',exit_code=0,
            timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
        return plan,review,helper

    def test_intent_before_transport_all_hashes_before_files_then_hash_only_names(self):
        pins,bodies = fixture()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            plan,review,helper = self.setup_execution(root,pins,bodies)
            phase = root/m.PHASE_NAME
            observed = helper.transport.return_value
            def transport(*args):
                self.assertTrue((phase/'start.json').is_file())
                self.assertFalse((phase/'files').exists())
                return observed
            helper.transport.side_effect = transport
            with mock.patch.object(m,'FILES',pins),mock.patch.object(m,'prepare',return_value=plan), \
                    mock.patch.object(control,'STAGING',root),mock.patch.object(control,'load_transport',return_value=helper), \
                    mock.patch.object(control,'execute_phase',side_effect=AssertionError('OLD GRANT')):
                result = m.execute(review,plan['payload_sha256'])
                with self.assertRaises(FileExistsError):
                    m.execute(review,plan['payload_sha256'])
            self.assertEqual(helper.transport.call_count,1)
            self.assertEqual([row['file'] for row in result['files']],[pin['sha256'] for pin in pins])
            self.assertEqual([(phase/'files'/pin['sha256']).read_bytes() for pin in pins],bodies)

    def test_last_bad_hash_saves_raw_but_no_decoded_file_and_post_validation_deadline(self):
        pins,bodies = fixture()
        for corrupt in (True,False):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                plan,review,helper = self.setup_execution(root,pins,bodies,corrupt)
                phase = root/m.PHASE_NAME
                with mock.patch.object(m,'FILES',pins),mock.patch.object(m,'prepare',return_value=plan), \
                        mock.patch.object(control,'STAGING',root),mock.patch.object(control,'load_transport',return_value=helper), \
                        mock.patch.object(m,'_remaining',side_effect=[100,99,ValueError('POST_VALIDATION_DEADLINE')]):
                    with self.assertRaises(ValueError):
                        m.execute(review,plan['payload_sha256'])
                self.assertTrue((phase/'stdout.json').is_file())
                self.assertTrue((phase/'stderr.log').is_file())
                self.assertTrue((phase/'transport.json').is_file())
                self.assertFalse((phase/'files').exists())

    def test_review_failure_before_transport_and_local_dual_clock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pins,bodies = fixture()
            plan,review,helper = self.setup_execution(root,pins,bodies)
            review.write_bytes(b'{"status":"FAIL"}')
            with mock.patch.object(m,'prepare',return_value=plan),mock.patch.object(control,'load_transport') as load:
                with self.assertRaisesRegex(ValueError,'INDEPENDENT_EXACT_NEW_REVIEW_REQUIRED'):
                    m.execute(review,plan['payload_sha256'])
                load.assert_not_called()
        now = m.time.monotonic()
        first = dict(local_monotonic_start=now-301,local_monotonic_deadline=now-1,
            local_utc_deadline=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=300)).isoformat(timespec='microseconds'),
            local_clock_domain=dict(pid=m.os.getpid(),host=m.platform.node(),clock=m.time.get_clock_info('monotonic').implementation))
        with self.assertRaisesRegex(ValueError,'LOCAL_MONOTONIC_CAPTURE_EXPIRED'):
            m._remaining(first)
        first.update(local_monotonic_start=now,local_monotonic_deadline=now+300,
            local_utc_deadline=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=1)).isoformat(timespec='microseconds'))
        with self.assertRaisesRegex(ValueError,'LOCAL_WALL_CAPTURE_EXPIRED'):
            m._remaining(first)


if __name__ == '__main__':
    unittest.main()
