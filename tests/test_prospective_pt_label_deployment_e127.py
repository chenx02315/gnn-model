"""Local-only E127 deployment tests: source loading is inert, all execution mocked."""
import ast
import base64
import builtins
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from scripts import run_pt_label_generation_e127 as r
from scripts import worker_pt_label_generation_e127 as w

BOOT = '3ebeb9bb-410c-476c-a000-5c625f590473'


def clock():
    return dict(authorization_sha256=r.AUTH_SHA256,boot_id=BOOT,start_monotonic=1234.0,
        deadline_monotonic=51634.0,root=r.bundle.ROOT,new_authorized_package_clock=True,cohort_snapshot_is_clock=False)


def result():
    return dict(schema=w.SCHEMA,status='FIXED_78_TASKS_COLLECTED',clock=clock(),bootstrap=None,
        execution_ready=False,training_release=False,runtime_values_disclosed=False,
        summary=dict(root=r.bundle.ROOT,original_package_start=1234.0,original_package_deadline=51634.0,
            counts=dict(tessent_debited=48,translation_debited=30,selftest_cases_reserved=3,
                        selftest_cases_accepted=3,committed_tasks=78)))


class PackageTests(unittest.TestCase):
    def test_prepare_is_offline_exact_auth_after_hashes_and_cohort_only(self):
        with mock.patch.object(r.transport,'load_transport',side_effect=AssertionError('NO NETWORK')):
            plan = r.prepare()
        self.assertEqual(plan['authorization_sha256'],r.AUTH_SHA256)
        self.assertEqual(plan['input_sha256']['e112'],r.E112_SHA256)
        self.assertEqual(plan['payload_sha256'],r.transport.sha(plan['payload']))
        self.assertNotIn('original_clock_sha256',plan)
        self.assertNotIn('e121_worker',plan['source_sha256'])
        self.assertIn('e127_worker',plan['source_sha256'])
        self.assertEqual(len(plan['source_sha256']),36)
        self.assertIn('prospective_report_dialect_e126',plan['source_sha256'])
        self.assertNotEqual(plan['source_sha256']['prospective_generation_recipe_e108'],
                            plan['origin_source_sha256']['prospective_generation_recipe_e108'])
        payload = plan['payload'].decode('ascii')
        self.assertTrue(payload.startswith('import time\nbootstrap_started=time.monotonic()\n'))
        self.assertLess(payload.index('bootstrap_started=time.monotonic()'),payload.index('for row in p["sources"]'))
        self.assertIn('if row["name"]=="prospective_generation_context_e127":',payload)
        for path in (Path(w.__file__),Path(r.__file__),Path(__file__)):
            ast.parse(path.read_text(),feature_version=(3,6))
        ast.parse(payload,feature_version=(3,6))

    def load_inert(self,payload):
        real_open = builtins.open
        def boot_open(path,mode='r',*args,**kwargs):
            if path == '/proc/sys/kernel/random/boot_id':
                return io.BytesIO((BOOT+'\n').encode('ascii'))
            return real_open(path,mode,*args,**kwargs)
        stdout = io.StringIO()
        import platform
        with mock.patch.dict(sys.modules),mock.patch.object(w.time,'monotonic',return_value=1234.0), \
                mock.patch.object(platform,'node',return_value='bupt-vncs2'), \
                mock.patch.object(os,'getuid',return_value=1047,create=True), \
                mock.patch.object(sys,'platform','linux'),redirect_stdout(stdout):
            exec(compile(payload,'<inert-e127-load>','exec'),{'open':boot_open})
            context = sys.modules.get('src.data.prospective_generation_context_e127')
            config = dict(context.CONFIG) if context is not None and context.CONFIG is not None else None
            worker = sys.modules.get('src.data.e127_worker')
            executed = getattr(worker,'_EXECUTED',None)
        return json.loads(stdout.getvalue()),config,executed

    def test_actual_derived_payload_inert_load_new_context_and_no_worker_execution(self):
        plan = r.prepare()
        payload = plan['payload'].decode('ascii')
        target = 'result=sys.modules["src.data.e127_worker"].execute(p["package"])'
        self.assertEqual(payload.count(target),1)
        payload = payload.replace(target,'result={"inert_source_load":True,"clock":clock,"reports":sys.modules["src.data.prospective_generation_artifacts_e117"].reports.__name__}')
        value,config,executed = self.load_inert(payload)
        self.assertTrue(value['inert_source_load'])
        self.assertEqual(config['PACKAGE_START'],1234.0)
        self.assertEqual(config['PACKAGE_END'],51634.0)
        self.assertEqual(config['ROOT'],r.bundle.ROOT)
        self.assertEqual(config['AUTH_SHA256'],r.AUTH_SHA256)
        self.assertFalse(executed)
        self.assertEqual(value['reports'],'src.data.prospective_report_dialect_e126')

    def test_original_e124_worker_is_preserved_and_new_scope_is_exact(self):
        parent = Path(w.__file__).with_name('worker_identifier_generation_e124.py').read_bytes()
        self.assertEqual(r.transport.sha(parent),'762a5b80bcd2058a51be54a734ff7ecc3a9b6fcf2a37c324dbe1780608419993')
        self.assertEqual(w.NEW_ROOT,'/temp/jiangchuanc/multimode_ate_pt_label_repair_e127_20261027_r1')
        self.assertEqual(w.NEW_AUTH,'106c9d5c874b79a2400ca11b17c08708c285cfcdd8147c226af10d81a9c73e52')
        self.assertEqual(r.PHASE.name,'v6_e127_pt_label_generation_20261027_r1')
        parent_runner = Path(r.__file__).with_name('run_identifier_generation_e124.py').read_bytes()
        self.assertEqual(r.transport.sha(parent_runner),'f1d941f2333ca743d46254719a204a2ae7ca2606f0b06a12ce6eb43300fe534a')

    def test_actual_authority_reply_has_exact_unicode_codepoints(self):
        raw = (r.ROOT/r.AUTH).read_bytes()
        authority = json.loads(raw.decode('utf-8'))
        expected = '\u6279\u51c6 E127 \u65b0\u6574\u5305'
        self.assertEqual(authority['user_reply'],expected)
        self.assertEqual([ord(char) for char in authority['user_reply']],[ord(char) for char in expected])
        self.assertNotIn('\ufffd',raw.decode('utf-8'))
        self.assertEqual(r.transport.sha(raw),r.AUTH_SHA256)

    def test_source_load_failure_preserves_first_call_clock_not_exception_values(self):
        plan = r.prepare()
        payload = plan['payload'].decode('ascii').replace('for row in p["sources"]:',
            'raise ValueError("PRIVATE_EXCEPTION_MUST_NOT_LEAK")\n for row in p["sources"]:',1)
        value,config,executed = self.load_inert(payload)
        self.assertEqual(value['status'],'STOPPED_FIRST_FAILURE')
        self.assertEqual(value['clock']['start_monotonic'],1234.0)
        self.assertEqual(value['clock']['deadline_monotonic'],51634.0)
        self.assertNotIn('PRIVATE_EXCEPTION_MUST_NOT_LEAK',json.dumps(value))
        self.assertIsNone(config)
        self.assertIsNone(executed)


class WorkerTests(unittest.TestCase):
    def test_local_context_none_no_permission_and_single_invocation_guard(self):
        self.assertIsNone(w.CONFIG)
        with mock.patch.object(w,'_EXECUTED',False),mock.patch.object(w,'capture_runtime') as capture:
            value = w.execute({})
            self.assertEqual(value['status'],'STOPPED_FIRST_FAILURE')
            self.assertFalse(value['runtime_values_disclosed'])
            capture.assert_not_called()
            with self.assertRaisesRegex(ValueError,'ONE_E127_WORKER_INVOCATION_NO_RETRY'):
                w.execute({})

    def test_private_capture_exact_cohort_profile_only_metadata_leaves_ram(self):
        values = dict(PATH='/bin:/usr/bin',LD_LIBRARY_PATH='/vendor/lib',
            LM_LICENSE_FILE='1717@private-env-host',MGLS_LICENSE_FILE='1717@private-env-host')
        profile = w.profile.snapshot(values,False)
        source = Path(w.profile.__file__).read_bytes()
        package = dict(runtime_profile_source=base64.b64encode(source).decode('ascii'),
            runtime_profile_source_sha256=w.sha(source),source_sha256={'prospective_runtime_profile_e112':w.sha(source)},
            inputs={'e112':base64.b64encode(json.dumps(dict(runtime_profile=profile)).encode('ascii')).decode('ascii')})
        raw = json.dumps(dict(nonce=w.NONCE,values=values,profile=profile)).encode('ascii')
        with mock.patch.object(w.direct.base,'supervise',return_value=dict(output=raw,cleaned=True,
                returncode=0,launch_attempted=True,failure=None)) as supervise, \
                mock.patch.object(w.controller,'PACKAGE_END',51634.0), \
                mock.patch.object(w.time,'monotonic',return_value=1234.0):
            captured,metadata = w.capture_runtime(package,mock.Mock())
        self.assertEqual(captured,values)
        self.assertNotIn('private-env-host',json.dumps(metadata))
        self.assertEqual(metadata['sha256'],w.sha(raw))
        self.assertEqual(supervise.call_args.args[2],1264.0)

    def test_fixed_selftests_three_and_first_failure_no_retry(self):
        ctx = dict(end=51634.0,root=r.bundle.ROOT,sample=mock.Mock(),persist=mock.Mock())
        observations = [dict(output=b'DIRECT_SYNTHETIC_OK\n',cleaned=True,returncode=0,failure=None,
                            launch_attempted=True,readiness=None),
                        dict(output=b'',cleaned=True,returncode=-9,failure='CASE_TIMEOUT',
                            launch_attempted=True,readiness=None),
                        dict(output=b'DIRECT_SETSID_READY 123\n',cleaned=True,returncode=-9,failure='CASE_TIMEOUT',
                            launch_attempted=True,readiness={'pid':123})]
        domain = mock.Mock()
        with mock.patch.object(w.direct.base,'supervise',side_effect=observations) as supervise, \
                mock.patch.object(w.time,'monotonic',return_value=1234.0):
            cases = w.run_selftests(ctx,domain)
        self.assertEqual([v['case'] for v in cases],['success','timeout','setsid_child'])
        self.assertEqual([call.args[2] for call in supervise.call_args_list],[1249.0,1244.5,1247.0])
        self.assertTrue(all(call.args[3] is domain for call in supervise.call_args_list))
        self.assertTrue(all(call.args[1] == r.bundle.ROOT+'/journal' for call in supervise.call_args_list))

    def test_bootstrap_failure_metadata_precedes_validation_without_private_output(self):
        source = Path(w.profile.__file__).read_bytes()
        package = dict(runtime_profile_source=base64.b64encode(source).decode('ascii'),
            runtime_profile_source_sha256=w.sha(source),source_sha256={'prospective_runtime_profile_e112':w.sha(source)})
        evidence = {}
        private = b'private runtime values must remain in RAM'
        with mock.patch.object(w.direct.base,'supervise',return_value=dict(output=private,cleaned=True,
                returncode=1,launch_attempted=True,failure=None)):
            with self.assertRaisesRegex(ValueError,'BOOTSTRAP_FAILED'):
                w.capture_runtime(package,mock.Mock(),evidence)
        self.assertEqual(evidence['sha256'],w.sha(private))
        self.assertEqual(evidence['bytes'],len(private))
        self.assertEqual(evidence['returncode'],1)
        self.assertFalse(evidence['values_disclosed'])
        self.assertNotIn('private runtime',json.dumps(evidence))

    def test_failed_selftest_persists_observation_before_output_and_stops(self):
        ctx = dict(end=51634.0,root=r.bundle.ROOT,sample=mock.Mock(),persist=mock.Mock())
        with mock.patch.object(w.direct.base,'supervise',return_value=dict(output=b'failed',cleaned=True,
                returncode=1,failure=None,launch_attempted=True,readiness=None)) as supervise, \
                mock.patch.object(w.time,'monotonic',return_value=1234.0):
            with self.assertRaisesRegex(ValueError,'ACTUAL_SELFTEST_FAILED'):
                w.run_selftests(ctx,mock.Mock())
        self.assertEqual(supervise.call_count,1)
        self.assertEqual([call.args[0] for call in ctx['persist'].call_args_list],
                         ['success_intent.json','success_observation.json','success_output.log'])


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.phase = self.root/'phase'
        self.review = self.root/'review.json'
        self.plan = {k:'a'*64 for k in r.REVIEW_KEYS}
        self.plan.update(payload=b'offline',source_sha256={},origin_source_sha256={},input_sha256={})
        self.review.write_text(json.dumps(dict(status='PASS',reviewed={k:self.plan[k] for k in r.REVIEW_KEYS})))
        self.helper = mock.Mock()
        self.helper.verify_cached_host.return_value = 'cached-A'
        self.helper.transport.return_value = dict(stdout=json.dumps(result()).encode('ascii'),stderr=b'',
            exit_code=0,timeout=False,overflow=False,write_failed=False,threads_incomplete=False)

    def execute(self):
        with mock.patch.object(r,'prepare',return_value=self.plan),mock.patch.object(r,'PHASE',self.phase), \
                mock.patch.object(r.transport,'load_transport',return_value=self.helper), \
                mock.patch.object(r.transport,'execute_phase',side_effect=AssertionError('OLD GRANT FORBIDDEN')):
            return r.execute(self.review,self.plan['payload_sha256'])

    def test_fresh_exact_review_required_before_transport_loading(self):
        self.review.write_text('{"status":"FAIL"}')
        with mock.patch.object(r,'prepare',return_value=self.plan),mock.patch.object(r.transport,'load_transport') as load:
            with self.assertRaisesRegex(ValueError,'FRESH_INDEPENDENT_EXACT_REVIEW'):
                r.execute(self.review,self.plan['payload_sha256'])
        load.assert_not_called()

    def test_create_once_consumed_intent_before_session_fresh_budget_no_reconnect(self):
        observed = self.helper.transport.return_value
        def transport(*args):
            self.assertTrue((self.phase/'start.json').is_file())
            self.assertGreater(self.helper.TIMEOUT,0)
            self.assertLessEqual(self.helper.TIMEOUT,50400)
            return observed
        self.helper.transport.side_effect = transport
        self.assertEqual(self.execute()['status'],'FIXED_78_TASKS_COLLECTED')
        with self.assertRaises(FileExistsError):
            self.execute()
        self.assertEqual(self.helper.transport.call_count,1)
        intent = json.loads((self.phase/'start.json').read_bytes())
        self.assertEqual(intent['sessions_max'],1)
        self.assertEqual(intent['automatic_retries'],0)
        self.assertFalse(intent['cohort_snapshot_is_clock'])
        self.assertTrue(intent['first_new_package_call_consumed'])
        self.assertEqual(json.loads((self.phase/'package_clock.json').read_bytes()),clock())

    def test_raw_receipts_persist_before_invalid_response_failure(self):
        self.helper.transport.return_value['stdout'] = b'invalid JSON'
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual((self.phase/'stdout.json').read_bytes(),b'invalid JSON')
        self.assertTrue((self.phase/'stderr.log').is_file())
        self.assertTrue((self.phase/'transport.json').is_file())
        self.assertEqual(self.helper.transport.call_count,1)

    def test_metadata_only_and_clock_authority_root_scope(self):
        self.assertEqual(r.validate_response(json.dumps(result()).encode('ascii'))['clock'],clock())
        for field,bad in (('authorization_sha256','0'*64),('root','/old/root'),('boot_id',123),
                          ('cohort_snapshot_is_clock',True),('deadline_monotonic',2382888.679409259)):
            value = result()
            value['clock'][field] = bad
            with self.subTest(field=field),self.assertRaises(ValueError):
                r.validate_response(json.dumps(value).encode('ascii'))
        value = result()
        value['bootstrap'] = {'values':{'PATH':'secret'}}
        with self.assertRaisesRegex(ValueError,'BOOTSTRAP_METADATA_ONLY'):
            r.validate_response(json.dumps(value).encode('ascii'))


if __name__ == '__main__':
    unittest.main()
