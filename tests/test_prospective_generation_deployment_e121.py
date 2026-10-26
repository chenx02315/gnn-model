"""Deployment assembly with mocks only; never launches a tool or network session."""
import ast
import base64
from contextlib import redirect_stdout
import io
import json
import shlex
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import worker_prospective_generation_e121 as w
from scripts import run_prospective_generation_e121 as r


def b64(raw):
    return base64.b64encode(raw).decode('ascii')


class WorkerTests(unittest.TestCase):
    def package(self):
        source = Path(w.profile.__file__).read_bytes()
        values = dict(PATH='/bin:/usr/bin', LD_LIBRARY_PATH='/vendor/lib',
                      LM_LICENSE_FILE='1717@private-host', MGLS_LICENSE_FILE='1717@private-host')
        metadata = w.profile.snapshot(values, False)
        package = dict(runtime_profile_source=b64(source), runtime_profile_source_sha256=w.sha(source),
            source_sha256={'prospective_runtime_profile_e112':w.sha(source)},
            inputs={k:b64(b'fixture') for k in ('authority','e85','e88','e93','common_tcl','incremental_tcl','diagnostic_policy')},
            review_gates=dict(implementation_review_passed_claim=True, independent_review_passed_claim=True))
        package['inputs']['e112'] = b64(json.dumps(dict(runtime_profile=metadata)).encode('ascii'))
        return package, values, metadata

    def test_private_bootstrap_values_in_ram_only_exact_profile(self):
        package, values, metadata = self.package()
        output = json.dumps(dict(nonce=w.NONCE, values=values, profile=metadata)).encode('ascii')
        domain = mock.Mock()
        with mock.patch.object(w.direct.base, 'supervise', return_value=dict(output=output, cleaned=True,
                returncode=0, launch_attempted=True, failure=None)) as supervise, \
                mock.patch.object(w.time, 'monotonic', return_value=2332500.0):
            actual, receipt = w.capture_runtime(package, domain)
        self.assertEqual(actual, values)
        self.assertEqual(receipt['sha256'], w.sha(output))
        self.assertNotIn('private-host', json.dumps(receipt))
        args = supervise.call_args.args
        self.assertEqual(args[0][:2], ['/bin/bash', '-lc'])
        self.assertIn('module load mentor/tessent2021', args[0][2])
        self.assertIn('/usr/bin/python3 -I -S -B -c', args[0][2])
        self.assertEqual(args[1], '/')
        self.assertEqual(args[2], 2332530.0)
        self.assertIs(args[3], domain)
        child = shlex.split(args[0][2])[-1]
        compile(child, '<private-profile-child>', 'exec')
        ast.parse(child, feature_version=(3, 6))

    def test_bad_private_output_sanitized_but_digest_retained(self):
        package, _, _ = self.package()
        output = b'private-host invalid'
        evidence = {}
        with mock.patch.object(w.direct.base, 'supervise', return_value=dict(output=output, cleaned=True,
                returncode=0, launch_attempted=True, failure=None)):
            with self.assertRaisesRegex(ValueError, '^BOOTSTRAP_PRIVATE_VALIDATION_FAILED$'):
                w.capture_runtime(package, mock.Mock(), evidence)
        self.assertEqual(evidence['sha256'], w.sha(output))
        self.assertNotIn('private-host', json.dumps(evidence))

    def test_three_selftests_fixed_codes_readiness_deadline_and_evidence(self):
        saved = {}
        ctx = dict(end=w.controller.PACKAGE_END, root=w.controller.ROOT, sample=mock.Mock(),
                   persist=lambda name, raw:saved.setdefault(name, raw))
        outputs = [dict(output=b'DIRECT_SYNTHETIC_OK\n', returncode=0, failure=None, cleaned=True,
                        launch_attempted=True, readiness=None),
                   dict(output=b'', returncode=-9, failure='CASE_TIMEOUT', cleaned=True,
                        launch_attempted=True, readiness=None),
                   dict(output=b'DIRECT_SETSID_READY 123\n', returncode=-9, failure='CASE_TIMEOUT', cleaned=True,
                        launch_attempted=True, readiness=dict(pid=123))]
        domain = mock.Mock()
        with mock.patch.object(w.direct.base, 'supervise', side_effect=outputs) as supervise, \
                mock.patch.object(w.time, 'monotonic', return_value=2332500.0):
            receipts = w.run_selftests(ctx, domain)
        self.assertEqual([v['case'] for v in receipts], ['success','timeout','setsid_child'])
        self.assertTrue(all(v['passed'] and v['actual_linux_process'] for v in receipts))
        self.assertEqual(len(saved), 12)
        self.assertEqual([call.args[2] for call in supervise.call_args_list], [2332515.0,2332510.5,2332513.0])
        for call in supervise.call_args_list:
            self.assertIs(call.args[3], domain)
            self.assertEqual(call.args[1], w.controller.ROOT+'/journal')
            self.assertEqual(call.args[0][:4], ['/usr/bin/python3','-I','-S','-B'])
        self.assertIs(supervise.call_args_list[-1].kwargs['ready_check'], w.direct.base._setsid_readiness)

    def test_first_failed_selftest_stops_after_observation_no_retry(self):
        persisted = mock.Mock()
        ctx = dict(end=w.controller.PACKAGE_END, root=w.controller.ROOT, sample=mock.Mock(), persist=persisted)
        with mock.patch.object(w.direct.base, 'supervise', return_value=dict(output=b'bad', returncode=1,
                failure=None, cleaned=True, launch_attempted=True, readiness=None)) as supervise, \
                mock.patch.object(w.time, 'monotonic', return_value=2332500.0):
            with self.assertRaisesRegex(ValueError, 'ACTUAL_SELFTEST_FAILED'):
                w.run_selftests(ctx, mock.Mock())
        self.assertEqual(supervise.call_count, 1)
        self.assertEqual([call.args[0] for call in persisted.call_args_list],
                         ['success_intent.json','success_observation.json','success_output.log'])

    def test_selftest_log_failure_keeps_metadata(self):
        saved = {}
        def persist(name, raw):
            if name.endswith('_output.log'):
                raise OSError('LOG_WRITE_FAILED')
            saved[name] = raw
        ctx = dict(end=w.controller.PACKAGE_END, root=w.controller.ROOT,
                   sample=mock.Mock(), persist=persist)
        with mock.patch.object(w.direct.base, 'supervise', return_value=dict(
                output=b'DIRECT_SYNTHETIC_OK\n', returncode=0, failure=None,
                cleaned=True, launch_attempted=True, readiness=None)) as supervise:
            with self.assertRaises(OSError):
                w.run_selftests(ctx, mock.Mock())
        self.assertEqual(supervise.call_count, 1)
        observation = json.loads(saved['success_observation.json'])
        self.assertTrue(observation['cleaned'])
        self.assertEqual(observation['output_sha256'], w.sha(b'DIRECT_SYNTHETIC_OK\n'))
        self.assertFalse(observation['output_publication_ack'])

    def test_execute_lazy_callbacks_use_actual_maker_and_e120_gate(self):
        package, values, _ = self.package()
        diagnostic_gate = mock.Mock()
        fake = SimpleNamespace(maker=object(), domain=object(), run=mock.Mock(return_value=dict(status='FIXED_78_TASKS_COLLECTED')))
        artifact = mock.Mock()
        with mock.patch.object(w, 'host_gate'), \
                mock.patch.object(w.artifacts.diagnostics, 'build_gate', return_value=diagnostic_gate), \
                mock.patch.object(w.direct, 'Descendants'), \
                mock.patch.object(w, 'capture_runtime', return_value=(values, {})), \
                mock.patch.object(w.controller, 'Controller', return_value=fake) as factory, \
                mock.patch.object(w.artifacts, 'Artifacts', return_value=artifact) as artifacts:
            result = w.execute(package)
            args = factory.call_args.args
            args[11]('binding','freeze','envelope','observed','ctx')
            args[12]('binding','freeze','prep','parent','ctx')
        artifacts.assert_called_once_with(fake.maker, diagnostic_gate)
        artifact.read_artifacts.assert_called_once()
        artifact.run_translation.assert_called_once()
        fake.run.assert_called_once()
        self.assertFalse(result['runtime_values_disclosed'])
        self.assertNotIn('private-host', json.dumps(result))

    def test_host_failure_never_bootstraps_and_never_discloses_exception(self):
        with mock.patch.object(w, 'host_gate', side_effect=ValueError('SECRET')), \
                mock.patch.object(w, 'capture_runtime') as bootstrap:
            value = w.execute({})
        self.assertEqual(value['status'], 'STOPPED_FIRST_FAILURE')
        self.assertNotIn('SECRET', json.dumps(value))
        bootstrap.assert_not_called()


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.phase = self.root/'phase'
        self.review = self.root/'review.json'
        self.plan = {k:'a'*64 for k in r.REVIEW_KEYS}
        self.plan.update(payload=b'offline', source_sha256={}, input_sha256={})
        self.review.write_text(json.dumps(dict(status='PASS', reviewed={k:self.plan[k] for k in r.REVIEW_KEYS})))
        self.helper = mock.Mock()
        self.helper.verify_cached_host.return_value = 'cached-A'
        value = dict(schema=w.SCHEMA, status='FIXED_78_TASKS_COLLECTED', execution_ready=False, bootstrap=None,
            training_release=False, runtime_values_disclosed=False, summary=dict(counts=dict(tessent_debited=48,
            translation_debited=30,selftest_cases_reserved=3,selftest_cases_accepted=3,committed_tasks=78)))
        self.helper.transport.return_value = dict(stdout=json.dumps(value).encode('ascii'), stderr=b'',
            exit_code=0, timeout=False, overflow=False, write_failed=False, threads_incomplete=False)

    def execute(self):
        with mock.patch.object(r, 'prepare', return_value=self.plan), \
                mock.patch.object(r, 'remaining_seconds', return_value=600), mock.patch.object(r, 'PHASE', self.phase), \
                mock.patch.object(r.transport, 'load_transport', return_value=self.helper), \
                mock.patch.object(r.transport, 'execute_phase', side_effect=AssertionError('OLD GRANT')):
            return r.execute(self.review, self.plan['payload_sha256'])

    def test_missing_e120_failclosed_offline_and_sources_explicit_no_e105(self):
        with mock.patch.object(r.transport, 'load_transport', side_effect=AssertionError('NETWORK')):
            with mock.patch.object(Path, 'is_file', return_value=False):
                with self.assertRaisesRegex(ValueError, 'REVIEWED_E120_POLICY_AND_MODULE_REQUIRED'):
                    r.prepare()
        self.assertNotIn('prospective_acquisition_protocol_e105', r.PURE)
        self.assertEqual(len(r.PURE), len(set(r.PURE)))

    def test_exact_review_before_loading_transport(self):
        self.review.write_text('{"status":"FAIL"}')
        with mock.patch.object(r, 'prepare', return_value=self.plan), \
                mock.patch.object(r, 'remaining_seconds', return_value=600), \
                mock.patch.object(r.transport, 'load_transport') as load:
            with self.assertRaisesRegex(ValueError, 'INDEPENDENT_EXACT_REVIEW'):
                r.execute(self.review, self.plan['payload_sha256'])
        load.assert_not_called()

    def test_offline_payload_full_allowlist_topological_load_without_execute(self):
        actual_read = Path.read_bytes
        def read(path):
            if path.name == 'prospective_generation_diagnostics_e120.py':
                return b'def build_gate(raw):\n return lambda *args: {"passed": True}\n'
            if str(path).endswith(r.POLICY.replace('/', '\\')) or path.as_posix().endswith(r.POLICY):
                return b'{"synthetic_test_only":true}'
            return actual_read(path)
        with mock.patch.object(Path, 'is_file', return_value=True), \
                mock.patch.object(Path, 'read_bytes', read), \
                mock.patch.object(r.importlib, 'import_module', return_value=SimpleNamespace(build_gate=mock.Mock())):
            plan = r.prepare()
        ast.parse(plan['payload'].decode('ascii'), feature_version=(3, 6))
        self.assertEqual(len(plan['source_sha256']), len(r.PINS)+len(r.PURE)+1)
        # Source load is executed in an isolated module registry; worker entry is replaced.
        raw = plan['payload'].decode('ascii')
        marker = 'result=sys.modules["src.data.e121_worker"].execute(p["package"])'
        self.assertEqual(raw.count(marker), 1)
        raw = raw.replace(marker, 'result={"offline_source_load_only":True}')
        with mock.patch.dict(sys.modules), redirect_stdout(io.StringIO()):
            exec(compile(raw, '<offline-topology-only>', 'exec'), {})

    def test_original_deadline_precedes_transport_and_no_new_window(self):
        past = r.LOCAL_END+__import__('datetime').timedelta(seconds=1)
        with mock.patch.object(r.datetime, 'datetime') as clock:
            clock.now.return_value = past
            with self.assertRaisesRegex(ValueError, 'ORIGINAL_LOCAL_DEADLINE'):
                r.remaining_seconds()

    def test_create_once_intent_before_transport_original_remaining_timeout(self):
        observed = self.helper.transport.return_value
        def run(*args):
            self.assertTrue((self.phase/'start.json').is_file())
            self.assertEqual(self.helper.TIMEOUT, 600)
            return observed
        self.helper.transport.side_effect = run
        self.assertEqual(self.execute()['status'], 'FIXED_78_TASKS_COLLECTED')
        with self.assertRaises(FileExistsError):
            self.execute()
        self.assertEqual(self.helper.transport.call_count, 1)
        intent = json.loads((self.phase/'start.json').read_bytes())
        self.assertEqual(intent['original_local_deadline'], r.LOCAL_END.isoformat())

    def test_raw_outputs_and_receipt_survive_validation_failure(self):
        self.helper.transport.return_value['stdout'] = b'bad-json'
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual((self.phase/'stdout.json').read_bytes(), b'bad-json')
        self.assertTrue((self.phase/'stderr.log').is_file())
        self.assertTrue((self.phase/'transport.json').is_file())
        self.assertEqual(self.helper.transport.call_count, 1)

    def test_python36_sources_and_response_never_releases(self):
        for module in (w, r):
            ast.parse(Path(module.__file__).read_text(), feature_version=(3, 6))
        value = json.loads(self.helper.transport.return_value['stdout'])
        value['training_release'] = True
        with self.assertRaisesRegex(ValueError, 'RESPONSE_SCHEMA_OR_RELEASE'):
            r.validate_response(json.dumps(value).encode('ascii'))


if __name__ == '__main__':
    unittest.main()
