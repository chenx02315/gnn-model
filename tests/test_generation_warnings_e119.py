"""Offline fixtures/mocks only: this suite cannot contact A or launch tools."""
import ast
import base64
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import probe_generation_warnings_e119 as p
from scripts import run_generation_warnings_e119 as c
from tests.test_preparation_probe_e112 import StablePosixFakeIO


def response():
    rows = [dict(path=path, bytes=4, sha256=c.control.sha(b'log\n'),
                 body_base64=base64.b64encode(b'log\n').decode('ascii'), whole_file_hashed=True) for path in p.PATHS]
    return dict(schema=p.SCHEMA, hostname='bupt-vncs2', uid=1047, boot_id=p.BOOT,
                remote_start_monotonic=2332500.0, remote_end_monotonic=2332501.0,
                original_deadline_monotonic=p.END, clock_must_not_be_reset=True,
                reports=rows, capture_complete=True, error=None, body_bytes_hashed=8,
                sampled_peak_rss_swap_bytes=1234, explicit_filesystem_writes=0, child_launches=0,
                environment_reads=0, atpg_launches=0, training_runs=0, execution_ready=False,
                training_release=False, warnings_qualified=False, sampling_is_hard_memory_guarantee=False)


class ResponseTests(unittest.TestCase):
    def encode(self, value):
        return json.dumps(value).encode('ascii')

    def test_complete_response_full_hash_no_release(self):
        value = response()
        self.assertEqual(c.validate_response(self.encode(value)), value)

    def test_identity_clock_and_scope_are_exact(self):
        for key, bad in (('hostname', 'other'), ('uid', True), ('boot_id', 'x'*36),
                         ('original_deadline_monotonic', p.END+1), ('clock_must_not_be_reset', False),
                         ('remote_end_monotonic', p.END), ('remote_end_monotonic', 2332530.0),
                         ('remote_start_monotonic', float('nan')), ('remote_start_monotonic', 1)):
            value = response()
            value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                c.validate_response(self.encode(value))
        for rows in ([response()['reports'][1]], response()['reports'][::-1],
                     response()['reports']+[response()['reports'][0]], [dict(response()['reports'][0], path='/private')]):
            value = response()
            value['reports'] = rows
            with self.assertRaises(ValueError):
                c.validate_response(self.encode(value))

    def test_body_prefix_mutation_missing_and_unknown_fields_rejected(self):
        for field, bad in (('body_base64', 'eA=='), ('sha256', '0'*64), ('bytes', p.MAX_FILE+1),
                           ('bytes', True), ('whole_file_hashed', False), ('extra', 'x')):
            value = response()
            value['reports'][0][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                c.validate_response(self.encode(value))

    def test_no_write_launch_env_or_warning_qualification(self):
        for field in ('explicit_filesystem_writes', 'child_launches', 'environment_reads', 'atpg_launches',
                      'training_runs', 'execution_ready', 'training_release', 'warnings_qualified',
                      'sampling_is_hard_memory_guarantee'):
            value = response()
            value[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                c.validate_response(self.encode(value))

    def test_partial_first_failure_retained_and_duplicate_json_forbidden(self):
        value = response()
        value.update(reports=value['reports'][:1], capture_complete=False,
                     body_bytes_hashed=4, error=dict(type='ValueError', code='FIRST_FAILURE'))
        self.assertEqual(len(c.validate_response(self.encode(value))['reports']), 1)
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
            c.validate_response(b'{"schema":1,"schema":2}')
        with self.assertRaisesRegex(ValueError, 'RESPONSE_BOUND'):
            c.validate_response(b'x'*(c.CAP+1))


class ReadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'tree'
        self.root.mkdir()
        self.path = self.root/'driver.log'
        self.path.write_bytes(b'a'*65536+b'last')
        self.fake = StablePosixFakeIO(self.root)
        self.budget = p.Budget(SimpleNamespace(peak=0, sample=mock.Mock(return_value={})), 2332500.0)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(p, 'PATHS', ('/tree/driver.log',)).start()
        mock.patch.object(p.time, 'monotonic', return_value=2332501.0).start()
        mock.patch.object(p.io.sys, 'platform', 'linux').start()

    def test_full_body_not_prefix_and_domain_sampling(self):
        raw = self.path.read_bytes()
        with self.fake.installed():
            row = p.read_report('/tree/driver.log', self.budget)
        self.assertEqual(base64.b64decode(row['body_base64']), raw)
        self.assertEqual(row['sha256'], c.control.sha(raw))
        self.assertEqual(self.budget.bytes, len(raw))
        self.assertGreaterEqual(self.budget.domain.sample.call_count, 4)

    def test_missing_symlink_hardlink_and_size_bounds(self):
        with self.assertRaisesRegex(ValueError, 'FIXED_REPORT_PATH'):
            p.read_report('/tree/other', self.budget)
        self.fake.links.add(self.path)
        with self.fake.installed(), self.assertRaises((OSError, ValueError)):
            p.read_report('/tree/driver.log', self.budget)
        self.fake.links.clear()
        os.link(str(self.path), str(self.root/'alias'))
        with self.fake.installed(), self.assertRaisesRegex(ValueError, 'SINGLE_LINK'):
            p.read_report('/tree/driver.log', self.budget)

    def test_short_read_mutation_and_oversized_before_read(self):
        with self.fake.installed(), mock.patch.object(p.os, 'read', return_value=b''):
            with self.assertRaisesRegex(ValueError, 'SHORT_READ'):
                p.read_report('/tree/driver.log', self.budget)
        original = self.fake.read
        def mutate(fd, n):
            raw = original(fd, n)
            self.path.write_bytes(b'changed')
            return raw
        with self.fake.installed(), mock.patch.object(p.os, 'read', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'SHORT_READ|CHANGED'):
                p.read_report('/tree/driver.log', self.budget)
        self.path.write_bytes(b'x'*(p.MAX_FILE+1))
        self.fake.body_reads = 0
        with self.fake.installed(), self.assertRaisesRegex(ValueError, 'BOUNDED_SINGLE_LINK'):
            p.read_report('/tree/driver.log', self.budget)
        self.assertEqual(self.fake.body_reads, 0)

    def test_original_deadline_and_memory_stop_before_open(self):
        with mock.patch.object(p.time, 'monotonic', return_value=p.END), mock.patch.object(p.io, '_directory') as opened:
            with self.assertRaisesRegex(ValueError, 'DEADLINE'):
                p.read_report('/tree/driver.log', self.budget)
            opened.assert_not_called()
        self.budget.domain.peak = 536870913
        with self.assertRaisesRegex(ValueError, 'MEMORY_STOP'):
            self.budget.tick()


class CollectorTests(unittest.TestCase):
    def collect(self, reader=None, boot=p.BOOT, now=2332500.0):
        domain = SimpleNamespace(peak=0, sample=mock.Mock(return_value={}))
        with mock.patch.object(p.sys, 'platform', 'linux'), mock.patch.object(p.platform, 'node', return_value='bupt-vncs2'), \
                mock.patch.object(p.os, 'getuid', return_value=1047, create=True), \
                mock.patch.object(p.time, 'monotonic', return_value=now), \
                mock.patch.object(p.direct.base, '_small', return_value=boot.encode('ascii')), \
                mock.patch.object(p.direct, 'Descendants', return_value=domain), \
                mock.patch.object(p, 'read_report', side_effect=reader) as read:
            result = p.collect(now)
        return result, read

    def test_first_failure_stops_without_second_report_or_retry(self):
        value, read = self.collect(reader=ValueError('FIRST'))
        self.assertFalse(value['capture_complete'])
        self.assertEqual(read.call_count, 1)
        self.assertEqual(value['error']['code'], 'FIRST')

    def test_boot_and_original_expiry_gate_report_access(self):
        for boot, now in (('x'*36, 2332500.0), (p.BOOT, p.END)):
            value, read = self.collect(boot=boot, now=now)
            self.assertFalse(value['capture_complete'])
            read.assert_not_called()


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.phase = self.root/'phase'
        self.review = self.root/'review.json'
        self.plan = dict(payload=b'offline', payload_sha256='a'*64, controller_sha256='b'*64,
                         authorization_sha256=c.AUTH_SHA, source_sha256={'probe': 'c'*64},
                         prior_response_sha256=c.PRIOR_SHA, original_clock_sha256='d'*64)
        self.review.write_text(json.dumps(dict(status='PASS', reviewed={k:self.plan[k] for k in c.REVIEW_KEYS})))
        self.helper = mock.Mock()
        self.helper.verify_cached_host.return_value = 'cached-A'
        self.helper.command.return_value = ['mock-only']
        self.helper.transport.return_value = dict(stdout=json.dumps(response()).encode('ascii'), stderr=b'',
            exit_code=0, timeout=False, overflow=False, write_failed=False, threads_incomplete=False)

    def execute(self):
        with mock.patch.object(c, 'prepare', return_value=self.plan), mock.patch.object(c, 'PHASE', self.phase), \
                mock.patch.object(c.control, 'load_transport', return_value=self.helper), \
                mock.patch.object(c.control, 'execute_phase', side_effect=AssertionError('OLD GRANT FORBIDDEN')):
            return c.execute(self.review, self.plan['payload_sha256'])

    def test_prepare_real_local_pins_offline_and_python36_payload(self):
        with mock.patch.object(c.control, 'load_transport', side_effect=AssertionError('NETWORK FORBIDDEN')):
            plan = c.prepare()
        self.assertEqual(len(plan['source_sha256']), 15)
        self.assertEqual(plan['authorization_sha256'], c.AUTH_SHA)
        self.assertEqual(plan['prior_response_sha256'], c.PRIOR_SHA)
        self.assertEqual(plan['payload_sha256'], c.control.sha(plan['payload']))
        ast.parse(plan['payload'].decode('ascii'), feature_version=(3, 6))
        for module in (p, c):
            ast.parse(Path(module.__file__).read_text(), feature_version=(3, 6))

    def test_review_failure_before_transport_loading(self):
        self.review.write_text('{"status":"FAIL"}')
        with mock.patch.object(c, 'prepare', return_value=self.plan), mock.patch.object(c.control, 'load_transport') as load:
            with self.assertRaisesRegex(ValueError, 'INDEPENDENT_EXACT_REVIEW'):
                c.execute(self.review, self.plan['payload_sha256'])
            load.assert_not_called()

    def test_changed_actual_authorization_blocks_offline_prepare(self):
        with mock.patch.object(c, 'ROOT', self.root):
            auth = self.root/c.AUTH
            auth.parent.mkdir(parents=True)
            auth.write_bytes(b'not actual authorization')
            with self.assertRaisesRegex(ValueError, 'ACTUAL_AUTHORIZATION_CHANGED'):
                c.prepare()

    def test_pinned_prior_evidence_and_original_clock_required(self):
        prior = self.root/'prior'
        prior.mkdir()
        (prior/'stdout.json').write_bytes(b'changed')
        with mock.patch.object(c, 'PRIOR', prior):
            with self.assertRaisesRegex(ValueError, 'ORIGINAL_PREPARATION_RESPONSE_CHANGED'):
                c._prior_proof()

    def test_intent_before_transport_create_once_and_no_old_grant(self):
        observed = self.helper.transport.return_value
        def transport(*args):
            self.assertTrue((self.phase/'start.json').is_file())
            return observed
        self.helper.transport.side_effect = transport
        result = self.execute()
        self.assertEqual(result['report_count'], 2)
        self.assertFalse(result['warnings_qualified'])
        intent = json.loads((self.phase/'start.json').read_bytes())
        self.assertEqual(intent['original_deadline_monotonic'], p.END)
        self.assertTrue(intent['clock_must_not_be_reset'])
        self.assertEqual(intent['additional_historical_reports_max'], 2)
        self.helper.verify_cached_host.assert_called_once_with('A')
        with self.assertRaises(FileExistsError):
            self.execute()
        self.assertEqual(self.helper.transport.call_count, 1)

    def test_raw_receipts_saved_before_validation_failure(self):
        self.helper.transport.return_value['stdout'] = b'invalid JSON'
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual((self.phase/'stdout.json').read_bytes(), b'invalid JSON')
        self.assertTrue((self.phase/'stderr.log').is_file())
        self.assertTrue((self.phase/'transport.json').is_file())
        self.assertEqual(self.helper.transport.call_count, 1)

    def test_transport_failure_and_exception_retain_consumed_attempt(self):
        self.helper.transport.side_effect = RuntimeError('mock transport')
        with self.assertRaises(RuntimeError):
            self.execute()
        self.assertTrue((self.phase/'start.json').is_file())
        self.assertTrue((self.phase/'transport.json').is_file())
        self.assertEqual(self.helper.transport.call_count, 1)


if __name__ == '__main__':
    unittest.main()
