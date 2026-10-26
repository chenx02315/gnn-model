import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import run_preparation_e112 as module


def response():
    base = '/temp/jiangchuanc/multimode_ate_phase4_20260825_A/10_circuits/'
    from scripts import probe_preparation_e112 as probe
    e85 = json.loads((module.ROOT / module.INPUTS[0][1]).read_bytes())
    e88 = json.loads((module.ROOT / module.INPUTS[1][1]).read_bytes())
    frozen = [dict(path=r['root'], bytes=r['body_bytes'], sha256=r['tree_sha256']) for r in e85['tsdb_trees']]
    frozen.append(dict(path=probe.pins.LIBRARY, bytes=e85['library']['bytes'], sha256=probe.pins.LIBRARY_SHA256))
    for row in e88['roots']:
        common = base + row['circuit'] + '/03_fault_universe/common_' + row['circuit'] + '_m16_phase4_v2/'
        frozen.extend(dict(path=common+n, **pin) for n, pin in row['files'].items())
    return dict(schema='e112-readonly-preparation-v1', hostname='bupt-vncs2', uid=1047,
                execution_ready=False, training_release=False, explicit_filesystem_writes=0,
                atpg_launches=0, training_runs=0, capture_complete=True, error=None,
                remote_start_monotonic=100., remote_end_monotonic=101.,
                frozen_inputs=frozen, runtime_profile=probe.profile.snapshot({}, False),
                launcher=dict(path=probe.pins.LAUNCHER, bytes=e85['binary']['bytes'], sha256=probe.pins.LAUNCHER_SHA256),
                boot_id='00000000-0000-0000-0000-000000000001',
                reports=[dict(path=base+c+'/04_single_mode/H_'+c+'_H_full_phase4_v2/'+n)
                         for c in ('aes_core', 'spi')
                         for n in ('statistics.rpt', 'patterns.rpt', 'tester.stil')])


class Controller(unittest.TestCase):
    def test_prepare_offline_deterministic(self):
        with mock.patch.object(module.control, 'load_transport', side_effect=AssertionError('NETWORK')):
            first = module.prepare()
            second = module.prepare()
        self.assertEqual(first, second)
        self.assertLess(first['payload_bytes'], module.CAP)
        self.assertEqual(first['authorization_sha256'], module.AUTH_SHA)

    def test_good_response_and_partial(self):
        value = response()
        self.assertEqual(module.validate_response(module.control.encode(value)), value)
        value.update(capture_complete=False, reports=[], error=dict(code='BOUNDED_ERROR'))
        self.assertEqual(module.validate_response(module.control.encode(value)), value)

    def test_fail_closed_scope_clock_and_release(self):
        cases = [
            dict(hostname='B'), dict(uid=True), dict(atpg_launches=1),
            dict(execution_ready=True), dict(training_release=True),
            dict(remote_start_monotonic=True), dict(remote_end_monotonic=99.),
            dict(boot_id='bad'), dict(reports=[]), dict(capture_complete=1),
            dict(reports=[dict(path='/BLIND/secret')]),
            dict(frozen_inputs=[]), dict(runtime_profile={'normalized_values': {'SECRET': 'value'}}),
        ]
        for changes in cases:
            value = response()
            value.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                module.validate_response(module.control.encode(value))
        with self.assertRaises(ValueError):
            module.validate_response(b' ' * (module.CAP + 1))

    def test_mismatched_review_never_loads_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'review.json'
            path.write_text('{"status":"PASS","reviewed":{}}', encoding='utf-8')
            with mock.patch.object(module.control, 'load_transport', side_effect=AssertionError('NETWORK')):
                with self.assertRaisesRegex(ValueError, 'EXACT_REVIEW'):
                    module.execute(path, '0' * 64)

    def test_create_once_and_preserve_transport_evidence(self):
        plan = module.prepare()
        review = dict(status='PASS', reviewed={k: plan[k] for k in (
            'payload_sha256', 'controller_sha256', 'authorization_sha256', 'source_sha256')})
        transport = mock.Mock()
        transport.verify_cached_host.return_value = 'fixed-fingerprint'
        transport.command.return_value = ['fixed-A-command']
        result = dict(exit_code=0, timeout=False, overflow=False, write_failed=False,
                      threads_incomplete=False, remote_termination_verified=False,
                      stdout=module.control.encode(response()), stderr=b'')
        transport.transport.return_value = result
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            review_path = root / 'review.json'
            review_path.write_text(json.dumps(review), encoding='utf-8')
            with mock.patch.object(module, 'PHASE', root / 'phase'), mock.patch.object(
                    module.control, 'load_transport', return_value=transport), mock.patch('builtins.print'):
                module.execute(review_path, plan['payload_sha256'])
                with self.assertRaises(FileExistsError):
                    module.execute(review_path, plan['payload_sha256'])
                clock = json.loads((root/'phase/package_clock.json').read_text())
                self.assertEqual(clock['remote_deadline_monotonic'], 50500.)
                self.assertEqual((root/'phase/stdout.json').read_bytes(), result['stdout'])
                self.assertEqual(transport.transport.call_count, 1)

    def test_transport_failure_keeps_raw_and_does_not_retry(self):
        plan = module.prepare()
        review = dict(status='PASS', reviewed={k: plan[k] for k in (
            'payload_sha256', 'controller_sha256', 'authorization_sha256', 'source_sha256')})
        helper = mock.Mock()
        helper.verify_cached_host.return_value = 'fixed'
        helper.transport.return_value = dict(exit_code=1, timeout=True, overflow=False,
            write_failed=False, threads_incomplete=False, stdout=b'partial', stderr=b'error')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'review.json'
            path.write_text(json.dumps(review), encoding='utf-8')
            with mock.patch.object(module, 'PHASE', root/'phase'), mock.patch.object(
                    module.control, 'load_transport', return_value=helper):
                with self.assertRaisesRegex(ValueError, 'UNKNOWN_NO_RETRY'):
                    module.execute(path, plan['payload_sha256'])
            self.assertEqual((root/'phase/stdout.json').read_bytes(), b'partial')
            self.assertTrue((root/'phase/transport.json').is_file())
            self.assertFalse((root/'phase/package_clock.json').exists())
            intent = json.loads((root/'phase/package_clock_intent.json').read_text())
            self.assertTrue(intent['clock_must_not_be_reset'])
            self.assertTrue(intent['missing_remote_clock_blocks_further_remote_execution'])
            self.assertEqual(helper.transport.call_count, 1)


if __name__ == '__main__':
    unittest.main()
