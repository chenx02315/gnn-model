"""Virtual owned files and mocked transport only; never contact A or launch."""
import ast
import base64
import copy
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import read_identifier_failure_e125 as m
from scripts import acceptance_transport_e98 as control
from src.data import prospective_acceptance_materializer_v1 as io
from src.data import direct_tessent_acceptance_e104 as direct


class Files(object):
    def __init__(self):
        self.info, self.body, self.handles = {}, {}, {}
        self.next_fd, self.next_ino = 100, 10
        self.opened, self.read_hook = [], None
        for path in m.PATHS:
            parent = path.rsplit('/', 1)[0]
            self.add(parent, directory=True)
            self.add(path, raw=b'fixed-owned-fixture')

    def add(self, path, raw=b'', directory=False):
        self.info[path] = SimpleNamespace(st_dev=1, st_ino=self.next_ino,
            st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | 0o600,
            st_nlink=1, st_uid=1047, st_size=len(raw), st_mtime_ns=100, st_ctime_ns=100)
        self.body[path] = raw
        self.next_ino += 1

    def directory(self, path):
        if path not in self.info:
            raise FileNotFoundError()
        if not stat.S_ISDIR(self.info[path].st_mode):
            raise OSError('nofollow')
        return self.handle(path)

    def handle(self, path):
        fd = self.next_fd
        self.next_fd += 1
        self.handles[fd] = [path, 0]
        return fd

    def stat(self, name, dir_fd=None, follow_symlinks=False):
        path = self.handles[dir_fd][0] + '/' + name
        if path not in self.info:
            raise FileNotFoundError()
        return copy.copy(self.info[path])

    def fstat(self, fd):
        return copy.copy(self.info[self.handles[fd][0]])

    def open(self, name, flags, dir_fd=None):
        path = self.handles[dir_fd][0] + '/' + name
        if not stat.S_ISREG(self.info[path].st_mode):
            raise OSError('nofollow')
        self.opened.append(path)
        return self.handle(path)

    def read(self, fd, count):
        path, offset = self.handles[fd]
        raw = self.body[path][offset:offset + count]
        self.handles[fd][1] += len(raw)
        if self.read_hook:
            self.read_hook(path)
        return raw

    def close(self, fd):
        self.handles.pop(fd)


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.fs = Files()
        self.domain = mock.Mock(peak=123)
        self.domain.sample.return_value = {}
        self.clock = mock.Mock(return_value=m.START + 100)
        self.patchers = [
            mock.patch.object(io, '_directory', side_effect=self.fs.directory),
            mock.patch.object(m.os, 'stat', side_effect=self.fs.stat),
            mock.patch.object(m.os, 'fstat', side_effect=self.fs.fstat),
            mock.patch.object(m.os, 'open', side_effect=self.fs.open),
            mock.patch.object(m.os, 'read', side_effect=self.fs.read),
            mock.patch.object(m.os, 'close', side_effect=self.fs.close),
            mock.patch.object(m.os, 'getuid', return_value=1047, create=True),
            mock.patch.object(m.os, 'O_NOFOLLOW', 131072, create=True),
            mock.patch.object(m.os, 'O_NONBLOCK', 262144, create=True),
            mock.patch.object(m.sys, 'platform', 'linux'),
            mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'),
            mock.patch.object(m.time, 'monotonic', self.clock),
            mock.patch.object(direct, 'Descendants', return_value=self.domain),
            mock.patch.object(direct.base, '_small', return_value=m.BOOT.encode('ascii'))]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(lambda: self.assertEqual(self.fs.handles, {}))

    def test_exact_fixed_owned_scope_and_full_sha_base64_no_process_or_scan(self):
        with mock.patch('subprocess.Popen') as spawn, mock.patch.object(m.os, 'scandir') as scan:
            result = m.collect()
            spawn.assert_not_called()
            scan.assert_not_called()
        self.assertTrue(result['capture_complete'], result['error'])
        self.assertEqual(len(m.PATHS), 24)
        self.assertEqual([row['path'] for row in result['files']], list(m.PATHS))
        self.assertEqual(self.fs.opened, list(m.PATHS))
        self.assertEqual(result['additional_historical_reports'], 0)
        for row in result['files']:
            raw = base64.b64decode(row['body_base64'])
            self.assertEqual(row['sha256'], m.sha(raw))
        m.validate_response(m.canonical(result))

    def test_only_optional_tool_log_leaf_can_be_missing(self):
        del self.fs.info[m.TOOL_LOG]
        result = m.collect()
        self.assertTrue(result['capture_complete'])
        self.assertEqual(result['files'][-2], dict(path=m.TOOL_LOG, status='MISSING'))
        m.validate_response(m.canonical(result))

    def test_optional_parent_missing_is_a_failure_not_exists_fallback(self):
        del self.fs.info[m.TOOL_LOG.rsplit('/', 1)[0]]
        result = m.collect()
        self.assertFalse(result['capture_complete'])
        self.assertEqual(len(result['files']), 22)
        self.assertEqual(result['error']['type'], 'FileNotFoundError')

    def test_required_missing_stops_at_first_prefix_no_retry(self):
        del self.fs.info[m.PATHS[3]]
        result = m.collect()
        self.assertFalse(result['capture_complete'])
        self.assertEqual(len(result['files']), 3)
        self.assertEqual(self.fs.opened, list(m.PATHS[:3]))
        m.validate_response(m.canonical(result))

    def test_metadata_and_two_log_bounds_checked_before_body_open(self):
        for path, size in ((m.PATHS[0], 65537), (m.JOURNAL + 'task_000_stdout.log', m.MAX_LOG + 1)):
            self.fs.info[path].st_size = size
            result = m.collect()
            self.assertFalse(result['capture_complete'])
            self.assertEqual(result['error']['code'], 'READBACK_BODY_BOUND')
            self.assertNotIn(path, self.fs.opened)
            self.fs.info[path].st_size = len(self.fs.body[path])

    def test_symlink_hardlink_or_foreign_owner_fail_before_read(self):
        path = m.PATHS[0]
        for field, value in (('st_mode', stat.S_IFLNK), ('st_nlink', 2), ('st_uid', 999)):
            original = getattr(self.fs.info[path], field)
            setattr(self.fs.info[path], field, value)
            result = m.collect()
            self.assertFalse(result['capture_complete'])
            self.assertEqual(result['error']['code'], 'SINGLE_LINK_OWNED_REGULAR_REQUIRED')
            setattr(self.fs.info[path], field, original)
        self.assertEqual(self.fs.opened, [])

    def test_source_change_stops_without_publishing_bad_row(self):
        def mutate(path):
            self.fs.info[path].st_mtime_ns += 1
        self.fs.read_hook = mutate
        result = m.collect()
        self.assertFalse(result['capture_complete'])
        self.assertEqual(result['error']['code'], 'OWNED_FILE_CHANGED')
        self.assertEqual(result['files'], [])

    def test_total_stream_bound_and_cooperative_thirty_second_deadline(self):
        with mock.patch.object(m, 'MAX_TOTAL', 50):
            result = m.collect()
        self.assertFalse(result['capture_complete'])
        self.assertEqual(result['error']['code'], 'READBACK_BODY_BOUND')
        self.assertEqual(len(result['files']), 2)
        def expire(path):
            self.clock.return_value += 31
        self.fs.read_hook = expire
        result = m.collect()
        self.assertFalse(result['capture_complete'])
        self.assertEqual(result['error']['code'], 'READBACK_DEADLINE')
        self.assertEqual(result['files'], [])

    def test_empty_owned_log_is_valid_complete_evidence(self):
        path = m.JOURNAL + 'task_000_stdout.log'
        self.fs.body[path], self.fs.info[path].st_size = b'', 0
        result = m.collect()
        self.assertTrue(result['capture_complete'])
        row = next(row for row in result['files'] if row['path'] == path)
        self.assertEqual(row['body_base64'], '')
        self.assertEqual(row['sha256'], m.sha(b''))

    def test_original_boot_deadline_or_unexpected_children_prevent_all_reads(self):
        with mock.patch.object(direct.base, '_small', return_value=b'wrong-boot'):
            self.assertFalse(m.collect()['capture_complete'])
        self.clock.return_value = m.END
        self.assertFalse(m.collect()['capture_complete'])
        self.clock.return_value = m.START + 100
        self.domain.sample.return_value = {999: 'unexpected'}
        self.assertFalse(m.collect()['capture_complete'])
        self.assertEqual(self.fs.opened, [])

    def test_validator_refuses_other_path_body_tamper_or_fake_missing(self):
        result = m.collect()
        for mutate in (lambda v: v['files'][0].update(path='/not-owned'),
                       lambda v: v['files'][0].update(sha256='a' * 64),
                       lambda v: v['files'][0].update(status='MISSING')):
            value = copy.deepcopy(result)
            mutate(value)
            with self.assertRaises(ValueError):
                m.validate_response(m.canonical(value))

    def test_statistics_is_mandatory_bounded_and_no_other_pattern_bodies(self):
        self.assertEqual(m.PATHS[-1],m.STATISTICS)
        self.assertEqual(len(m.PATHS),24)
        self.assertIn('/runs/e116-aes_core/attempts/H_aes_core:HF:h1:H/statistics.rpt',m.STATISTICS)
        self.assertFalse(any(path.endswith(('.mtfi','.stil')) for path in m.PATHS))
        self.fs.info[m.STATISTICS].st_size = 65537
        result = m.collect()
        self.assertFalse(result['capture_complete'])
        self.assertEqual(len(result['files']),23)
        self.assertNotIn(m.STATISTICS,self.fs.opened)
        del self.fs.info[m.STATISTICS]
        result = m.collect()
        self.assertFalse(result['capture_complete'])
        self.assertEqual(result['error']['code'],'REQUIRED_OWNED_FILE_MISSING')

    def test_short_read_and_sampled_memory_stop_retains_prefix(self):
        self.fs.body[m.PATHS[0]] = b''
        result = m.collect()
        self.assertFalse(result['capture_complete'])
        self.assertEqual(result['error']['code'],'OWNED_FILE_SHORT_READ')
        self.assertEqual(result['files'],[])
        self.fs.opened.clear()
        self.domain.peak = 536870913
        result = m.collect()
        self.assertFalse(result['capture_complete'])
        self.assertEqual(result['error']['code'],'SAMPLED_MEMORY_STOP')
        self.assertEqual(self.fs.opened,[])


class ControllerTests(unittest.TestCase):
    def test_prepare_offline_actual_e124_proofs_and_exact_derived_statistics_path(self):
        with mock.patch.object(control,'load_transport',side_effect=AssertionError('NO NETWORK')):
            plan = m.prepare()
        self.assertEqual(plan['authorization_sha256'],m.AUTH_SHA)
        self.assertEqual(plan['prior_response_sha256'],m.PRIOR_SHA)
        self.assertEqual(plan['original_clock_sha256'],m.EXECUTION_CLOCK_SHA)
        self.assertEqual(plan['execution_review_sha256'],m.EXECUTION_REVIEW_SHA)
        self.assertEqual(plan['local_deadline_sha256'],m.EXECUTION_START_SHA)
        self.assertEqual(len(plan['source_sha256']),15)
        ast.parse(plan['payload'].decode('ascii'),feature_version=(3,6))
        self.assertEqual(m.START,2372217.531936861)
        self.assertEqual(m.END,2422617.531936861)

    def test_raw_transport_outputs_saved_before_validation_and_no_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            staging = Path(temp)
            plan = dict(payload=b'pass', payload_sha256=m.sha(b'pass'), controller_sha256='a' * 64,
                source_sha256={}, authorization_sha256=m.AUTH_SHA,
                prior_response_sha256=m.PRIOR_SHA, original_clock_sha256='b' * 64, execution_review_sha256='c' * 64,
                execution_source_sha256={}, local_deadline_sha256='d' * 64)
            reviewed = {key: plan[key] for key in m.REVIEW_KEYS}
            review_path = staging / 'review.json'
            review_path.write_bytes(m.canonical(dict(status='PASS', reviewed=reviewed)))
            helper = mock.Mock()
            helper.verify_cached_host.return_value = 'cached-A-fingerprint'
            helper.transport.return_value = dict(stdout=b'RAW_INVALID_RESPONSE', stderr=b'raw stderr',
                exit_code=0, timeout=False, overflow=False, write_failed=False, threads_incomplete=False)
            phase = staging / 'v6_e125_failure_readback_20261027_r1'
            def validate(raw):
                self.assertEqual((phase / 'stdout.json').read_bytes(), b'RAW_INVALID_RESPONSE')
                self.assertEqual((phase / 'stderr.log').read_bytes(), b'raw stderr')
                self.assertTrue((phase / 'transport.json').is_file())
                raise ValueError('INTENTIONAL_VALIDATE_REJECTION')
            with mock.patch.object(control, 'STAGING', staging), \
                    mock.patch.object(control, 'load_transport', return_value=helper), \
                    mock.patch.object(m, '_local_remaining', return_value=100), \
                    mock.patch.object(m, 'prepare', return_value=plan), \
                    mock.patch.object(m, 'validate_response', side_effect=validate):
                with self.assertRaisesRegex(ValueError, 'INTENTIONAL_VALIDATE_REJECTION'):
                    m.execute(str(review_path), plan['payload_sha256'])
                with self.assertRaises(FileExistsError):
                    m.execute(str(review_path), plan['payload_sha256'])
            self.assertEqual(helper.transport.call_count, 1)
            helper.verify_cached_host.assert_called_with('A')

    def test_sources_python36(self):
        root = Path(__file__).resolve().parents[1]
        for path in ('scripts/read_identifier_failure_e125.py', 'tests/test_identifier_failure_readback_e125.py'):
            ast.parse((root / path).read_text(), feature_version=(3, 6))
