"""Tiny tempfile fixtures and mocked hosts/processes only; no A access."""
import ast
import base64
import copy
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import probe_preparation_e112 as m
from src.data import prospective_runtime_profile_e112 as p
from tests.test_prospective_acquisition_tree_inputs_e85 import FakeAnchoredIO


class StablePosixFakeIO(FakeAnchoredIO):
    """Adapt Windows stat/fstat ctime disagreement in this POSIX IO fixture.

    Python's Windows named stat exposes birth time as ctime while CRT fstat can
    expose modification time. Linux production keeps its full ctime checks;
    only this fake supplies fstat's ctime from the same named real-stat API,
    retaining real inode/size/mtime/ctime mutation checks across observations.
    """
    def _posix_stat(self, info, path):
        if m.os.name != 'nt' or not hasattr(info, 'st_mtime_ns'):
            return info
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns')
        result = {key: getattr(info, key) for key in fields}
        result['st_ctime_ns'] = self.real_stat(path).st_ctime_ns
        return SimpleNamespace(**result)

    def fstat(self, fd):
        return self._posix_stat(super(StablePosixFakeIO, self).fstat(fd), self.handles[fd][0])


class RuntimeProfileTests(unittest.TestCase):
    def environment(self):
        return dict(PATH=':/bin/:/usr/bin::', LD_LIBRARY_PATH='/vendor/lib///:',
                    MGC_HOME='/vendor/root/', LM_LICENSE_FILE='1717@license.invalid',
                    MGC_SECRET='do-not-return-this-secret', UNRELATED='hidden-value')

    def test_metadata_only_normalization_no_values_or_mutation(self):
        env = self.environment()
        before = copy.deepcopy(env)
        result = p.snapshot(env)
        self.assertEqual(env, before)
        self.assertTrue(result['strict_compatible'])
        encoded = json.dumps(result)
        for value in env.values():
            self.assertNotIn(value, encoded)
        self.assertEqual(result['vendor_key_names'], ['MGC_SECRET'])
        self.assertEqual(result['normalization']['PATH']['empty_search_items_removed'], 3)
        self.assertNotEqual(result['raw_sha256'], result['normalized_sha256'])
        internal = p.snapshot(env, True)
        self.assertEqual(internal['normalized_values']['PATH'], '/bin:/usr/bin')
        self.assertEqual(internal['normalized_values']['LD_LIBRARY_PATH'], '/vendor/lib')
        self.assertNotIn('MGC_SECRET', internal['normalized_values'])

    def test_relative_dotdot_and_invalid_license_never_collapsed_or_disclosed(self):
        for key, value in (('PATH', '/bin:relative'), ('MGC_HOME', '/vendor/../root'),
                           ('LD_LIBRARY_PATH', '/lib/./x'), ('LM_LICENSE_FILE', '99999@host'),
                           ('MGC_ROOT', ''), ('PATH', '/bin\x00')):
            env = self.environment()
            env[key] = value
            result = p.snapshot(env)
            self.assertFalse(result['strict_compatible'])
            with self.assertRaisesRegex(ValueError, 'PROFILE_NOT_STRICT_COMPATIBLE'):
                p.snapshot(env, True)

    def test_missing_environment_is_unknown_not_compatible(self):
        result = p.snapshot({})
        self.assertFalse(result['strict_compatible'])
        self.assertFalse(result['environment_authenticated'])
        with self.assertRaises(ValueError):
            p.snapshot({'PATH': 'x' * 16385})


class EvidenceTests(unittest.TestCase):
    def test_stil_cross_chunk_markers_huge_line_and_samples_are_bounded(self):
        evidence = m.Evidence(report=True, stil=True)
        raw = b'a' * 800 + b'TesterCycle:12\n' + b'TesterCycle:34\n' * 30
        for offset in range(0, len(raw), 7):
            evidence.block(raw[offset:offset + 7])
        result = evidence.metadata()
        self.assertEqual(result['raw_marker_count'], 31)
        self.assertEqual(len(result['line_samples']), 16)
        self.assertTrue(result['line_samples'][0]['truncated'])
        self.assertEqual(len(base64.b64decode(result['line_samples'][0]['prefix_base64'])), 512)
        self.assertNotIn('body_base64', result)
        self.assertFalse(result['new_cycles_or_labels_derived'])

    def test_stil_prefix_and_long_unterminated_line_bounded(self):
        evidence = m.Evidence(report=True, stil=True)
        for _ in range(5):
            evidence.block(b'x' * 65536)
        evidence.block(b'TesterCycle:9')
        result = evidence.metadata()
        self.assertEqual(result['prefix_bytes'], 32768)
        self.assertEqual(len(result['line_samples']), 1)
        self.assertTrue(result['line_samples'][0]['truncated'])
        self.assertEqual(result['raw_marker_count'], 1)


class PhysicalFakeIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'tree'
        self.root.mkdir()
        self.domain = mock.Mock(peak=0)
        self.budget = m.Budget(self.domain, time.monotonic() + 30)

    def fake(self):
        return StablePosixFakeIO(self.root)

    def test_file_stream_sha_and_small_report_body(self):
        raw = b'DS 3\nDI 1\n'
        (self.root / 'statistics.rpt').write_bytes(raw)
        fake = self.fake()
        with fake.installed(), mock.patch.object(m.io.sys, 'platform', 'linux'):
            result = m._read_file('/tree/statistics.rpt', self.budget,
                                  dict(bytes=len(raw), sha256=m.pins.sha(raw)), report=True)
        self.assertEqual(base64.b64decode(result['body_base64']), raw)
        self.assertTrue(result['whole_file_hashed'])
        self.assertEqual(self.budget.bytes, len(raw))
        self.domain.sample.assert_called()

    def test_tree_digest_matches_existing_e85_dfs_not_global_sort(self):
        (self.root / 'a').mkdir()
        (self.root / 'a/z').write_bytes(b'z')
        (self.root / 'a.txt').write_bytes(b't')
        fake = self.fake()
        with fake.installed(), mock.patch.object(m.io.sys, 'platform', 'linux'):
            digest = m.io._tree('/tree', expected_bytes=2, expected_files=2, expected_directories=2)
            pin = dict(body_bytes=2, regular_files_hashed=2, directories=2, tree_sha256=digest)
            result = m._tree('/tree', pin, self.budget)
        self.assertEqual(result['sha256'], digest)
        self.assertEqual(result['bytes'], 2)
        self.assertEqual(result['directories'], 2)

    def test_symlink_and_pinned_size_refused_before_body_read(self):
        (self.root / 'data').write_bytes(b'x')
        fake = self.fake()
        with fake.installed(), mock.patch.object(m.io.sys, 'platform', 'linux'):
            with self.assertRaisesRegex(ValueError, 'PINNED_SIZE_MISMATCH'):
                m._read_file('/tree/data', self.budget, {'bytes': 2})
            self.assertEqual(fake.body_reads, 0)
            fake.links.add(self.root / 'data')
            with self.assertRaisesRegex(ValueError, 'SINGLE_LINK_REGULAR_REQUIRED'):
                m._read_file('/tree/data', self.budget)

    def test_source_mutation_detected(self):
        source = self.root / 'data'
        source.write_bytes(b'abc')
        fake = self.fake()
        original = fake.read
        def mutate(fd, count):
            raw = original(fd, count)
            source.write_bytes(b'changed')
            return raw
        with fake.installed(), mock.patch.object(m.io.sys, 'platform', 'linux'), \
                mock.patch.object(m.os, 'read', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'SOURCE_CHANGED'):
                m._read_file('/tree/data', self.budget)

    def test_deadline_and_global_bounds_before_body_open(self):
        (self.root / 'data').write_bytes(b'abc')
        fake = self.fake()
        self.budget.bytes = m.MAX_TOTAL - 1
        with fake.installed(), mock.patch.object(m.io.sys, 'platform', 'linux'):
            with self.assertRaisesRegex(ValueError, 'BODY_BYTE_BOUND'):
                m._read_file('/tree/data', self.budget)
            self.budget.end = 0
            with self.assertRaisesRegex(ValueError, 'COLLECTOR_DEADLINE'):
                m._read_file('/tree/data', self.budget)
            self.assertEqual(fake.body_reads, 0)

    def test_tree_rejects_actual_nul_filename_before_body_read(self):
        fake = self.fake()
        listing = mock.MagicMock()
        listing.__enter__.return_value = iter([SimpleNamespace(name='bad\x00name')])
        pin = dict(body_bytes=0, regular_files_hashed=0, directories=1, tree_sha256='a' * 64)
        with fake.installed(), mock.patch.object(m.io.sys, 'platform', 'linux'), \
                mock.patch.object(m.os, 'scandir', return_value=listing):
            with self.assertRaisesRegex(ValueError, 'PROTECTED_OR_INVALID_TREE_NAME'):
                m._tree('/tree', pin, self.budget)
            self.assertEqual(fake.body_reads, 0)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        manifests = self.root / 'data/manifests'
        self.e85 = (manifests / 'ranking_v6_e85_input_observation_20261023_r1.json').read_bytes()
        self.e88 = (manifests / 'ranking_v6_e88_input_observation_20261023_r1.json').read_bytes()
        self.source = (self.root / 'src/data/prospective_runtime_profile_e112.py').read_bytes()
        self.domain = mock.Mock(peak=123)
        self.metadata = p.snapshot(RuntimeProfileTests().environment())
        self.output = m.pins.canonical(dict(nonce=m.NONCE, profile=self.metadata))
        self.observed = dict(returncode=0, failure=None, cleaned=True, output=self.output)
        self.files, self.trees = [], []
        self.patchers = [
            mock.patch.object(m.sys, 'platform', 'linux'),
            mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'),
            mock.patch.object(m.os, 'getuid', return_value=1047, create=True),
            mock.patch.object(m.direct.base, '_small', return_value=b'12345678-1234-1234-1234-123456789abc\n'),
            mock.patch.object(m.direct, 'Descendants', return_value=self.domain),
            mock.patch.object(m.direct.base, 'supervise', return_value=self.observed),
            mock.patch.object(p, '__source_sha256__', m.pins.sha(self.source), create=True),
            mock.patch.object(m, '_read_file', side_effect=self.file),
            mock.patch.object(m, '_tree', side_effect=self.tree)]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def file(self, path, budget, expected=None, report=False, stil=False, launcher=False):
        self.files.append(path)
        count = expected['bytes'] if expected else 7
        result = dict(path=path, bytes=count, sha256=expected['sha256'] if expected else 'a' * 64,
                      whole_file_hashed=True)
        if launcher:
            result['body_base64'] = m._b64(b'launcher fixture')
        return result

    def tree(self, path, pin, budget):
        self.trees.append(path)
        return dict(path=path, bytes=pin['body_bytes'], sha256=pin['tree_sha256'], kind='tree')

    def test_fixed_scope_only_metadata_and_no_atpg(self):
        with mock.patch('subprocess.Popen') as spawn:
            result = m.collect(self.e85, self.e88, self.source)
            spawn.assert_not_called()
        self.assertTrue(result['capture_complete'], result['error'])
        self.assertEqual(len(result['frozen_inputs']), 17)
        self.assertEqual(len(result['reports']), 6)
        self.assertEqual(len(self.trees), 6)
        self.assertEqual(len(self.files), 18)
        self.assertEqual(result['runtime_profile'], self.metadata)
        self.assertLess(len(m.pins.canonical(result)), m.MAX_RESPONSE)
        for path in self.files[-3:]:
            self.assertIn('/spi/04_single_mode/H_spi_H_full_phase4_v2/', path)
        self.assertEqual(result['atpg_launches'], 0)
        self.assertEqual(result['explicit_filesystem_writes'], 0)
        self.assertFalse(result['execution_ready'])

    def test_first_io_failure_partial_evidence_no_retry(self):
        original = self.file
        def fail(path, *args, **kwargs):
            if path == m.pins.LIBRARY:
                raise OSError('sensitive-raw-message-not-returned')
            return original(path, *args, **kwargs)
        with mock.patch.object(m, '_read_file', side_effect=fail) as read:
            result = m.collect(self.e85, self.e88, self.source)
        self.assertFalse(result['capture_complete'])
        self.assertEqual(read.call_count, 2)
        self.assertIsNotNone(result['launcher'])
        self.assertEqual(result['reports'], [])
        self.assertEqual(result['boot_id'], '12345678-1234-1234-1234-123456789abc')
        self.assertNotIn('sensitive', json.dumps(result))
        self.assertGreaterEqual(result['remote_end_monotonic'], result['remote_start_monotonic'])

    def test_bad_source_or_old_observation_fails_before_child_and_input(self):
        for e85, e88, source in ((self.e85 + b' ', self.e88, self.source),
                                 (self.e85, self.e88 + b' ', self.source),
                                 (self.e85, self.e88, self.source + b' ')):
            with mock.patch.object(m.direct.base, 'supervise') as child:
                result = m.collect(e85, e88, source)
                child.assert_not_called()
            self.assertFalse(result['capture_complete'])
        self.assertEqual(self.files, [])

    def test_profile_fixed_command_no_scratch_and_metadata_only_snapshot(self):
        with mock.patch.object(m.direct.base, 'supervise', return_value=self.observed) as supervise:
            m.collect(self.e85, self.e88, self.source)
        args = supervise.call_args[0]
        self.assertEqual(args[0][:2], ['/bin/bash', '-lc'])
        self.assertIn('module load mentor/tessent2021 >/dev/null && /usr/bin/python3 -I -S -B -c ', args[0][2])
        self.assertIn('snapshot(dict(os.environ),False)', args[0][2])
        # Parse the actual shell argument, not a separately reconstructed string.
        tokens = m.shlex.split(args[0][2])
        code = tokens[tokens.index('-c') + 1]
        compile(code, '<e112-profile-child-offline>', 'exec')
        ast.parse(code, feature_version=(3, 6))
        self.assertIn('\nimport os\n', code)
        self.assertNotIn('\\nimport os\\n', code)
        self.assertEqual(args[1], '/')
        self.assertEqual(args[4], [65536])
        self.assertEqual(len(args), 5)

    def test_unknown_or_value_leaking_profile_unqualified_without_raw(self):
        for raw in (b'warning unknown format secret-data',
                    m.pins.canonical(dict(nonce=m.NONCE, profile=dict(self.metadata, normalized_values={'PATH': 'secret-data'}))),
                    m.pins.canonical(dict(nonce=m.NONCE, profile=dict(self.metadata, normalization={'PATH': {'secret': 'secret-data'}})))):
            self.observed['output'] = raw
            result = m.collect(self.e85, self.e88, self.source)
            self.assertTrue(result['capture_complete'])
            self.assertFalse(result['runtime_profile']['qualified'])
            self.assertNotIn('secret-data', json.dumps(result))

    def test_profile_not_strict_still_facts_only_not_gate(self):
        value = p.snapshot({})
        self.observed['output'] = m.pins.canonical(dict(nonce=m.NONCE, profile=value))
        result = m.collect(self.e85, self.e88, self.source)
        self.assertTrue(result['capture_complete'])
        self.assertFalse(result['runtime_profile']['strict_compatible'])
        self.assertFalse(result['execution_ready'])

    def test_failed_profile_child_stops_before_source_reads(self):
        self.observed['failure'] = 'CASE_TIMEOUT'
        result = m.collect(self.e85, self.e88, self.source)
        self.assertFalse(result['capture_complete'])
        self.assertEqual(result['error']['code'], 'PROFILE_CHILD_FAILED')
        self.assertEqual(self.files, [])

    def test_wrong_host_uid_fail_with_start_identity_no_reads(self):
        with mock.patch.object(m.platform, 'node', return_value='not-A'), \
                mock.patch.object(m.direct.base, '_small') as system_read:
            result = m.collect(self.e85, self.e88, self.source)
            system_read.assert_not_called()
        self.assertFalse(result['capture_complete'])
        self.assertEqual(result['hostname'], 'not-A')
        self.assertEqual(self.files, [])

    def test_all_owned_sources_python36_parse(self):
        for path in ('src/data/prospective_runtime_profile_e112.py', 'scripts/probe_preparation_e112.py',
                     'tests/test_preparation_probe_e112.py'):
            ast.parse((self.root / path).read_text(), feature_version=(3, 6))
