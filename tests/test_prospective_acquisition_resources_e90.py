"""Synthetic projections and fd mocks, not actual historical result access."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from scripts import probe_acquisition_resources_e90 as m
from tests.test_prospective_acquisition_tree_inputs_e85 import FakeAnchoredIO

MTFI = b'''FaultInformation {
 version : 1;
 FaultType (Stuck) {
  FaultList {
   FaultCollapsing : FALSE;
   Format : Identifier, Class, Location;
   Instance ("") {
 0, DS, "private/fault/a";
 1, DI_1, "private/fault/b";
   }
  }
 }
}
'''


class ResourceDialectTests(unittest.TestCase):
    def test_dialect_projection_without_fault_rows_or_class_counts(self):
        out = m.mtfi_projection(MTFI, 2)
        self.assertTrue(out['standard_envelope_matches'])
        self.assertTrue(out['exact_e89_envelope_matches'])
        self.assertTrue(out['e89_line_endings_compatible'])
        self.assertTrue(out['provisional_e89_classes_compatible'])
        self.assertTrue(out['fault_row_count_matches'])
        self.assertEqual(out['class_dialect_spellings'], ['DI_1', 'DS'])
        self.assertNotIn('private/fault', json.dumps(out))
        self.assertFalse(out['source_native_key_identity_verified'])
        self.assertFalse(out['quality_or_detection_counts_exported'])

    def test_malformed_and_unknown_envelope_are_not_qualified(self):
        out = m.mtfi_projection(MTFI, 3)
        self.assertFalse(out['fault_row_count_matches'])
        with self.assertRaisesRegex(m.ProbeError, 'UNSUPPORTED_CLASS_SPELLING'):
            m.mtfi_projection(MTFI.replace(b'0, DS,', b'0, broken,'), 2)
        out = m.mtfi_projection(MTFI.replace(b'FALSE', b'TRUE'), 2)
        self.assertFalse(out['standard_envelope_matches'])
        self.assertFalse(out['exact_e89_envelope_matches'])
        self.assertFalse(m.mtfi_projection(MTFI.replace(b'DI_1', b'DI_0'),2)
                         ['provisional_e89_classes_compatible'])
        out = m.mtfi_projection(MTFI.replace(b'0, DS, "private/fault/a";', b'0, invalid'), 2)
        self.assertEqual(out['malformed_fault_line_count'], 1)

    def test_class_bound_and_encoding_fail(self):
        with self.assertRaises(m.ProbeError):
            m.mtfi_projection(MTFI.replace(b'DI_1', b'DI\x00bad'), 2)
        with self.assertRaises(UnicodeError):
            m.mtfi_projection(b'\xff', 2)

    def test_rss_observation_does_not_create_limit_or_runtime(self):
        out = m.resource_projection(b'2user 1system 0:03elapsed 1234maxresident\n')
        self.assertEqual(out['compact_maxresident_values'], ['1234'])
        self.assertFalse(out['compact_units_verified'])
        self.assertTrue(out['record_is_unique'])
        self.assertIsNone(out['actual_atpg_limit_bytes'])
        self.assertNotIn('elapsed', json.dumps(out))
        out = m.resource_projection(b'Maximum resident set size (kbytes): 5000\n')
        self.assertEqual(out['explicit_kbytes_values'], ['5000'])

    def test_missing_duplicate_and_too_many_rss_no_fastest_selection(self):
        self.assertFalse(m.resource_projection(b'none')['record_is_unique'])
        out = m.resource_projection(b'1maxresident\n9maxresident\n')
        self.assertFalse(out['record_is_unique'])
        self.assertEqual(out['compact_maxresident_values'], ['1', '9'])
        with self.assertRaises(m.ProbeError):
            m.resource_projection(b'1maxresident\n' * 9)

    def test_exact_scope_and_no_follow_bound(self):
        with self.assertRaisesRegex(m.ProbeError, 'EXACT_FILE_SCOPE'):
            m.read_file('/etc/passwd', [0])
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / 'tree'
            tree.mkdir()
            (tree / 'safe').write_bytes(b'abc')
            io = FakeAnchoredIO(tree)
            # Windows mock lstat/fstat ctime semantics differ from Linux.
            # Normalize only this fixture; production identity retains ctime.
            real_identity = m.identity
            fixture_identity = lambda info: real_identity(info)[:-1]
            caps = mock.patch.multiple(m.os, O_NOFOLLOW=getattr(m.os, 'O_NOFOLLOW', 0x20000),
                                       O_DIRECTORY=getattr(m.os, 'O_DIRECTORY', 0x10000),
                                       O_NONBLOCK=getattr(m.os, 'O_NONBLOCK', 0x800), create=True)
            with caps, io.installed(), mock.patch.object(m, 'identity', side_effect=fixture_identity), \
                 mock.patch.object(m, 'specs', return_value=[('aes_core','MTFI_H','/tree/safe')]), \
                 mock.patch.object(m.sys, 'platform', 'linux'), \
                 mock.patch.object(m.os, 'supports_dir_fd', {m.os.open,m.os.stat}), \
                 mock.patch.object(m.os, 'supports_follow_symlinks', {m.os.stat}):
                count=[0]
                self.assertEqual(m.read_file('/tree/safe', count), b'abc')
                self.assertEqual(count, [3])
                with mock.patch.object(m, 'MAX_BODY', 2):
                    with self.assertRaisesRegex(m.ProbeError, 'BYTE_BOUND'):
                        m.read_file('/tree/safe', [0])

    def test_host_guard_prevents_reads_and_limit_failure_prevents_reads(self):
        with mock.patch.object(m.socket, 'gethostname', return_value='other'), \
             mock.patch.object(m, 'read_file') as reader:
            self.assertEqual(m.collect()['status'], 'PARTIAL')
            reader.assert_not_called()
        with mock.patch.object(m.socket, 'gethostname', return_value=m.HOST), \
             mock.patch.object(m.sys, 'platform', 'linux'), \
             mock.patch.object(m, 'enforce_limits', side_effect=OSError), \
             mock.patch.object(m, 'read_file') as reader:
            self.assertEqual(m.collect()['reason'], 'SELF_LIMITS_BEFORE_READS')
            reader.assert_not_called()


if __name__ == '__main__':
    unittest.main()
