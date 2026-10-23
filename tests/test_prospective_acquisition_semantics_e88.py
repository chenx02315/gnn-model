"""Synthetic bounded files/mocks only; never call the A-side controller."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import probe_acquisition_semantics_e88 as m
from scripts import execute_acquisition_semantics_probe_e88 as controller
from tests.test_prospective_acquisition_tree_inputs_e85 import FakeAnchoredIO


def mapping(rows):
    lines = ['stuck_value\tcanonical_core_path\tH_native_path\tM_native_path\tF_native_path']
    lines.extend('\t'.join(row) for row in rows)
    return ('\n'.join(lines) + '\n').encode('utf-8')


ROWS = [('0', 'canonical/a', 'canonical/a', 'canonical/a', 'canonical/a'),
        ('1', 'canonical/b', 'canonical/b', 'canonical/b', 'canonical/b')]


class SemanticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tree = Path(self.tmp.name) / 'tree'
        self.tree.mkdir()
        self.io = FakeAnchoredIO(self.tree)

    def put(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def fixture(self):
        launcher = self.tree / 'launcher'
        self.put(launcher, b'opaque-launcher-fixture')
        for circuit in ('aes_core', 'spi'):
            root = (self.tree / 'phase/10_circuits' / circuit /
                    ('03_fault_universe/common_' + circuit + '_m16_phase4_v2'))
            map_raw = mapping(ROWS)
            self.put(root / 'canonical_fault_mapping.tsv', map_raw)
            files = {}
            for mode in m.MODES:
                name = mode + '_common_initial_faults.basic'
                raw = b'0 SA canonical/a\n1 SA "canonical/b"\n'
                self.put(root / name, raw)
                files[mode] = {'path': name, 'sha256': m.sha(raw), 'fault_count': 2}
            manifest = {'schema': 'multimode_common_fault_universe_v1',
                        'fault_model': 'stuck-at', 'f_flat_instance_offset': 0,
                        'common_fault_count': 2, 'files': files,
                        'mapping': {'path': 'canonical_fault_mapping.tsv',
                                    'sha256': m.sha(map_raw),
                                    'row_count_excluding_header': 2}}
            self.put(root / 'manifest.json', json.dumps(manifest).encode('ascii'))

    def context(self):
        return mock.patch.multiple(m, ROOT='/tree/phase', LAUNCHER='/tree/launcher',
            LAUNCHER_SHA256=m.sha(b'opaque-launcher-fixture'),
            EXPECTED={'aes_core': 2, 'spi': 2})

    def test_exact_sets_and_eleventh_launcher_body(self):
        self.fixture()
        with self.context(), self.io.installed(), \
             mock.patch.object(m, 'require_capability'), \
             mock.patch.object(m.socket, 'gethostname', return_value=m.HOST), \
             mock.patch.object(m.sys, 'platform', 'linux'), \
             mock.patch.object(m, 'enforce_limits'):
            value = m.collect()
        self.assertEqual(value['status'], 'PASS_BOUNDED_NAMESPACE_SETS_AND_LAUNCHER_BODY_ONLY')
        self.assertEqual(value['files_read'], 11)
        self.assertEqual(len(value['roots']), 2)
        self.assertTrue(value['launcher']['pin_match'])
        self.assertTrue(value['mapping_namespace_and_set_consistency_verified'])
        self.assertFalse(value['fault_mapping_semantics_verified'])
        self.assertEqual(value['directory_entries_enumerated'], 0)
        self.assertEqual(value['external_programs_launched'], 0)
        self.assertNotIn('canonical/a', json.dumps(value))

    def test_mapping_duplicate_missing_swapped_and_stuck_fail(self):
        for rows, expected, reason in ((ROWS + [ROWS[0]], 3,
                                        'MAPPING_DUPLICATE_CANONICAL'),
                                       ([ROWS[0]], 2, 'MAPPING_COUNT'),
                                       ([('2',) + ROWS[0][1:], ROWS[1]], 2,
                                        'MAPPING_STUCK'),
                                       ([ROWS[0], ('1', 'canonical/b',
                                                   'canonical/a', 'canonical/b',
                                                   'canonical/b')], 2,
                                        'MAPPING_H_CANONICAL')):
            with self.assertRaisesRegex(m.ProbeError, reason):
                m.parse_mapping(mapping(rows), expected, 0)
        sets = m.parse_mapping(mapping(ROWS), 2, 0)
        wrong = m.parse_basic(b'0 SA canonical/a\n1 SA H/other\n', 'H', 2)
        self.assertNotEqual(sets['H'], wrong)

    def test_mapping_extra_metadata_column_allowed_but_width_and_header_strict(self):
        raw = mapping(ROWS).decode('utf-8').splitlines()
        valid = ('fault_id\t' + raw[0] + '\n' +
                 'id-a\t' + raw[1] + '\n' +
                 'id-b\t' + raw[2] + '\n').encode('utf-8')
        self.assertEqual(len(m.parse_mapping(valid, 2, 0)['H']), 2)
        for bad, code in ((valid.replace(b'fault_id', b'stuck_value', 1),
                           'MAPPING_HEADER'),
                          (valid.replace(b'id-b\t', b'', 1), 'MAPPING_ROW'),
                          (valid + b'id-c\t0\ttoo\tmany\tcolumns\n',
                           'MAPPING_ROW')):
            with self.assertRaisesRegex(m.ProbeError, code):
                m.parse_mapping(bad, 2, 0)

    def test_basic_duplicate_quotes_stuck_and_count_fail(self):
        cases = ((b'0 SA a\n0 SA a\n', 'BASIC_DUPLICATE'),
                 (b'2 SA a\n1 SA b\n', 'BASIC_LINE'),
                 (b'0 SA "a\n1 SA b\n', 'BASIC_QUOTE'),
                 (b'0 SA a\n', 'BASIC_COUNT'),
                 (b'0 SA a"b\n1 SA b\n', 'BASIC_PATH'))
        for raw, code in cases:
            with self.assertRaisesRegex(m.ProbeError, code):
                m.parse_basic(raw, 'H', 2)

    def test_manifest_required_fields_and_duplicate_json(self):
        self.fixture()
        path = (self.tree / 'phase/10_circuits/aes_core/'
                '03_fault_universe/common_aes_core_m16_phase4_v2/manifest.json')
        valid = json.loads(path.read_text())
        bad = dict(valid, files={'H': valid['files']['H']})
        with self.assertRaisesRegex(m.ProbeError, 'MANIFEST_MODE_COUNTS'):
            m.parse_manifest(json.dumps(bad).encode('ascii'), 2)
        with self.assertRaisesRegex(m.ProbeError, 'DUPLICATE_JSON_KEY'):
            m.parse_manifest(b'{"common_fault_count":2,"common_fault_count":2}', 2)
        bad = dict(valid, common_fault_count=True)
        with self.assertRaisesRegex(m.ProbeError, 'MANIFEST_COMMON_COUNT'):
            m.parse_manifest(json.dumps(bad).encode('ascii'), 2)

    def test_file_cap_and_fd_nofollow_swap_no_body_read_or_leak(self):
        target = self.tree / 'launcher'
        target.write_bytes(b'abcdef')
        with mock.patch.object(m, 'LAUNCHER', '/tree/launcher'), \
             self.io.installed(), mock.patch.object(m, 'require_capability'):
            with mock.patch.object(m, 'MAX_FILE', 5):
                with self.assertRaisesRegex(m.ProbeError, 'BODY_BYTE_BOUND'):
                    m.read_file('/tree/launcher', m.Budget())
            self.assertEqual(self.io.body_reads, 0)
            self.io.on_open = lambda path: self.io.links.add(path) if path == target else None
            with self.assertRaises(OSError):
                m.read_file('/tree/launcher', m.Budget())
            self.assertEqual(self.io.body_reads, 0)

    def test_ancestor_swap_to_symlink_stops_before_body(self):
        self.fixture()
        target = self.tree / 'phase'
        with self.context(), self.io.installed(), \
             mock.patch.object(m, 'require_capability'):
            self.io.on_open = lambda path: self.io.links.add(path) if path == target else None
            with self.assertRaises(OSError):
                m.read_file('/tree/phase/10_circuits/aes_core/'
                    '03_fault_universe/common_aes_core_m16_phase4_v2/manifest.json',
                    m.Budget())
            self.assertEqual(self.io.body_reads, 0)

    def test_fixed_scope_and_host_guard_before_read(self):
        with self.assertRaisesRegex(m.ProbeError, 'FIXED_FILE_SCOPE'):
            m.read_file('/etc/passwd', m.Budget())
        with mock.patch.object(m.socket, 'gethostname', return_value='other'), \
             mock.patch.object(m, 'read_file') as reader:
            value = m.collect()
        self.assertEqual(value['status'], 'PARTIAL')
        reader.assert_not_called()

    def test_partial_stops_following_files(self):
        self.fixture()
        with self.context(), self.io.installed(), \
             mock.patch.object(m, 'require_capability'), \
             mock.patch.object(m.socket, 'gethostname', return_value=m.HOST), \
             mock.patch.object(m.sys, 'platform', 'linux'), \
             mock.patch.object(m, 'enforce_limits'), \
             mock.patch.object(m, 'MAX_BODY', 30):
            value = m.collect()
        self.assertEqual(value['status'], 'PARTIAL')
        self.assertEqual(value['reason'], 'BODY_BYTE_BOUND')
        self.assertLess(value['files_read'], 11)
        self.assertLessEqual(value['body_bytes'], 30)

    def test_swapped_mode_mapping_fails_set_equality(self):
        self.fixture()
        root = (self.tree / 'phase/10_circuits/aes_core/'
                '03_fault_universe/common_aes_core_m16_phase4_v2')
        wrong = [('0', 'canonical/a', 'wrong/a', 'canonical/a', 'canonical/a'),
                 ROWS[1]]
        raw = mapping(wrong)
        (root / 'canonical_fault_mapping.tsv').write_bytes(raw)
        manifest_path = root / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['mapping']['sha256'] = m.sha(raw)
        manifest_path.write_text(json.dumps(manifest))
        with self.context(), self.io.installed(), \
             mock.patch.object(m, 'require_capability'), \
             mock.patch.object(m.socket, 'gethostname', return_value=m.HOST), \
             mock.patch.object(m.sys, 'platform', 'linux'), \
             mock.patch.object(m, 'enforce_limits'):
            value = m.collect()
        self.assertEqual(value['status'], 'PARTIAL')
        self.assertEqual(value['reason'], 'MAPPING_H_CANONICAL')
        self.assertLess(value['files_read'], 11)

    def test_swapped_f_rows_same_set_rejected_by_per_row_offset(self):
        rows = [('0', '/U2/a', '/U2/a', '/U2/a', '/U1/a'),
                ('0', '/U3/a', '/U3/a', '/U3/a', '/U2/a')]
        sets = m.parse_mapping(mapping(rows), 2, 1)
        self.assertEqual(sets['F'], {('0', '/U1/a'), ('0', '/U2/a')})
        swapped = [('0', '/U2/a', '/U2/a', '/U2/a', '/U2/a'),
                   ('0', '/U3/a', '/U3/a', '/U3/a', '/U1/a')]
        with self.assertRaisesRegex(m.ProbeError, 'MAPPING_F_OFFSET_CANONICAL'):
            m.parse_mapping(mapping(swapped), 2, 1)

    def test_manifest_raw_sha_binding_fails_before_set_claim(self):
        self.fixture()
        root = (self.tree / 'phase/10_circuits/aes_core/'
                '03_fault_universe/common_aes_core_m16_phase4_v2')
        (root / 'H_common_initial_faults.basic').write_bytes(
            b'0 SA canonical/a\n1 SA canonical/b\n')
        with self.context(), self.io.installed(), \
             mock.patch.object(m, 'require_capability'), \
             mock.patch.object(m.socket, 'gethostname', return_value=m.HOST), \
             mock.patch.object(m.sys, 'platform', 'linux'), \
             mock.patch.object(m, 'enforce_limits'):
            value = m.collect()
        self.assertEqual(value['reason'], 'MANIFEST_H_SHA')
        self.assertFalse(value['mapping_namespace_and_set_consistency_verified'])

    def test_controller_bad_reader_pin_fails_before_phase_or_transport(self):
        with mock.patch.object(controller.sys, 'argv', ['controller', '0' * 64]), \
             mock.patch.object(controller, 'PHASE') as phase, \
             mock.patch.object(controller, 'TRANSPORT') as transport:
            with self.assertRaisesRegex(ValueError, 'READER_CHANGED'):
                controller.main()
        phase.mkdir.assert_not_called()
        transport.read_bytes.assert_not_called()


if __name__ == '__main__':
    unittest.main()
