"""Synthetic bytes and mocks only; never run the E93 controller or remote probe."""
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import probe_acquisition_translation_e93 as m
from scripts import execute_acquisition_translation_probe_e93 as controller
from src.data import prospective_fault_translation_v2 as core
from tests.test_prospective_acquisition_tree_inputs_e85 import FakeAnchoredIO


ROWS = (('0', '/U2/a', '/U2/a', '/U2/a', '/U1/a'),
        ('1', '/U3/b', '/U3/b', '/U3/b', '/U2/b'))


def mapping():
    header = ('stuck_value\tcanonical_core_path\tH_native_path\t'
              'M_native_path\tF_native_path\n')
    return (header + ''.join('\t'.join(row) + '\n' for row in ROWS)).encode('ascii')


def basic(mode):
    column = 3 if mode == 'M' else 4
    return ''.join('%s %s "%s"\n' %
                   (row[0], ('DS' if index == 0 else 'RE'), row[column])
                   for index, row in enumerate(ROWS)).encode('ascii')


def mtfi():
    lines = list(core.HEADER)
    lines.extend('   %s, %s, "%s";\n' %
                 (row[0], ('DI.CLK' if index == 0 else 'EQ'), row[2])
                 for index, row in enumerate(ROWS))
    lines.extend(core.FOOTER)
    return ''.join(lines).encode('ascii')


class TranslationProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tree = Path(self.tmp.name) / 'tree'
        self.tree.mkdir()
        self.io = FakeAnchoredIO(self.tree)
        self.root = self.tree / 'phase/10_circuits'

    def put(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def fixture(self):
        configured = {}
        for circuit in m.CIRCUITS:
            common = (self.root / circuit / '03_fault_universe' /
                      ('common_' + circuit + '_m16_phase4_v2'))
            raws = {'mapping': mapping(), 'M_basic': basic('M'),
                    'F_basic': basic('F'), 'source_mtfi': mtfi()}
            manifest = {
                'schema': 'multimode_common_fault_universe_v1',
                'fault_model': 'stuck-at', 'common_fault_count': 2,
                'f_flat_instance_offset': 1,
                'mapping': {'path': 'canonical_fault_mapping.tsv',
                            'sha256': m.sha(raws['mapping']),
                            'row_count_excluding_header': 2},
                'files': {
                    mode: {'path': mode + '_common_initial_faults.basic',
                           'sha256': m.sha(raws[mode + '_basic']),
                           'fault_count': 2} for mode in m.TARGETS}}
            raws['manifest'] = json.dumps(manifest, sort_keys=True).encode('ascii')
            self.put(common / 'manifest.json', raws['manifest'])
            self.put(common / 'canonical_fault_mapping.tsv', raws['mapping'])
            self.put(common / 'M_common_initial_faults.basic', raws['M_basic'])
            self.put(common / 'F_common_initial_faults.basic', raws['F_basic'])
            self.put(self.root / circuit / '04_single_mode' /
                     ('H_' + circuit + '_H_full_phase4_v2/faults.mtfi'),
                     raws['source_mtfi'])
            configured[circuit] = {'common_count': 2}
            configured[circuit].update({name: m.sha(raw) for name, raw in raws.items()})
        return {'schema': 'e93-translation-input-binding-v1',
                'core_sha256': m.CORE_SHA256,
                'observations': {'e88': '8' * 64, 'e90': '9' * 64},
                'circuits': configured}

    def installed(self):
        return mock.patch.multiple(m, ROOT='/tree/phase/10_circuits')

    def test_ten_reads_produce_exactly_four_sanitized_compatibility_results(self):
        config = self.fixture()
        core_raw = controller.CORE.read_bytes()
        with self.installed(), self.io.installed(), \
             mock.patch.object(m, 'require_capability'), \
             mock.patch.object(m.socket, 'gethostname', return_value=m.HOST), \
             mock.patch.object(m.sys, 'platform', 'linux'), \
             mock.patch.object(m, 'enforce_limits'):
            value = m.collect(config, core_raw)
        self.assertEqual(len(value['results']), 4)
        self.assertEqual({row['transition'] for row in value['results']},
                         {'H_TO_M', 'H_TO_F'})
        self.assertTrue(all(row['status'] ==
                            'PASS_COMPUTED_COMPATIBILITY_ONLY'
                            for row in value['results']))
        text = json.dumps(value, sort_keys=True).lower()
        for forbidden in ('/u2/a', 'fault_rows', 'class_counts',
                          'detected_entries', 'cycles', 'runtime'):
            self.assertNotIn(forbidden, text)
        self.assertIn('not_tessent_acceptance_atpg_or_pilot_cost', text)
        self.assertEqual(value['files_read'], 10)
        self.assertEqual(len(value['input_files']), 10)
        self.assertEqual(value['body_bytes'],
                         sum(item['bytes'] for item in value['input_files']))
        self.assertFalse(value['execution_ready'])
        self.assertFalse(value['training_release'])
        self.assertEqual(self.io.body_reads, 10)

    def test_each_input_is_read_once_and_raw_pin_change_fails_closed(self):
        config = self.fixture()
        config['circuits']['aes_core']['M_basic'] = '0' * 64
        with self.installed(), self.io.installed(), \
             mock.patch.object(m, 'require_capability'), \
             mock.patch.object(m.socket, 'gethostname', return_value=m.HOST), \
             mock.patch.object(m.sys, 'platform', 'linux'), \
             mock.patch.object(m, 'enforce_limits'):
            with self.assertRaisesRegex(m.ProbeError,
                                        'INPUT_SHA_MISMATCH_aes_core_M_basic'):
                m.collect(config, controller.CORE.read_bytes())
        self.assertLessEqual(self.io.body_reads, 4)

    def test_host_and_limit_guards_are_before_any_input_read(self):
        config = self.fixture()
        with mock.patch.object(m.socket, 'gethostname', return_value='other'), \
             mock.patch.object(m, 'read_file') as reader, \
             mock.patch.object(m, 'enforce_limits') as limits:
            with self.assertRaisesRegex(m.ProbeError, 'HOST_OR_PLATFORM_BEFORE_READS'):
                m.collect(config, controller.CORE.read_bytes())
        reader.assert_not_called()
        limits.assert_not_called()
        with mock.patch.object(m.socket, 'gethostname', return_value=m.HOST), \
             mock.patch.object(m.sys, 'platform', 'linux'), \
             mock.patch.object(m, 'enforce_limits', side_effect=OSError), \
             mock.patch.object(m, 'read_file') as reader:
            with self.assertRaises(OSError):
                m.collect(config, controller.CORE.read_bytes())
        reader.assert_not_called()

    def test_exact_scope_per_file_total_cap_and_nofollow_swap(self):
        config = self.fixture()
        with self.installed(), self.io.installed(), \
             mock.patch.object(m, 'require_capability'):
            path = m.file_paths('aes_core')['manifest']
            with self.assertRaisesRegex(m.ProbeError, 'EXACT_FILE_SCOPE'):
                m.read_file('/etc/passwd', m.Budget())
            with mock.patch.object(m, 'MAX_FILE', 1):
                with self.assertRaisesRegex(m.ProbeError, 'BODY_BYTE_BOUND'):
                    m.read_file(path, m.Budget())
            target = self.root / 'aes_core/03_fault_universe/common_aes_core_m16_phase4_v2/manifest.json'
            self.io.on_open = lambda opened: self.io.links.add(opened) \
                if opened == target else None
            with self.assertRaises(OSError):
                m.read_file(path, m.Budget())
        self.assertEqual(self.io.body_reads, 0)
        self.assertIsNotNone(config)

    def test_ancestor_nofollow_swap_stops_before_body(self):
        self.fixture()
        target = self.tree / 'phase'
        with self.installed(), self.io.installed(), \
             mock.patch.object(m, 'require_capability'):
            path = m.file_paths('aes_core')['manifest']
            self.io.on_open = lambda opened: self.io.links.add(opened) \
                if opened == target else None
            with self.assertRaises(OSError):
                m.read_file(path, m.Budget())
        self.assertEqual(self.io.body_reads, 0)

    def test_core_source_is_pinned_and_executed_as_isolated_module(self):
        module = m.load_core(controller.CORE.read_bytes())
        self.assertTrue(callable(module.translate))
        with self.assertRaisesRegex(m.ProbeError, 'CORE_SOURCE_PIN'):
            m.load_core(controller.CORE.read_bytes() + b'\n')

    def test_manifest_requires_actual_count_offset_and_target_bindings(self):
        config = self.fixture()
        circuit = 'aes_core'
        raw = (self.root / circuit / '03_fault_universe' /
               ('common_' + circuit + '_m16_phase4_v2/manifest.json')).read_bytes()
        self.assertEqual(m.parse_manifest(raw, circuit,
                         config['circuits'][circuit]), (2, 1))
        changed = json.loads(raw)
        changed['files']['M']['fault_count'] = 1
        with self.assertRaisesRegex(m.ProbeError, 'MANIFEST_M_BINDING'):
            m.parse_manifest(json.dumps(changed).encode('ascii'), circuit,
                             config['circuits'][circuit])

    def test_error_or_partial_response_cannot_validate_as_ready(self):
        valid = {'schema': 'e93-real-input-translation-compatibility-v1',
                 'validation_role':
                 'READ_ONLY_COMPUTED_COMPATIBILITY_NOT_TESSENT_ACCEPTANCE_ATPG_OR_PILOT_COST',
                 'observation_sha256': {'e88': '8' * 64, 'e90': '9' * 64},
                 'files_read': 10, 'body_bytes': 10,
                 'input_files': [
                     {'circuit': circuit, 'role': role,
                      'sha256': 'f' * 64, 'bytes': 1}
                     for circuit in ('aes_core', 'spi')
                     for role in ('manifest', 'mapping', 'M_basic', 'F_basic',
                                  'source_mtfi')],
                 'actual_atpg_calls': 0, 'training_runs': 0,
                 'remote_writes': 0, 'programs_launched': 0,
                 'execution_ready': False, 'training_release': False,
                 'results': []}
        for count in (0, 3):
            value = dict(valid)
            value['results'] = [self.result('aes_core', 'H_TO_M')] * count
            with self.assertRaises(ValueError):
                controller.validate_response(json.dumps(value).encode('ascii'))
        value = dict(valid)
        value['results'] = [self.result(circuit, 'H_TO_' + mode)
                            for circuit in ('aes_core', 'spi')
                            for mode in ('M', 'F')]
        value['results'][0]['status'] = 'PARTIAL'
        with self.assertRaisesRegex(ValueError, 'RESULT_STATUS_OR_FIELDS'):
            controller.validate_response(json.dumps(value).encode('ascii'))

    @staticmethod
    def result(circuit, transition):
        return {'circuit': circuit, 'transition': transition,
                'status': 'PASS_COMPUTED_COMPATIBILITY_ONLY',
                'output_mtfi_sha256': 'a' * 64, 'manifest_sha256': 'b' * 64,
                'byte_counts': {'mapping': 1, 'source_mtfi': 1,
                                'target_basic': 1, 'output_mtfi': 1,
                                'manifest': 1},
                'input_sha256': {'mapping': 'c' * 64,
                                 'source_mtfi': 'd' * 64,
                                 'target_basic': 'e' * 64}}

    def test_controller_binds_current_e88_e90_and_independent_review(self):
        core_raw = controller.CORE.read_bytes()
        binding = controller.input_binding(controller.E88.read_bytes(),
            controller.E90.read_bytes(), controller.E93_REVIEW.read_bytes(), core_raw)
        self.assertEqual(binding['core_sha256'], controller.CORE_SHA)
        self.assertEqual(binding['observations'],
                         {'e88': controller.E88_SHA, 'e90': controller.E90_SHA})
        self.assertEqual(binding['circuits']['aes_core']['manifest'],
                         'c1239fb3ff04b6db8ef49265bf5902cfbaf058b229ad84214c4c8d21748a1f2f')
        self.assertEqual(binding['circuits']['spi']['source_mtfi'],
                         '39ff4c0919ab70b53b7ebd67d0a460220719ac905a97df065ee92a631f838be9')
        bad = json.loads(controller.E93_REVIEW.read_text())
        bad['verdict'] = 'FAIL'
        with self.assertRaisesRegex(ValueError, 'CORE_REVIEW_OR_SOURCE_PIN'):
            controller.input_binding(controller.E88.read_bytes(),
                controller.E90.read_bytes(), json.dumps(bad).encode('ascii'), core_raw)
        with self.assertRaisesRegex(ValueError, 'INPUT_OBSERVATION_SOURCE_PIN'):
            controller.input_binding(controller.E88.read_bytes() + b'\n',
                controller.E90.read_bytes(), controller.E93_REVIEW.read_bytes(), core_raw)

    def test_old_review_and_v1_core_are_rejected_by_version_boundary(self):
        old_review = (controller.ROOT /
            'data/manifests/ranking_v6_e91_review_20261023_r1.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'CORE_REVIEW_OR_SOURCE_PIN'):
            controller.input_binding(controller.E88.read_bytes(),
                controller.E90.read_bytes(), old_review, controller.CORE.read_bytes())
        old_core = (controller.ROOT /
                    'src/data/prospective_fault_translation_v1.py').read_bytes()
        with self.assertRaisesRegex(m.ProbeError, 'CORE_SOURCE_PIN'):
            m.load_core(old_core)
        self.assertNotEqual(controller.PHASE.name,
                            'v6_e92_translation_compat_20261023_r1')
        self.assertEqual(controller.PHASE.name,
                         'v6_e93_translation_compat_20261023_r1')

    def test_payload_contains_exact_sources_and_obeys_64k_cap(self):
        reader = controller.SOURCE.read_bytes()
        core_raw = controller.CORE.read_bytes()
        binding = {'small': True}
        payload = controller.build_payload(reader, core_raw, binding)
        self.assertTrue(payload.startswith(reader))
        self.assertIn(repr(core_raw).encode('ascii'), payload)
        self.assertLessEqual(len(payload), 65536)
        with mock.patch.object(controller, 'PAYLOAD_MAX', len(payload) - 1):
            with self.assertRaisesRegex(ValueError, 'PAYLOAD_BYTE_BOUND'):
                controller.build_payload(reader, core_raw, binding)

    def test_two_required_source_pins_fail_before_phase_and_transport(self):
        with mock.patch.object(controller.sys, 'argv', ['controller']), \
             mock.patch.object(controller, 'PHASE') as phase, \
             mock.patch.object(controller, 'TRANSPORT') as transport:
            with self.assertRaisesRegex(ValueError,
                                        'READER_AND_CORE_REVIEWED_SHA_REQUIRED'):
                controller.main()
        phase.mkdir.assert_not_called()
        transport.read_bytes.assert_not_called()
        with mock.patch.object(controller.sys, 'argv',
                               ['controller', '0' * 64, controller.CORE_SHA]), \
             mock.patch.object(controller, 'PHASE') as phase, \
             mock.patch.object(controller, 'TRANSPORT') as transport:
            with self.assertRaisesRegex(ValueError, 'READER_CHANGED'):
                controller.main()
        phase.mkdir.assert_not_called()
        transport.read_bytes.assert_not_called()

    def test_reader_ast_has_no_scan_write_process_or_runtime_labels(self):
        tree = ast.parse(controller.SOURCE.read_text(encoding='utf-8'))
        calls = {node.func.attr for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & {'scandir', 'listdir', 'walk', 'system',
                                  'popen', 'Popen', 'run'})
        self.assertNotIn('runtime', controller.SOURCE.read_text(encoding='utf-8').lower())


if __name__ == '__main__':
    unittest.main()

