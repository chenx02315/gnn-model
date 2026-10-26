"""Fixed local historical evidence and explicitly adapted synthetic replay only."""
import ast
import base64
import copy
import json
from pathlib import Path
import unittest
from unittest import mock

from scripts import build_generation_diagnostic_policy_e120 as b
from src.data import prospective_generation_diagnostics_e120 as m


POLICY = Path(__file__).resolve().parents[1]/'contracts/prospective_generation_diagnostics_e120_v1.json'


def error_echoes(tcl):
    """Render actual frozen source command blocks in the observed Tessent dialect."""
    blocks, pending, balance = [], [], 0
    for line in tcl.splitlines():
        if not pending and not line.strip():
            continue
        pending.append(line)
        balance += line.count(b'{')-line.count(b'}')
        if balance == 0:
            if m.ERROR.search(b'\n'.join(pending)):
                blocks.append(b'\n'.join([b'//  command: '+pending[0]]+
                                         [b'//           '+item for item in pending[1:]]))
            pending = []
    assert not pending
    return blocks


class DiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw_policy = POLICY.read_bytes()
        cls.policy = json.loads(cls.raw_policy)
        cls.sources, cls.pins = b.load_sources()

    def setUp(self):
        self.gate = m.build_gate(self.raw_policy)

    def context(self, circuit='aes_core', mode='H'):
        library = m.recipe.ROOT+'/'+circuit+'/inputs/'+circuit+'/cells.lib'
        return dict(circuit=circuit), dict(stage=mode, env=dict(CELL_LIBRARY=library))

    def historical_h(self, circuit='aes_core', adapt_source=False):
        binding, envelope = self.context(circuit)
        raw = self.sources[circuit+':H'].replace(b.OLD_LIBRARY.encode('ascii'),
                                                envelope['env']['CELL_LIBRARY'].encode('ascii'))
        if adapt_source:
            # Synthetic source adaptation only. This is NOT a replay of current physical execution.
            old = b'//  command: foreach required {CIRCUIT_ROOT CIRCUIT TOP_MODULE CELL_LIBRARY MODE RUN_ID} {'
            new = b'//  command: foreach required {CIRCUIT_ROOT CIRCUIT TOP_MODULE CELL_LIBRARY MODE RUN_ID TSDB_INPUT_DIR} {'
            self.assertEqual(raw.count(old), 1)
            raw = raw.replace(old, new, 1)
        return raw, binding, envelope

    def test_policy_reproducible_small_and_historical_sources_unchanged(self):
        before = {key:m.sha(raw) for key, raw in self.sources.items()}
        built = b.build()
        self.assertEqual(built, self.policy)
        self.assertLessEqual(len(self.raw_policy), 65536)
        sources, metadata = b.load_sources()
        self.assertEqual({key:m.sha(raw) for key, raw in sources.items()}, before)
        self.assertEqual(metadata, self.pins)
        self.assertTrue(built['known_post_messages_applied_MF_by_limited_policy_inference_not_observed_MF_generation'])
        self.assertTrue(built['warnings_risk_not_quality_harmlessness'])
        self.assertFalse(built['d95_verified'])
        self.assertEqual(built['readback_sha256']['e103'],
                         'a451a0409aee9e470a65ebd2ce15313ef8b5c06976a0f45451d62850e01bf513')
        self.assertEqual(built['source_pins']['aes_core:M']['sha256'],
                         '5fe275ab8cf80f3001f42b9b0a4154e8310030b8e2072de9d22a7c0e70aff7c0')

    def test_exact_six_startup_profiles_from_full_byte_sources(self):
        expected = {'aes_core:H':5,'aes_core:M':5,'aes_core:F':4,'spi:H':5,'spi:M':5,'spi:F':4}
        self.assertEqual({k:len(v) for k,v in self.policy['startup'].items()}, expected)
        for key, raw in self.sources.items():
            rows, imports, creates = m.extract(raw, b.OLD_LIBRARY if key.endswith(':H') else b.pins.LIBRARY)
            selected = [{field:row[field] for field in b.FIELDS} for row in rows if row['phase'] == 'STARTUP']
            self.assertEqual(selected, self.policy['startup'][key])
            self.assertTrue(all(set(row) == set(b.FIELDS) for row in selected))

    def test_historical_h_exact_source_mismatch_is_not_current_source_pass(self):
        for circuit in ('aes_core','spi'):
            raw, binding, envelope = self.historical_h(circuit)
            with self.subTest(circuit=circuit), self.assertRaisesRegex(ValueError, 'ACTUAL_ERROR_DIAGNOSTIC'):
                self.gate(raw, binding, envelope)

    def test_synthetic_source_adapted_h_preserves_real_warning_dialect(self):
        for circuit, warning_count in (('aes_core',9), ('spi',8)):
            raw, binding, envelope = self.historical_h(circuit, adapt_source=True)
            result = self.gate(raw, binding, envelope)
            self.assertEqual(result['warning_count'], warning_count)
            self.assertEqual(result['unknown_warnings_ignored'], 0)
            self.assertFalse(result['quality_harmlessness_proven'])
            self.assertTrue(result['outcome_risks_remain'])
            self.assertFalse(result['d95_verified'])
            self.assertFalse(result['training_release'])

    def test_only_exact_full_library_attribute_source_line_normalized(self):
        raw = self.sources['aes_core:H']
        old_line = m.LIBRARY_LINE+b.OLD_LIBRARY.encode('ascii')+b"'."
        self.assertEqual(raw.splitlines().count(old_line), 1)
        rows, _, _ = m.extract(raw, b.OLD_LIBRARY)
        library_row = next(row for row in rows if row['category'] == 'LIBRARY_ATTRIBUTE_MODELS_UNMATCHED')
        normalized = base64.b64decode(library_row['block_base64'])
        self.assertIn(m.LIBRARY_TOKEN, normalized)
        self.assertNotIn(b.OLD_LIBRARY.encode('ascii'), normalized)
        with self.assertRaisesRegex(ValueError, 'EXACT_LIBRARY_ATTRIBUTE_SOURCE_LINE'):
            m.extract(raw.replace(old_line, old_line+b' '), b.OLD_LIBRARY)
        with self.assertRaisesRegex(ValueError, 'EXACT_LIBRARY_ATTRIBUTE_SOURCE_LINE'):
            m.extract(raw.replace(old_line, old_line+b'\n'+old_line), b.OLD_LIBRARY)

    def test_exact_current_error_guard_echoes_only_and_tsdb_guard(self):
        for mode in ('H','M','F'):
            tcl = base64.b64decode(self.policy['effective_tcl_base64'][mode])
            blocks = error_echoes(tcl)
            self.assertTrue(any(b'if {![file isdirectory $tsdb_input]}' in block for block in blocks))
            filtered, count = m.strip_frozen_echo(b'\n'.join(blocks)+b'\n', tcl)
            self.assertEqual(count, len(blocks))
            self.assertIsNone(m.ERROR.search(filtered))
            guard = next(block for block in blocks if b'if {![file isdirectory $tsdb_input]}' in block)
            near = guard.replace(b'ERROR: missing', b'ERROR:  missing', 1)
            filtered, count = m.strip_frozen_echo(near, tcl)
            self.assertEqual(count, 0)
            self.assertIsNotNone(m.ERROR.search(filtered))

    def test_near_echo_actual_error_fatal_and_invalid_pin_remain_fatal(self):
        raw, binding, envelope = self.historical_h(adapt_source=True)
        for extra in (b'ERROR: live failure\n', b'FATAL live failure\n', b'Invalid pin_pathname /x\n',
                      b'//  command: if {![file isdirectory $tsdb_input]} { puts stderr "ERROR:  missing isolated TSDB $tsdb_input"; exit 2 }\n'):
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, 'ACTUAL_ERROR_DIAGNOSTIC'):
                self.gate(raw+b'\n'+extra, binding, envelope)

    def test_unknown_warning_wrong_phase_and_changed_complete_block_rejected(self):
        raw, binding, envelope = self.historical_h(adapt_source=True)
        split = base64.b64decode(self.policy['generation']['SPLIT_CAPTURE_COST_NOTICE'])
        self.assertEqual(raw.count(split), 1)
        for bad in (raw+b'\n// Warning: unseen condition\n',
                    raw.replace(split, b'')+b'\n'+split+b'\n',
                    raw.replace(split, split.replace(b'unnecessarily.',b'unnecessarily!'), 1)):
            with self.assertRaises(ValueError):
                self.gate(bad, binding, envelope)

    def test_au_percentage_typed_bound_is_not_assumed_hundred_percent(self):
        raw, binding, envelope = self.historical_h('spi', adapt_source=True)
        token = b'28.22% since the start of this ATPG run.'
        self.assertEqual(raw.count(token), 1)
        def render(percent):
            lines = raw.splitlines()
            index = next(i for i, line in enumerate(lines) if token in line)
            changed = lines[index].replace(token, percent+b'% since the start of this ATPG run.')
            core = changed[:-1].rstrip(b' ')
            lines[index] = core+b' '*(self.policy['au_table_line_bytes']-len(core)-1)+b'|'
            return b'\n'.join(lines)+b'\n'
        for percent in (b'0.00', b'99.99', b'100.00', b'100.01', b'200.00'):
            value = self.gate(render(percent), binding, envelope)
            self.assertTrue(value['passed'])
        bound = str(100*m.recipe.identities.COUNTS['spi']+1).encode()+b'.00'
        for percent in (bound,b'-1.00',b'NaN',b'Inf',b'1',b'1.0',b'1.000'):
            with self.subTest(percent=percent), self.assertRaises(ValueError):
                self.gate(render(percent), binding, envelope)
        with self.assertRaisesRegex(ValueError, 'AU_FIXED_TABLE_PADDING_CHANGED'):
            self.gate(raw.replace(token, b'200.00% since the start of this ATPG run.'), binding, envelope)
        with self.assertRaisesRegex(ValueError, 'AU_PERCENTAGE_GRAMMAR'):
            self.gate(raw.replace(token, b'28.22%  since the start of this ATPG run.'), binding, envelope)

    def test_outcome_warnings_retained_not_harmlessness_or_raw_pass_marker(self):
        for circuit, kind in (('aes_core','UNSUCCESSFUL_SEARCH_PHASE'),('spi','AU_INCREASE_RISK')):
            raw, binding, envelope = self.historical_h(circuit, adapt_source=True)
            value = self.gate(raw, binding, envelope)
            risks = [row for row in value['reviewed'] if row['category'] == kind]
            self.assertTrue(risks)
            self.assertTrue(all('RISK_NOT_HARMLESSNESS' in row['disposition'] for row in risks))
            with self.assertRaisesRegex(ValueError, 'EXACT_GENERATION_PHASES'):
                self.gate(b'MAPPED_COMMON_ATPG_STATUS=PASS\n', binding, envelope)

    def test_known_post_messages_mf_application_is_explicit_policy_inference(self):
        # Historical M/F logs establish startup only. This assembled message is synthetic.
        for mode in ('M','F'):
            binding, envelope = self.context('spi', mode)
            rows, _, _ = m.extract(self.sources['spi:'+mode], b.pins.LIBRARY)
            blocks = [base64.b64decode(row['block_base64']).replace(m.LIBRARY_TOKEN,
                      envelope['env']['CELL_LIBRARY'].encode('ascii')) for row in rows if row['phase'] == 'STARTUP']
            raw = b'\n//  --- synthetic block boundary\n'.join(blocks)+b'\n//  command: read_faults $common_source -show_warnings\n//  command: read_faults $status -merge -show_warnings\n'+\
                b'//  command: create_patterns -compaction_effort High -coverage_effort High\n'+\
                base64.b64decode(self.policy['generation']['UNSUCCESSFUL_SEARCH_PHASE'])+b'\n//  command: report_statistics -detailed_analysis > [file join $out statistics.rpt]\n'
            value = self.gate(raw, binding, envelope)
            self.assertTrue(value['passed'])
            self.assertTrue(value['outcome_risks_remain'])
            self.assertFalse(value['quality_harmlessness_proven'])

    def test_generation_extra_continuation_not_silently_truncated(self):
        raw, binding, envelope = self.historical_h('aes_core', adapt_source=True)
        block = base64.b64decode(self.policy['generation']['SPLIT_CAPTURE_COST_NOTICE'])
        raw = raw.replace(block, block+b'\n// | Additional unreviewed restriction applies. |')
        with self.assertRaisesRegex(ValueError, 'BLOCK_CHANGED'):
            self.gate(raw, binding, envelope)

    def test_import_order_and_exact_frozen_import_syntax(self):
        raw, binding, envelope = self.historical_h('aes_core', adapt_source=True)
        command = b'//  command: read_faults $source -show_warnings'
        create = b'//  command: create_patterns -compaction_effort High -coverage_effort High'
        for changed in (raw.replace(command, b'//  command: read_faults wrong -show_warnings'),
                        raw.replace(command, b'// moved import').replace(create, create+b'\n'+command)):
            with self.assertRaisesRegex(ValueError, 'FROZEN_IMPORT_GENERATION_REPORT_ORDER'):
                self.gate(changed, binding, envelope)

    def test_invalid_file_and_pin_path_spelling_variants(self):
        raw, binding, envelope = self.historical_h('aes_core', adapt_source=True)
        for message in (b'Invalid file path /x', b'Invalid pin-pathname /x', b'Invalid pin_pathname /x'):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, 'ACTUAL_ERROR'):
                self.gate(raw+b'\n'+message, binding, envelope)

    def test_policy_tcl_sixprofile_and_library_pins_not_guessed(self):
        for mutate in (lambda p:p['startup'].pop('spi:F'),
                       lambda p:p.update(library_sha256='0'*64),
                       lambda p:p['effective_tcl_base64'].update(H=base64.b64encode(b'guessed').decode('ascii'))):
            policy = copy.deepcopy(self.policy)
            mutate(policy)
            with self.assertRaises(ValueError):
                m.build_gate(b.control.encode(policy))

    def test_builder_refuses_wrong_received_body_and_nonidentical_duplicate(self):
        with self.assertRaisesRegex(ValueError, 'COMPLETE_RECEIVED_FILE_BYTES_SHA'):
            b._body(dict(bytes=2, sha256='0'*64, body_b64='eA=='), 'body_b64')
        original_extract = b.diagnostic.extract
        def changed(*args):
            rows, imports, creates = original_extract(*args)
            for row in rows:
                if row['category'] == 'SPLIT_CAPTURE_COST_NOTICE' and b'spi' in args[0][:1000]:
                    row['block_base64'] = base64.b64encode(b'changed').decode('ascii')
            return rows, imports, creates
        with mock.patch.object(b.diagnostic, 'extract', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'DUPLICATE_GENERATION_BLOCK_CHANGED'):
                b.build()

    def test_python36_module_builder_and_tests(self):
        for path in (Path(m.__file__), Path(b.__file__), Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 6))


if __name__ == '__main__':
    unittest.main()
