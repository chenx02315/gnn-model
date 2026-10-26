"""Tiny local E117 fixtures only; no tool execution or physical ATPG claims."""
import ast
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from src.data import prospective_generation_artifacts_e117 as m
from tests.test_preparation_probe_e112 import StablePosixFakeIO
from tests.test_prospective_acquisition_result_integration_e107 import Outputs


class PhysicalReads(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'tree'
        self.root.mkdir()
        self.fake = StablePosixFakeIO(self.root)
        self.tick = mock.Mock()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(m.recipe, 'ROOT', '/tree').start()
        mock.patch.object(m.io.sys, 'platform', 'linux').start()

    def put(self, raw):
        path = self.root / 'artifact'
        path.write_bytes(raw)
        return path, dict(path='/tree/artifact', bytes=len(raw), sha256=m.sha(raw))

    def test_complete_hash_not_prefix_and_discard_body(self):
        raw = b'a' * 65536 + b'last-byte'
        _, pin = self.put(raw)
        with self.fake.installed():
            kept, receipt = m.read_file(pin['path'], len(raw), self.tick, expected=pin)
            discarded, second = m.read_file(pin['path'], len(raw), self.tick, keep=False)
        self.assertEqual(kept, raw)
        self.assertEqual(receipt, pin)
        self.assertEqual(second, pin)
        self.assertIsNone(discarded)
        self.assertNotEqual(pin['sha256'], m.sha(raw[:65536]))
        self.assertGreaterEqual(self.tick.call_count, 8)

    def test_missing_empty_oversize_and_expected_pin_rejected(self):
        with self.fake.installed():
            with self.assertRaises(FileNotFoundError):
                m.read_file('/tree/missing', 8, self.tick)
        for raw, cap, expected in ((b'', 8, None), (b'123', 2, None),
                                   (b'123', 8, dict(path='/tree/artifact', bytes=4, sha256='0'*64)),
                                   (b'123', 8, dict(path='/tree/artifact', bytes=3, sha256='0'*64))):
            self.put(raw)
            with self.subTest(raw=raw, expected=expected), self.fake.installed():
                with self.assertRaises(ValueError):
                    m.read_file('/tree/artifact', cap, self.tick, expected=expected)

    def test_symlink_and_real_hardlink_rejected(self):
        path, _ = self.put(b'abc')
        self.fake.links.add(path)
        with self.fake.installed(), self.assertRaises((ValueError, OSError)):
            m.read_file('/tree/artifact', 8, self.tick)
        self.fake.links.clear()
        os.link(str(path), str(self.root / 'alias'))
        with self.fake.installed(), self.assertRaisesRegex(ValueError, 'SINGLE_LINK'):
            m.read_file('/tree/artifact', 8, self.tick)

    def test_short_read_and_same_size_mutation_rejected(self):
        path, _ = self.put(b'abc')
        with self.fake.installed(), mock.patch.object(m.os, 'read', return_value=b''):
            with self.assertRaisesRegex(ValueError, 'SHORT_READ'):
                m.read_file('/tree/artifact', 8, self.tick)
        original = self.fake.read
        def mutate(fd, size):
            raw = original(fd, size)
            path.write_bytes(b'xyz')
            return raw
        with self.fake.installed(), mock.patch.object(m.os, 'read', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'CHANGED'):
                m.read_file('/tree/artifact', 8, self.tick)

    def test_full_stil_split_markers_duplicate_annotations_and_bad_hash(self):
        raw = b'STIL 1.0;\n// TesterCycle:9\nAnn {* TesterCycle:9 *}\n// TesterCycle:40\n'
        _, pin = self.put(raw)
        original = self.fake.read
        with self.fake.installed(), mock.patch.object(m.os, 'read', side_effect=lambda fd, n: original(fd, min(n, 3))):
            result = m.scan_stil_file(pin, self.tick)
        self.assertEqual(result['annotation_records'], 3)
        self.assertEqual(result['maximum_reported_tester_cycle'], 40)
        self.assertTrue(result['whole_file_consumed'])
        self.assertFalse(result['stil_semantics_qualified'])
        for bad in (dict(pin, bytes=len(raw)-1), dict(pin, sha256=m.sha(raw[:20]))):
            with self.fake.installed(), self.assertRaises(ValueError):
                m.scan_stil_file(bad, self.tick)

    def test_stil_short_read_refuses_partial_summary(self):
        _, pin = self.put(b'// TesterCycle:1\n')
        with self.fake.installed(), mock.patch.object(m.os, 'read', return_value=b''):
            with self.assertRaisesRegex(ValueError, 'SHORT_READ'):
                m.scan_stil_file(pin, self.tick)


class CallbackTests(unittest.TestCase):
    def setUp(self):
        self.recipe = m.recipe
        self.plan = self.recipe.pilot.build_plan()
        self.mapping = Outputs({}).mapping
        manifest = dict(schema='multimode_common_fault_universe_v1', fault_model='stuck-at',
                        common_fault_count=20, f_flat_instance_offset=1,
                        mapping=dict(sha256=m.sha(self.mapping)))
        manifest_raw = m.canonical(manifest)
        self.freeze = self.recipe.requests.freeze_acquisition(self.plan, 'aes_core', 20, m.sha(manifest_raw))
        self.binder = self.recipe.bindings.Binder(self.plan, 'aes_core', self.freeze, 'e117-local')
        templates = Path(m.__file__).parent / 'templates'
        self.sources = self.recipe.freeze_sources((templates/'e108_common_base.tcl').read_bytes(),
                                                 (templates/'e108_incremental_base.tcl').read_bytes())
        common = self.recipe.ROOT+'/aes_core/03_fault_universe/common_frozen/'
        self.common = common
        self.files = {common+'manifest.json': manifest_raw, common+'canonical_fault_mapping.tsv': self.mapping}
        for mode in ('H', 'M', 'F'):
            self.files[common+mode+'_common_initial_faults.basic'] = ''.join(
                '0 FU "/U%d/p"\n'%((9 if mode == 'F' else 10)+i) for i in range(20)).encode('ascii')
        pins = {path[len(common):]: dict(bytes=len(raw), sha256=m.sha(raw)) for path, raw in self.files.items()}
        self.published = []
        self.maker = SimpleNamespace(common={'aes_core': pins}, _publish=self.publish, sources=self.sources)
        self.art = m.Artifacts(self.maker, lambda *args: dict(passed=True, scope='SYNTHETIC_TEST_REVIEW'))
        self.art._read = self.read
        self.art._tick = mock.Mock()
        self.ctx = dict(sample=mock.Mock())
        self.nodes = self.plan['phases'][0]['tasks'][:3]
        self.fixture = Outputs({})

    def publish(self, path, raw):
        if path in self.files:
            raise FileExistsError(path)
        self.files[path] = raw
        self.published.append((path, raw))

    def read(self, path, cap, ctx, keep=True, expected=None):
        raw = self.files[path]
        self.assertLessEqual(len(raw), cap)
        pin = dict(path=path, bytes=len(raw), sha256=m.sha(raw))
        if expected is not None:
            self.assertEqual(pin, expected)
        return (raw if keep else None), pin

    def commit(self, binding, raw):
        self.binder.commit_next(binding, dict(task_uid=binding['task_uid'], binding_sha256=binding['binding_sha256'],
            output_sha256=m.sha(raw), status='SUCCESS', live_acknowledged_claim=True,
            output_authenticated_claim=True), raw)

    def stats(self, count, patterns=True):
        return ('Statistics Report\nFault Classes #faults\n FU (full) 20\n DS (det_simulation) %d\n'
                ' DI (det_implication) 0\n RE (redundant) %d\nFault Sub-classes\nCoverage\n'%
                (count, 20-count) + ('#test_patterns 1\n' if patterns else '')).encode('ascii')

    def stage(self, binding, count):
        env = self.recipe.compile_execution(self.freeze, binding, self.sources)
        mode = env['stage']
        key = 'MAPPED_COMMON_ATPG' if mode == 'H' else 'MAPPED_INCREMENTAL'
        control = binding['request']['control']
        markers = {key+('_STATUS' if mode == 'H' else '_ATPG_STATUS'): 'PASS',
                   key+'_MODE': mode, key+'_RUN_ID': binding['task_uid']}
        markers['ATPG_TEST_COVERAGE_LIMIT' if control['kind'] == 'COVERAGE_PERCENT' else 'ATPG_PATTERN_LIMIT'] = str(control['value'])
        if mode != 'H':
            markers[key+'_TRANSLATED_STATUS_FILE'] = env['env']['STATUS_FILE']
            markers[key+'_TRANSLATION_MANIFEST'] = env['env']['STATUS_TRANSLATION_MANIFEST']
            self.files[env['pre_statistics_path']] = self.stats(10, False)
        for role, path in env['output_paths'].items():
            self.files[path] = (self.stats(count) if role == 'statistics' else self.fixture.mtfi(mode, count)
                                if role == 'mtfi' else b'// TesterCycle:40\n' if role == 'stil' else b'tiny report\n')
        observed = dict(cleaned=True, returncode=0, failure=None,
                        output=''.join(k+'='+v+'\n' for k, v in sorted(markers.items())).encode('ascii'))
        return env, observed

    def execute_stage(self, binding, envelope, observed):
        def scan(pin, tick):
            raw = self.files[pin['path']]
            return m.reports.scan_stil([raw], len(raw), m.sha(raw), tick)
        with mock.patch.object(m, 'scan_stil_file', side_effect=scan):
            return self.art.read_artifacts(binding, self.freeze, envelope, observed, self.ctx)

    def h(self):
        binding = self.binder.bind_next(self.nodes[0]['task_uid'])
        env, observed = self.stage(binding, 10)
        raw, receipt = self.execute_stage(binding, env, observed)
        self.commit(binding, raw)
        return binding, raw, receipt

    def translation(self):
        _, parent, _ = self.h()
        binding = self.binder.bind_next(self.nodes[1]['task_uid'])
        prereq = self.recipe.ROOT+'/aes_core/runs/e117-local/attempts/_prereq/'+self.nodes[2]['task_uid']
        prep = dict(mapping=self.common+'canonical_fault_mapping.tsv',
                    target_native_common_faults=self.common+'F_common_initial_faults.basic',
                    output_status_file=prereq+'/translated_status.mtfi',
                    output_manifest=prereq+'/translation_manifest.json')
        raw, receipt = self.art.run_translation(binding, self.freeze, prep, parent, self.ctx)
        self.commit(binding, raw)
        return binding, prep, raw, receipt

    def f(self):
        _, prep, translation, _ = self.translation()
        binding = self.binder.bind_next(self.nodes[2]['task_uid'])
        env, observed = self.stage(binding, 19)
        self.assertEqual(json.loads(translation)['artifacts']['status']['path'], prep['output_status_file'])
        self.assertEqual(env['env']['STATUS_FILE'], prep['output_status_file'])
        self.assertEqual(env['env']['STATUS_TRANSLATION_MANIFEST'], prep['output_manifest'])
        return binding, env, observed

    def test_three_task_binder_references_union_set_dedup_and_no_release(self):
        with mock.patch('subprocess.Popen') as spawn:
            binding, env, observed = self.f()
            raw, receipt = self.execute_stage(binding, env, observed)
            self.commit(binding, raw)
            spawn.assert_not_called()
        value = json.loads(raw)
        self.assertEqual(self.binder.snapshot()['next_slot'], 3)
        self.assertEqual(value['action_union']['explicit_conservative_ds_di_union_count'], 19)
        self.assertTrue(value['action_union']['mathematical_d95'])
        self.assertFalse(value['action_union']['d95_verified'])
        self.assertFalse(receipt['d95_verified'])
        self.assertIsNone(value['actual_atpg_runtime_ns'])
        self.assertFalse(value['training_release'])
        self.assertEqual(binding['parent_result_sha256'], m.sha(self.art.references[self.nodes[0]['task_uid']]))
        self.assertEqual(binding['translation_result_sha256'], m.sha(self.art.references[self.nodes[1]['task_uid']]))
        self.assertNotEqual(binding['parent_result_sha256'], value['artifacts']['mtfi']['sha256'])
        self.assertIsNone(self.art.action)

    def test_translation_native_hashes_immutable_publish_and_readback(self):
        binding, prep, raw, _ = self.translation()
        value = json.loads(raw)
        parent = json.loads(self.art.references[self.nodes[0]['task_uid']])
        self.assertEqual(value['parent_native_mtfi'], parent['artifacts']['mtfi'])
        self.assertNotEqual(value['parent_native_mtfi']['sha256'], binding['parent_result_sha256'])
        self.assertEqual(value['expected_minimum_pre_detected'], 10)
        self.assertEqual(len(self.published), 2)
        for path, published in self.published:
            self.assertEqual(self.files[path], published)
        with self.assertRaises(FileExistsError):
            self.art.run_translation(binding, self.freeze, prep,
                                     self.art.references[self.nodes[0]['task_uid']], self.ctx)

    def test_translation_bad_parent_and_wrong_mode_mapping_rejected(self):
        binding, prep, _, _ = self.translation()
        parent = self.art.references[self.nodes[0]['task_uid']]
        with self.assertRaisesRegex(ValueError, 'TRANSLATION_PARENT'):
            self.art.run_translation(binding, self.freeze, prep, parent+b' ', self.ctx)
        pin = json.loads(parent)['artifacts']['mtfi']
        changed = self.files[pin['path']].replace(b'/U10/p', b'/U999/p')
        self.files[pin['path']] = changed
        # Preserve readback pin checking: stale pinned bytes must fail first.
        with self.assertRaises(AssertionError):
            self.art.run_translation(binding, self.freeze, prep, parent, self.ctx)

    def test_translation_corrupt_published_readback_never_finishes_reference(self):
        _, parent, _ = self.h()
        binding = self.binder.bind_next(self.nodes[1]['task_uid'])
        prep = dict(mapping=self.common+'canonical_fault_mapping.tsv',
                    target_native_common_faults=self.common+'F_common_initial_faults.basic',
                    output_status_file=self.recipe.ROOT+'/corrupt-output.mtfi',
                    output_manifest=self.recipe.ROOT+'/corrupt-output.json')
        def corrupt(path, raw):
            self.publish(path, raw+b'corrupted')
        self.maker._publish = corrupt
        with self.assertRaises(AssertionError):
            self.art.run_translation(binding, self.freeze, prep, parent, self.ctx)
        self.assertNotIn(binding['task_uid'], self.art.references)
        self.assertNotIn(binding['task_uid'], self.art.translations)

    def test_incremental_pre_statistics_missing_and_below_minimum_rejected(self):
        binding, env, observed = self.f()
        path = env['pre_statistics_path']
        del self.files[path]
        with self.assertRaises(KeyError):
            self.execute_stage(binding, env, observed)
        self.files[path] = self.stats(9, False)
        with self.assertRaisesRegex(ValueError, 'INHERITED_DETECTION_MINIMUM'):
            self.execute_stage(binding, env, observed)
        self.files[path] = self.stats(10, False).replace(b'FU (full) 20', b'FU (full) 21')
        with self.assertRaisesRegex(ValueError, 'CLASS_PARTITION_AND_COMMON_COUNT'):
            self.execute_stage(binding, env, observed)
        self.assertNotIn(binding['task_uid'], self.art.references)

    def test_requested_control_not_assumed_realized_and_complete_table_required(self):
        binding = self.binder.bind_next(self.nodes[0]['task_uid'])
        env, observed = self.stage(binding, 10)
        path = env['output_paths']['statistics']
        self.files[path] = self.stats(10).split(b'Coverage')[0]
        with self.assertRaisesRegex(ValueError, 'REQUIRED_STATISTICS_FIELDS'):
            self.execute_stage(binding, env, observed)
        self.assertNotIn(binding['task_uid'], self.art.references)
        self.files[path] = self.stats(10).replace(b'#test_patterns 1', b'#test_patterns 2')
        raw, metadata = self.execute_stage(binding, env, observed)
        result = json.loads(raw)
        self.assertEqual(result['requested_control']['value'], 1)
        self.assertEqual(result['statistics']['generated_patterns'], 2)
        self.assertFalse(result['requested_vs_realized_equivalence_verified'])

    def test_wrong_mode_mtfi_rejected(self):
        binding, env, observed = self.f()
        self.files[env['output_paths']['mtfi']] = self.fixture.mtfi('H', 19)
        with self.assertRaisesRegex(ValueError, 'SOURCE_EXTRA_OR_WRONG_MODE'):
            self.execute_stage(binding, env, observed)

    def test_explicit_native_detection_cannot_exceed_reported_detection(self):
        binding = self.binder.bind_next(self.nodes[0]['task_uid'])
        env, observed = self.stage(binding, 10)
        self.files[env['output_paths']['statistics']] = self.stats(0)
        with self.assertRaisesRegex(ValueError, 'EXPLICIT_DETECTED_SUBSET_EXCEEDS'):
            self.execute_stage(binding, env, observed)

    def test_unknown_diagnostic_and_failed_observation_rejected(self):
        binding = self.binder.bind_next(self.nodes[0]['task_uid'])
        env, observed = self.stage(binding, 10)
        self.art.diagnostic_gate = lambda *args: dict(passed=False, unknown=['warning'])
        with self.assertRaisesRegex(ValueError, 'UNREVIEWED_DIAGNOSTIC'):
            self.execute_stage(binding, env, observed)
        for field, value in (('cleaned', False), ('returncode', 1), ('failure', 'TIMEOUT')):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'SUCCESSFUL_OBSERVATION'):
                self.execute_stage(binding, env, dict(observed, **{field: value}))

    def test_driver_exact_markers_error_unknown_duplicate_and_indent(self):
        binding = self.binder.bind_next(self.nodes[0]['task_uid'])
        env, observed = self.stage(binding, 10)
        raw = observed['output']
        self.assertEqual(m.validate_driver(raw, binding, env)['sha256'], m.sha(raw))
        for bad in (raw+b'ERROR\n', raw+b'fatal\n', raw+b'invalid pin_pathname\n',
                    raw+b'ATPG_UNKNOWN=1\n', raw+raw.splitlines()[0]+b'\n',
                    b' '+raw, b'\n'.join(raw.splitlines()[1:])+b'\n'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                m.validate_driver(bad, binding, env)

    def test_python36_source_and_tests(self):
        for path in (Path(m.__file__), Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 6))


if __name__ == '__main__':
    unittest.main()
