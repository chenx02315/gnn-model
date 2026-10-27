"""Pinned offline bundle checks and inert full-plan mocks, never remote/EDA."""
import ast
import base64
import copy
from contextlib import contextmanager
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

from src.data import prospective_pt_label_bundle_e127 as m

BOOT = '12345678-1234-1234-1234-123456789abc'
WORKER = b'"""Inert E127 worker fixture."""\n'


@contextmanager
def inert(bundle, authority):
    with mock.patch.dict(sys.modules):
        src, data = types.ModuleType('src'), types.ModuleType('src.data')
        src.__path__, data.__path__, src.data = [], [], data
        sys.modules['src'], sys.modules['src.data'] = src, data
        modules = {}
        for row in bundle['sources']:
            raw = base64.b64decode(row['body'], validate=True)
            assert m.sha(raw) == row['sha256']
            module = types.ModuleType('src.data.' + row['name'])
            module.__package__ = 'src.data'
            if row['name'] == m.CONTEXT_NAME:
                module.__runtime_context__ = dict(authority_bytes=authority, boot_id=BOOT,
                    start_monotonic=100.0, current_monotonic=101.0)
            sys.modules[module.__name__] = module
            setattr(data, row['name'], module)
            exec(compile(raw, '<inert-' + row['name'] + '>', 'exec'), module.__dict__)
            module.__source_sha256__ = row['sha256']
            modules[row['name']] = module
        yield modules


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.authority = (cls.repo / 'contracts/prospective_pt_label_repair_authorization_e127_20261027.json').read_bytes()
        assert m.sha(cls.authority) == m.AUTH_SHA256
        cls.bundle = m.build_sources(worker_source_bytes=WORKER)
        cls.old = m.predecessor.build_sources()
        cls.common = (cls.repo / 'src/data/templates/e108_common_base.tcl').read_bytes()
        cls.incremental = (cls.repo / 'src/data/templates/e108_incremental_base.tcl').read_bytes()
        raw = (cls.repo.parent / 'runtime_training_staging_20260928/v6_e125_failure_readback_20261027_r1/stdout.json').read_bytes()
        assert m.sha(raw) == 'b5765db14b6f9ae3ab0a0d19791723badc693e113d6c1af4ed0817c72a2fdbac'
        row = next(row for row in json.loads(raw)['files'] if row['path'].endswith('/statistics.rpt'))
        cls.stats = base64.b64decode(row['body_base64'], validate=True)
        assert len(cls.stats) == 2681 and m.sha(cls.stats) == '6a2c43dda14dc5c383ef50312b1af4682908db9649b1a5a13a29016e0094903d'

    def test_exact_reviewed_35_baseline_and_ordered_36_source_allowlist(self):
        rows = self.bundle['sources']
        names = [row['name'] for row in rows]
        expected = m.ALLOWLIST | {m.CONTEXT_NAME, m.WORKER_NAME, 'prospective_tool_identifiers_e123'}
        self.assertEqual(len(m.ALLOWLIST), 33)
        self.assertEqual(len(names), 36)
        self.assertEqual(len(set(names)), 36)
        self.assertEqual(set(names), expected)
        self.assertNotIn(m.predecessor.CONTEXT_NAME, names)
        self.assertNotIn(m.predecessor.WORKER_NAME, names)
        self.assertLess(names.index('prospective_report_dialect_e115'), names.index(m.PARSER_NAME))
        self.assertLess(names.index(m.PARSER_NAME), names.index('prospective_generation_artifacts_e117'))
        self.assertLess(names.index(m.CONTEXT_NAME), names.index('prospective_generation_controller_e116'))
        self.assertEqual(names[-1], m.WORKER_NAME)

    def test_closed_four_module_derivation_and_exact_audit_ranges(self):
        changed = {row['name'] for row in self.bundle['manifest']['sources']
                   if row['changed'] and row['name'] not in (m.predecessor.CONTEXT_NAME, m.predecessor.WORKER_NAME)}
        self.assertEqual(changed, {'prospective_generation_recipe_e108', 'prospective_generation_controller_e116',
            'prospective_generation_storage_e118', 'prospective_generation_artifacts_e117'})
        for row in self.bundle['manifest']['sources']:
            for edit in row['edits']:
                self.assertEqual(edit['actual_count'], edit['expected_count'])
                self.assertEqual(len(edit['allowed_byte_ranges']), edit['expected_count'])
            if row['changed']:
                self.assertTrue(row['unified_diff'])
        self.assertFalse(self.bundle['manifest']['run_uid_changed'])
        self.assertFalse(self.bundle['manifest']['runtime_run_id_changed'])

    def test_policy_changes_only_source_derivation_metadata_no_tcl_or_warning_changes(self):
        old, new = json.loads(self.old['policy_bytes']), json.loads(self.bundle['policy_bytes'])
        self.assertEqual({key for key in old if old[key] != new[key]}, {'execution_source_derivation'})
        self.assertEqual(new['effective_tcl_base64'], old['effective_tcl_base64'])
        self.assertEqual(new['startup'], old['startup'])
        self.assertEqual(new['generation'], old['generation'])
        self.assertEqual(self.bundle['tool_identifier_manifest'], self.old['tool_identifier_manifest'])
        with inert(self.bundle, self.authority) as modules:
            self.assertTrue(callable(modules['prospective_generation_diagnostics_e120'].build_gate(self.bundle['policy_bytes'])))

    def test_report_dependency_uses_actual_e125_bytes_and_never_changes_old_labels(self):
        with mock.patch('subprocess.Popen') as spawn, inert(self.bundle, self.authority) as modules:
            old = modules['prospective_report_dialect_e115']
            new = modules[m.PARSER_NAME]
            artifacts = modules['prospective_generation_artifacts_e117']
            self.assertIs(artifacts.reports, new)
            self.assertEqual(old.LABELS['PT'], 'possibly_testable')
            self.assertEqual(new.LABELS['PT'], 'posdet_testable')
            with self.assertRaisesRegex(ValueError, 'CLASS_LABEL_OR_DUPLICATE'):
                old.parse_statistics(self.stats, 71216)
            result = artifacts.reports.parse_statistics(self.stats, 71216)
            self.assertEqual(result['detected_common_faults'], 18323)
            self.assertEqual(result['classes']['PT'], 64)
            self.assertEqual(result['sha256'], m.sha(self.stats))
            spawn.assert_not_called()

    def test_all_48_envelopes_preserve_semantics_and_only_move_root_prefix(self):
        from tests.test_prospective_identifier_bundle_e124 import inert as old_inert, CONFIG, CONTEXT
        old_fixture = m.predecessor.build_sources(CONTEXT, WORKER)
        with old_inert(old_fixture) as old_modules:
            old_recipe = old_modules['prospective_generation_recipe_e108']
            old_sources = old_recipe.freeze_sources(self.common, self.incremental)
            old_compile = old_recipe.compile_execution
            with inert(self.bundle, self.authority) as modules:
                recipe = modules['prospective_generation_recipe_e108']
                sources = recipe.freeze_sources(self.common, self.incremental)
                self.assertEqual(sources, old_sources)
                count = 0
                for phase in recipe.pilot.build_plan()['phases']:
                    freeze = recipe.requests.freeze_acquisition(recipe.pilot.build_plan(), phase['circuit'], 20, 'a' * 64)
                    binder = recipe.bindings.Binder(recipe.pilot.build_plan(), phase['circuit'], freeze, 'e116-' + phase['circuit'])
                    for task in phase['tasks']:
                        binding = binder.bind_next(task['task_uid'])
                        if task['kind'] == 'TESSENT':
                            expected = old_compile(freeze, binding, old_sources)
                            actual = recipe.compile_execution(freeze, binding, sources)
                            # Envelope root, relocated paths and envelope digest are
                            # the only differences; semantic hashes remain exact.
                            normalized = copy.deepcopy(actual)
                            def replace(value):
                                if type(value) is str:
                                    return value.replace(m.ROOT, m.predecessor.ROOT)
                                if type(value) is list:
                                    return [replace(item) for item in value]
                                if type(value) is dict:
                                    return {key: replace(item) for key, item in value.items()}
                                return value
                            normalized = replace(normalized)
                            normalized.pop('envelope_sha256')
                            expected.pop('envelope_sha256')
                            self.assertEqual(normalized, expected)
                            self.assertEqual(actual['env']['RUN_ID'], task['task_uid'])
                            count += 1
                        raw = task['task_uid'].encode('ascii')
                        binder.commit_next(binding, dict(task_uid=task['task_uid'], binding_sha256=binding['binding_sha256'],
                            output_sha256=m.sha(raw), status='SUCCESS', live_acknowledged_claim=True,
                            output_authenticated_claim=True), raw)
                self.assertEqual(count, 48)

    def test_full_78_task_mock_uses_derived_sources_real_auth_and_report_binding(self):
        repo = self.repo
        raw_inputs = [(repo / ('data/manifests/ranking_v6_' + key + '_input_observation_20261023_r1.json')).read_bytes()
                      for key in ('e85', 'e88', 'e93')]
        e112 = (repo.parent / 'runtime_training_staging_20260928/v6_e112_preparation_20261026_r1/stdout.json').read_bytes()
        with inert(self.bundle, self.authority) as modules:
            recipe = modules['prospective_generation_recipe_e108']
            controller = modules['prospective_generation_controller_e116']
            process = modules['prospective_generation_process_e113']
            observed, parsed = [], []
            class Maker(object):
                def __init__(self, r85, r88, r93, common, incremental, admit):
                    self.sources = recipe.freeze_sources(common, incremental)
                    recipe._sources(self.sources)
                    self.admit, self.e85 = admit, json.loads(r85)
                    self.common = {row['circuit']: row['files'] for row in json.loads(r88)['roots']}
                    self.files, self.preparations = {}, []
                def initialize_bundle(self):
                    self.admit({})
                def _mkdir(self, path):
                    pass
                def _publish(self, path, raw):
                    if path in self.files:
                        raise FileExistsError()
                    self.files[path] = raw
                    return dict(path=path, bytes=len(raw), sha256=m.sha(raw))
                def materialize_attempt(self, freeze, binding):
                    self.admit({})
                    self.preparations.append(recipe.compile_execution(freeze, binding, self.sources))
                    return dict(prereq_dir=recipe.ROOT + '/' + binding['circuit'] + '/runs/' +
                        binding['request']['run_uid'] + '/attempts/_prereq/' + binding['task_uid'])
                def prepare_translation(self, freeze, binding):
                    self.admit({})
                    return {}
                def close(self):
                    pass
            def reference(binding, *args):
                if binding['task_uid'] == 'aes_core:HF:h1:H':
                    parsed.append(modules['prospective_generation_artifacts_e117'].reports.parse_statistics(self.stats, 71216))
                return m.canonical(dict(uid=binding['task_uid'])), dict(binding_sha256=binding['binding_sha256'],
                    validation_passed=True, output_authenticated_claim=True)
            def observe(launch, end, domain, budget, on_spawn, monitor):
                identity = dict(schema=process.IDENTITY_SCHEMA, boot_id=BOOT,
                    launch_spec_sha256=launch['launch_spec_sha256'], environment_sha256=launch['environment_sha256'],
                    effective_envelope_sha256=launch['effective_envelope_sha256'])
                identity['identity_sha256'] = m.sha(m.canonical(identity))
                on_spawn(identity)
                result = dict(schema=process.SCHEMA, launch_spec_sha256=launch['launch_spec_sha256'],
                    environment_sha256=launch['environment_sha256'], effective_envelope_sha256=launch['effective_envelope_sha256'],
                    launch_attempted=True, known_process_handle=True, returncode=0, failure=None, cleaned=True,
                    output=b'EXPLICIT_UNIT_TEST_MOCK', spawn_identity=identity,
                    spawn_identity_persisted_claim=True, physical_process_identity_observed=True)
                observed.append(result)
                return result
            monitor = mock.Mock()
            monitor.sample.return_value = dict(root=m.ROOT, sidecar=m.ROOT + '.initial_intent.json',
                sidecar_accounted=True, threshold_bytes=8589934592, sampled_named_bytes=1)
            selftests = lambda ctx: [dict(case=name, passed=True, cleaned=True, authenticated_claim=True,
                actual_linux_process=True) for name in ('success', 'timeout', 'setsid_child')]
            with mock.patch('subprocess.Popen') as spawn, \
                    mock.patch.object(controller.material, 'Materializer', Maker), \
                    mock.patch.object(controller.material, '_hash_file', side_effect=lambda path, count:
                        dict(path=path, bytes=count, sha256=controller.material.pins.LAUNCHER_SHA256)), \
                    mock.patch.object(controller.runtime, 'prepare_runtime', return_value=({'PATH': '/usr/bin:/bin'}, {})), \
                    mock.patch.object(process.direct, 'Descendants', return_value=mock.Mock(peak=1)), \
                    mock.patch.object(process, '_check_worker'), \
                    mock.patch.object(process, '_boot_id', return_value=BOOT), \
                    mock.patch.object(process, 'observe_tessent', side_effect=observe), \
                    mock.patch.object(controller.sys, 'platform', 'linux'), \
                    mock.patch.object(controller.platform, 'node', return_value='bupt-vncs2'), \
                    mock.patch.object(controller.os, 'getuid', return_value=1047, create=True), \
                    mock.patch.object(controller.time, 'monotonic', return_value=101):
                obj = controller.Controller(self.authority, e112, *(raw_inputs + [self.common, self.incremental, {},
                    lambda raw: dict(path=m.ROOT + '.initial_intent.json', bytes=len(raw), sha256=m.sha(raw)),
                    selftests, monitor, reference, reference,
                    dict(implementation_review_passed_claim=True, independent_review_passed_claim=True)]))
                summary = obj.run()
                spawn.assert_not_called()
            self.assertEqual(summary['status'], 'FIXED_78_TASKS_COLLECTED', summary['error'])
            self.assertEqual(summary['counts']['committed_tasks'], 78)
            self.assertEqual(summary['counts']['translation_debited'], 30)
            self.assertEqual(len(observed), 48)
            self.assertEqual(parsed[0]['detected_common_faults'], 18323)
            self.assertEqual(parsed[0]['classes']['PT'], 64)
            self.assertEqual(controller.AUTH_SHA256, m.AUTH_SHA256)
            self.assertEqual(summary['original_package_start'], 100)
            self.assertEqual(summary['original_package_deadline'], 50500)
            for envelope in obj.maker.preparations:
                self.assertIn('/runs/e116-', envelope['result_dir'])
                self.assertIn(':', envelope['env']['RUN_ID'])

    def test_e124_origin_body_map_or_manifest_drift_is_rejected(self):
        for mutate in (lambda b: b['sources'][0].update(sha256='0' * 64),
                       lambda b: b['sources'][0].update(body=base64.b64encode(b'changed').decode('ascii')),
                       lambda b: b['manifest'].update(manifest_sha256='0' * 64)):
            bad = copy.deepcopy(self.old)
            mutate(bad)
            with mock.patch.object(m.predecessor, 'build_sources', return_value=bad):
                with self.assertRaises(ValueError):
                    m.build_sources(worker_source_bytes=WORKER)

    def test_no_old_file_or_global_changes_and_all_sources_python36(self):
        old_root = m.predecessor.ROOT
        before = (self.repo / 'src/data/prospective_identifier_bundle_e124.py').read_bytes()
        with mock.patch('subprocess.Popen') as spawn:
            m.build_sources(worker_source_bytes=WORKER)
            spawn.assert_not_called()
        self.assertEqual(m.predecessor.ROOT, old_root)
        self.assertEqual((self.repo / 'src/data/prospective_identifier_bundle_e124.py').read_bytes(), before)
        for row in self.bundle['sources']:
            ast.parse(base64.b64decode(row['body']).decode('utf-8'), feature_version=(3, 6))
        for path in ('src/data/prospective_pt_label_bundle_e127.py', 'tests/test_prospective_pt_label_bundle_e127.py'):
            ast.parse((self.repo / path).read_text(), feature_version=(3, 6))
