"""Offline source derivation and inert module loads; no process or deployment."""
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

from src.data import prospective_identifier_bundle_e124 as m


CONFIG = dict(AUTH_SHA256=m.AUTH_SHA256, BOOT_ID='12345678-1234-1234-1234-123456789abc',
              PACKAGE_START=100.0, PACKAGE_END=50500.0, ROOT=m.ROOT,
              SIDECAR=m.ROOT + '.initial_intent.json')
CONTEXT = ('from types import MappingProxyType\nCONFIG = MappingProxyType(' + repr(CONFIG) + ')\n').encode('ascii')
WORKER = b'"""Inert test worker. No execution on import."""\n'


@contextmanager
def inert(bundle, runtime_context=None):
    with mock.patch.dict(sys.modules):
        src = types.ModuleType('src')
        data = types.ModuleType('src.data')
        src.__path__, data.__path__, src.data = [], [], data
        sys.modules['src'], sys.modules['src.data'] = src, data
        modules = {}
        for row in bundle['sources']:
            name = 'src.data.' + row['name']
            module = types.ModuleType(name)
            module.__package__ = 'src.data'
            if row['name'] == m.CONTEXT_NAME and runtime_context is not None:
                module.__runtime_context__ = runtime_context
            raw = base64.b64decode(row['body'], validate=True)
            if m.sha(raw) != row['sha256']:
                raise AssertionError('fixture source hash')
            sys.modules[name] = module
            setattr(data, row['name'], module)
            exec(compile(raw, '<inert-' + row['name'] + '>', 'exec'), module.__dict__)
            module.__source_sha256__ = row['sha256']
            modules[row['name']] = module
        yield modules


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.bundle = m.build_sources(CONTEXT, WORKER)
        cls.common = (cls.repo / 'src/data/templates/e108_common_base.tcl').read_bytes()
        cls.incremental = (cls.repo / 'src/data/templates/e108_incremental_base.tcl').read_bytes()

    def test_exact_whitelist_topology_origin_pins_and_no_backend(self):
        rows = self.bundle['sources']
        names = [row['name'] for row in rows]
        self.assertEqual(len(names), 35)
        self.assertEqual(len(set(names)), 35)
        self.assertEqual(set(names), m.ALLOWLIST | {m.CONTEXT_NAME, 'prospective_tool_identifiers_e123', m.WORKER_NAME})
        self.assertNotIn('e121_worker', names)
        self.assertTrue(all('e105' not in name and 'backend' not in name for name in names))
        for consumer in ('prospective_generation_controller_e116', 'prospective_generation_storage_e118'):
            self.assertLess(names.index(m.CONTEXT_NAME), names.index(consumer))
        self.assertLess(names.index('prospective_generation_recipe_e108'), names.index('prospective_generation_supervision_e109'))
        self.assertLess(names.index('prospective_generation_recipe_e108'), names.index('prospective_generation_materializer_e111'))
        self.assertEqual(names[-1], m.WORKER_NAME)
        for row in rows:
            raw = base64.b64decode(row['body'], validate=True)
            self.assertEqual(m.sha(raw), row['sha256'])

    def test_only_fixed_five_old_modules_derived_and_all_changes_audited(self):
        changed = {row['name'] for row in self.bundle['manifest']['sources'] if row['changed']}
        self.assertEqual(changed, {'prospective_generation_recipe_e108', 'prospective_generation_controller_e116',
            'prospective_generation_storage_e118', 'prospective_generation_artifacts_e117',
            'prospective_generation_diagnostics_e120'})
        for row in self.bundle['manifest']['sources']:
            for edit in row['edits']:
                self.assertEqual(edit['actual_count'], edit['expected_count'])
                self.assertEqual(len(edit['allowed_byte_ranges']), edit['expected_count'])
                self.assertEqual(len(edit['before_source_sha256']), 64)
                self.assertEqual(len(edit['after_source_sha256']), 64)
            if row['changed']:
                self.assertTrue(row['unified_diff'])

    def test_build_and_inert_load_never_modify_v1_files_globals_or_spawn(self):
        original_root = m.identifiers.recipe.ROOT
        before = {name: (self.repo / ('src/data/' + name + '.py')).read_bytes() for name in m.ALLOWLIST}
        with mock.patch('subprocess.Popen') as spawn:
            bundle = m.build_sources(CONTEXT, WORKER)
            with inert(bundle) as modules:
                self.assertEqual(modules['prospective_generation_recipe_e108'].ROOT, m.ROOT)
            spawn.assert_not_called()
        self.assertEqual(m.identifiers.recipe.ROOT, original_root)
        for name, raw in before.items():
            self.assertEqual((self.repo / ('src/data/' + name + '.py')).read_bytes(), raw)

    def test_derived_freeze_preserves_base_verification_but_accepts_only_repaired_bytes(self):
        with inert(self.bundle) as modules:
            recipe = modules['prospective_generation_recipe_e108']
            sources = recipe.freeze_sources(self.common, self.incremental)
            expected = m.identifiers.transform_sources(m.identifiers.recipe.freeze_sources(self.common, self.incremental))
            for name, row in sources.items():
                self.assertEqual(row['tcl_bytes'], expected['derived_sources'][name])
                self.assertEqual(row['base_sha256'], recipe.SOURCE_PINS[name][1])
                self.assertEqual(row['tcl_sha256'], recipe.EXECUTION_SOURCE_PINS[name][2])
            recipe._sources(sources)
            with self.assertRaises(ValueError):
                recipe.freeze_sources(self.common + b'\n', self.incremental)
            old = m.identifiers.recipe.freeze_sources(self.common, self.incremental)
            with self.assertRaises(ValueError):
                recipe._sources(old)

    def test_all_78_semantic_bindings_and_48_effective_envelopes_keep_uids_controls(self):
        with inert(self.bundle) as modules:
            recipe = modules['prospective_generation_recipe_e108']
            sources = recipe.freeze_sources(self.common, self.incremental)
            plan = recipe.pilot.build_plan()
            count, tessent = 0, 0
            for phase in plan['phases']:
                freeze = recipe.requests.freeze_acquisition(plan, phase['circuit'], 20, 'a' * 64)
                binder = recipe.bindings.Binder(plan, phase['circuit'], freeze, 'e124-test-' + phase['circuit'])
                for node in phase['tasks']:
                    binding = binder.bind_next(node['task_uid'])
                    before = copy.deepcopy(binding)
                    if node['kind'] == 'TESSENT':
                        envelope = recipe.compile_execution(freeze, binding, sources)
                        tessent += 1
                        self.assertTrue(envelope['result_dir'].startswith(m.ROOT + '/'))
                        self.assertEqual(envelope['env']['RUN_ID'], node['task_uid'])
                        self.assertIn(node['task_uid'], envelope['result_dir'])
                        self.assertEqual(binding, before)
                        self.assertIn('E123', envelope['transformation'])
                    raw = ('opaque fixture:' + node['task_uid']).encode('ascii')
                    binder.commit_next(binding, dict(task_uid=node['task_uid'], binding_sha256=binding['binding_sha256'],
                        output_sha256=recipe.sha(raw), status='SUCCESS', live_acknowledged_claim=True,
                        output_authenticated_claim=True), raw)
                    count += 1
            self.assertEqual((count, tessent), (78, 48))

    def test_new_execution_clock_and_auth_do_not_rewrite_old_e112_capture_gate(self):
        with inert(self.bundle) as modules:
            controller = modules['prospective_generation_controller_e116']
            self.assertEqual(controller.BOOT_ID, CONFIG['BOOT_ID'])
            self.assertEqual(controller.PACKAGE_START, 100)
            self.assertEqual(controller.PACKAGE_END, 50500)
            self.assertEqual(controller.AUTH_SHA256, m.AUTH_SHA256)
            self.assertEqual(modules['prospective_generation_storage_e118'].END, 50500)
            source = next(row for row in self.bundle['sources'] if row['name'] == 'prospective_generation_controller_e116')
            raw = base64.b64decode(source['body']).decode('ascii')
            self.assertIn("prep.get('boot_id') == '" + m.OLD_BOOT + "'", raw)
            self.assertIn("prep.get('remote_start_monotonic') == " + repr(m.OLD_START), raw)
            self.assertNotIn('The package clock is the original E112', raw)

    def test_derived_driver_requires_exact_encoded_token_and_rejects_unknown_duplicate_indent(self):
        with inert(self.bundle) as modules:
            artifacts = modules['prospective_generation_artifacts_e117']
            uid = 'aes_core:HF:h1:H'
            binding = dict(task_uid=uid, request=dict(control=dict(kind='PATTERN_LIMIT', value=1)))
            envelope = dict(stage='H')
            base = (b'MAPPED_COMMON_ATPG_STATUS=PASS\nMAPPED_COMMON_ATPG_MODE=H\n' +
                ('MAPPED_COMMON_ATPG_RUN_ID=' + uid + '\nATPG_PATTERN_LIMIT=1\n').encode('ascii'))
            token = ('TOOL_DESIGN_ID_TOKEN=' + m.identifiers.encode(uid) + '\n').encode('ascii')
            artifacts.validate_driver(base + token, binding, envelope)
            for bad in (base, base + token + token, base + b' ' + token,
                        base + b'TOOL_DESIGN_ID_TOKEN=wrong\n', base + token + b'TOOL_DESIGN_ID_TOKEN_UNKNOWN=x\n'):
                with self.assertRaises(ValueError):
                    artifacts.validate_driver(bad, binding, envelope)

    def test_policy_preserves_all_six_startup_and_generation_rules(self):
        old = json.loads((self.repo / 'contracts/prospective_generation_diagnostics_e120_v1.json').read_bytes())
        new = json.loads(self.bundle['policy_bytes'])
        changed = {key for key in old if old[key] != new[key]}
        self.assertEqual(changed, {'effective_tcl_base64'})
        self.assertEqual(set(new) - set(old), {'execution_source_derivation'})
        self.assertEqual(new['startup'], old['startup'])
        self.assertEqual(new['generation'], old['generation'])
        self.assertEqual(new['source_pins'], old['source_pins'])
        with inert(self.bundle) as modules:
            gate = modules['prospective_generation_diagnostics_e120'].build_gate(self.bundle['policy_bytes'])
            self.assertTrue(callable(gate))
            recipe = modules['prospective_generation_recipe_e108']
            self.assertNotEqual(recipe.SOURCE_PINS['common'][2], recipe.EXECUTION_SOURCE_PINS['common'][2])

    def test_full_78_task_controller_mock_uses_real_derived_freeze_and_preserves_run_uids(self):
        repo, common, incremental = self.repo, self.common, self.incremental
        manifests = repo / 'data/manifests'
        raws = [(manifests / ('ranking_v6_' + key + '_input_observation_20261023_r1.json')).read_bytes()
                for key in ('e85', 'e88', 'e93')]
        e112 = (repo.parent / 'runtime_training_staging_20260928/v6_e112_preparation_20261026_r1/stdout.json').read_bytes()
        authority = (repo / 'contracts/prospective_identifier_repair_authorization_e124_20261027.json').read_bytes()
        with inert(self.bundle) as modules:
            recipe = modules['prospective_generation_recipe_e108']
            controller = modules['prospective_generation_controller_e116']
            process = modules['prospective_generation_process_e113']
            observations = []
            class Maker(object):
                def __init__(self, r85, r88, r93, base_common, base_incremental, admit):
                    self.admit = admit
                    self.e85 = json.loads(r85.decode('ascii'))
                    self.sources = recipe.freeze_sources(base_common, base_incremental)
                    recipe._sources(self.sources)
                    self.common = {row['circuit']: row['files'] for row in json.loads(r88.decode('ascii'))['roots']}
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
                    recipe._sources(self.sources)
                    envelope = recipe.compile_execution(freeze, binding, self.sources)
                    self.preparations.append((copy.deepcopy(binding), envelope))
                    return dict(prereq_dir=recipe.ROOT + '/' + binding['circuit'] + '/runs/' +
                        binding['request']['run_uid'] + '/attempts/_prereq/' + binding['task_uid'])
                def prepare_translation(self, freeze, binding):
                    self.admit({})
                    return dict(prereq_dir=recipe.ROOT + '/mock-owned-translation')
                def close(self):
                    pass
            def callback(binding, *args):
                return m.canonical(dict(task_uid=binding['task_uid'])), dict(
                    binding_sha256=binding['binding_sha256'], validation_passed=True, output_authenticated_claim=True)
            def observe(launch, end, domain, budget, on_spawn, monitor):
                identity = dict(schema=process.IDENTITY_SCHEMA, boot_id=CONFIG['BOOT_ID'],
                    launch_spec_sha256=launch['launch_spec_sha256'], environment_sha256=launch['environment_sha256'],
                    effective_envelope_sha256=launch['effective_envelope_sha256'])
                identity['identity_sha256'] = m.sha(m.canonical(identity))
                on_spawn(identity)
                value = dict(schema=process.SCHEMA, launch_spec_sha256=launch['launch_spec_sha256'],
                    environment_sha256=launch['environment_sha256'], effective_envelope_sha256=launch['effective_envelope_sha256'],
                    launch_attempted=True, known_process_handle=True, returncode=0, failure=None, cleaned=True,
                    output=b'MOCK_ONLY', spawn_identity=identity, spawn_identity_persisted_claim=True,
                    physical_process_identity_observed=True)
                observations.append(value)
                return value
            monitor = mock.Mock()
            monitor.sample.return_value = dict(root=m.ROOT, sidecar=m.ROOT + '.initial_intent.json',
                sidecar_accounted=True, threshold_bytes=8589934592, sampled_named_bytes=1)
            tests = lambda ctx: [dict(case=name, passed=True, cleaned=True, authenticated_claim=True,
                actual_linux_process=True) for name in ('success', 'timeout', 'setsid_child')]
            with mock.patch('subprocess.Popen') as spawn, \
                    mock.patch.object(controller.material, 'Materializer', Maker), \
                    mock.patch.object(controller.material, '_hash_file', side_effect=lambda path, size:
                        dict(path=path, bytes=size, sha256=controller.material.pins.LAUNCHER_SHA256)), \
                    mock.patch.object(controller.runtime, 'prepare_runtime', return_value=({'PATH': '/usr/bin:/bin'}, {})), \
                    mock.patch.object(process.direct, 'Descendants', return_value=mock.Mock(peak=123)), \
                    mock.patch.object(process, '_check_worker'), \
                    mock.patch.object(process, '_boot_id', return_value=CONFIG['BOOT_ID']), \
                    mock.patch.object(process, 'observe_tessent', side_effect=observe), \
                    mock.patch.object(controller.sys, 'platform', 'linux'), \
                    mock.patch.object(controller.platform, 'node', return_value='bupt-vncs2'), \
                    mock.patch.object(controller.os, 'getuid', return_value=1047, create=True), \
                    mock.patch.object(controller.time, 'monotonic', return_value=101):
                obj = controller.Controller(authority, e112, *(raws + [common, incremental, {},
                    lambda raw: dict(path=m.ROOT + '.initial_intent.json', bytes=len(raw), sha256=m.sha(raw)),
                    tests, monitor, callback, callback,
                    dict(implementation_review_passed_claim=True, independent_review_passed_claim=True)]))
                result = obj.run()
                spawn.assert_not_called()
            self.assertEqual(result['status'], 'FIXED_78_TASKS_COLLECTED', result['error'])
            self.assertEqual(result['counts']['committed_tasks'], 78)
            self.assertEqual(result['counts']['translation_debited'], 30)
            self.assertEqual(len(observations), 48)
            for binding, envelope in obj.maker.preparations:
                self.assertEqual(binding['request']['run_uid'], 'e116-' + binding['circuit'])
                self.assertEqual(envelope['env']['RUN_ID'], binding['task_uid'])
                self.assertIn('/runs/e116-' + binding['circuit'] + '/', envelope['result_dir'])
                self.assertTrue(envelope['result_dir'].startswith(m.ROOT + '/'))

    def test_real_new_context_source_is_inert_until_bound_to_real_authority(self):
        bundle = m.build_sources(worker_source_bytes=WORKER)
        authority = (self.repo / 'contracts/prospective_identifier_repair_authorization_e124_20261027.json').read_bytes()
        injected = dict(authority_bytes=authority, boot_id=CONFIG['BOOT_ID'],
                        start_monotonic=100.0, current_monotonic=101.0)
        with mock.patch('subprocess.Popen') as spawn, inert(bundle, injected) as modules:
            bound = modules[m.CONTEXT_NAME].CONFIG
            self.assertEqual(bound['AUTH_SHA256'], m.AUTH_SHA256)
            self.assertEqual(bound['ROOT'], m.ROOT)
            self.assertEqual(bound['PACKAGE_END'], 50500)
            self.assertEqual(modules['prospective_generation_controller_e116'].PACKAGE_START, 100)
            with self.assertRaises(TypeError):
                bound['PACKAGE_START'] = 500
            spawn.assert_not_called()

    def test_origin_drift_or_unknown_roster_is_failclosed(self):
        original = m._read
        def drift(repo, relative, pin=None):
            raw = original(repo, relative, pin)
            if relative == 'src/data/prospective_generation_recipe_e108.py':
                return raw.replace(b"ROOT='", b"ROOT='tampered-")
            return raw
        with mock.patch.object(m, '_read', side_effect=drift):
            with self.assertRaises(ValueError):
                m.build_sources(CONTEXT, WORKER)

    def test_all_derived_sources_and_owned_files_python36(self):
        for row in self.bundle['sources']:
            ast.parse(base64.b64decode(row['body']).decode('utf-8'), feature_version=(3, 6))
        for path in ('src/data/prospective_identifier_bundle_e124.py', 'tests/test_prospective_identifier_bundle_e124.py'):
            ast.parse((self.repo / path).read_text(), feature_version=(3, 6))
