"""Real local source graph, synthetic admission/clock; zero physical execution.

Only fixed local preparation reads files. Source tags are assigned by the real
verified loader to exact effective bytes, never fabricated. Test-only frozen
input maps and a conspicuously synthetic consistency record are not a grant,
review evidence or release. Invalid role1 data stops before host/clock/FS/tool.
"""
import ast
import base64
from contextlib import contextmanager, ExitStack
import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest import mock

from scripts import e138_deployment_materials as materials
from scripts import e138_source_session as loader
from scripts import e139_native_graph_candidate as m

REPO = Path(__file__).resolve().parents[1]
sha = lambda raw: hashlib.sha256(raw).hexdigest()


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prepared = materials.prepare()
        if prepared.public_summary()['status'] != 'READY_LOCAL_MATERIALS_ONLY':
            raise AssertionError('Fixed local materials unavailable; no substitutions allowed')
        cls.material = prepared.private_bytes()
        cls.sources = {name: raw for bundle in cls.material['roles'].values()
                       for name, raw in bundle['sources'].items()}
        cls.result = m.build(cls.sources)
        cls.effective = cls.result.private_sources()
        cls.pins = {row['name']: row['effective_sha256'] for row in cls.result.public_manifest()['sources']}
        cls.proposal = (REPO / 'contracts/physical_f_clean_replay_proposal_e139_v1.json').read_bytes()

    def snapshot(self):
        return {k: v for k, v in sys.modules.items() if k == 'src' or k.startswith('src.')}

    @contextmanager
    def session(self):
        rows = m.source_rows(self.sources)
        before = self.snapshot()
        old_pins, old_order = loader.FROZEN_SOURCE_SHA256, loader.FROZEN_SOURCE_ORDER
        try:
            with mock.patch.object(loader, 'FROZEN_SOURCE_SHA256', dict(self.pins)), \
                 mock.patch.object(loader, 'FROZEN_SOURCE_ORDER', m.SOURCE_ORDER):
                with loader.source_session(rows) as loaded:
                    yield loaded
        finally:
            self.assertEqual(before, self.snapshot())
            self.assertIs(loader.FROZEN_SOURCE_SHA256, old_pins)
            self.assertIs(loader.FROZEN_SOURCE_ORDER, old_order)
            self.assertFalse(loader._ACTIVE)

    def test_all_literal_pins_counts_syntax_and_exact_helper_identity(self):
        spec = m.specification()
        self.assertEqual(len(spec['origins']), 56)
        self.assertEqual(set(self.sources), set(m.SOURCE_ORDER))
        for row in spec['origins']:
            name = row['name']
            self.assertEqual(sha(self.sources[name]), row['sha256'])
            self.assertEqual(sha(self.effective[name]), row['effective_sha256'])
            ast.parse(self.effective[name], feature_version=(3, 6))
        for rule in spec['rules']:
            self.assertEqual(self.sources[rule['source']].count(bytes.fromhex(rule['old_hex'])), rule['count'])
        for name in m.UNCHANGED_PINS:
            self.assertEqual(self.sources[name], self.effective[name])
        for name, raw in self.sources.items():
            self.assertEqual(raw, (REPO / 'src/data' / (name + '.py')).read_bytes())

    def test_derived_only_build_zero_io_compile_registry_and_failclosed(self):
        before = self.snapshot()
        with mock.patch('builtins.open') as opened, mock.patch('builtins.compile') as compiled:
            result = m.build(self.sources)
            rows = m.source_rows(self.sources)
        opened.assert_not_called(); compiled.assert_not_called()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(tuple(r['name'] for r in rows), m.SOURCE_ORDER)
        self.assertFalse(result.public_manifest()['native_graph']['execution_ready'])
        bad = dict(self.sources); bad['physical_e138_contract'] += b' '
        for sources in (bad, dict(self.sources, unknown=b'x'), {}):
            with self.assertRaises(ValueError):
                m.build(sources)

    def test_actual_loader_and_private_components_share_effective_contract(self):
        with self.session() as loaded, mock.patch('builtins.open') as opened, \
             mock.patch('subprocess.Popen') as spawn:
            contract = loaded['physical_e138_contract']
            assembler = loaded['physical_e138_batch_assembler']
            self.assertIsNone(contract.FROZEN)
            self.assertEqual(contract.ROOT, m.pair.ROOT_NEW)
            for name, module in loaded.items():
                self.assertEqual(module.__source_sha256__, self.pins[name])
            with mock.patch.object(assembler, 'FROZEN_SOURCE_SHA256', dict(self.pins)):
                components = assembler._components(self.effective)
            for component in components.values():
                if hasattr(component, 'contract'):
                    self.assertIs(component.contract, contract)
            self.assertEqual(components['bootstrap'].ROOT, contract.ROOT)
            self.assertEqual(components['bootstrap'].PHASE, contract.PHASE)
            self.assertIs(components['roots'].worker, components['runtime'])
            self.assertIs(components['collector'].binding, components['binding'])
            components['capture']._source_bindings()
            self.assertEqual(components['capture'].DEPENDENCY_SHA256['physical_e138_contract'],
                             self.pins['physical_e138_contract'])
            self.assertEqual(loaded['physical_e138_role2_join'].runtime.SCHEMA,
                             components['runtime'].SCHEMA)
            self.assertIs(loaded['physical_e138_role3_export'].contract, contract)
            self.assertIs(loaded['physical_e138_readback_runtime'].contract, contract)
            for node in (components['runtime'], loaded['physical_e138_runtime_primitives']):
                self.assertIsNone(node.FACTORY_FREEZE)
            self.assertIsNone(loaded['physical_e138_batch_candidate'].AUTH_SHA256)
        opened.assert_not_called(); spawn.assert_not_called()

    def test_actual_recipe_main_helper_inherit_new_root_with_science_preserved(self):
        with self.session() as loaded:
            recipe = loaded['physical_f_replay_recipe_e138']
            inputs = self.material['execution_inputs']
            parent = recipe.parent.build_candidate(inputs['incremental'], inputs['parent_helper'])
            result = recipe.build_candidate(inputs['incremental'], inputs['parent_helper'])
            self.assertEqual(result['schema'], 'physical-f-clean-replay-recipe-e139-candidate-v1')
            for body_key, pin_key in (('body', 'sha256'),
                                      ('baseline_expectations_body', 'baseline_expectations_sha256')):
                raw = result[body_key]
                self.assertEqual(sha(raw), result[pin_key])
                self.assertIn(m.pair.ROOT_NEW.encode(), raw)
                self.assertNotIn(m.pair.ROOT_OLD.encode(), raw)
                self.assertNotIn(recipe.parent.ROOT.encode(), raw)
                self.assertEqual(raw.replace(m.pair.ROOT_NEW.encode(), recipe.parent.ROOT.encode()), parent[body_key])
            self.assertFalse(result['execution_authorized'])

    def synthetic_inputs(self, loaded):
        c = loaded['physical_e138_contract']
        runtime = loaded['physical_e138_runtime_primitives']
        package = dict(self.material['execution_inputs'])
        package.update(proposal=self.proposal, policy=c.canonical(c.POLICY),
            authority=c.canonical(dict(schema='e139-explicit-whole-package-authorization-v1',
                approved_package='E139', approval_source='explicit_user_reply',
                user_reply='SYNTHETIC UNIT TEST ONLY - NOT USER CONSENT - 中文“原话”',
                user_authorization_received=True, proposal_sha256=sha(self.proposal),
                approved_scope=copy.deepcopy(c.POLICY), execution_ready=False)),
            role1_response=b'{}', role2_intent=b'{}')
        for key, name in loaded['physical_e138_batch_assembler'].INPUT_SOURCES.items():
            package[key] = self.effective[name]
        # Pure clock consistency only. No real clock/domain sampling.
        package['original_clock'] = c.canonical(dict(schema=runtime.CLOCK_SCHEMA,
            authorization_sha256=sha(package['authority']), proposal_sha256=sha(package['proposal']),
            reader_payload_sha256='3'*64, initial_response_sha256='4'*64, start_file_sha256='5'*64,
            boot_id='3ebeb9bb-410c-476c-a000-5c625f590473', root=c.ROOT, phase=c.PHASE,
            remote_start_monotonic=1000., remote_deadline_monotonic=4600.,
            remote_clock_sample_monotonic=1001., remote_utc_sample='2026-10-30T00:00:01.000000+0000',
            local_utc_start='2026-10-30T00:00:00.000000+0000',
            local_utc_deadline='2026-10-30T01:00:00.000000+0000',
            local_monotonic_start=800000., local_monotonic_deadline=803600.,
            local_clock_domain=dict(host='SYNTHETIC', clock='NO_CLOCK_SAMPLED')))
        return package

    @contextmanager
    def synthetic_freeze(self, loaded, package):
        c = loaded['physical_e138_contract']
        a = loaded['physical_e138_batch_assembler']
        freeze = dict(authorization_sha256=sha(package['authority']), proposal_sha256=sha(package['proposal']),
            policy_sha256=sha(package['policy']), payload_sha256='a'*64,
            input_sha256={k: sha(v) for k, v in package.items()},
            source_sha256=dict(self.pins), source_order=m.SOURCE_ORDER)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(c, 'FROZEN', freeze))
            stack.enter_context(mock.patch.object(c, 'LOADED_SOURCE_ORDER', m.SOURCE_ORDER))
            for attr, key in (('AUTH_SHA256','authorization_sha256'), ('PROPOSAL_SHA256','proposal_sha256'),
                    ('POLICY_SHA256','policy_sha256'), ('PAYLOAD_SHA256','payload_sha256'),
                    ('FROZEN_INPUT_SHA256','input_sha256'), ('FROZEN_SOURCE_SHA256','source_sha256')):
                stack.enter_context(mock.patch.object(a, attr, freeze[key]))
            yield a

    def test_actual_admission_pin_propagation_then_pretool_stop_without_fake_source_tags(self):
        with self.session() as loaded:
            package = self.synthetic_inputs(loaded)
            with self.synthetic_freeze(loaded, package) as assembler, \
                 mock.patch('builtins.open') as opened, mock.patch('subprocess.Popen') as spawn, \
                 mock.patch.object(assembler.platform, 'node') as host, \
                 mock.patch.object(assembler.time, 'monotonic') as now:
                admitted = assembler.admission(package, self.effective)
                self.assertEqual(admitted['package'], 'E139')
                self.assertFalse(admitted['execution_ready'])
                self.assertEqual(admitted['source_manifest_sha256'], sha(assembler.canonical(self.pins)))
                result = assembler.execute(package, self.effective, 2000.)
                self.assertEqual(result['worker_response']['schema'], 'physical-f-clean-replay-execution-e139-v1')
                self.assertEqual(result['worker_response']['launch_debit'], 0)
                self.assertTrue(result['worker_response']['attempt_consumed'])
                self.assertIsNone(result['owned_root'])
                self.assertFalse(result['execution_ready'])
                self.assertEqual(result['worker_response']['diagnostic']['stage_attempted'], 'ADMISSION')
            opened.assert_not_called(); spawn.assert_not_called(); host.assert_not_called(); now.assert_not_called()

    def test_actual_source_crossjoin_rejects_old_bytes_even_with_test_input_freeze(self):
        with self.session() as loaded:
            package = self.synthetic_inputs(loaded)
            package['worker_source'] = self.sources['physical_e138_runtime_primitives']
            with self.synthetic_freeze(loaded, package) as assembler:
                with self.assertRaisesRegex(ValueError, 'E138_ASSEMBLER_INPUT_SOURCE_CROSSJOIN'):
                    assembler.admission(package, self.effective)
            self.assertIsNone(loaded['physical_e138_contract'].FROZEN)

    def test_actual_bootstrap_ascii_unicode_context_json_and_source_binding_prehost_stops(self):
        for stage in ('CONTEXT_JSON', 'ARGUMENTS'):
            with self.subTest(stage=stage), self.session() as loaded:
                inputs = self.synthetic_inputs(loaded)
                bootstrap = loaded['physical_runtime_bootstrap_e138']
                c = loaded['physical_e138_contract']
                context = b'not JSON' if stage == 'CONTEXT_JSON' else c.canonical(dict(
                    role='execution', authorization_sha256=sha(inputs['authority']),
                    boot_id='3ebeb9bb-410c-476c-a000-5c625f590473', package_start=1000.,
                    package_end=4600., connection_start=2000., utc_end=9000., root=c.ROOT, phase=c.PHASE))
                package = dict(authority=inputs['authority'], proposal=inputs['proposal'], context=context,
                    e112=inputs['e112'], worker_source=inputs['parent_worker_source'], profile_source=inputs['profile_source'])
                frozen = dict(authorization_sha256=sha(package['authority']), proposal_sha256=sha(package['proposal']),
                    context_sha256=sha(context), expected_boot_id='3ebeb9bb-410c-476c-a000-5c625f590473',
                    root=c.ROOT, phase=c.PHASE)
                evidence = {}
                tick = mock.Mock()
                self.assertTrue(package['authority'].isascii())
                self.assertIn('中文“原话”', bootstrap.decode(package['authority'])['user_reply'])
                with ExitStack() as stack:
                    for attr, key in (('AUTH_SHA256','authorization_sha256'), ('PROPOSAL_SHA256','proposal_sha256'),
                                      ('CONTEXT_SHA256','context_sha256'), ('EXPECTED_BOOT_ID','expected_boot_id')):
                        stack.enter_context(mock.patch.object(bootstrap, attr, frozen[key]))
                    host = stack.enter_context(mock.patch.object(bootstrap.platform, 'node'))
                    supervise = stack.enter_context(mock.patch.object(bootstrap.direct.base, 'supervise'))
                    now = stack.enter_context(mock.patch.object(bootstrap.time, 'monotonic'))
                    opened = stack.enter_context(mock.patch('builtins.open'))
                    with self.assertRaisesRegex(ValueError, '^E138_BOOTSTRAP_' + stage + '_FAILED$'):
                        bootstrap.bootstrap(package, None, tick, frozen, evidence)
                host.assert_not_called(); supervise.assert_not_called(); now.assert_not_called()
                opened.assert_not_called(); tick.assert_not_called()
                self.assertEqual(evidence['schema'], 'e139-private-runtime-bootstrap-v1')
                self.assertEqual(loaded['physical_e138_batch_assembler']._bootstrap_failure(evidence), evidence)
                self.assertEqual(evidence['bootstrap_children'], 0)
                self.assertFalse(evidence['execution_ready'])

    def test_session_exception_restores_registry_and_loader_freeze(self):
        with self.assertRaisesRegex(RuntimeError, 'synthetic-body-failure'):
            with self.session():
                raise RuntimeError('synthetic-body-failure')


if __name__ == '__main__':
    unittest.main()
